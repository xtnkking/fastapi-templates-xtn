# Local Username And Password Authentication

Read this for registration, login, self password change, administrator reset,
or the sole-super-admin offline recovery.
For quota numbers read [Rate limiting](rate-limiting.md); for required images
read [Graphical CAPTCHA](verification-and-abuse-defense.md); for JWT/JTI read
[JWT security](jwt-session-security.md). Existing applications retain an
intentional different identity contract unless the owner requests migration.

## Ask Only Product Choices

For a new project, default to `user_name` plus password, public registration
without an enable/disable switch, no self-service forgot-password endpoint, and no email/phone field or
delivery provider. Before implementation, ask in one batch:

1. Is username comparison case-sensitive? Require the owner to choose; neither
   behavior is a generic recommendation and `全部接受` / `Accept all` cannot
   choose it. Leading/trailing spaces always trim, and deleted usernames remain
   permanently reserved.
2. Besides length 8..32 characters, must the password contain uppercase,
   lowercase, digits, or symbols? Each composition condition defaults to no.
3. What is the maximum simultaneously active login count for one user? The
   number is the project's choice and must be a positive integer. Do not invent
   or recommend a generic number, and do not let `全部接受` / `Accept all` supply
   a missing number. When full, a successful new login atomically evicts the
   oldest. These are Redis login records and timestamps, not a physical-device
   inventory.
4. If existing users have no password, how will an administrator verify and
   enroll them? The administrator may set a new password after verifying their
   identity outside the API; never use a shared initial password.

Show quota defaults together and allow the user to accept them or name changes.
Do not ask repeatedly about already decided product facts. `iss`/`aud` require
their own explicit consent as described in [JWT security](jwt-session-security.md).
Tell the owner separately that Access Tokens default to 86,400 seconds (24
hours) and point to the setting; this is a required notice, not another blocking
choice unless the owner asks to change it.

Application soft deletion cannot stop a database owner running direct SQL.
Explain this limitation; database-account permissions belong to the owner or
operations. Ask about a professional operations team only when production
database permissions are actually in scope, not as a prerequisite to generating
authentication code. See [Identity lifecycle](identity-soft-delete.md#direct-sql-and-deployment-choice).

## Username And Password Policy

- `app/core/security/user_name.py` owns username configuration: minimum/maximum
  length, allowed character range and its Chinese/English labels, the derived
  pattern, reserved names and the `validate_user_name` entry point, which trims
  whitespace, validates the rules and returns the checked username. Request schemas, username query
  parameters, ORM column/check definitions and localized format messages reuse
  it. Change length there instead of editing each consumer. If allowed
  characters change, update their two labels in that same file as well.
  These are code rules, not `.env` settings. Restart after changing them;
  existing database columns/constraints require a user-owned migration and do
  not change just because the Python constants changed.
- Trim username edges before registration, login, administrator creation, and
  lookup. After trim, require exactly 3..32 ASCII characters matching
  `[A-Za-z0-9_]{3,32}`. Ask whether username case matters; use the same
  canonical value in storage, uniqueness, login, and comparison. Never NFKC
  incompatible text into this allowed set.
- Reject complete names in `core/security/user_name.py::RESERVED_USER_NAMES`
  irrespective of case. The single list groups system identities, official and
  support identities, development technologies and tools, data services,
  infrastructure, and development/test placeholders. Maintain the list only in
  that file; examples include `admin`, `admins`, `kefu`, `data`, `python`, `mysql`,
  `php` and `java`. Also check the name after removing ASCII digits and
  underscores from both ends: `admin01`, `ADMIN_001`, `_admin_`, `01admin` and
  `python123` are rejected. Use the original and stripped names for at most two
  in-memory set lookups; do not iterate over the list or query a store for this
  check. This does not change the stored username. Names containing additional
  letters, such as `my_admin` and `admin_bob`, remain allowed by this check.
  Say "该用户名不可使用，请更换" for a reserved name and
  "用户名已被占用" for an existing or soft-deleted name.
- Password creation defaults to 8..32 visible ASCII characters (`!` through
  `~`, code points 33..126): English letters, digits and all ordinary ASCII
  punctuation are allowed; spaces, Chinese, emoji and invisible characters are
  not. Do not trim, case-fold, or normalize the password. The limited character
  set is for predictable input, not protection against SQL injection; continue
  storing only the Argon2id hash through structured database APIs. Composition
  rules above are project choices, not
  automatic requirements. Reject only a password consisting wholly of a
  consecutive ascending/descending numeral or ASCII letter sequence, a
  repetition of one character, or exactly the complete username ignoring
  case. In the last case say "密码不能与用户名相同". Do not add a mandatory common
  password list or reject any password merely containing the username.
  Explain honestly that this small policy cannot detect every weak password.
- HTTP password fields use two shared types from `schemas/common.py`, both
  based on `SecretStr` with direct `Field` constraints. Login `password` and
  self-change `current_password` use `Password`: nonempty text with an independent
  input ceiling, default 1024 characters. Registration, administrator creation,
  self-change `new_password` and administrator-reset `new_password` use
  `NewPassword`: the current password-setting length bounds, default 8..32
  characters. An out-of-range HTTP input returns request-validation code `42201`.
  Do not add `AfterValidator`, a custom length-validator wrapper, a third
  `ExistingPassword` alias or a separate module for these two field types.
  Password creation also checks the character, weak-password and chosen
  composition rules in the business policy. Login and current-password
  verification only check input type, nonempty value, valid UTF-8 and the
  independent input ceiling before checking the stored hash; they never apply
  new-password length, character or strength rules. Raising the new minimum or
  lowering the new maximum must not prevent an existing password from being
  verified, as long as it is within that independent input boundary.
  Invalid, disabled, deleted, unknown,
  or password-less accounts perform real-or-dummy Argon2id work and all use one
  public `40110` failure. Keep the candidate password and hash out of logs,
  audit, and responses.

`app/core/security/passwords.py` owns `MIN_PASSWORD_CHARACTERS` and
`MAX_PASSWORD_CHARACTERS` for newly set passwords, plus
`MAX_PASSWORD_INPUT_CHARACTERS` for login and old-password input. Change the
first two constants to adjust the new-password policy; the `NewPassword`
request constraints and Chinese field description use them directly.
The bilingual `error.password_length` entries use `{min_length}` and
`{max_length}` placeholders, filled from the same constants by the translation
function. Do not duplicate numeric ranges in active comments or catalog text.
Restart after changing source so request models reload the updated bounds;
maintain a separately developed frontend's input limits accordingly.
The input ceiling is a resource-protection boundary, not permission to set a
1024-character password. Keep it stable when changing the new-password policy.
For example, changing the new minimum from 8 to 10 still allows a valid existing
8-character password to log in or authorize a password change. If the owner
later allows new passwords longer than the input ceiling, first assess resource
cost and deliberately update that ceiling; do not silently synchronize the two
maximums or create passwords that the login input contract cannot accept.

Use Argon2id off the async event loop, bounded concurrency, and a benchmarked
starting profile (memory 65536 KiB, time 3, parallelism 4, hash length 32,
salt length 16). `users.password_hash` is nullable, with
nullable `password_changed_at` and `token_version`
on the same user row. There is no extra credential table, password-count field,
routine password expiry, or password-change version separate from
`token_version`. Soft-deleting an account clears its hash and tombstones roles;
restoration never revives old access or passwords. Pydantic password fields
use `SecretStr` and `writeOnly`, with `Cache-Control: no-store` on all auth
responses. An Argon2 parameter rehash, if implemented, is not a password
change and cannot undo a concurrent credential rotation.

`PasswordManager` bounds native password work within each worker process:
`PASSWORD_MAX_RUNNING=2` permits two calculations at once,
`PASSWORD_MAX_WAITING=4` permits four additional callers to wait, and
`PASSWORD_WAIT_TIMEOUT_SECONDS=0.5` bounds only the wait for a calculation slot.
An available slot starts immediately. A full queue or expired wait returns
HTTP `503`, business code `50301` and the bilingual service-busy message without
starting that calculation. Setting the waiting count to zero rejects immediately
when all running slots are occupied. A running native calculation keeps its
slot until it finishes, even if its caller is cancelled; do not pretend that an
async timeout stops the native thread. All PasswordManager hash and verification
entrypoints share this protection, including dummy verification and hash upgrades.
The three values live in `app/core/config.py` and `.env.example`; restart after
changing them. These are process-local resource limits, separate from Redis
business request counters, with no shared queue between workers or servers.
The preceding one-use CAPTCHA has already been consumed when a password task
is rejected as busy. Do not restore it or automatically retry the request;
the user obtains a new CAPTCHA before submitting again. See
[Capacity and availability](application-capacity-and-availability.md) for sizing.

## Public And Protected Commands

All commands use `POST`, a closed Pydantic JSON request body when input is
needed, the normal four-field JSON envelope and server request ID. Target user
IDs belong in that body, never the URL. Reads use `GET` with `/list` or
`/detail` suffixes and query parameters. Follow the
[request contract](api-response-standard.md#methods-paths-and-request-parameters).
Only listed authentication routes may be anonymous; all ordinary business
reads, writes, and administrator APIs first authenticate.

| Operation | Requirements and outcome |
| --- | --- |
| `POST /api/v1/auth/captcha` | Public; issues a new image for the `login` or `register` scene. |
| `POST /api/v1/me/captcha` | Authenticated; issues a new image for the `admin_create_user`, `admin_reset_user_password`, or `user_change_password` scene for the current user. |
| `POST /api/v1/auth/register` | Public without a registration switch; scene `register` CAPTCHA and per-IP limit; creates user, initial `user` assignment, password and audits together; returns ID only, never auto-login. |
| `POST /api/v1/auth/login` | Scene `login` CAPTCHA, per-IP limit, real/dummy password check, active account reload, then minimal JWT registered as a Redis active JTI. |
| `GET /api/v1/me/user_info` | Authenticated with `account:read`; returns only the current user's ID, role level and effective permissions. |
| `POST /api/v1/me/password/change` | Authenticated with `account:change_password`; scene `user_change_password` CAPTCHA and current password required; rotate hash, increment `token_version`, and audit in one PostgreSQL transaction. No replacement Token. |
| `POST /api/v1/users/create` | Administrator with creation capability; scene `admin_create_user` CAPTCHA; supplies a directly usable password to deliver through a trusted offline channel. Creates only `user`. |
| `POST /api/v1/users/password/reset` | JSON supplies `user_id`, the scene `admin_reset_user_password` CAPTCHA fields, and `new_password`. Administrator with exact reset capability, locked current user/target recheck and strict lower-target rule. The new password is directly usable; reset increments target token version and audits. Do not ask for the current user's password again. |
| `POST /api/v1/auth/logout` | Validate JWT and the presented active JTI, then revoke only that login; no quota, limiter-client dependency, PostgreSQL read or business-permission check. There is no self-service logout-all command. |
| `GET /api/v1/users/sessions/list?user_id=<id>` | Administrator with `users:read` may see the current login count and login times of a visible user; ordinary users have no default self-session-list route. Login records are not physical devices. |
| `POST /api/v1/users/sessions/logout-all` | JSON supplies `user_id`. Only an administrator with capability may force a strictly lower user's active logins out, with locked hierarchy and security audit; it cannot target self, peers, or higher identities. |

There is no registration-state read, update command, database field, or frontend
toggle contract in the default project. An initial account from either creation path
always gets exactly `user` and never accepts a requested role, tier, protection,
or JWT claim from the request.
The fixed `user` role grants `account:read` and `account:change_password`; both
keys are also explicitly present in the administrator role allowlists. These
two own-account routes use `require_permission` with ordinary user quotas,
not management quotas. CAPTCHA issuance still requires login without an
operation permission; receiving an image does not grant the later operation.

Registration and administrator creation validate and hash the initial password
outside database locks, then pass the required `password_hash` to
`UserService.create_user`. Its first INSERT sets both the hash and
`password_changed_at` using PostgreSQL `statement_timestamp()`; default-role
binding and one account-category creation audit remain in the caller's outer transaction.
Shared `create_user` performs the inserts without a second permission audit;
registration and administrator creation each record their own single result.
Do not create a user without a hash and then call `update_password` to finish
creation. Initial `token_version` remains zero.

Default-role lookup uses `RoleRepository.lock_role_by_key` with the fixed `user`
key to read and lock the role in one query; do not first fetch its ID and then
query it again. Creation checks that the locked role exists and is an active
system role; the query already excludes soft-deleted roles. Do not revalidate
its fixed tier, protection and super-admin flags against `SYSTEM_ROLE_SPECS`
during each creation. The Role model's
`user_role_shape` constraint owns those fixed attributes, and online role
management rejects changes to system roles. The user must install the declared
model constraints through their own database preparation.

Shared user creation owns username-conflict translation, including the insert
race after its pre-check. Both entrypoints retain their outer transaction and
use the shared business error directly; see
[reuse and abstraction](reuse-and-abstraction.md) for the exact constraint and
retry boundary.

`AuthService.register` accepts registration business inputs without a
`request_id` parameter; shared user creation and account audit construction also
read correlation automatically. HTTP middleware binds the server request ID
once, and the audit constructor obtains it through the no-argument
`core/audit.py::get_audit_request_id()`. A missing or inactive execution context
raises `RuntimeError` instead of creating an unrelated audit ID.

For existing-account password changes or resets, do Argon2 work outside locks;
then lock the shared
`rbac_state` guard, reload current user/target/old hash and authority, reject races,
update hash/timestamp/token version, and stage account-security audit in one
PostgreSQL transaction. A failed allowed-audit insertion rolls back the
mutation. A denied-audit failure never replaces the original denial with `500`.
Never do Redis I/O while holding authorization locks.

Administrator creation and reset set a directly usable password. The
administrator must deliver it privately; the API, logs, and audit rows never
echo it. A person who forgot a password contacts an
administrator for identity verification outside the API. The sole `super_admin`
is recovered only through a user-owned trusted offline procedure
(hidden input, immutable user ID, locked check, audit). The historical asset's
interactive operator command is maintenance reference and is not exported into
a new project. Do not generate or execute database initialization/migration
scripts as part of authentication implementation. There is no
email/SMS provider or anonymous self-service reset route.
Administrator-created users and sole-super-admin operator recovery also set
directly usable passwords; no temporary-password flow is included.
The maintenance command binds one `operator:<UUID>` operation ID at its entrypoint
and does not pass `request_id` to the password service. Its `finally` deactivates
and resets the context even when closing the database engine fails; other
non-HTTP entrypoints follow the same single-binding lifetime.

On a login success, Redis atomically registers the JTI and maintains an index
of valid active logins with login times. A required project-chosen positive
maximum determines whether to evict the oldest session on a new issuance.
Failed new issuance must never log out an older session. Password rotation and
administrator revocation invalidate existing records through
`users.token_version`; stale indexed JTIs must not count against the new
version. This Redis index is not a PostgreSQL Token/session table.

In the bundled asset, `AuthService.login` shows the login steps directly:
copy required account fields into `user_info` with `_build_user_info`, close its query session, verify the password
outside locks, then lock and recheck the current state. Close that database
transaction before calling `self.issue_access_token`, which signs through the
JWT codec and registers through `login_session_repository`.
Return `LoginResult` containing `user_id`, `access_token` and `expires_in` only
after confirmed active-JTI registration; a signing or registration failure
returns no login result. The route passes Redis, settings, username and password
to `login`, then constructs the normal HTTP response from that result. It does
not call the issuer itself or receive an intermediate password-only result.
Keep the single password verification and final locked recheck. A password hash,
account-state or revocation change during verification rejects the login;
do not retry or perform a second password verification, including when another
login merely upgraded the old hash parameters. That rare conflict requires a
new CAPTCHA and login request. A stale hash can still be upgraded when the
locked state and hash both match the verified `user_info`.
`_same_account_state` owns shared state comparison; compare the password hash
directly at the call site. Self-change uses `_verify_current_password`, which
reads its own `user_info` without a separate query wrapper.
Close that query session before verifying the old password. Password-input
errors and invalid account state share one denial-audit/403 branch; catch only
`InvalidLoginCredentialsError` from password verification. Database failures,
damaged stored hashes and password-work saturation remain service failures.
The private `_UserInfo` holds copied field values, including the password hash,
and must not enter logs or responses. Leaving the query's `async with` releases
the connection; copying values alone does not. Already-loaded ORM fields can be
read after closing the session, but this fixed copy keeps the pre-verification
values separate from the freshly locked ORM user used for database writes.
Do not hide the flow behind a forwarding method or move Redis I/O inside the
database transaction to make the steps appear contiguous.

## Verification

Test username normalization and full-name denylist, the three simple weak
password patterns, Argon2 work, CAPTCHA for all five protected actions,
public registration without a switch, only-`user` registration,
generic login errors, directly usable administrator creation/reset passwords,
current user reauthentication only for self-change, admin strict-target rules, atomic hash/audit commits,
and absent self logout-all/forgot-password routes. Test real Redis session
count, independent login times, oldest eviction after successful issuance,
concurrent issuance, and version-change invalidation; also test PostgreSQL
rollback and secret-free logs/responses. See [Testing](testing.md).
