# Local Username And Password Authentication

Read this for registration, login, self password change, administrator reset,
temporary-password completion, or the sole-super-admin offline recovery.
For quota numbers read [Rate limiting](rate-limiting.md); for required images
read [Graphical CAPTCHA](verification-and-abuse-defense.md); for JWT/JTI read
[JWT security](jwt-session-security.md). Existing applications retain an
intentional different identity contract unless the owner requests migration.

## Ask Only Product Choices

For a new project, default to `user_name` plus password, public registration
enabled, no self-service forgot-password endpoint, and no email/phone field or
delivery provider. Before implementation, ask in one batch:

1. Is username comparison case-sensitive? Require the owner to choose; neither
   behavior is a generic recommendation and `全部接受` / `Accept all` cannot
   choose it. Leading/trailing spaces always trim, and deleted usernames remain
   permanently reserved.
2. Besides length 8..60 characters, must the password contain uppercase,
   lowercase, digits, or symbols? Each composition condition defaults to no.
3. What is the maximum simultaneously active login count for one user? The
   number is the project's choice and must be a positive integer. Do not invent
   or recommend a generic number, and do not let `全部接受` / `Accept all` supply
   a missing number. When full, a successful new login atomically evicts the
   oldest. These are Redis login records and timestamps, not a physical-device
   inventory.
4. Which project-wide administrator password-reset mode applies? Default to
   `direct`: the administrator supplies a new permanent password and the user
   may log in without another password-change step. It is simpler, but the
   administrator knows and must privately deliver the final password. Offer
   `temporary`: the supplied password may only complete one formal-password
   setup. It adds one step, but the user chooses the final password. Explain both
   and require a choice before generation; a request body never selects the mode.
5. If existing users have no password, how will an administrator verify and
   enroll them? Reuse the selected administrator-reset mode unless the owner
   explicitly chooses a different controlled enrollment; never use a shared
   initial password.

Show quota defaults together and allow the user to accept them or name changes.
Do not ask repeatedly about already decided product facts. `iss`/`aud` require
their own explicit consent as described in [JWT security](jwt-session-security.md).
Tell the owner separately that Access Tokens default to 3600 seconds and point
to the setting; this is a required notice, not another blocking choice unless
the owner asks to change it.

## Username And Password Policy

- Trim username edges before registration, login, administrator creation, and
  lookup. After trim, require exactly 3..32 ASCII characters matching
  `[A-Za-z0-9_]{3,32}`. Ask whether username case matters; use the same
  canonical value in storage, uniqueness, login, and comparison. Never NFKC
  incompatible text into this allowed set.
- Reject the 12 complete names `admin`, `administrator`, `root`, `superadmin`,
  `super_admin`, `sysadmin`, `system`, `support`, `user`, `test`, `guest`, and
  `ceshi` irrespective of case. A longer name merely containing one is not
  prohibited. Say "该用户名不可使用，请更换" for a reserved name and
  "用户名已被占用" for an existing or soft-deleted name.
- Password creation defaults to 8..60 Unicode characters. Do not trim,
  case-fold, or normalize the password; reject control characters and invalid
  Unicode before hashing. Composition rules above are project choices, not
  automatic requirements. Reject only a password consisting wholly of a
  consecutive ascending/descending numeral or ASCII letter sequence, a
  repetition of one character, or exactly the complete username ignoring
  case. In the last case say "密码不能与用户名相同". Do not add a mandatory common
  password list or reject any password merely containing the username.
  Explain honestly that this small policy cannot detect every weak password.
- At login, permit existing passwords compatible with the original persisted
  policy, bounded against excessive input. Invalid, disabled, deleted, unknown,
  or password-less accounts perform real-or-dummy Argon2id work and all use one
  public `401001` failure. Keep the candidate password and hash out of logs,
  audit, and responses.

Use Argon2id off the async event loop, bounded concurrency, and a benchmarked
starting profile (memory 65536 KiB, time 3, parallelism 4, hash length 32,
salt length 16). `users.password_hash` is nullable, with
`must_change_password`, nullable `password_changed_at`, and `token_version`
on the same user row. There is no extra credential table, password-count field,
routine password expiry, or password-change version separate from
`token_version`. Soft-deleting an account clears its hash and tombstones roles;
restoration never revives old access or passwords. Pydantic password fields
use `SecretStr` and `writeOnly`, with `Cache-Control: no-store` on all auth
responses. An Argon2 parameter rehash, if implemented, is not a password
change and cannot undo a concurrent credential rotation.

## Public And Protected Commands

All commands use `POST`, normal four-field JSON envelope and server request ID.
Only listed authentication routes may be anonymous; all ordinary business
reads, writes, and administrator APIs first authenticate.

| Operation | Requirements and outcome |
| --- | --- |
| `GET /api/v1/auth/registration/status` | Public; returns only `registration_enabled` from persisted server state. |
| `POST /api/v1/auth/registration/status` | Current `super_admin` only; updates the persisted registration switch. |
| `POST /api/v1/auth/captcha` | Public; issues or refreshes only the `login` or `register` scene. |
| `POST /api/v1/me/captcha` | Authenticated; issues or refreshes only the `admin_create`, `admin_reset`, or `self_change` scene for the current actor. |
| `POST /api/v1/auth/register` | Public while registration enabled (default on); scene `register` CAPTCHA, per-IP limit, server-side toggle recheck in creation transaction; creates user, initial `user` assignment, password and audits together; returns ID only, never auto-login. When closed, return "暂未开放注册". |
| `POST /api/v1/auth/login` | Scene `login` CAPTCHA, per-IP limit, real/dummy password check, active account reload, then minimal JWT registered as a Redis active JTI. A temporary credential returns password-change-required and no Token. |
| `POST /api/v1/auth/password/reset/complete` | Public for a temporary credential from administrator user creation or the optional `temporary` reset mode; separate trusted-IP quota, verifies the temporary password, sets a new permanent hash and revokes old Tokens. It is **not** an anonymous forgot-password or ownership-proof endpoint. |
| `POST /api/v1/me/password/change` | Authenticated; scene `self_change` CAPTCHA and current password required; rotate hash, clear temporary flag, increment `token_version`, and audit in one PostgreSQL transaction. No replacement Token. |
| `POST /api/v1/users` | Administrator with creation capability; scene `admin_create` CAPTCHA; supplies a temporary password to deliver through a trusted offline channel. Creates only `user` regardless of registration switch. |
| `POST /api/v1/users/{user_id}/password/reset` | Administrator with exact reset capability; scene `admin_reset` CAPTCHA, locked actor/target recheck and strict lower-target rule. The request always supplies `new_password`; project setting `ADMIN_PASSWORD_RESET_MODE`, never a client field, decides whether it is permanent (`direct`, default) or requires one completion (`temporary`). Both modes increment target token version and audit. Do not ask for the actor's password again. |
| `POST /api/v1/auth/logout` | Any authenticated user revokes only the presented active JTI. There is no self-service logout-all command. |
| `POST /api/v1/users/{user_id}/sessions/revoke` | Only an administrator with capability may force a strictly lower user's active logins out, with locked hierarchy and security audit; it cannot target self, peers, or higher identities. |

The registration switch has a super-admin-only `POST` command. Never trust a
frontend toggle alone; the backend checks persisted state inside the actual
registration transaction. Existing login and administrator creation continue
when the public switch is closed. An initial account from either creation path
always gets exactly `user` and never accepts a requested role, tier, protection,
or JWT claim from the request.

For any password mutation, do Argon2 work outside locks; then lock the shared
`rbac_state` guard, reload actor/target/old hash and authority, reject races,
update hash/timestamp/token version, and stage account-security audit in one
PostgreSQL transaction. A failed allowed-audit insertion rolls back the
mutation. A denied-audit failure never replaces the original denial with `500`.
Never do Redis I/O while holding authorization locks.

Administrator reset is a project-wide choice, not a per-request switch. In the
default `direct` mode, the supplied value immediately becomes the permanent
password and `must_change_password` is false. In `temporary` mode it is true,
so login issues no Token until the user successfully completes one formal
password setup. That temporary credential does **not** expire on a timer: it
remains valid until successful completion, another reset, or account deletion.
In both modes the administrator must deliver the password privately; the API,
logs, and audit rows never echo it. A person who forgot a password contacts an
administrator for identity verification outside the API. The sole `super_admin`
is recovered only from a trusted host using the supplied interactive operator command
(hidden input, immutable user ID, locked check, audit). There is no
email/SMS provider or anonymous self-service reset route.
Administrator-created users and this sole-super-admin operator recovery always use
temporary credentials.
`ADMIN_PASSWORD_RESET_MODE` controls only the administrator HTTP reset of an
existing ordinary target.

On a login success, Redis atomically registers the JTI and maintains an index
of valid active logins with login times. A required project-chosen positive
maximum determines whether to evict the oldest session on a new issuance.
Failed new issuance must never log out an older session. Password rotation and
administrator revocation invalidate existing records through
`users.token_version`; stale indexed JTIs must not count against the new
version. This Redis index is not a PostgreSQL Token/session table.

## Verification

Test username normalization and full-name denylist, the three simple weak
password patterns, Argon2 work, CAPTCHA for all five protected actions,
registration on/off and stale-page submission, only-`user` registration,
generic login errors, default direct reset, optional one-use temporary reset,
actor reauthentication only for self-change, admin strict-target rules, atomic hash/audit commits,
and absent self logout-all/forgot-password routes. Test real Redis session
count, independent login times, oldest eviction after successful issuance,
concurrent issuance, and version-change invalidation; also test PostgreSQL
rollback and secret-free logs/responses. See [Testing](testing.md).
