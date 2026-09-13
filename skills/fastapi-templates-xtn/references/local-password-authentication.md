# Local Password Authentication

Load this reference for username/password registration or login, password
hashing, self-service password change, administrator reset, temporary
credentials, or account recovery. Also load the rate-limit reference when code
for any public authentication surface will be generated, the JWT reference when
a successful login issues an Access Token, and the atomic/audit references when
changing persistence behavior.

This baseline deliberately works without email, SMS, CAPTCHA, or MFA. It uses one
short-lived Access Token, requires authentication again after expiry, and has no
per-Token PostgreSQL table. The omitted verification features are separate
product choices.

## Ask The Product Questions Once

Ask only unresolved questions, in one batch, before generating public routes.
Send the actual questions, plain-language effect, and recommended answer in the
conversation; do not merely link this reference or name a setting. Let the user
reply `全部接受` / `Accept all` or list only overrides.

These are product decisions, not optional implementation trivia. When repository
evidence or an earlier explicit answer does not settle one, explain the practical
effect in plain language and wait for the answer. Do not treat a general request
to start, or `全部接受` given before this complete batch was displayed, as consent
to an unasked choice. Once the batch has been displayed, `全部接受` accepts exactly
the shown defaults; do not ask the same settled questions again.

| Product question | Why the user must decide | Recommended answer when the request is silent |
| --- | --- | --- |
| What identifies an account, and what may be typed at login? | This decides which fields must exist and whether a person signs in with a username, email, or either one. Guessing later creates ambiguous accounts and surprising login behavior. | Require `user_name`; keep `email` optional and do not accept it at login or use it for recovery. |
| How is `user_name` compared? | This decides whether `Alice`, `alice`, and names with surrounding spaces are the same account, and whether a deleted name may be claimed by someone else. | NFKC, trim surrounding whitespace, then case-fold; reserve a deleted name permanently. |
| Who may create an account? | This decides whether anybody on the internet gets a registration endpoint or only trusted administrators create accounts. | Keep public registration disabled unless the product explicitly asks for it; every public or ordinary administrative creation receives only the mandatory `user` role. |
| How is ownership proved during recovery? | Knowing a username does not prove who owns it. The product must name a trustworthy recovery channel before an anonymous reset endpoint can be safe. | Without a previously verified channel, use human verification and an administrator-issued temporary credential; provide no anonymous self-service recovery. |
| May one account have several logged-in devices? | This decides whether a second login logs out the first device or both sessions remain usable. | Yes; each login gets its own active Redis JTI, while password change/reset and logout-all revoke the whole account through `users.token_version`. |
| What happens to existing users that have no password credential? | A migration cannot invent a safe password. The product must decide how those people prove identity before receiving one. | Keep them unable to log in; enroll them through a controlled administrator reset, never a generated shared/default password. |

If the user chooses email or phone recovery, additionally settle whether that
address was verified before the account was lost, the delivery provider, code
purpose and lifetime, enumeration behavior, delivery/submit limits, and the
recovery result. Merely having an `email` column does not make it a verified
recovery channel. Do not accept a client boolean such as
`identity_verified=true` as proof.

Before adding optional JWT `iss` and `aud`, use the separate consent rule in the
Skill entrypoint. Before writing authentication rate-limit code, show the exact
applicable quota defaults from the rate-limit reference and obtain the required
single confirmation.

## Fixed Security Baseline

Do not make the user choose these implementation details unless existing project
requirements conflict:

- use Argon2id with memory cost `65536` KiB, time cost `3`, parallelism `4`,
  hash length `32`, and salt length `16` as the starting profile;
- benchmark the deployment before production and raise cost when its latency and
  memory budget allow it; never silently lower cost to make a test pass;
- offload every hash and verification from the async event loop and bound local
  hashing concurrency to `2` per worker by default;
- keep password work outside open PostgreSQL transactions and authorization
  locks;
- require new passwords to contain `15..128` Unicode code points and no more
  than `1024` UTF-8 bytes;
- hash the exact password string: do not trim, case-fold, or Unicode-normalize
  it; ordinary spaces and Unicode are allowed, while Unicode `Cc` control
  characters are rejected;
- do not require an arbitrary uppercase/lowercase/digit/symbol composition;
- reject a password containing the canonical login identifier and reject exact
  matches from a versioned local common/known-compromised password denylist;
- treat the asset's `xtn-minimal-v1` denylist as a replaceable minimum runnable
  baseline, not a complete breach corpus; before production, replace it with a
  maintained offline dataset and change `LOCAL_PASSWORD_DENYLIST_VERSION` so the
  deployed data version is reviewable;
- reject strings that cannot be encoded as valid UTF-8 (including lone Unicode
  surrogates) through normal input-validation errors before hashing, limiter-key
  derivation, logging, or persistence; never allow a raw encoding exception to
  become an HTTP `500`;
- never call an online breach service while holding a transaction, and never
  log the candidate password or a hash of that candidate;
- accept `1..128` code points and at most `1024` bytes at the login boundary so
  an existing valid password is not rejected by a newer creation policy;
- do not periodically expire healthy passwords; rotate after user choice,
  administrator recovery, or credible compromise;
- unknown, deleted, disabled, credential-less, and invalid-password cases perform
  one real Argon2 verification against either the stored hash or a process dummy
  hash and produce the same public authentication failure;
- treat a malformed stored hash as a credential-store failure, not an invalid
  password, and emit no hash in the response or logs; and
- store password values in Pydantic `SecretStr` fields marked `writeOnly` in
  OpenAPI, reject extra request fields, and set `Cache-Control: no-store` on all
  password and login responses.

Keep the default Access Token lifetime at `3600` seconds and tell the project
owner to review it against business risk and login experience. Successful login
uses the existing minimal JWT plus Redis active-JTI contract; after expiry the
user authenticates again. Do not add cookies, username/profile/role claims, or a
per-Token PostgreSQL table.

## Persistence Model

Use a separate `user_password_credentials` episode table instead of placing a
mutable hash on `users`:

| Column | Contract |
| --- | --- |
| `id` | UUIDv4 primary key |
| `user_id` | required `users.id` foreign key with `ON DELETE RESTRICT` |
| `password_hash` | Argon2id string on a live episode; `NULL` after retirement |
| `must_change_password` | true only for an administrator/operator temporary credential |
| `created_at` | database timestamp |
| `created_by_user_id` | nullable actor ID; `NULL` for public registration |
| `deleted_at` | retirement timestamp; this is the soft-delete marker |
| `deleted_by_user_id` | nullable retiring actor ID |

Enforce one live credential per user with a partial unique index. Named checks
must enforce UUIDv4 identifiers, a valid live `$argon2id$` shape, cleared hashes
and `must_change_password=false` on tombstones, and coherent deletion metadata.
Never update an old episode into a new password and never hard-delete it: clear
and tombstone the old row, flush, then insert a fresh UUIDv4 episode. Old hashes
must not remain queryable from the application table. WAL and backups still need
their own access and retention controls. Set the new episode version to one more
than that user's maximum historical version, even when no live episode exists;
never restart at version `1` after tombstoning or account recovery.

Treat an Argon2 parameter upgrade differently from a password change. After a
successful verification, calculate the replacement hash before taking database
locks, re-lock and compare the exact user and credential episode, then update
only that live row's `password_hash`. Do not change its episode version,
`password_changed_at`, `token_version`, or `must_change_password`; the user's
secret did not change. The database shape check must accept structurally valid
Argon2id v19 hashes with older positive `m`, `t`, and `p` values so they can be
verified and upgraded. Parse the stored header before Argon2 work and reject any
hash whose memory, time, or parallelism cost exceeds the application's configured
maximum; otherwise a corrupted or compromised database row could request
unbounded verification resources. A concurrent credential change wins and
cancels the upgrade rather than overwriting the new password. Two concurrent
logins may both verify the same legacy encoding: after one login upgrades the
live row, the other may continue only when the credential episode ID, version,
live state, temporary-credential flag, user status, and `token_version` are
unchanged. It must release all database locks, verify that the newly observed
hash accepts the same password and already uses current parameters, then lock and
compare that exact state again before succeeding. Never perform this additional
Argon2 verification while holding a database lock.

Soft-deleting a user must retire its live password credential and increment
`users.token_version` in the same transaction. Restoring the user must not revive
the old credential or any former role assignment. A controlled reset creates a
new credential episode.

## Required HTTP Commands

Keep command routes on `POST`, use the standard four-field JSON response, return
the same server UUIDv4 in `request_id` and `X-Request-ID`, and use the existing
numeric business-code registry.

### Registration

`POST /api/v1/auth/register`

- Public registration is opt-in. Keep `PUBLIC_REGISTRATION_ENABLED=false` and
  omit the route from OpenAPI until the product owner explicitly enables it;
  enabling it also accepts responsibility for the confirmed registration
  quotas and account-creation policy.
- A deployed service must keep `RATE_LIMIT_ENABLED=true`, so registration,
  login, temporary-password completion, and current-password reauthentication
  always pass through `IdentityAbuseFlow`. The asset permits `false` only under
  an explicit `dev`, `development`, `local`, `test`, or `testing` environment;
  that intentional bypass is for isolated local work and tests, never a
  deployment profile. `APP_ENVIRONMENT` itself is required and has no code
  default, so omitting it stops startup rather than silently selecting
  `development`.
- Accept the product-selected registration identity plus `password`; the bundled
  username baseline accepts `user_name` and `password` only.
- Canonicalize and bound the username before deriving limiter keys or querying.
- Run registration through `IdentityAbuseFlow.register`.
- Perform password-policy checking and Argon2 hashing only after admission.
- In one PostgreSQL transaction create the user, mandatory `user` assignment,
  first normal credential, required version/epoch changes, RBAC provisioning
  audit, and account-security registration audit.
- Never accept a role, permission, tier, status, protection flag, or Token claim
  from the public body.
- Return HTTP `201` / business `201000` with only the immutable user ID. Do not
  automatically log the new user in.
- A duplicate identity uses the product's documented generic conflict. Public
  registration inherently reveals some availability information; use an invite
  or verified-contact design if that leakage is unacceptable.

### Login

`POST /api/v1/auth/login`

- Accept `user_name` and `password`; never guess whether one input means username
  or email when both namespaces exist.
- Use `IdentityAbuseFlow.authenticate`: admission first, exactly one real-or-dummy
  Argon2 verification, then record failure or clear the risk signal.
- Load a credential candidate without holding a transaction during Argon2 work.
  Before success, lock and reload the user and candidate credential and confirm
  the ID, hash, active state, deletion state, and token version did not change.
- Unknown user, wrong password, missing credential, disabled user, and deleted
  user all return HTTP `401` / `401001` with the same message and
  `WWW-Authenticate: Bearer`.
- A correct temporary credential returns the registered
  `password_change_required` forbidden response and no Token. It is completed by
  the dedicated recovery command below.
- Only after the abuse flow returns success, issue the one-hour Access Token and
  atomically register its JTI in Redis. If JTI registration is unavailable or
  ambiguous, return `503001` and do not return the encoded Token.
- Return `access_token`, `token_type: bearer`, and `expires_in`; do not return the
  JTI or copy password state into the JWT.

### Self-Service Change

`POST /api/v1/me/password/change`

- Require the full Bearer/JTI/PostgreSQL identity gate.
- Accept `current_password` and `new_password`; do not require a redundant
  `confirm_password` server field.
- Verify the current live credential and the new-password policy outside locks.
- Lock the global guard and current user/credential, recheck Token version and
  the credential candidate, then rotate the credential, increment
  `users.token_version`, and write the account-security audit in one transaction.
- Do not issue a replacement Token. The current request succeeds, then every old
  Token, including the one used for the change, fails on its next request.

### Administrator Recovery Reset

`POST /api/v1/users/{user_id}/password/reset`

- Require the dedicated non-delegable `users:password:reset` permission and the
  administrator's `current_password` again; possessing a stolen unlocked admin
  Token is not sufficient.
- The caller supplies the temporary password through a secret request field; the
  server never generates, returns, emails, or logs it.
- Apply the same visibility, strict-tier, protected-user, full-delegation, and
  no-self-management policy used by other user administration. An `admin` may
  reset only a strictly lower visible non-protected user. A `super_admin` still
  cannot reset itself through HTTP. Hidden, peer, higher, protected, deleted, and
  unknown targets must follow the established non-disclosure order.
- Rotate to `must_change_password=true`, increment target
  `users.token_version`, and commit both the allowed RBAC decision and the
  account-security event with the mutation. Do not issue a Token.
- A disabled visible lower user may receive a temporary credential but remains
  unable to authenticate until separately enabled by an authorized command.

### Complete A Temporary Recovery

`POST /api/v1/auth/password/reset/complete`

- Accept `user_name`, `temporary_password`, and `new_password`.
- Apply the same trusted-IP, IP+account, global login buckets and real-or-dummy
  verification used by login. Do not add an attacker-triggerable account-only
  lock.
- Lock and reload before rotating the temporary episode into a normal episode,
  incrementing `users.token_version`, and writing the security audit atomically.
- Return success without a Token. The user performs an ordinary login next.
- A used, superseded, normal, unknown, disabled, or deleted credential must not
  be reusable and must not disclose account state.

## Account Recovery Boundaries

A username locates an account; it does not prove ownership. For a username-only
product, the default recovery procedure is:

1. The person contacts a trusted administrator or support process.
2. Identity is verified outside this API using the product's real-world rules.
3. An authorized administrator selects the immutable user ID and sets a temporary
   credential through the reset command.
4. The temporary credential is delivered through an already trusted offline
   channel, never through the API response or logs.
5. The user completes the temporary reset and then logs in normally.

The API cannot prove that support completed step 2. Document the human procedure
instead of pretending that a client flag proves it.

If the sole `super_admin` loses its password, no lower administrator and no
anonymous HTTP route may reset it. Supply an offline operator command that:

- runs only from a trusted host with separately authorized database credentials;
- targets the immutable user ID and verifies it is the sole live
  `super_admin` holder;
- reads the temporary password twice using hidden interactive input, never a
  command-line argument or environment variable;
- uses the same policy validation and Argon2 implementation;
- locks the global guard and user/credential, rotates to a temporary credential,
  increments `token_version`, and writes an operator-source security audit in one
  transaction; and
- refuses ambiguous identities, extra holders, disabled/deleted targets, and any
  incomplete commit.

From the copied asset directory, the operator runs:

```bash
python -B -m app.password_operator --user-id <immutable-uuidv4-users-id>
```

The command reads and confirms the temporary password through two hidden prompts.
It requires the target deployment's `DATABASE_URL` and must run from a trusted
administration host. It is recovery for the already existing sole
`super_admin`; it never creates a user, binds the role, promotes another user, or
accepts a password through command-line arguments or environment variables.

Database owner/superuser access can bypass application rules. Production teams
should separate migration, runtime, and emergency operator roles; small projects
must at least restrict who receives database-owner credentials.

## Atomicity And Concurrency

Argon2 work occurs before database locks, so retain the candidate credential ID
and hash and recheck them under lock. Use the shared order:

1. `rbac_state(scope='global')`;
2. actor and target users in canonical ID order;
3. their live credential rows;
4. roles/grants needed for an administrator decision;
5. mutation, version increment, and audits.

Do not perform Redis I/O inside this PostgreSQL transaction. Incrementing
`token_version` makes existing Redis JTI records unusable on their next request;
there is no Redis `SCAN` cleanup requirement. Do not change `authz_version` or
the global authorization epoch for a password-only rotation.

Concurrent self-change, administrator reset, user deletion, status change, and
privileged writes must resolve from the locked current state. Never report
success for a credential that lost the race. A successful password mutation and
its account-security audit either commit together or both roll back. A failed
post-rollback denial audit must be logged safely but must not turn the original
`401`, `403`, `404`, or `409` into `500`.

## Account-Security Audit

Keep password lifecycle evidence out of `rbac_audit_events` and ordinary business
events. Use the append-only `account_security_audit_events` boundary for:

- `account_security.registration.completed`;
- `account_security.password.changed`;
- `account_security.password.admin_reset`;
- `account_security.password.reset_completed`; and
- `account_security.password.operator_reset`.

Store actor/target immutable IDs, trusted source, action, outcome/reason,
request/correlation ID, schema version, database time, and only bounded safe
booleans/enums such as `authenticator_present`, `rotation_required`, and
`sessions_revoked`. Never store username, email, IP, password, password hash,
JWT, JTI, request body, Redis key, or raw exception text. Login attempts belong
in redacted operational security telemetry and the expiring Redis risk signal,
not an unbounded row for every password guess.

## Default Quotas

Use the confirmed quota table in the rate-limit reference. In addition to its
outer global/IP API admission:

- login and temporary-reset completion use `login_ip` (`20`, refill `20/300s`),
  `login_pair` (`5`, refill `5/900s`), and `login_global` (burst `200`, refill
  `1000/300s`);
- public registration uses `registration_ip` (`5/3600s`),
  `registration_target` (`3/3600s`), `registration_pair` (`3/3600s`), and
  `registration_global` (burst `100`, refill `500/3600s`);
- self password change uses the ordinary-write user quota (`60/60s`); and
- administrator reset uses the authorization-write user quota (`30/60s`).

The login-failure risk signal expires after `86400s` and is cleared after valid
credentials. It never denies a correct password by itself. A quota denial is
`429001`; unavailable or malformed limiter authority is fail-closed `503001`.

## Verification Checklist

At minimum prove:

- Argon2 parameter shape, new/login input boundaries, denylist and username
  checks, async offload, and hashing-concurrency bound;
- one live credential per user, UUIDv4 constraints, cleared tombstone hashes,
  no hard delete, monotonic episode versions after a tombstone-only history, and
  restore without credential resurrection;
- equal public failures plus real/dummy work for unknown, deleted, disabled,
  missing-credential, and wrong-password cases;
- Token issuance only after successful admission and verification, and no Token
  when Redis JTI registration fails or a temporary credential is presented;
- registration assigns only `user` and rolls back identity, role, credential,
  versions, and audits together on any failure;
- self-change current-password checks, administrator reauthentication, the full
  hierarchy matrix, operator recovery guards, and one-time temporary completion;
- two independently issued Tokens both fail after change/reset completion;
- deterministic concurrency tests use barriers rather than sleeps and cover
  concurrent legacy-hash login upgrades, change-vs-reset, reset-vs-delete, and
  reset-vs-protected-status writes;
- allowed-audit failure rolls back the password mutation, while denied-audit
  failure preserves the original rejection;
- password fields are `writeOnly`, every response is `no-store`, OpenAPI exposes
  only the intended `GET`/`POST` contract, and no log/audit/response contains a
  password, hash, Token, JTI, username, email, or request body; and
- real PostgreSQL and Redis integration tests run in CI. If they could not run
  locally, report that fact rather than claiming production readiness.

## Bundled Asset Map

The PostgreSQL asset provides the copyable baseline in:

- `app/passwords.py` for validation and bounded async Argon2id work;
- `app/password_models.py` for credential and account-security audit models;
- `app/authentication_api.py` and `app/authentication_service.py` for the public
  and authenticated commands;
- `app/password_operator.py` for the offline sole-super-admin reset;
- `alembic/versions/0004_password_auth.py` for schema, permission seeds, and
  append-only controls; and
- focused unit and PostgreSQL tests under `tests/`.

Copy the complete set together. Do not copy only the routes and omit the
migration, limiter, JWT/JTI adapter, hierarchy decision, audit, or tests.
