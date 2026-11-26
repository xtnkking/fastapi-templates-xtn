# FastAPI And RBAC Testing

Read this reference before implementing or reviewing tests. Match the repository's
pinned versions and plugins instead of copying obsolete client fixtures.

The runnable PostgreSQL examples are under
[`assets/postgresql-rbac/tests`](../assets/postgresql-rbac/tests/). In particular,
`test_rbac_api.py` covers the neutral public API, system-role and administrative
workflows, optimistic preconditions, and rollback-before-denial audit, while
`test_postgresql_locking.py` covers global-guard ordering, identity-map refresh,
committed current user revocation, and concurrent assignments.

The official verification profile for this Skill is Python 3.12,
PostgreSQL 17, and Redis 7. A concrete project may test and support other
versions, but do not describe an untested version as verified by this Skill.

## Generated Project Versus Maintainer Tests

The asset's complete `tests/` tree is the Skill maintainer's regression suite,
not a directory to copy wholesale into every new application. Generate through
[New-project delivery](new-project-delivery.md), keep the selected small
application tests, and add targeted tests when actual product behavior changes.
Preserve meaningful authentication, authorization, CAPTCHA, atomicity, and
response checks; do not manufacture tests for trivial one-use wrappers.
Cluster, multiple-process, load-tool, historical migration, and topology helpers
are not default output. Load the related matrix only for work on that boundary.

The Skill delivers models, not migration files or database initialization.
New-project tests import model metadata, exercise isolated application logic,
and use explicit test dependencies without creating tables, migrating,
seeding, or repairing a database. The user generates, reviews, and executes
their own migrations, database-only protections and initial data. Deliver the
[database handoff](migrations.md) and report real database verification as
pending until that setup and validation are completed by the user.
Model tests cannot prove PostgreSQL triggers or direct-SQL enforcement.

The full matrices below document expected behavior and the maintenance
regression coverage. They do not require every generated project to receive
every test file, or authorize executing database-mutating fixtures during
project generation. An explicitly requested maintenance regression of the
historical asset is separate and retains its strict disposable-target guards.

For Access Token tests use
[JWT access-token security](jwt-session-security.md). For schema and API identifier
tests use [identifier policy](identifier-policy.md). Do not load either reference
for an unrelated test-infrastructure-only task.
For login-identifier selection, soft deletion, relation episodes, restore, and
purge-boundary tests, use
[Identity and soft-delete lifecycle](identity-soft-delete.md).

## Current ASGI Test Shape

With modern HTTPX, construct an explicit ASGI transport. Ensure application
lifespan runs when the test depends on startup or shutdown resources. Use
`pytest_asyncio.fixture` for async fixtures when pytest-asyncio uses strict mode.

```python
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def client(app):
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as test_client:
            yield test_client
```

If the application or framework version exposes a different supported lifespan
test API, use that or a maintained lifespan manager. Clear dependency overrides
after each test. Dispose test engines and isolate transactions or schemas so test
order cannot affect results.

## Baseline Tests

- Import and construct the application with explicit test settings.
- Exercise validation errors and the documented error envelope. Prove
  `/health/live` and `/health/ready` return `404` in the default project. Only
  test liveness/readiness behavior when the adopter explicitly requests probes;
  verify access is restricted to an internal network or trusted probes.
- Verify default `zh-CN` and requested `en` runtime messages, bounded
  `Accept-Language` negotiation, `Content-Language`, merged `Vary`, exact catalog
  key parity, localized validation details, simple `q` preference ordering,
  default-Chinese and hostile-header fallback, untrusted validation-key
  masking, unhandled-error headers, and concurrent request isolation. Follow
  [API internationalization](api-internationalization.md).
- Verify transaction commit and rollback behavior.
- Test pagination bounds and deterministic ordering.
- Confirm secrets and internal model fields never appear in responses or logs.
- Capture structured request events and verify response/header/log request-ID
  equality, correct status/business code, route templates, context isolation,
  recursive secret-marker redaction, and no duplicate access event. Follow
  [Operational logging](operational-logging.md).
- Verify machine-timezone-independent Beijing timestamps with millisecond ISO 8601 `+08:00` offsets and matching date folders; only the response envelope's outer `message` retains ordinary text under existing credential filtering and length bounds, while request/nested free text stays redacted.
- Verify HTTP log actions use existing endpoint function names without route-level
  action/result assignments; the response builder maps `2xxxx` to `success` and
  `4xxxx`/`5xxxx` to `failure`, preserving earlier success on a later error response.
  Cover the middleware fallback without a unified response, success followed by
  send failure (`operation_outcome=success`, `outcome=error`), automatic affected
  targets without route assignments, and unchanged database audit action enums
  and audit behavior. Cover new user/role IDs before send failure, authenticated
  self-password targets on success/denial, null total-list targets, requested
  user-session targets and rejection of fake IDs in failed creation inputs.
- Verify fixed null fields, affected user/role separation, redacted JSON/query
  summaries, bounded passive body observation and independent `LOG_HMAC_KEY`.
  Only four password-setting operations fingerprint the proposed new password;
  login/current-password fields never do. Denials retain the requested target
  and fingerprint when a complete body was read; they do not imply a successful
  mutation. File logs omit generic target and service metadata.
- Verify the unified operation audit has exactly the approved 16 fields, OA IDs,
  account/permission categories, safe request/business-result summaries and only
  new-password fingerprints. Registration and administrator creation each write
  one event; optional business-audit files and model registration stay excluded
  from default project output. A stored response snapshot must not claim HTTP
  delivery or require a post-response UPDATE.
- Verify required audit fields, safe bounded snapshots, atomic successful writes,
  rollback-before-denial audit, append-only database enforcement, and absence of
  tokens, JTI, credentials, email, and username. Follow
  [Audit module](audit-module.md).
- For greenfield identity, prove the selected required fields, accepted login
  inputs, normalization, database uniqueness, and post-deletion reuse policy.
  For an existing project, prove the task did not silently change that contract.
- For every delete, unbind, or restore path the product actually implements or
  changes, prove tombstones replace physical deletion, parent relation cleanup
  is atomic, rebind creates a new relation episode, and restore revives no old
  authority. The bundled asset directly exercises custom-role deletion and both
  RBAC unbind paths; its user/permission lifecycle scenarios are adaptation
  examples rather than public lifecycle endpoints.
- Inspect delivered ORM metadata without executing DDL. Migration generation,
  upgrade checks and verification of the completed schema belong to the user;
  historical upgrade regression is maintenance-only.
- Prove `/docs`, `/docs/oauth2-redirect`, `/redoc`, and `/openapi.json` return
  `404` in the default project. Also prove public paths, response fields and
  error codes do not expose `rbac`; internal database and audit names are outside
  this assertion.
- Assert that every business route uses only `GET` or `POST`, no target ID is a
  path parameter, and no `PUT`, `PATCH`, `DELETE`, or legacy `/rbac` alias is
  registered. Business list/detail reads end in `/list` or `/detail`; any
  explicitly requested health probes use their documented unversioned paths.
  FastAPI route metadata places GET
  filters/IDs in Query and POST target IDs in a required closed JSON body. Test absent/invalid
  IDs, forbidden extra fields and a POST query ID that cannot replace its
  required body field. Repeat target-visibility tests with the new locations;
  moving an ID must not change authorization.

## Local Password Authentication

When the project uses local passwords, load and test the complete contract in
[Local password authentication](local-password-authentication.md). A password
hasher or an isolated login-flow mock is not a completed authentication system.

Prove the product questions were answered once: username case comparison,
password composition and simultaneous-login maximum,
and existing-account
enrollment. Then cover the bundled baseline end to end:

- public registration remains available with no state-read or switch-update
  endpoint, while authorized administrator creation remains available;
- runtime settings and environment examples do not require `APP_ENVIRONMENT`;
  rate limiting remains mandatory without a disable setting or test escape hatch;
- Argon2id parameters, off-event-loop execution, the per-worker concurrency
  bound, creation versus login input limits, reserved username and three
  simple password-pattern checks,
  and corrupted stored-hash handling;
- password admission defaults of 2 running, 4 waiting and a 0.5-second wait,
  including immediate execution with a free slot, queue-full rejection, timeout,
  zero-waiting mode and recovery after rejection/cancellation. Use controllable
  worker barriers rather than repeated real hashing or timing-sensitive sleeps:
  a cancelled waiter must leave no queue entry, and cancellation of a started
  native calculation must not release its slot before that work finishes.
  Assert queue-full/timeout uses the bilingual `50301` envelope, starts no
  rejected calculation, and never issues a Token or mutates account data.
  Verify settings defaults, finite positive timeout and bounds, plus configured
  values reaching the application's existing PasswordManager. Already consumed
  CAPTCHA remains consumed on busy rejection, with no automatic replay;
- `Password` accepts nonempty login/current-password text up to the independent
  `MAX_PASSWORD_INPUT_CHARACTERS` ceiling; `NewPassword` applies the current
  minimum and maximum only to newly set passwords. Raising the policy minimum
  or lowering its maximum must leave valid old passwords usable for login and
  current-password verification within that input ceiling. Cover both HTTP
  model validation and direct Service input checks, including empty, invalid
  type, malformed UTF-8 and over-ceiling input; new-password character and
  composition rules must not reject an existing password. Keep field
  descriptions and bilingual length messages derived from their owning
  constants rather than stale numeric strings;
- nullable `users.password_hash` and `users.password_changed_at`, and unchanged
  `users.token_version`; password-state checks, cleared hash/timestamp on user
  soft deletion, and no password resurrection after restore;
- uniform `40110` plus real-or-dummy Argon2 work for unknown, wrong-password,
  disabled, deleted, and credential-less login states;
- one password verification per login, followed by a locked state/hash check;
  a concurrent hash upgrade rejects that request without reverifying or
  overwriting the newer hash, while an unchanged stale hash can still upgrade;
- public registration creates only the mandatory `user` role and commits the
  user, role binding, password state and one account-category operation audit
  atomically; shared user creation must not add a duplicate permission event;
- login issues no Token before successful Redis active-JTI registration;
- the five required graphical-CAPTCHA scenes are correctly isolated and each
  challenge is single-use on a wrong or right answer; self change requires its
  current password, while administrator reset needs the exact capability,
  CAPTCHA, and strict-lower policy, not the current user's password again;
  administrator creation and sole-super-admin offline recovery set directly
  usable passwords;
- administrator reset requires JSON `user_id`, the purpose-bound CAPTCHA fields,
  and `new_password`; it permits login with that password immediately and
  increments `users.token_version`, so independently issued old Tokens both
  fail their next authentication. The reset audit records the completed change;
- change-versus-reset, reset-versus-delete, and reset-versus-protected-write
  races use barriers and assert both possible commit orders without sleeps;
- required successful account audit failure rolls back the password mutation,
  denied-audit failure preserves the original rejection, and no response,
  schema example, log, Redis key or audit contains plaintext passwords, database
  password hashes, Tokens/JTIs or unredacted request bodies. Request summaries
  hide usernames, raw IPs and secrets; only the dedicated new-password comparison
  field may contain a permitted keyed fingerprint;
- `HttpLogDetails.audit_request_data()` returns a bounded, recursively redacted
  query/body snapshot without actively reading the body; `AuditService.audit_success()`
  derives category/user/source and retains the intended code, message, safe data
  and existing request ID before commit, without claiming final HTTP delivery
  or requiring an audit UPDATE. `audit_denied()` preserves the original rejection
  after rollback, while server errors do not become denied events;
- password-change counts come from succeeded account-security events for the
  target and the four password-change/reset actions, excluding registration;
- every password response is `Cache-Control: no-store`, password schema fields
  remain write-only in application metadata, and the public contract exposes
  only the intended `GET` and `POST` routes.

Real PostgreSQL and Redis validation remains necessary evidence for their
actual behavior. The user runs it after completing their schema and isolated
test setup. Ordinary Skill delivery does not run historical database-creating
fixtures to fill that gap. Report unavailable or unperformed checks instead of
calling the password baseline production-ready from unit tests alone.

## Rate Limiting, Abuse Defense, And Verification

When the delivered surface uses Redis-backed rate limiting, first prove that the generated
settings exactly match the centralized values accepted by the user under
[Rate limiting and abuse-control quotas](rate-limiting.md). Graphical CAPTCHA
is required in five scenes; email/SMS or MFA is not part of this asset. Test
policy selection separately from the Redis algorithm: a correctly constructed
but unwired policy does not protect a route.

Unit-test validation, key construction, policy selection, result parsing, and
HTTP response composition. Also run the Lua behavior against the supported real
Redis version; a mocked `eval` cannot prove expiry, atomicity, Cluster
slot behavior, or concurrency.

| Surface | Required proof |
| --- | --- |
| Fixed-window core | One per-business key, atomic first `INCR`/`EXPIRE`/remaining PTTL, finite TTL, full quota restored at expiry |
| Concurrency | No more than the configured number of calls are admitted inside one window; no global or cross-business bucket exists |
| Key privacy | Raw IP, account, user, target, HMAC digest, and complete key never reach logs or responses |
| API composition | After JWT and active-JTI validation, increment the named current user window exactly once before PostgreSQL; excess requests stop without an account read. A later disabled/stale-account denial retains that count and attempts exact-JTI cleanup; forged or Redis-revoked Tokens spend no current user quota and perform no account read. No coarse all-API middleware runs |
| Login defense | Trusted IP for that business is the only quota subject; no account-only, pair, global, or login-failure risk counter exists |
| Login orchestration | The auth route declares `Depends(rate_limit_login)` before `Depends(require_captcha(CaptchaScene.LOGIN))`; CAPTCHA does not call the limiter again. The limiter counts once and its denial prevents consumption; CAPTCHA failure blocks `AuthService.login`. Real-or-dummy password validation preserves generic denial, and Token issuance runs only after success |
| Registration | One per-IP registration check runs before product side effects |
| Registration orchestration | The auth route declares `Depends(rate_limit_register)` before `Depends(require_captcha(CaptchaScene.REGISTER))`; the limiter runs once before CAPTCHA validation/consumption and `AuthService.register`. A denial or unavailable Redis never reaches either later step |
| Protected CAPTCHA dependencies | All five actions declare their fixed `CaptchaScene`; authenticated actions declare their authorization/permission context before CAPTCHA, using one identity load and one quota count. CAPTCHA reads the previously authenticated `request.state.user_id`, refuses a missing private identity, directly extracts strings and checks UUID/answer length. Dependency parameter errors return 40001 without consumption; JSON syntax rejected earlier by FastAPI remains 42201. Service parameters and digest inputs use user_id. Limit/permission denial does not consume a challenge; other business-field errors may follow consumption. CAPTCHA failure skips business work; submitted scene/user_id cannot override server bindings |
| Graphical CAPTCHA | Fixed scenes `login`, `register`, `admin_create_user`, `admin_reset_user_password`, `user_change_password`; public `/api/v1/auth/captcha` versus authenticated `/api/v1/me/captcha`; per-scene issuance quota, independent new images, expiry and NX storage of a single HMAC digest binding scene/user_id/ID/answer. GETDEL precedes comparison: correct answer, wrong answer, wrong scene and wrong user each consume that ID and a later correct retry fails. Private user binding, public acceptance after IP changes, atomic one-winner consumption, malformed digest/Redis failures closed and safe image response |
| Rejected CAPTCHA scene | Missing/unknown scene or a valid scene at the wrong issue endpoint: count one independent 10-per-five-minute rejection quota once, keyed on trusted IP or authenticated current user; authenticated counting follows JWT/active-JTI validation and precedes PostgreSQL. No image or normal-scene quota is consumed; excess returns `42901` without PostgreSQL, unavailable limiter authority returns `50301`. A valid scene with an invalid unrelated field instead spends its scene quota once and returns `422` after identity validation, while invalid JSON syntax fails before authentication dependencies; no global bucket |
| Optional delivery extensions | Email/SMS/MFA are not bundled and need a future product decision and tests |

For a real limiter denial, assert HTTP `429`, `42901`, `Cache-Control: no-store`,
the equal body/header request ID and correctly rounded-up `Retry-After` from
the remaining fixed-window TTL. If exposing the optional RateLimit headers,
verify they describe this window, not a Token Bucket refill.

For missing Redis, timeout, Redis command error, malformed script result, or
invalid stored state, assert HTTP `503`, `50301`, `Cache-Control: no-store`, no
`Retry-After`, no dependency detail, and that the
protected handler, credential verifier, delivery call, Token issue, or business
mutation did not run. A middleware-owned limiter failure must not invent a bucket
result. When an earlier layer already admitted a request, allow its ordinary
`RateLimit-*` headers on a later downstream `503`, but prove they do not include
or imply `Retry-After`. Verify the stable log events and secret-marker exclusions
under [Operational logging](operational-logging.md).

When a product explicitly adds an optional email/SMS/MFA extension, follow
[Verification and abuse defense](verification-and-abuse-defense.md) for the
challenge-specific matrix. Do not mark that surface verified when only the
mocked unit suite ran; report unavailable real Redis explicitly.

## Public Administration Contract

Exercise all thirteen minimum routes rather than testing only one representative
dependency:

```text
GET  /api/v1/permissions/list
GET  /api/v1/permissions/detail?permission_id=<id>
GET  /api/v1/roles/list
GET  /api/v1/roles/detail?role_id=<id>
POST /api/v1/roles/create
POST /api/v1/roles/update
POST /api/v1/roles/disable
POST /api/v1/roles/enable
POST /api/v1/roles/delete
POST /api/v1/roles/permissions/bind
POST /api/v1/roles/permissions/unbind
POST /api/v1/users/roles/bind
POST /api/v1/users/roles/unbind
```

Every existing-role POST supplies `role_id` in its JSON body. User-role commands
supply `user_id` in their JSON body; creation has no preexisting target ID.

For each route, cover missing credentials (`401`), a current `user` without the
capability (`403`), the exact capability gate, a concealed object (`404`), input
validation, and its positive path. Capability success alone does not satisfy a
write test; also prove the strict hierarchy, current user-held permission, protected-target,
affected-user, system-role, and self-elevation decisions. Prove an early denied
`POST` attempts a safe audit, and prove the service's locked capability recheck
returns `40301` before `40401` or `40931` to an unprivileged or newly revoked
caller.

For every user or role management write, test the ordered visibility boundary
inside the authoritative service transaction. A caller missing the exact
operation capability returns `40301` before target existence, visibility, or
version can affect the response. Once capability passes, self, peer, higher, and
protected user or role targets return the same `40401` body as an unknown ID.
User-role bind/unbind must also return `40401` when any requested role ID is
hidden or unknown and must not partially change the visible subset. Only a
visible target that fails grant authority, affected-user, system-role, self-elevation,
or another operation-specific decision returns `40301`. Cover the service
directly so an alternate route cannot bypass this ordering, then repeat
representative user and role writes through the public API.

Role update, enable, disable, delete, and permission commands require
a nonnegative strict JSON integer body `expected_version`. Test missing, string,
float, boolean, and negative values as `42201`; test an unauthorized stale write
as `40301`, an authorized stale write as `40931`, current success, and two
authorized administrators starting from the same role version. The second writer
must not silently overwrite the first. Reserve `40901` for another client-visible
state conflict such as exhausted bounded retries. User-role bind/unbind is instead
tested as an incremental, idempotent, single-transaction command with post-lock
authority reload; this version does not require a user version. Successful
unbind tombstones the live episode, and a later bind creates a new episode with
a new non-sequential ID. Binding must evaluate the target's complete final live
set under the global guard and return `40921` when it would exceed 10 roles;
PostgreSQL independently enforces the same final-state limit only after the
user installs and verifies the custom database protection in the handoff.

For role and user administration writes, prove the service builds the response
while it still owns the authorization locks and the route returns that immutable
snapshot without a post-commit `Session` query. Cover user-role bind/unbind and
user disable/enable explicitly. Use a deterministic concurrency barrier to show
that a later committed role or status change cannot contaminate the earlier
command's response. For `bound_role_ids`, verify an ordinary administrator
cannot see a live assignment to a disabled peer or higher role, while
`super_admin` receives the complete live, non-deleted assignment set.

For response envelopes, numeric business codes, request ID coverage, framework
errors, pagination, route metadata, and disabled documentation-route assertions, follow
[API response standard](api-response-standard.md).

## Authorization Matrix

For every protected capability, cover the meaningful rows of this matrix:

| Context | Expected result |
| --- | --- |
| Missing or invalid bearer token | `401` with `WWW-Authenticate: Bearer` |
| Active user, no required permission | `403` |
| Required permission through one role | Success |
| Required permission supplied by any one of several active roles | Success for union semantics |
| Tenth live role binding | Success; the user's final count is 10 |
| Eleventh live role binding | Atomic `40921` conflict with no mutation |
| Disabled identity or inactive Redis JTI | `401` under the documented policy |
| Suspended user | `401` under the documented policy |
| Missing or deliberately concealed resource | Same generic `404` response |

Also test:

- each route's exact single-permission gate, including a grant from a later role
  in the user's merged authority snapshot;
- users with no role and roles with no permissions;
- list, detail, search, count, export, bulk, and nested-resource capability and
  row-policy enforcement;
- leaked resource IDs and IDOR attempts through every lookup variant;
- mass-assignment attempts for roles, permissions, `super_admin` status, and
  system flags;
- self-escalation, granting permissions the current user does not hold, system-role
  mutation, and removal of the final `super_admin`;
- attempts to use `roles:bind` to create a role or replace its permissions, and
  attempts to assign a role outside the current user's own authority;
- immutable `super_admin`, `admin`, and `user` role keys, tiers, flags,
  lifecycle, and permission composition through every route and direct service
  entry point;
- normal registration, administrator creation, identity synchronization, and
  import paths atomically assigning `user`, with public role selection and
  `user` unbind attempts rejected;
- the required username-only new-project baseline, mandatory trim and ASCII
  validation, selected case rule, permanent reservation of deleted names, and
  database uniqueness under concurrent registration; existing-project work
  must preserve its chosen identity contract unless a change was requested;
- `user` denied on every management endpoint; `admin` allowed only for strictly
  lower users and custom roles, and denied for role deletion, system-role
  mutation, online `super_admin` handover, peers, and higher targets;
- management writes returning `40301` before lookup when capability is absent,
  returning non-leaking `40401` for self, peer, higher, protected, unknown, or
  hidden requested-role targets after capability passes, and reserving `40301`
  for visible targets outside current user-held grant or affected-authority policy;
- administrative user and role lists, counts, searches, details, exports, and
  nested reads showing all non-deleted targets only to `super_admin`; every other
  administrator sees only strictly lower, non-protected targets, cannot see
  itself or peers, and receives the same `40401` for hidden and unknown IDs;
- role and user pages loading grants and authority in a bounded number of
  queries whose count does not grow with page size, with list `total` using the
  exact visibility predicate;
- role/user mutation responses using immutable in-transaction snapshots rather
  than post-commit request-session reloads, with nested `bound_role_ids`
  filtered to the current user's visible roles;
- ordinary role binding unable to grant `super_admin`, `admin` assignment or
  revocation requiring the current `super_admin`, and no online route to
  transfer the sole `super_admin`;
- the user-owned offline PostgreSQL bootstrap transaction accepting only immutable
  `users.user_id`, requiring an existing live active identity with `user`, assigning
  only `super_admin`, and auditing in one
  transaction; a same-identity replay is idempotent, while a missing, invalid,
  deleted, or different second identity is rejected without partial state;
- an upgrade preserving an ordinary custom role whose key is `owner` without
  granting it system semantics, and direct SQL rejecting both a second
  `super_admin` and removal of the final holder while allowing bootstrap and
  atomic transfer;
- custom-role soft deletion immediately removing effective access while
  atomically tombstoning every live grant and assignment, preventing enablement
  and key reuse, and leaving all three system roles undeletable; an ordinary
  custom role may use the non-reserved key `owner` without special authority;
- permission and role bind/unbind batches rejecting duplicate IDs and one bad
  target atomically, and treating already-bound or already-unbound relations as
  idempotent no-ops; successful unbinds leave tombstones and later binds create
  new relation episodes;
- the 10-live-role limit counting mandatory `user`, any `super_admin`, and
  disabled-role bindings while excluding tombstones; cover the tenth success,
  eleventh rejection, an idempotent bind when already full, unbind then reuse,
  bootstrap, offline handover, direct SQL, and a concurrent race for the tenth
  slot;
- targets whose ordinary role hides an additional peer, higher, protected, or
  incomparable role, proving authorization uses the complete multi-role snapshot;
- shared-role edits involving suspended or inactive assignees whose assignments
  would become effective after reactivation;
- concurrent assignment and shared-role edits, proving the global guard is the
  first lock and freezes the affected set before it is scanned;
- concurrent role changes that target the same sole-super-admin invariant;
- offline `super_admin` password recovery refusing zero holders, a different
  sole holder, or multiple holders and proceeding only when the locked live
  holder set is exactly the requested user;
- successful login upgrading an older valid Argon2id encoding only after the
  exact user and credential are rechecked under lock, while a concurrent
  credential change cancels the upgrade without overwriting it; two logins that
  race to upgrade the same legacy hash must both succeed only after the loser
  verifies the winner's current-parameter hash outside locks and then re-locks
  and compares the exact user and credential state;
- direct service calls, background tasks, and WebSockets that could bypass route
  dependencies;
- the default exact `user_id`/`jti`/`iat`/`exp`/`token_type` profile, the
  explicitly consented profile adding both `iss` and `aud`, rejection of a
  partial pair or profile mismatch, preservation of an existing configured pair,
  configurable 24-hour default, canonical selected-policy subject and UUIDv4
  JTI, startup rejection of weak/example secrets, 4096-byte input and output
  limits, registration-before-return without a Redis record on oversized output,
  exact Redis record, outage, confirmed current-Token logout, account-wide logout
  invalidating two independently issued Tokens, and the revocation matrix in
  [JWT access-token security](jwt-session-security.md);
- revocation while access tokens remain valid, including multiple application
  workers, proving current PostgreSQL permissions are reloaded;
- immediate-revocation endpoints with an old token, proving transaction-local
  authority is reloaded after acquiring the required locks;
- if the project adds a permission cache, its declared stale-access window and
  outage behavior must be tested; reload the authority or fail closed.
- PostgreSQL schema inspection proving every RBAC, audit, and business
  primary/public ID follows [identifier policy](identifier-policy.md), including
  exact prefix format or UUIDv4 shape as selected, and no integer sequence or
  identity generator is hidden beside the public key.
- absence of an individual PostgreSQL Token table and of any per-request
  Token-record query; authentication still loads the existing user and current
  RBAC state after Redis validation.
- every implemented user, custom-role, permission-catalog, or business-parent
  deletion atomically tombstoning every live owned relation, rollback preserving
  all rows, and every implemented restore reviving no old role, permission,
  ownership, share, or Redis JTI;
- direct and concurrent relation writes allowing at most one live pair while
  keeping historical tombstones and issuing a new ID on each later bind;
- runtime `UPDATE`, `DELETE`, and `TRUNCATE` against audit rows failing, audit
  tables having no soft-delete path, and direct deletion/truncation of the
  singleton `rbac_state` failing;
- controlled maintenance rejecting audit and `rbac_state` purge targets, and
  destructive test cleanup refusing any database not verified as disposable.

For identity administration, role assignment, or hierarchy rules, run the full
negative and concurrency matrix in
[administrative-hierarchy.md](administrative-hierarchy.md). A route-level
permission test alone does not prove that lower-authority, peer, indirect, bulk,
or concurrent privilege escalation is blocked.

For authorization writes, immediate revocation, concurrency, denial auditing, or
external effects, run the canonical verification matrix in
[atomic authorization consistency](atomic-consistency.md). Implement those tests
with deterministic transaction barriers rather than timing-based sleeps, run
them against PostgreSQL, assert the actual isolation level, and make deadlocks or
exhausted internal retries observable failures.

## Database Coverage And User Handoff

SQLite can make unit tests fast but does not reproduce PostgreSQL constraints,
locking, isolation, JSON behavior, or row-level security. The user's completed
schema needs validation against the selected PostgreSQL engine for foreign keys, the singleton global
authorization guard, system-role protection, default-user assignment, concurrent
super-admin changes, partial live-relation uniqueness, every implemented
soft-delete/restore transaction, audit and `rbac_state` deletion guards,
migrations, and query plans. Explain these unverified boundaries when delivering
models; do not claim ORM creation includes custom trigger or grant enforcement.

### Historical Maintainer Integration Harness

The retained historical suite is not copied into a generated project and is
not run by the new-project workflow. For separately requested maintenance
regression only, it requires fresh disposable targets. Set
`TEST_DATABASE_URL` to a new empty PostgreSQL database ending in `_test`, and
set `TEST_DISPOSABLE_DATABASE` to that exact database name. Set both
`TEST_REDIS_URL` and `TEST_RATE_LIMIT_REDIS_URL` to separate, initially empty
Redis targets, and set `TEST_REDIS_ISOLATION_CONFIRMED=yes` only after checking
that they are dedicated to these tests. The fixture verifies the actual
PostgreSQL database and empty schema before Alembic runs, and reads Redis
`DBSIZE` before any test key cleanup. Migration tests downgrade to `base`, so
never point these variables at a database or Redis holding valuable data.
The Redis-only CAPTCHA/session test needs a third initially empty disposable
`TEST_CAPTCHA_REDIS_URL` whose logical database number differs from both
integration Redis targets; it deliberately leaves its own test keys, so it
must not make a later integration target nonempty. CI uses logical DBs 14,
15, and 0 across two Redis services. If a prior run left objects or keys,
recreate the disposable targets instead of bypassing the guard. Ordinary unit
tests do not require these settings.

## Completion Evidence

Verify the changed code boundary using the repository's existing commands.
For entrypoint changes, verify actual handler, middleware and router registration,
partial-startup cleanup, and continued release after a cleanup failure. Patch
the implementation's owning module in tests rather than adding unused exports
back to `main.py` solely to preserve old test imports.
Run relevant format, lint, type, contract and isolated authorization checks;
report exact commands and results. Import and exercise generated code rather
than only inspecting it. Confirm output contains no migration histories,
initialization SQL, maintenance-only test helpers, build products or caches.
Report user-owned schema initialization, database-only protection, migration,
and real PostgreSQL/Redis concurrency verification separately as pending when
they were not performed. Do not run DDL through tests as a workaround. Production
capacity certification, rolling releases, and cluster exercises are outside
ordinary coding scope.

For readability/documentation changes, manually follow one endpoint → Service →
Repository chain and compare comments with the real permission checks, callback
invocation and commit ownership. Inspect a generated project, not just the rules.
Verify Chinese public field/query descriptions in source and model metadata while
keeping types, requiredness, defaults and constraints unchanged; runtime language tests cover
messages separately. Use executable-AST comparison for formatting-only changes
and contract comparison for documentation metadata changes. Do not count comments
or create brittle exact-wording tests as a substitute for reviewing their meaning.

For connection pools, timeouts, or shared process state, read
[Capacity and availability](application-capacity-and-availability.md).
Select the existing boundary tests that apply:

- Database network deadlines: use the controllable forwarding proxy against
  disposable PostgreSQL to withhold replies while sockets remain open. Cover
  checkout and active commands, bounded safe `50301`, bad-connection retirement,
  healthy-peer preservation, and fresh access after recovery.
- Transaction/cancellation behavior: the built-in checkout ping opens no
  explicit transaction, cancellation propagates, and connection retirement
  does not wait for network cleanup. Unrelated business timeouts remain ordinary application failures.
  Lost commit replies must not cause automatic replay or assumed rollback.
- Shared sessions and quotas: use independent processes with shared real
  PostgreSQL/Redis when changing that behavior; in-process ASGI clients alone
  cannot establish process isolation.
- Standalone Redis client changes: run `tests/test_redis_clients.py` for URL,
  bounded pool, TLS parameter and no-command-replay behavior. For Lua semantics,
  use the separately prepared disposable Redis targets described above to check
  session atomicity, CAPTCHA single-use consumption and concurrent quotas. Unit TLS
  configuration checks do not prove a TLS handshake or dependency failover.
- Runtime logging: when changing it, preserve safe JSON formatting, output
  failure isolation, request-ID correlation and clean handler removal. Direct
  stdout can block a request; do not claim non-blocking delivery. See
  [Operational logging](operational-logging.md).
- Load tooling: test count/time exclusivity, finite bounds, launch cutoff, and
  bounded samples when modifying the tool. Using it is optional for requested
  performance work; results describe the tested workload only.

A driver-command deadline is not a total HTTP-request budget. Functional tests
do not certify production capacity or cluster failover. State these evidence
limits without making extra infrastructure or deployment work a delivery gate.
