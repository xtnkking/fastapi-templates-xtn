# FastAPI And RBAC Testing

Read this reference before implementing or reviewing tests. Match the repository's
pinned versions and plugins instead of copying obsolete client fixtures.

The runnable PostgreSQL examples are under
[`assets/postgresql-rbac/tests`](../assets/postgresql-rbac/tests/). In particular,
`test_rbac_api.py` covers the neutral public API, system-role and administrative
workflows, optimistic preconditions, and rollback-before-denial audit, while
`test_postgresql_locking.py` covers global-guard ordering, identity-map refresh,
committed actor revocation, and concurrent assignments.

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
- Exercise liveness, readiness, validation errors, and the documented error
  envelope.
- Verify transaction commit and rollback behavior.
- Test pagination bounds and deterministic ordering.
- Confirm secrets and internal model fields never appear in responses or logs.
- Capture structured request events and verify response/header/log request-ID
  equality, correct status/business code, route templates, context isolation,
  recursive secret-marker redaction, and no duplicate access event. Follow
  [Operational logging](operational-logging.md).
- Verify required audit fields, safe bounded snapshots, atomic allowed writes,
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
- Run migration upgrade from an empty database and from supported prior revisions.
- Inspect generated OpenAPI and prove that no public path, tag, operation ID,
  application title, response schema, or error code contains `rbac`. Internal
  packages such as `app.rbac` are outside this assertion.
- Assert that every authorization-management route uses only `GET` or `POST` and
  that no `PUT`, `PATCH`, `DELETE`, or legacy `/rbac` alias is registered.

## Local Password Authentication

When the project uses local passwords, load and test the complete contract in
[Local password authentication](local-password-authentication.md). A password
hasher or an isolated login-flow mock is not a completed authentication system.

Prove the product questions were answered once: identity/login input,
registration mode, recovery proof and channel, simultaneous-device policy, and
existing-account enrollment. Then cover the bundled baseline end to end:

- default settings do not register `POST /api/v1/auth/register` and omit it from
  OpenAPI, while an explicitly enabled setting registers exactly that `POST`;
- settings require `APP_ENVIRONMENT` with no code default even when limiting is
  enabled, and reject `RATE_LIMIT_ENABLED=false` for every environment except
  the explicit `dev`, `development`, `local`, `test`, and `testing` escape hatch;
- Argon2id parameters, off-event-loop execution, the per-worker concurrency
  bound, creation versus login input limits, common-password/identifier checks,
  and corrupted stored-hash handling;
- one live `user_password_credentials` episode per user, fresh UUIDv4 on every
  rotation, a version above the maximum historical episode even when no live
  credential remains, cleared hashes on tombstones, no hard delete, and no
  password resurrection after user restore;
- uniform `401001` plus real-or-dummy Argon2 work for unknown, wrong-password,
  disabled, deleted, and credential-less login states;
- public registration creates only the mandatory `user` role and commits the
  user, role binding, credential, versions, and both required audits atomically;
- login issues no Token before successful Redis active-JTI registration, and a
  correct temporary credential returns the password-change-required contract
  without a Token;
- self change requires the current password; administrator reset requires the
  actor's current password, `users:password:reset`, and the complete strict-lower
  visibility/delegation policy; and sole-super-admin reset is offline only;
- temporary reset completion is one-time, issues no Token, and successful
  change/reset increments `users.token_version` so two independently issued old
  Tokens both fail their next authentication;
- change-versus-reset, reset-versus-delete, and reset-versus-protected-write
  races use barriers and assert both possible commit orders without sleeps;
- allowed account-security audit failure rolls back the password mutation,
  denied-audit failure preserves the original rejection, and no response,
  OpenAPI example, log, Redis key, or audit contains a password, hash, Token,
  JTI, username, email, raw IP, or request body; and
- every password response is `Cache-Control: no-store`, password schema fields
  are `writeOnly`, and the public contract exposes only the intended `GET` and
  `POST` routes.

Run PostgreSQL constraints and transactional tests against the supported real
database and login/admission/JTI tests against real Redis. Report an unavailable
service instead of calling the password baseline production-ready from unit
tests alone.

## Rate Limiting, Abuse Defense, And Verification

When the delivered surface uses Redis admission, first prove that the generated
settings exactly match the centralized values accepted by the user under
[Rate limiting and abuse-control quotas](rate-limiting.md). Apply the optional
verification rows only when the user explicitly selected that feature. Test
policy selection separately from the Redis algorithm: a correctly constructed
but unwired policy does not protect a route.

Unit-test validation, key construction, policy selection, result parsing, and
HTTP response composition. Also run the Lua behavior against the supported real
Redis version; a mocked `eval` cannot prove server time, TTL, atomicity, Cluster
slot behavior, or concurrency.

| Surface | Required proof |
| --- | --- |
| Token Bucket core | Continuous integer-microtoken refill, one-token cost, Redis `TIME`, finite TTL, and configured burst/refill semantics |
| Batch decision | One to 16 unique buckets, stable result order, longest retry, and no key mutation or TTL refresh when any bucket denies |
| Concurrency | Accepted calls never exceed currently available tokens and no partial quota is consumed |
| Key privacy | All batch keys share the static namespace hash slot; raw IP, account, user, target, HMAC digest, and complete key never reach logs or responses |
| API composition | Coarse global/IP middleware and the intended actor/route policy both run; `OPTIONS` and health exclusions match the documented deployment contract |
| Login defense | IP/pair/global are the only hard admission limits; the failure-risk signal increments atomically, has finite retention, clears on success, and never blocks correct credentials by itself |
| Login orchestration | `IdentityAbuseFlow.authenticate` admits first, invokes one real-or-dummy credential callback, records one failure for `None`, clears state before returning a verified value, and the application Token issuer is invoked only afterward |
| Registration | IP, target, pair, and global checks run together before product side effects |
| Registration orchestration | `IdentityAbuseFlow.register` never invokes `registration_action` after a denial or unavailable Redis decision |
| Optional verification disabled | No verification secret, purpose, channel, provider, field, or route is required by a username-and-password-only product |
| Optional verification send | When selected, target cooldown, target-average Token Bucket, IP, pair, channel, and global checks run together; tests prove the accepted starting credits and gradual daily-average refill rather than a hard arbitrary-24-hour maximum |
| Optional verification submit | When selected, IP, target, pair, and global checks precede the per-challenge attempt counter |
| Optional challenge state | No plaintext target/code/raw challenge ID in Redis; resend replacement, matching cancellation, expiry, final wrong attempt, and exactly one concurrent successful consume |
| Optional delivery failure | Only the matching challenge is cancelled, quota is not refunded, and provider detail is absent from response and logs |

For a real limiter denial, assert HTTP `429`, `429001`, `Cache-Control: no-store`,
the equal body/header request ID, correctly rounded-up `Retry-After`, and the
three rate-limit headers. A login-failure risk count is not a limiter result and
must not create a `429` or any rate-limit header by itself.

For missing Redis, timeout, Redis command error, malformed script result, or
invalid stored state, assert HTTP `503`, `503001`, `Cache-Control: no-store`, no
`Retry-After`, no dependency detail, and that the
protected handler, credential verifier, delivery call, Token issue, or business
mutation did not run. A middleware-owned limiter failure must not invent a bucket
result. When an earlier layer already admitted a request, allow its ordinary
`RateLimit-*` headers on a later downstream `503`, but prove they do not include
or imply `Retry-After`. Verify the stable log events and secret-marker exclusions
under [Operational logging](operational-logging.md).

When optional verification was selected, follow
[Verification and abuse defense](verification-and-abuse-defense.md) for the
challenge-specific matrix. Do not mark that surface verified when only the
mocked unit suite ran; report unavailable real Redis explicitly.

## Public Administration Contract

Exercise all thirteen minimum routes rather than testing only one representative
dependency:

```text
GET  /api/v1/permissions
GET  /api/v1/permissions/{permission_id}
GET  /api/v1/roles
GET  /api/v1/roles/{role_id}
POST /api/v1/roles
POST /api/v1/roles/{role_id}/update
POST /api/v1/roles/{role_id}/disable
POST /api/v1/roles/{role_id}/enable
POST /api/v1/roles/{role_id}/delete
POST /api/v1/roles/{role_id}/permissions/bind
POST /api/v1/roles/{role_id}/permissions/unbind
POST /api/v1/users/{user_id}/roles/bind
POST /api/v1/users/{user_id}/roles/unbind
```

For each route, cover missing credentials (`401`), a current `user` without the
capability (`403`), the exact capability gate, a concealed object (`404`), input
validation, and its positive path. Capability success alone does not satisfy a
write test; also prove the strict hierarchy, delegable-set, protected-target,
affected-user, system-role, and self-elevation decisions. Prove an early denied
`POST` attempts a safe audit, and prove the service's locked capability recheck
returns `403001` before `404001` or `409002` to an unprivileged or newly revoked
caller.

For every user or role management write, test the ordered visibility boundary
inside the authoritative service transaction. A caller missing the exact
operation capability returns `403001` before target existence, visibility, or
version can affect the response. Once capability passes, self, peer, higher, and
protected user or role targets return the same `404001` body as an unknown ID.
User-role bind/unbind must also return `404001` when any requested role ID is
hidden or unknown and must not partially change the visible subset. Only a
visible target that fails delegation, affected-user, system-role, self-elevation,
or another operation-specific decision returns `403001`. Cover the service
directly so an alternate route cannot bypass this ordering, then repeat
representative user and role writes through the public API.

Role update, enable, disable, delete, permission, and delegation commands require
a nonnegative strict JSON integer body `expected_version`. Test missing, string,
float, boolean, and negative values as `422001`; test an unauthorized stale write
as `403001`, an authorized stale write as `409002`, current success, and two
authorized administrators starting from the same role version. The second writer
must not silently overwrite the first. Reserve `409001` for another client-visible
state conflict such as exhausted bounded retries. User-role bind/unbind is instead
tested as an incremental, idempotent, single-transaction command with post-lock
authority reload; this version does not require a user version. Successful
unbind tombstones the live episode, and a later bind creates a new episode with
a new non-sequential ID. Binding must evaluate the target's complete final live
set under the global guard and return `409001` when it would exceed 10 roles;
PostgreSQL independently enforces the same final-state limit.

For role and user administration writes, prove the service builds the response
while it still owns the authorization locks and the route returns that immutable
snapshot without a post-commit `Session` query. Cover user-role bind/unbind and
user disable/enable explicitly. Use a deterministic concurrency barrier to show
that a later committed role or status change cannot contaminate the earlier
command's response. For `assigned_role_ids`, verify an ordinary administrator
cannot see a live assignment to a disabled peer or higher role, while
`super_admin` receives the complete live, non-deleted assignment set.

For response envelopes, numeric business codes, request ID coverage, framework
errors, pagination, and OpenAPI assertions, follow
[API response standard](api-response-standard.md).

## Authorization Matrix

For every protected capability, cover the meaningful rows of this matrix:

| Context | Expected result |
| --- | --- |
| Missing or invalid bearer token | `401` with `WWW-Authenticate: Bearer` |
| Active user, no required permission | `403` |
| Required permission through one role | Success |
| Required permissions split across multiple roles | Success for union semantics |
| Tenth live role binding | Success; the user's final count is 10 |
| Eleventh live role binding | Atomic `409001` conflict with no mutation |
| Disabled identity or inactive Redis JTI | `401` under the documented policy |
| Suspended user | `401` under the documented policy |
| Missing or deliberately concealed resource | Same generic `404` response |

Also test:

- ALL and ANY permission modes, including an empty requirement configuration;
- users with no role and roles with no permissions;
- list, detail, search, count, export, bulk, and nested-resource capability and
  row-policy enforcement;
- leaked resource IDs and IDOR attempts through every lookup variant;
- mass-assignment attempts for roles, permissions, `super_admin` status, and
  system flags;
- self-escalation, unauthorized delegation, system-role mutation, and removal of
  the final `super_admin`;
- attempts to use `roles:assign` to create a role or replace its permissions, and
  attempts to assign a role outside the actor's explicit delegable set;
- immutable `super_admin`, `admin`, and `user` role keys, tiers, flags,
  lifecycle, permission composition, and delegation composition through every
  route and direct service entry point;
- normal registration, administrator creation, identity synchronization, and
  import paths atomically assigning `user`, with public role selection and
  `user` unbind attempts rejected;
- the chosen email/`user_name` fields, per-flow requiredness, accepted login
  input, shared normalization, database uniqueness under concurrency,
  cross-column ambiguity rejection for an either-identifier login input, and
  both sides of the chosen reuse-after-soft-delete policy; existing-project work
  must prove those choices were preserved unless migration was requested;
- `user` denied on every management endpoint; `admin` allowed only for strictly
  lower users and custom roles, and denied for role deletion, system-role
  mutation, delegation changes, `super_admin` transfer, peers, and higher targets;
- management writes returning `403001` before lookup when capability is absent,
  returning non-leaking `404001` for self, peer, higher, protected, unknown, or
  hidden requested-role targets after capability passes, and reserving `403001`
  for visible targets outside delegation or affected-authority policy;
- administrative user and role lists, counts, searches, details, exports, and
  nested reads showing all non-deleted targets only to `super_admin`; every other
  administrator sees only strictly lower, non-protected targets, cannot see
  itself or peers, and receives the same `404001` for hidden and unknown IDs;
- role and user pages loading grants and authority in a bounded number of
  queries whose count does not grow with page size, with list `total` using the
  exact visibility predicate;
- role/user mutation responses using immutable in-transaction snapshots rather
  than post-commit request-session reloads, with nested `assigned_role_ids`
  filtered to the actor's visible roles;
- ordinary role binding unable to grant `super_admin`, `admin` assignment or
  revocation requiring the current `super_admin`, and `super_admin` transfer
  leaving exactly one holder;
- the operator-run PostgreSQL bootstrap script accepting only immutable
  `users.id`, requiring an existing live active identity with `user`, assigning
  only `super_admin`, updating the user
  authorization version and global epoch only when changed, and auditing in one
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
  bootstrap, transfer, direct SQL, and a concurrent race for the tenth slot;
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
- the default exact `sub`/`jti`/`iat`/`exp`/`token_type` profile, the
  explicitly consented profile adding both `iss` and `aud`, rejection of a
  partial pair or profile mismatch, preservation of an existing configured pair,
  configurable one-hour default, canonical selected-policy subject and UUIDv4
  JTI, startup rejection of weak/example secrets, 4096-byte input and output
  limits, registration-before-return without a Redis record on oversized output,
  exact Redis record, outage, confirmed current-Token logout, account-wide logout
  invalidating two independently issued Tokens, and the revocation matrix in
  [JWT access-token security](jwt-session-security.md);
- revocation while access tokens and authorization caches are warm, including
  multiple application workers and the declared maximum stale-access window;
- immediate-revocation endpoints with an old token and an old permission cache,
  proving that current authorization versions are resolved authoritatively;
- cache outage behavior, which must reload from the authority or fail closed.
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

## Database Coverage

SQLite can make unit tests fast but does not reproduce PostgreSQL constraints,
locking, isolation, JSON behavior, or row-level security. Run integration tests
against the production database engine for foreign keys, the singleton global
authorization guard, system-role protection, default-user assignment, concurrent
super-admin changes, partial live-relation uniqueness, every implemented
soft-delete/restore transaction, audit and `rbac_state` deletion guards,
migrations, and query plans.

Run the bundled integration suite only against fresh disposable targets. Set
`TEST_DATABASE_URL` to a new empty PostgreSQL database ending in `_test`, and
set `TEST_DISPOSABLE_DATABASE` to that exact database name. Set both
`TEST_REDIS_URL` and `TEST_RATE_LIMIT_REDIS_URL` to separate, initially empty
Redis targets, and set `TEST_REDIS_ISOLATION_CONFIRMED=yes` only after checking
that they are dedicated to these tests. The fixture verifies the actual
PostgreSQL database and empty schema before Alembic runs, and reads Redis
`DBSIZE` before any test key cleanup. Migration tests downgrade to `base`, so
never point these variables at a database or Redis holding valuable data.
If a prior run left objects or keys, recreate the disposable targets instead
of bypassing the guard. Ordinary unit tests do not require these settings.

## Completion Evidence

Use the repository's normal commands. A typical project may run tests, formatting,
linting, type checking, and migration checks, but do not invent tool requirements
that the project did not adopt. Report exact commands and failures. A generated
template is not complete if it was only inspected; at minimum import the app,
exercise the ASGI client, and run its authorization tests.
