# FastAPI And RBAC Testing

Read this reference before implementing or reviewing tests. Match the repository's
pinned versions and plugins instead of copying obsolete client fixtures.

The runnable PostgreSQL examples are under
[`assets/postgresql-rbac/tests`](../assets/postgresql-rbac/tests/). In particular,
`test_rbac_api.py` covers the neutral public API, system-role and administrative
workflows, optimistic preconditions, and rollback-before-denial audit, while
`test_postgresql_locking.py` covers global-guard ordering, identity-map refresh,
committed actor revocation, and concurrent assignments.

For token/session tests use
[JWT session security](jwt-session-security.md). For schema and API identifier
tests use [identifier policy](identifier-policy.md). Do not load either reference
for an unrelated test-infrastructure-only task.

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
- Run migration upgrade from an empty database and from supported prior revisions.
- Inspect generated OpenAPI and prove that no public path, tag, operation ID,
  application title, response schema, or error code contains `rbac`. Internal
  packages such as `app.rbac` are outside this assertion.
- Assert that every authorization-management route uses only `GET` or `POST` and
  that no `PUT`, `PATCH`, `DELETE`, or legacy `/rbac` alias is registered.

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
returns `403` before `404` or `412` to an unprivileged or newly revoked caller.

Role update, enable, disable, delete, permission, and delegation commands require
a strong current `If-Match`. Test missing (`428`), malformed/weak/wildcard or
wrong-resource (`422`), stale (`412`), current success, and two authorized
administrators starting from the same role version. The second writer must not
silently overwrite the first.
Reserve `409` for a server-detected conflict such as exhausted bounded retries.
User-role bind/unbind is instead tested as an incremental, idempotent,
single-transaction command with post-lock authority reload; this version does not
require a user ETag.

## Authorization Matrix

For every protected capability, cover the meaningful rows of this matrix:

| Context | Expected result |
| --- | --- |
| Missing or invalid bearer token | `401` with `WWW-Authenticate: Bearer` |
| Active user, no required permission | `403` |
| Required permission through one role | Success |
| Required permissions split across multiple roles | Success for union semantics |
| Disabled identity or revoked session | `401` under the documented policy |
| Suspended user | `401` under the documented policy |
| Missing or deliberately concealed resource | Same generic `404` response |

Also test:

- ALL and ANY permission modes, including an empty requirement configuration;
- users with no role and roles with no permissions;
- list, detail, search, count, export, bulk, and nested-resource capability and
  row-policy enforcement;
- leaked resource UUIDs and IDOR attempts through every lookup variant;
- mass-assignment attempts for roles, permissions, ownership, and
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
- `user` denied on every management endpoint; `admin` allowed only for strictly
  lower users and custom roles, and denied for role deletion, system-role
  mutation, delegation changes, super-admin transfer, peers, and higher targets;
- ordinary role binding unable to grant `super_admin`, `admin` assignment or
  revocation requiring the current `super_admin`, and ownership transfer leaving
  exactly one holder;
- the offline bootstrap command creating or loading the intended identity,
  preserving `user`, assigning `super_admin`, updating versions and epoch, and
  auditing in one transaction; repeat for the same identity is a no-op and a
  different second identity is rejected without partial state;
- an upgrade with multiple legacy owner holders failing before schema changes,
  and direct SQL rejecting both a second `super_admin` and removal of the final
  holder while allowing bootstrap and atomic transfer;
- custom-role soft deletion immediately removing effective access while
  retaining grants and assignments, preventing enablement and key reuse, and
  leaving all three system roles undeletable; also reject the reserved legacy
  role key `owner`;
- permission and role bind/unbind batches rejecting duplicate IDs and one bad
  target atomically, and treating already-bound or already-unbound relations as
  idempotent no-ops;
- targets whose ordinary role hides an additional peer, higher, protected, or
  incomparable role, proving authorization uses the complete multi-role snapshot;
- shared-role edits involving suspended or inactive assignees whose assignments
  would become effective after reactivation;
- concurrent assignment and shared-role edits, proving the global guard is the
  first lock and freezes the affected set before it is scanned;
- concurrent role changes that target the same sole-super-admin invariant;
- direct service calls, background tasks, and WebSockets that could bypass route
  dependencies;
- the minimal-claim, UUIDv4 subject/JTI, Redis allowlist, outage, activation,
  logout, and refresh matrix in [JWT session security](jwt-session-security.md);
- revocation while access tokens and authorization caches are warm, including
  multiple application workers and the declared maximum stale-access window;
- immediate-revocation endpoints with an old token and an old permission cache,
  proving that current authorization versions are resolved authoritatively;
- cache outage behavior, which must reload from the authority or fail closed.
- PostgreSQL schema inspection proving every RBAC, session, audit, and business
  primary/public ID follows [identifier policy](identifier-policy.md) and no
  integer sequence or identity generator is hidden beside a UUID key.

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
super-admin changes, migrations, and query plans.

## Completion Evidence

Use the repository's normal commands. A typical project may run tests, formatting,
linting, type checking, and migration checks, but do not invent tool requirements
that the project did not adopt. Report exact commands and failures. A generated
template is not complete if it was only inspected; at minimum import the app,
exercise the ASGI client, and run its authorization tests.
