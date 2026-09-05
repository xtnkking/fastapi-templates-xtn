# FastAPI And RBAC Testing

Read this reference before implementing or reviewing tests. Match the repository's
pinned versions and plugins instead of copying obsolete client fixtures.

The runnable PostgreSQL examples are under
[`assets/postgresql-rbac/tests`](../assets/postgresql-rbac/tests/). In particular,
`test_rbac_api.py` covers administrative workflows and rollback-before-denial
audit, while `test_postgresql_locking.py` covers identity-map refresh, committed
actor revocation, and phantom shared-role holders.

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

## Authorization Matrix

For every protected capability, cover the meaningful rows of this matrix:

| Context | Expected result |
| --- | --- |
| Missing or invalid bearer token | `401` with `WWW-Authenticate: Bearer` |
| Active identity and tenant, no permission | `403` |
| Required permission through one role | Success |
| Required permissions split across multiple roles | Success for union semantics |
| Wrong or invisible tenant | `404` when existence is concealed |
| Cross-tenant resource ID | Same response as a missing resource |
| Disabled identity or revoked session | `401` under the documented policy |
| Suspended membership | The documented, non-leaking tenant response |

Also test:

- ALL and ANY permission modes, including an empty requirement configuration;
- users with no role and roles with no permissions;
- list, detail, search, count, export, bulk, and nested-resource tenant isolation;
- forged tenant values in paths, headers, bodies, and tokens;
- mass-assignment attempts for roles, permissions, tenant IDs, ownership, and
  system flags;
- self-escalation, unauthorized delegation, system-role mutation, and removal of
  the final owner;
- attempts to use `roles:assign` to create a role or replace its permissions, and
  attempts to assign a role outside the actor's explicit delegable set;
- targets whose ordinary role hides an additional peer, higher, protected, or
  incomparable role, proving authorization uses the complete multi-role snapshot;
- scoped grants from different roles, proving that a permission and a narrow scope
  are not independently unioned into an authority pair that no role granted;
- shared-role edits involving suspended or inactive assignees whose assignments
  would become effective after reactivation;
- concurrent role changes that target the same last-owner invariant;
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
against the production database engine for database-enforced tenant isolation,
composite foreign keys, concurrent last-owner changes, migrations, and query
plans.

## Completion Evidence

Use the repository's normal commands. A typical project may run tests, formatting,
linting, type checking, and migration checks, but do not invent tool requirements
that the project did not adopt. Report exact commands and failures. A generated
template is not complete if it was only inspected; at minimum import the app,
exercise the ASGI client, and run its authorization tests.
