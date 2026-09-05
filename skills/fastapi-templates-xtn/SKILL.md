---
name: fastapi-templates-xtn
description: Build or harden FastAPI services that require tenant-scoped PostgreSQL RBAC, strict administrative hierarchy, minimal revocable JWT sessions, non-sequential identifiers, and transactionally consistent authorization writes. Use for new or existing FastAPI RBAC work; do not select for FastAPI tasks with no authorization requirement.
---

# FastAPI Templates XTN

> Independently maintained by XTN as an extension of
> [`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
> from `wshobson/agents`. See [NOTICE](NOTICE) and
> [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and licenses.

Deliver a runnable FastAPI service whose complexity matches the product. Preserve
an existing project's intentional architecture; use the opinionated PostgreSQL
baseline when the product has not already made conflicting choices.

## Inspect First

- Determine whether the task is greenfield or extends an existing service.
- Inspect Python and dependency versions, settings, database and migrations,
  identity provider, package layout, transaction ownership, and tests.
- Preserve the selected database, identity provider, package manager, module
  boundaries, and deployment model unless changing one is requested.
- Keep async handlers free of blocking work. Do not add background workers,
  multi-tenancy, or another architecture layer without a product need. An active
  JTI registry requested for token revocation is a valid Redis need; keep it
  separate from any RBAC permission cache.

## Load Only What The Task Needs

Start with this file and choose the narrowest primary reference:

| Task | Read |
| --- | --- |
| General FastAPI setup needed as part of the RBAC service | [Modern FastAPI stack](references/modern-fastapi-stack.md) |
| JWT payload, signing, JTI validation, Redis sessions, refresh, login, logout, or token revocation | [JWT session security](references/jwt-session-security.md) |
| Concrete JWT/PostgreSQL-session/Redis code or adapting the included token adapter | [JWT session security](references/jwt-session-security.md), then [JWT session implementation](references/jwt-session-implementation.md) |
| Identifier policy, UUID models, sequence avoidance, or public ID review | [Identifier policy](references/identifier-policy.md) |
| Concrete integer-to-UUID schema migration or identifier backfill | [Identifier policy](references/identifier-policy.md), then [Migrations](references/migrations.md) |
| Database-agnostic RBAC policy, flow, tenant isolation, or authorization cache | [RBAC design](references/rbac.md) |
| PostgreSQL models, services, endpoints, or runnable baseline | [PostgreSQL implementation](references/postgresql-rbac-implementation.md) |
| Hierarchy, delegation, ownership, protected identities, or self-elevation | [Administrative hierarchy](references/administrative-hierarchy.md) |
| Authorization writes, immediate revocation, concurrency, audit outcomes, cache invalidation, or outbox | [Atomic authorization consistency](references/atomic-consistency.md) |
| Tables, constraints, permission seeds, backfills, or upgrades | [Migrations](references/migrations.md) |
| Test-client or test-infrastructure work only | [Testing](references/testing.md) |

Add another reference only when the deliverable spans its concern. For example,
a concrete PostgreSQL hierarchy write needs the PostgreSQL, hierarchy, and atomic
references; a schema change adds migrations; implementing behavior tests adds
testing. A policy-only review need not load implementation or test files.

Decide this routing from the request and repository evidence before opening a
reference. Do not open a file merely to check whether it might be useful. A
PostgreSQL administrative write with no schema or baseline-policy change does not
need `rbac.md`, `migrations.md`, or `modern-fastapi-stack.md`.
Specialized rows override the general RBAC row: a hierarchy-only question reads
only `administrative-hierarchy.md`, and an atomicity-only question reads only
`atomic-consistency.md` in addition to this entrypoint.

The PostgreSQL implementation already fixes the baseline policy. Do not also read
the general RBAC reference unless changing its policy, model, or permission
semantics. Do not follow cross-links unless the current task meets their loading
condition.

Treat [assets/postgresql-rbac](assets/postgresql-rbac/) as output source, not
instructions. Copy it as one directory without reading every file. Never load the
asset recursively. Use `rg --files` and `rg -n "symbol-or-route"`, then inspect
only the code being adapted, its direct policy/query dependency, and matching
tests. Running a test does not require reading its implementation first.

## Fixed Baseline And Invariants

Unless existing product decisions conflict, keep these defaults:

- Python 3.12+, FastAPI, Pydantic 2, SQLAlchemy 2 async, asyncpg, Alembic, named
  constraints, tenant-safe composite foreign keys, and PostgreSQL integration
  tests. SQLite cannot prove this lock or constraint contract.
- Use non-sequential UUID primary/API IDs for users, tenants, memberships, roles,
  permissions, sessions, audit rows, and every business entity; generate new
  entity IDs as random UUIDv4. Only a deterministic seed whose stable key is
  already public may use the narrow UUIDv5 exception in the identifier policy.
  Do not use `SERIAL`,
  `BIGSERIAL`, `IDENTITY`, integer autoincrement, `max(id)+1`, or a hidden
  sequential public alias. Integer tiers, versions, epochs, and counts are not
  identifiers. UUIDs reduce casual enumeration; they never replace tenant-scoped
  SQL, object authorization, non-leaking `404`s, rate limits, or IDOR tests.
- Use stable, exact `resource:action` positive grants. Active roles union
  permissions and take the maximum tier. Do not add deny rules, wildcards, role
  inheritance, scope languages, or a permission cache to the baseline.
- Scope every tenant lookup in SQL, including list, search, count, export, bulk,
  and nested operations. Apply ownership and row policy separately from RBAC.
- Larger tiers are higher. Compare complete current and proposed multi-role
  authority: ordinary actors manage only strictly lower authority. Deny peer,
  higher, incomparable, protected, and cross-tenant targets, plus direct and
  indirect self-elevation. Owner alone uses tier `1000`; ordinary roles use
  `0..999`.
- Keep role assignment, role definition, permission replacement, delegation, and
  ownership transfer as separate capabilities. `can_delegate` is an explicit
  subset; new roles start non-delegable; only Owner changes delegation; delegation
  control and ownership transfer cannot be delegated.
- Privileged bodies use `extra="forbid"` and never accept tenant, ownership,
  protection, delegation, or mutable authorization-version fields. Protect system
  roles, the final Owner, bootstrap, and break-glass paths explicitly.
- In JWTs, `sub` is the only user identity claim and is the canonical UUIDv4
  string of immutable `users.id`; never put username, email, display name, roles,
  permissions, tier, status, protection flags, or versions in the payload. The
  tenant-bound baseline also carries `tid` as scope, not profile data. Require a
  unique random UUIDv4 `jti` and validate it against the server-side active
  session before authorization. Reload PostgreSQL identity, membership, and RBAC
  authority; fail closed on unavailable state. Follow
  [JWT session security](references/jwt-session-security.md).
- Use `401` for invalid, expired, missing, or revoked credentials; `403` for a
  visible but forbidden action; `404` to conceal missing or cross-tenant
  resources; and `503` when a required authentication authority is unavailable.
- Apply the same authorization service at HTTP, WebSocket, job, CLI, and direct
  service trust boundaries. Audit privileged decisions without secrets.

## Atomic Authorization Boundary

Every authorization control-plane write, and every protected business write that
promises immediate revocation, has one authoritative transaction. Under the
shared lock order, reload the actor and complete affected authority from
PostgreSQL, decide again, then commit the mutation, all version increments, the
allowed audit, and any outbox rows together. On denial, roll back the whole
attempt before writing a denied audit in a separate transaction. A route check,
old JWT, cached context, or earlier ORM read cannot replace this decision. Follow
[atomic authorization consistency](references/atomic-consistency.md). Full-set or
status replacement commands also require a post-lock `If-Match` check so one
authorized administrator cannot silently overwrite another's newer decision.
PostgreSQL and Redis are not one ACID boundary: persist authoritative session
state and any revocation outbox in PostgreSQL, fail closed during partial
activation, and never recreate a missing Redis allowlist entry from a JWT.

## Implementation Workflow

1. Define actors, protected resources, stable capabilities, tenant boundaries,
   row-level rules, administrative effects, and expected failure responses.
2. For greenfield PostgreSQL RBAC, copy the complete asset. In an existing app,
   preserve its policy, transaction, query, and migration boundaries.
3. Implement complete configuration, models, schemas, dependencies, services,
   routes, migrations, and tests. Never copy a route without its policy, locking
   query, tenant constraint, audit path, and negative tests.
4. Keep authentication, capability checks, tenant filtering, and row policy
   distinct. Run formatting, linting, typing, migrations, PostgreSQL tests, and an
   ASGI exercise; report anything not verified.

## Completion Criteria

- A clean environment installs and imports; configuration has no insecure
  production defaults or runtime `create_all()` migration substitute.
- Migrations work from empty and supported prior revisions. The result includes
  executable models, tenant constraints, permission seed, authorization service,
  transactional administration, Owner-only delegation, auditing, and identity
  integration points.
- PostgreSQL tests cover positive and negative policy, rollback, tenant isolation,
  low-to-high and peer denial, self-elevation, protected and Owner invariants,
  committed revocation, phantom holders, and cross-tenant assignment.
- JWT tests cover minimal claims, UUIDv4 `sub`/`jti`, Redis allowlist mismatch and
  outage, refresh separation, and revocation races. Schema inspection proves no
  RBAC or business identity column uses an integer sequence or identity default.
- Do not claim production readiness while required production assumptions or
  PostgreSQL behavior remain unverified.
