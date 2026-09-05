# PostgreSQL RBAC Reference Implementation

Read this reference when creating tenant RBAC on PostgreSQL or when concrete code
is requested. The maintained example is in
[`assets/postgresql-rbac`](../assets/postgresql-rbac/). Copy the asset as one
coherent baseline or adapt all of its equivalent boundaries in an existing
application. Do not copy only the route layer.

## Fixed Baseline

The example deliberately resolves the choices that most often produce security
gaps:

| Concern | Baseline decision |
| --- | --- |
| Database | PostgreSQL with asyncpg |
| Persistence | SQLAlchemy 2 typed mappings and Alembic |
| Identity scope | Global users, tenant memberships |
| Authorization scope | One complete tenant; no cross-tenant authority |
| Grants | Positive, exact `resource:action` permission keys |
| Multiple roles | Permission union and maximum management tier |
| Delegation | `role_permissions.can_delegate`; never inferred from possession |
| Hierarchy | Larger tier is higher; ordinary management requires strict `>` |
| Protected authority | Protected users, memberships, roles, and owner roles are outside ordinary administration |
| Production token target | Minimal `sub` user identity plus tenant-bound `tid` scope and protocol claims; no profile or authorization data |
| Current asset token adapter | Requires `sub`, `tid`, `ver`, and `jti`; accepts generic/non-canonical UUIDs for `sub`/`tid` and arbitrary JTI text, with no session-registry validation |
| RBAC cache | None in the baseline; version columns are retained for a later versioned permission cache |
| RBAC writes | PostgreSQL `READ COMMITTED`, canonical row locks, reload, policy decision, mutation, version bump, audit |
| API semantics | Tenant in path, no authority fields in bodies, generic external denial codes |

Do not add explicit deny, wildcard keys, role inheritance, per-resource scopes, or
an authorization cache merely because they are common elsewhere. Each changes
the policy algebra and requires its own precedence, invalidation, and concurrency
tests. A Redis active-JTI registry is authentication session state, not that
authorization cache; implement it through
[JWT session security](jwt-session-security.md) when revocable sessions are in
scope.

## Included Code

- [`app/rbac/models.py`](../assets/postgresql-rbac/app/rbac/models.py) defines
  users, tenants, authorization guards, memberships, roles, permissions, role
  grants, tenant-safe membership-role assignments, and audit events.
- [`app/rbac/domain.py`](../assets/postgresql-rbac/app/rbac/domain.py) defines
  immutable principal and complete multi-role authority snapshots.
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py) resolves
  effective and delegable permissions and contains tenant-scoped locking queries.
- [`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) contains the
  strict manageability and anti-self-elevation decisions.
- [`app/rbac/dependencies.py`](../assets/postgresql-rbac/app/rbac/dependencies.py)
  validates tenant-bound bearer claims, loads current PostgreSQL authority, and
  centralizes exact permission checks. It does not yet query a JTI registry.
- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py) implements
  membership lifecycle, role creation, assignment, revocation, shared-role
  permission replacement, owner-only delegation management, ownership transfer,
  rollback-before-denial-audit, and the common locking protocol.
- [`app/rbac/api.py`](../assets/postgresql-rbac/app/rbac/api.py) exposes narrow,
  tenant-scoped endpoints with privileged fields excluded from bodies.
- [`alembic/versions/0001_postgresql_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_postgresql_rbac.py)
  creates the schema, constraints, indexes, and initial permission catalog.
- [`alembic/versions/0002_complete_rbac_control_plane.py`](../assets/postgresql-rbac/alembic/versions/0002_complete_rbac_control_plane.py)
  upgrades existing tenants with member administration and owner-only delegation
  capabilities, reserves tier `1000` for Owner, and strengthens the system-role
  constraint. Its downgrade is intentionally lossy; use a database backup to
  recover removed grants and pre-normalization role values.
- [`tests`](../assets/postgresql-rbac/tests/) exercises PostgreSQL behavior,
  including multi-role union, strict hierarchy, delegation ceilings, direct and
  indirect self-elevation, protected roles, and composite tenant constraints.

Every Python name referenced by an example is implemented in the asset. The app
is intentionally RBAC-focused: it validates externally issued access tokens but
does not invent a signup, password-reset, or identity-provider flow.

## Schema Contract

The authoritative relationships are:

```text
users 1---* memberships *---1 tenants 1---1 tenant_authorization_state
memberships *---* roles (through tenant-bound membership_roles)
roles *---* permissions (through role_permissions.can_delegate)
tenants 1---* authorization_audit_events
```

The baseline fixes these nine tables:

| Table | Purpose and enforced boundary |
| --- | --- |
| `users` | Global identity status, protection flag, and token revocation version |
| `tenants` | Tenant lifecycle; every tenant-owned object carries its ID |
| `tenant_authorization_state` | One row per tenant used as the shared authorization lock and epoch |
| `memberships` | Unique `(tenant_id, user_id)` identity membership, status, protection, and version |
| `permissions` | Stable global permission catalog; tenant-manageable keys remain explicitly allowlisted |
| `roles` | Tenant role, management tier, lifecycle, version, and protected/system/owner flags; PostgreSQL reserves tier `1000` for Owner |
| `role_permissions` | Tenant-safe role grants plus the explicit `can_delegate` subset |
| `membership_roles` | Tenant-safe role assignment with composite foreign keys on both sides |
| `authorization_audit_events` | Allowed and denied privileged decisions with before/after summaries and request ID |

All primary and foreign identifier columns in these tables are PostgreSQL UUIDs.
New entity IDs are application-generated UUIDv4 values; join and guard tables
reuse UUIDs in composite or shared primary keys. There is no `SERIAL`,
`BIGSERIAL`, `IDENTITY`, or integer autoincrement identifier. The permission seed
uses a deterministic UUIDv5 only because the permission key is already a public,
stable catalog identifier. Follow [identifier policy](identifier-policy.md) for
new business tables, database-side UUID defaults, exposure rules, and migrations.

`membership_roles` repeats `tenant_id` and has composite foreign keys to both
`memberships(id, tenant_id)` and `roles(id, tenant_id)`. All three columns are
non-null. This makes a cross-tenant assignment fail in PostgreSQL even if an
application check is missed or races.

`role_permissions.can_delegate=true` means the permission is both usable and
delegable. Therefore delegable permissions are structurally a subset of effective
permissions. Ordinary role create and permission-replacement bodies never accept
`can_delegate`. They create new grants as non-delegable and preserve the flag on
retained grants. Only the owner-only `roles/{role_id}/delegable-permissions`
control path can replace that subset. `roles:delegation:update` and
`tenant_ownership:transfer` are themselves always non-delegable.

Tenant owners receive permissions from the explicit
`TENANT_OWNER_PERMISSION_KEYS` allowlist, not every row in the global permission
table. Adding a platform or break-glass key therefore does not silently grant it
to each tenant owner.

The example stores four independent change counters:

- `users.token_version` invalidates access tokens after global identity changes;
- `memberships.authz_version` changes after an individual role or status change;
- `roles.version` changes after a role definition change;
- `tenant_authorization_state.epoch` changes after a shared authorization change.

The baseline reads PostgreSQL for every request, so these are not used as a weak
cache check. Preserve them if adding a versioned cache later.

## Administrative Decision

Role assignment and revocation both calculate the target before and after the
complete proposed change. They allow the mutation only when all conditions hold:

1. The actor is current and active in the same active tenant. Assignment also
   requires an active target; revocation can clean up retained roles from a
   suspended or globally disabled target.
2. The actor has the exact operation permission (`roles:assign` or
   `roles:revoke`) after locks are held.
3. Actor and target are different identities.
4. No affected identity or role is protected.
5. Actor tier is strictly greater than the target before, target after, and
   changed role tier.
6. Target effective and delegable permissions before and after are subsets of the
   actor's delegable permissions.
7. The actor's own authority is unchanged by the proposed operation.
8. Owner and audit invariants remain valid.

Shared-role permission replacement expands every retained assignment, including
suspended memberships. It rejects the entire operation when the actor holds the
role or any affected identity is protected, peer, higher, or outside the actor's
delegation ceiling. This blocks indirect self-elevation and partial bulk writes.

The same complete impact analysis protects delegation replacement. The endpoint
also requires the current owner role after locks are held; merely injecting the
`roles:delegation:update` permission into an ordinary role is insufficient.

Membership creation accepts only an existing active, unprotected `user_id` from
the trusted identity adapter. New memberships start active with no roles and no
permissions. Suspension and reactivation deny self-management, protected
identities, peers, higher identities, and retained authority outside the actor's
delegation ceiling. Reactivation also requires the global user to remain active.

## Locking Contract

The canonical guarantees and failure semantics are defined in
[atomic authorization consistency](atomic-consistency.md). The current asset has
no authentication-session table, so it skips that unused lock class and maps the
protocol to:

```text
users, sorted by UUID
-> tenant_authorization_state
-> memberships, sorted by UUID
-> roles, sorted by UUID
-> role_permissions for the changed role
```

The engine fixes PostgreSQL isolation to `READ COMMITTED`, and the integration
suite asserts it. Locking queries use `populate_existing` so a row loaded before
a wait cannot remain stale in SQLAlchemy's identity map. Shared-role changes use
discover-lock-requery with bounded full-transaction retries.

The service-layer post-lock reload is the final decision for privileged writes.
The routes deliberately send every authenticated tenant member into the service
so denied attempts are audited. Future user-status, session, ownership, role
state, or protected business writers must enter the appropriate lock class and
reuse the same protocol; they must not add a second lock order.

## Default API Workflow

Do not invent another provisioning sequence for a greenfield service. Use this
one after the identity adapter has synchronized the prospective member's global
`users.id`:

```text
GET  /tenants/{tenant_id}/rbac/permissions
POST /tenants/{tenant_id}/rbac/memberships
POST /tenants/{tenant_id}/rbac/roles
PUT  /tenants/{tenant_id}/rbac/roles/{role_id}/delegable-permissions
PUT  /tenants/{tenant_id}/rbac/memberships/{membership_id}/roles/{role_id}
```

The concrete request bodies are:

```json
{"user_id":"8d662202-a9f7-4570-aa6e-54ef62c128ad"}
```

```json
{
  "key": "manager",
  "name": "Manager",
  "management_tier": 500,
  "permissions": [
    "roles:read",
    "roles:create",
    "roles:assign",
    "roles:revoke",
    "roles:permissions:update",
    "memberships:read",
    "memberships:create",
    "memberships:status:update",
    "projects:read",
    "projects:update"
  ]
}
```

```json
{
  "delegable_permissions": ["projects:read", "projects:update"]
}
```

The Owner creates the role, sets exactly what it may delegate, and then assigns
it. The resulting manager can create strictly lower roles and manage strictly
lower members, but cannot edit itself, a peer, a higher identity, a protected
role, ownership, or delegation policy. Use
`PATCH /memberships/{membership_id}/status` with `{"status":"suspended"}` or
`{"status":"active"}` for the included lifecycle.

## Running The Asset

The asset is a source template. Preserve its `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md` when adapting or redistributing it. Copy the environment
file, generate a fresh JWT
secret, and set the generated value as `JWT_SECRET` in `.env` before startup.
Never reuse the example, test, or documentation values in a deployment.

PowerShell:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

POSIX shell:

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Then, from the asset root:

```text
docker compose -f compose.dev.yaml up -d --wait
python -m pip install -e ".[test]"
alembic upgrade head
python -m app.rbac.bootstrap --owner-email owner@example.test --tenant-slug acme --tenant-name "Acme"
uvicorn app.main:app --reload
pytest
```

The Compose credentials are explicitly local-development values. Deployments
must supply separate secrets and a managed PostgreSQL URL. Startup rejects an
empty, known-placeholder, or shorter-than-32-byte JWT secret; length alone does
not prove entropy, so generate the value with a cryptographic random generator.
The application never runs `metadata.create_all()` and migrations are a separate
explicit step.
The Compose initializer creates a separate `rbac_example_test` database. Tests
ignore the application's `DATABASE_URL`, accept only `TEST_DATABASE_URL`, require
its database name to end in `_test`, and verify `current_database()` before any
`TRUNCATE` statement.
The development port is bound to `127.0.0.1`, not every host interface. If an
older Compose version lacks `--wait`, wait for `docker compose ps` to report the
database healthy before running Alembic.

## Required Adaptation Points

Only three product decisions are intentionally left open:

1. Replace the example permission catalog with the product's stable capabilities.
2. Connect `get_current_principal` and global `users` synchronization to the
   product's token issuer or identity provider. For production, follow
   [JWT session security](jwt-session-security.md) and its conditional
   [implementation shapes](jwt-session-implementation.md): require canonical
   UUIDv4 `sub`, tenant-bound `tid`, and `jti`; move `ver` to server-side session
   state; and add both PostgreSQL session and Redis active-JTI checks. The current
   asset only passes JTI through and must not be represented as providing
   per-token revocation. The tenant membership API deliberately does not create
   global identities.
3. Add business-resource queries that always include the tenant predicate and
   then compose any ownership or row policy after RBAC.

Do not ask the user to choose the basic table topology, multi-role semantics,
hierarchy direction, delegation meaning, default denial, lock order, or ordinary
self-management behavior unless their existing system already contradicts this
baseline.
