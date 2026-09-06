# PostgreSQL RBAC Reference Implementation

Read this reference when creating single-project RBAC on PostgreSQL or when
concrete code is requested. The maintained example is in
[`assets/postgresql-rbac`](../assets/postgresql-rbac/). Copy it as one coherent
baseline or adapt every equivalent boundary in an existing application. Do not
copy only the route layer.

## Fixed Baseline

The example deliberately resolves choices that commonly produce security gaps:

| Concern | Baseline decision |
| --- | --- |
| Database | PostgreSQL with asyncpg |
| Persistence | SQLAlchemy 2 typed mappings and Alembic |
| Identity | Application users with status, protection, and revocation versions |
| Authorization | One application-wide RBAC control plane |
| Grants | Positive, exact `resource:action` permission keys |
| Multiple roles | Permission union and maximum management tier |
| Delegation | `role_permissions.can_delegate`; never inferred from possession |
| Hierarchy | Larger tier is higher; ordinary management requires strict `>` |
| Protected authority | Protected users, roles, and the system Owner are outside ordinary administration |
| Production token target | Minimal `sub` user identity, unique `jti`, and protocol claims; no profile or authorization data |
| Current asset token adapter | Requires `sub`, `ver`, and `jti`; it has no active-JTI registry validation |
| RBAC cache | None; versions remain available for a later versioned permission cache |
| RBAC writes | Global guard first, canonical row locks, reload, policy decision, mutation, version bump, audit |
| API semantics | Application-level `/rbac` routes, no authority fields in request bodies, generic external denial codes |

Do not add explicit deny, wildcards, role inheritance, ad hoc resource-scope
languages, or an authorization cache merely because they are common elsewhere.
Each changes policy algebra and needs its own precedence, invalidation, and
concurrency tests. A Redis active-JTI registry is authentication session state,
not an RBAC permission cache; use [JWT session security](jwt-session-security.md)
when revocable sessions are in scope.

## Included Code

- [`app/rbac/models.py`](../assets/postgresql-rbac/app/rbac/models.py) defines
  users, the singleton authorization guard, roles, permissions, role grants,
  user-role assignments, and audit events.
- [`app/rbac/domain.py`](../assets/postgresql-rbac/app/rbac/domain.py) defines
  immutable principals and complete multi-role authority snapshots.
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py) resolves
  effective and delegable permissions and implements canonical locking queries.
- [`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) contains
  strict manageability and anti-self-elevation decisions.
- [`app/rbac/dependencies.py`](../assets/postgresql-rbac/app/rbac/dependencies.py)
  validates bearer claims, loads current PostgreSQL authority, and centralizes
  exact permission checks. It does not yet query an active-JTI registry.
- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py) implements
  user status, role creation, assignment, revocation, shared-role permission
  replacement, Owner-only delegation, system ownership transfer,
  rollback-before-denial-audit, and the common locking protocol.
- [`app/rbac/api.py`](../assets/postgresql-rbac/app/rbac/api.py) exposes narrow
  application-level endpoints with privileged fields excluded from bodies.
- [`alembic/versions`](../assets/postgresql-rbac/alembic/versions/) creates the
  schema, constraints, indexes, global guard, and permission catalog.
- [`tests`](../assets/postgresql-rbac/tests/) exercises PostgreSQL behavior,
  including multi-role union, strict hierarchy, delegation ceilings, direct and
  indirect self-elevation, protected roles, assignment constraints, and locking.

Every Python name referenced by an example is implemented in the asset. The app
is intentionally RBAC-focused: it validates externally issued access tokens but
does not invent signup, password-reset, or identity-provider behavior.

## Schema Contract

The authoritative relationships are:

```text
users *---* roles (through user_roles)
roles *---* permissions (through role_permissions.can_delegate)
authorization_state (exactly one global guard row)
users 1---* authorization_audit_events (actor and optional target)
```

The baseline fixes these seven tables:

| Table | Purpose and enforced boundary |
| --- | --- |
| `users` | Identity status, protection, token revocation version, and authorization version |
| `authorization_state` | Fixed `scope='global'` row used as the first lock and shared epoch |
| `permissions` | Stable capability catalog |
| `roles` | Stable unique key, tier, lifecycle, version, and protected/system/Owner flags; tier `1000` is reserved for Owner |
| `role_permissions` | Role grants plus the explicit `can_delegate` subset |
| `user_roles` | Unique user-role assignment with actor and timestamp metadata |
| `authorization_audit_events` | Allowed and denied privileged decisions with safe before/after summaries and request ID |

All user, role, permission, assignment metadata, session, audit, and business
entity identifiers are PostgreSQL UUIDs. New entity IDs are application-generated
UUIDv4 values. There is no `SERIAL`, `BIGSERIAL`, `IDENTITY`, integer
autoincrement identifier, or sequential public alias. The permission seed may
use deterministic UUIDv5 only because each permission key is already a public,
stable catalog identifier. The fixed authorization-state scope string is a
control key, not a business or API identifier. Follow
[identifier policy](identifier-policy.md) for new tables and migrations.

`user_roles` has non-null foreign keys to `users.id` and `roles.id` plus unique
`(user_id, role_id)`. Database constraints reject missing users, missing roles,
and duplicate assignments even if an application check races.

`role_permissions.can_delegate=true` means a permission is both usable and
delegable, making delegable permissions structurally a subset of effective
permissions. Ordinary role create and permission-replacement bodies never accept
`can_delegate`: new grants start non-delegable and retained grants preserve the
flag. Only the Owner-only `roles/{role_id}/delegable-permissions` path replaces
that subset. `roles:delegation:update` and `system_owner:transfer` are always
non-delegable.

The system Owner receives permissions from the explicit
`OWNER_PERMISSION_KEYS` allowlist, not every permission table row. Adding
a platform-internal or break-glass key therefore does not silently grant it to
the Owner.

The model maintains these change counters:

- `users.token_version` invalidates access tokens after identity-wide changes;
- `users.authz_version` changes after that user's role or status changes;
- `roles.version` changes after a role definition or delegation change;
- `authorization_state.epoch` changes after shared authorization changes.

The baseline reads PostgreSQL for each request, so these are not weak cache
checks. Preserve them when adding a versioned permission cache.

## Administrative Decision

Role assignment and revocation calculate complete target authority before and
after the proposal. Allow only when all conditions hold:

1. The actor is current and active. Assignment also requires an active target;
   revocation may clean retained roles from a suspended target.
2. The actor has the exact operation permission after locks are held.
3. Actor and target are different users.
4. No affected user or role is protected.
5. Actor tier is strictly greater than target-before, target-after, and changed
   role tier.
6. Target effective and delegable permissions before and after are subsets of
   the actor's delegable permissions.
7. The actor's own authority is unchanged by the proposal.
8. Owner and audit invariants remain valid.

Shared-role permission replacement expands every retained assignment, including
suspended users. It rejects the whole operation when the actor holds the role or
an affected user is protected, peer, higher, or outside the delegation ceiling.
This blocks indirect self-elevation and partial bulk writes.

Delegation replacement uses the same complete impact analysis and requires the
current Owner role after locks are held; injecting the permission into an
ordinary role never bypasses that check.

User suspension and reactivation deny self-management, protected users, peers,
higher users, and retained authority outside the actor's delegation ceiling.
Reactivation revalidates every retained role before restoring access.

## Locking Contract

Follow [atomic authorization consistency](atomic-consistency.md) for complete
failure semantics. Every RBAC writer first locks the fixed global guard, freezing
assignment topology before any affected-user scan. It then uses:

```text
authorization_state(scope='global')
-> users, sorted by UUID
-> authentication sessions when applicable, sorted by UUID
-> roles, sorted by UUID
-> role_permissions and user_roles for the changed authority
-> protected business rows when applicable
```

The engine uses PostgreSQL `READ COMMITTED`, and integration tests assert it.
Locking queries refresh existing ORM identities so a row loaded before waiting
cannot remain stale. The service-layer post-lock reload is the final decision for
privileged writes. All future user-status, session, ownership, role-state, and
protected-business writers must reuse this order.

## Default API Workflow

Do not invent another provisioning sequence for a greenfield service. After the
identity adapter has synchronized the prospective user's `users.id`, use:

```text
GET  /rbac/permissions
POST /rbac/roles
PUT  /rbac/roles/{role_id}/delegable-permissions
PUT  /rbac/users/{user_id}/roles/{role_id}
```

Role creation uses:

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
    "users:read",
    "users:status:update",
    "projects:read",
    "projects:update"
  ]
}
```

Delegation replacement uses:

```json
{"delegable_permissions":["projects:read","projects:update"]}
```

The Owner creates the role, sets exactly what it may delegate, and assigns it.
The resulting manager can create strictly lower roles and manage strictly lower
users, but cannot edit itself, a peer, a higher identity, a protected role,
system ownership, or delegation policy. Use
`PATCH /rbac/users/{user_id}/status` with `{"is_active":false}` or
`{"is_active":true}` for the included lifecycle.

## Running The Asset

The asset is a source template. Preserve its `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md` when adapting or redistributing it. Copy the environment
file, generate a fresh JWT secret, and set it as `JWT_SECRET` before startup.
Never reuse example, test, or documentation secrets.

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
python -m app.rbac.bootstrap --owner-email owner@example.test
uvicorn app.main:app --reload
pytest
```

Compose credentials are local-development values. Deployments supply separate
secrets and a managed PostgreSQL URL. Startup rejects empty, known-placeholder,
or shorter-than-32-byte JWT secrets; length alone does not prove entropy. The app
never uses runtime `metadata.create_all()` as a migration substitute.

The initializer creates a separate test database. Tests ignore the application's
`DATABASE_URL`, accept only `TEST_DATABASE_URL`, require its database name to end
in `_test`, and verify `current_database()` before destructive test cleanup. The
development port binds to `127.0.0.1`.

## Required Adaptation Points

Only three product decisions remain open:

1. Replace the example permission catalog with stable product capabilities.
2. Connect `get_current_principal` and `users` synchronization to the product's
   issuer or identity provider. For production, follow
   [JWT session security](jwt-session-security.md): require canonical UUIDv4
   `sub` and `jti`, move `ver` to server-side session state, and add PostgreSQL
   session plus Redis active-JTI checks. The current adapter only passes JTI
   through and does not provide per-token revocation.
3. Add business-resource queries and compose ownership or row policy after RBAC.

Do not ask the user to choose basic table topology, multi-role semantics,
hierarchy direction, delegation meaning, default denial, lock order, or ordinary
self-management behavior unless the existing application contradicts this
baseline.
