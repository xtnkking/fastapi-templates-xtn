# PostgreSQL RBAC Reference Implementation

Read this reference when creating single-project authorization on PostgreSQL or
when concrete code is requested. The maintained example is in
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
| System roles | Immutable `super_admin`, `admin`, and `user` roles |
| Grants | Positive, exact `resource:action` permission keys |
| Multiple roles | Permission union and maximum management tier |
| Delegation | `role_permissions.can_delegate`; never inferred from possession |
| Hierarchy | Larger tier is higher; ordinary management requires strict `>` |
| Protected authority | The `super_admin` identity is outside ordinary administration |
| Production token target | Minimal `sub` user identity, unique `jti`, and protocol claims; no profile or authorization data |
| Current asset token adapter | Requires `sub`, `ver`, and `jti`; it has no active-JTI registry validation |
| Permission cache | None; versions remain available for a later versioned cache |
| Authorization writes | Global guard first, canonical row locks, reload, policy decision, mutation, version bump, audit |
| Public API | Neutral `/api/v1` resource routes using only `GET` and `POST` |

Do not add explicit deny, wildcards, role inheritance, ad hoc resource-scope
languages, or an authorization cache merely because they are common elsewhere.
Each changes policy algebra and needs its own precedence, invalidation, and
concurrency tests. A Redis active-JTI registry is authentication session state,
not a permission cache; use [JWT session security](jwt-session-security.md) when
revocable sessions are in scope.

## Public Surface Does Not Reveal The Engine

RBAC is an internal implementation detail. Public paths, OpenAPI tags,
`operation_id` values, application titles, response fields, and error codes must
not contain `rbac`. Use resource names such as `permissions`, `roles`, `users`,
and `system`; use a neutral denial code such as `access_forbidden`. Do not retain
`/rbac` as a compatibility alias because an alias still exposes the mechanism.

The internal package and asset directory may remain `app.rbac` and
`assets/postgresql-rbac`; database and audit internals are not public API. Keep
internal policy reason codes out of responses.

All public administration routes in this baseline use only `GET` and `POST`.
Do not introduce `PUT`, `PATCH`, or `DELETE` aliases. Action-specific `POST`
paths make lifecycle and relationship commands explicit; method choice does not
weaken authentication, authorization, idempotency, or concurrency requirements.

## Included Code

- [`app/rbac/models.py`](../assets/postgresql-rbac/app/rbac/models.py) defines
  users, the singleton authorization guard, roles, permissions, role grants,
  user-role assignments, and audit events.
- [`app/rbac/domain.py`](../assets/postgresql-rbac/app/rbac/domain.py) defines
  immutable principals, the permission catalog, system-role specifications, and
  complete multi-role authority snapshots.
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py) resolves
  effective and delegable permissions and implements canonical locking queries.
- [`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) contains
  strict manageability, system-role, and anti-self-elevation decisions.
- [`app/rbac/dependencies.py`](../assets/postgresql-rbac/app/rbac/dependencies.py)
  validates bearer claims, loads current PostgreSQL authority, and centralizes
  exact permission checks. It does not yet query an active-JTI registry.
- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py) implements
  user and role lifecycle, role creation and update, permission and role
  bind/unbind commands, delegation, super-admin transfer,
  rollback-before-denial-audit, and the common locking protocol.
- [`app/rbac/api.py`](../assets/postgresql-rbac/app/rbac/api.py) exposes neutral
  application-level resource endpoints with privileged fields excluded from
  bodies.
- [`app/rbac/bootstrap.py`](../assets/postgresql-rbac/app/rbac/bootstrap.py)
  performs the one-time, offline first-super-admin transaction.
- [`alembic/versions`](../assets/postgresql-rbac/alembic/versions/) creates and
  upgrades the schema, constraints, system roles, global guard, and permission
  catalog.
- [`tests`](../assets/postgresql-rbac/tests/) exercises PostgreSQL behavior,
  including the public contract, system roles, multi-role union, strict
  hierarchy, delegation ceilings, direct and indirect self-elevation,
  assignment constraints, optimistic concurrency, and locking.

Every Python name referenced by an example is implemented in the asset. The app
is authorization-focused: it validates externally issued access tokens but does
not invent signup, password-reset, or identity-provider behavior.

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
| `roles` | Immutable key, display data, tier, active/soft-delete lifecycle, version, and system/protected/owner flags |
| `role_permissions` | Role grants plus the explicit `can_delegate` subset |
| `user_roles` | Unique user-role assignment with actor and timestamp metadata |
| `authorization_audit_events` | Allowed and denied privileged decisions with safe before/after summaries and request ID |

All user, role, permission, assignment metadata, session, audit, and business
entity identifiers are PostgreSQL UUIDs. New entity IDs are application-generated
UUIDv4 values. There is no `SERIAL`, `BIGSERIAL`, `IDENTITY`, integer
autoincrement identifier, or sequential public alias. The permission and
system-role seeds may use deterministic UUIDv5 only because their stable keys
are already public catalog identifiers. The fixed authorization-state scope
string is a control key, not a business or API identifier. Follow
[identifier policy](identifier-policy.md) for new tables and migrations.

`user_roles` has non-null foreign keys to `users.id` and `roles.id` plus unique
`(user_id, role_id)`. Database constraints reject missing users, missing roles,
and duplicate assignments even if an application check races.

`is_system` and `is_protected` are independent. `is_system` makes a role
application-defined and immutable at runtime; it must not automatically make
every holder protected. Only `super_admin` contributes protected owner
authority. This distinction lets a higher actor manage an ordinary user who
holds the system `user` role.

Custom-role deletion is soft deletion: set `deleted_at`,
`deleted_by_user_id`, and `is_active=false` in one transaction. Retain grants
and assignments for audit, exclude deleted or inactive roles from every
effective-authority query, never enable a deleted role, and never reuse its key.
Permanently reserve the legacy `owner` key even after the system role is renamed
to `super_admin`; otherwise a later downgrade can collide with a custom role.

## System Roles

Migrations seed exactly these roles before users are provisioned:

| Key | Tier | Flags | Runtime policy |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | system, protected, owner, active | Exactly one current holder after bootstrap; full explicit allowlist; only the transfer command changes its holder |
| `admin` | `500` | system, active | Manages only strictly lower users and custom roles within its delegation ceiling |
| `user` | `0` | system, active | Mandatory base role for every normal user; no authorization-management permissions |

All three keys, tiers, system flags, lifecycle state, and permission/delegation
composition are immutable through public APIs, including for `super_admin`.
They cannot be disabled, soft-deleted, or recreated. Change a system-role seed
only through a reviewed, versioned migration with the same impact analysis,
version increments, epoch update, and audit expectations as any other authority
change.

The control-plane portion of the seeded `admin` permission set is deliberately
incomplete and fixed to:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:assign
roles:revoke
roles:permissions:bind
roles:permissions:unbind
users:read
users:status:update
```

It does not include `roles:delete`, `roles:delegation:update`, or
`super_admin:transfer`. Possessing a capability is only the first gate: an
`admin` still cannot manage itself, another `admin`, a `super_admin`, any system
role, a custom role at tier `500` or above, or permissions outside its explicit
delegable set. The included `USER_PERMISSION_KEYS` is empty. The example
`projects:read` and `projects:update` permissions in `ADMIN_PERMISSION_KEYS`
form its whole delegable set. Replace those example business permissions through
a reviewed migration when adapting the asset; they do not broaden the fixed
control-plane set above.

Every public signup and trusted user-provisioning path creates or synchronizes
the user and binds `user` in the same PostgreSQL transaction. The request body
cannot choose an initial role. A user keeps `user` after receiving another role,
and the role-unbind service always rejects removal of `user`. Direct database
imports must use the same provisioning boundary or a database safeguard that
enforces this invariant.

## Permission Catalog

Seed stable descriptions for at least these administration capabilities:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:delete
roles:assign
roles:revoke
roles:permissions:bind
roles:permissions:unbind
roles:delegation:update
users:read
users:status:update
super_admin:transfer
```

`role_permissions.can_delegate=true` means a permission is both usable and
delegable, so delegable permissions are structurally a subset of effective
permissions. Delegation control and super-admin transfer are never delegable.
New custom roles start with no permissions; `POST /api/v1/roles` cannot smuggle
grants into creation. This preserves the independent bind and unbind
capabilities.

The `super_admin` receives permissions from an explicit
`SUPER_ADMIN_PERMISSION_KEYS` allowlist, not every permission-table row. Adding
a platform-internal or break-glass key therefore does not silently grant it.

The model maintains these change counters:

- `users.token_version` invalidates access tokens after identity-wide changes;
- `users.authz_version` changes after that user's role or status changes;
- `roles.version` changes after role information, lifecycle, grants, or
  delegation changes;
- `authorization_state.epoch` changes after shared authorization changes.

The baseline reads PostgreSQL for each request, so these are not weak cache
checks. Preserve them when adding a versioned permission cache.

## Minimum Public API

The baseline has at least these thirteen protected endpoints:

| Method | Path | Required capability | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/permissions` | `permissions:read` | Permission list |
| `GET` | `/api/v1/permissions/{permission_id}` | `permissions:read` | Permission detail |
| `GET` | `/api/v1/roles` | `roles:read` | Role list |
| `GET` | `/api/v1/roles/{role_id}` | `roles:read` | Role detail and strong ETag |
| `POST` | `/api/v1/roles` | `roles:create` | Create an empty custom role |
| `POST` | `/api/v1/roles/{role_id}/update` | `roles:update` | Update mutable role information |
| `POST` | `/api/v1/roles/{role_id}/disable` | `roles:status:update` | Disable a custom role |
| `POST` | `/api/v1/roles/{role_id}/enable` | `roles:status:update` | Re-enable a non-deleted custom role |
| `POST` | `/api/v1/roles/{role_id}/delete` | `roles:delete` | Soft-delete a custom role |
| `POST` | `/api/v1/roles/{role_id}/permissions/bind` | `roles:permissions:bind` | Atomically add permission grants |
| `POST` | `/api/v1/roles/{role_id}/permissions/unbind` | `roles:permissions:unbind` | Atomically remove permission grants |
| `POST` | `/api/v1/users/{user_id}/roles/bind` | `roles:assign` | Atomically add role assignments |
| `POST` | `/api/v1/users/{user_id}/roles/unbind` | `roles:revoke` | Atomically remove role assignments |

Every endpoint requires a current bearer identity and server-side PostgreSQL
authority. Missing or invalid authentication returns `401`; a visible but
forbidden action returns a generic `403`; a missing or deliberately concealed
target returns the same generic `404`. A normal `user` has none of the required
capabilities. An `admin` can call only its seeded capability subset, and every
write still applies hierarchy, delegation, protected-target, affected-user, and
anti-self-elevation checks after locking.

An early route capability gate is only a fast rejection. Record its denied
privileged `POST` decision without target secrets, and repeat the capability
decision from current PostgreSQL state inside the service transaction. The
service checks current capability before revealing target existence or a role
version, so a revoked or direct-service caller cannot probe with `403`, `404`,
or `412` differences.

Use explicit operation IDs such as `list_permissions`, `get_role`, and
`bind_user_roles`, and neutral OpenAPI tags such as `Permissions`, `Roles`,
`User access`, and `System administration`.

Role creation accepts only `key`, `name`, `description`, and
`management_tier`. The key is permanently immutable; permission IDs, system
flags, active/deleted state, owner state, and delegation are forbidden fields.
New roles start active and permissionless. Ordinary role information update
accepts only `name` and `description`; tier changes require a separate,
`super_admin`-only policy if the product truly needs them.

Permission bind/unbind requires a unique `permission_ids` array; user-role
bind/unbind requires a unique `role_ids` array. Limit each array to 100 IDs,
reject duplicate, unknown, or unmanageable objects, validate the complete
proposed result, and commit the whole request or none of it. Binding an existing relation or
unbinding a missing relation is an idempotent success with `changed=false`.
Ordinary binding can never grant `super_admin`; only the ownership-transfer
command may do that. Only `super_admin` can bind or unbind `admin`, while `user`
cannot be unbound from any user.

The baseline also exposes these neutral companion operations for the existing
user lifecycle, delegation, and transfer capabilities:

```text
GET  /api/v1/me/access
GET  /api/v1/users
GET  /api/v1/users/{user_id}
POST /api/v1/users/{user_id}/disable
POST /api/v1/users/{user_id}/enable
POST /api/v1/roles/{role_id}/delegable-permissions/bind
POST /api/v1/roles/{role_id}/delegable-permissions/unbind
POST /api/v1/system/super-admin/transfer
```

The delegation endpoints and ownership transfer additionally require the
current `super_admin` identity after locks are held. No route accepts an
authority override from the request body.

## Optimistic Concurrency

`GET /api/v1/roles/{role_id}` returns a strong validator such as
`ETag: "role:<uuid>:v<version>"`. Role update, disable, enable, delete, and
permission/delegation bind or unbind require that exact value in `If-Match`.
Role creation and every successful role mutation return the current strong ETag;
creation does not require `If-Match`. Reject a missing required header with
`428 Precondition Required`; reject malformed syntax, a weak validator, `*`, or
a validator for another role as `422`; reject a well-formed stale version with
`412 Precondition Failed`.

Compare a required role validator only after acquiring canonical locks and
reloading current rows, before mutation. Reserve `409 Conflict` for a
server-detected conflict such as exhausted bounded affected-set retries. Never
put expected authorization versions in a privileged JSON body. User role
bind/unbind is an incremental, idempotent, single-transaction command and does
not require a user ETag in this baseline; its post-lock hierarchy and authority
reload remains mandatory.

Construct the complete successful role representation and its ETag from one
immutable snapshot while the authoritative transaction still owns the locks.
Do not commit, requery grants through a request session, and combine that newer
state with an older role version; a delete response must not become `404` after
the deletion already committed.

## Administrative Decision

Role assignment and revocation calculate complete target authority before and
after the proposal. Allow only when all applicable conditions hold:

1. The actor is current and active. Assignment also requires an active target;
   revocation may clean retained roles from a suspended target.
2. The actor has the exact operation permission after locks are held.
3. Actor and target are different users.
4. No affected identity or role is protected or an immutable system role.
5. Actor tier is strictly greater than target-before, target-after, and every
   changed role tier.
6. Target effective and delegable permissions before and after are subsets of
   the actor's explicit delegable permissions.
7. The actor's own authority is unchanged by the proposal.
8. Mandatory `user`, sole-`super_admin`, soft-delete, and audit invariants remain
   valid.

Shared custom-role updates expand every retained assignment, including suspended
users. Reject the whole operation when the actor holds the role or an affected
user is protected, peer, higher, or outside the delegation ceiling. This blocks
indirect self-elevation and partial bulk writes.

Delegation changes use the same complete impact analysis and require the current
`super_admin` after locks are held; injecting `roles:delegation:update` into an
ordinary role never bypasses that identity check.

User suspension and reactivation deny self-management, protected users, peers,
higher users, and retained authority outside the actor's delegation ceiling.
Reactivation revalidates every retained role before restoring access.

## First Super Admin And Transfer

Do not promote the first registered user and do not tell an operator to insert a
bare `user_roles` row. A naked SQL insert omits the global lock, mandatory base
role, uniqueness decision, version increments, and audit event.

After migrations, run the offline command from a trusted host:

```text
python -m app.rbac.bootstrap --super-admin-email admin@example.com
```

The command writes PostgreSQL directly through the same transaction protocol. It
locks `authorization_state(scope='global')` first, proves that no different
current super admin exists, creates or loads the named active user, ensures the
`user` assignment, binds the pre-seeded `super_admin`, increments the affected
user authorization version and global epoch, writes an audit event, and commits
once. Re-running for the same resulting identity is a no-op; attempting to name
a second identity is refused. It is not an HTTP endpoint and never accepts a
role definition or arbitrary grants.

The migration rejects a legacy owner role with multiple holders before changing
the schema. A deferred PostgreSQL constraint runs whenever a `super_admin`
assignment changes and requires the final transaction state to contain exactly
one holder. This permits the first bootstrap and an atomic remove-plus-add
transfer, but rejects both a second holder and removal of the final holder.

After bootstrap, change the sole holder only through
`POST /api/v1/system/super-admin/transfer`. The transfer atomically binds
`super_admin` to the target, removes it from the actor, preserves `user` for
both, increments both user versions and the global epoch, revokes sessions when
the product policy requires it, and writes the allowed audit. Exactly one active
holder remains after commit.

## Locking Contract

Follow [atomic authorization consistency](atomic-consistency.md) for complete
failure semantics. Every authorization writer first locks the fixed global
guard, freezing assignment topology before any affected-user scan. It then uses:

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
python -m app.rbac.bootstrap --super-admin-email admin@example.com
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

1. Add stable business capabilities without weakening the fixed administration
   catalog or system-role invariants.
2. Connect `get_current_principal` and user provisioning to the product's issuer
   or identity provider. For production, follow
   [JWT session security](jwt-session-security.md): require canonical UUIDv4
   `sub` and `jti`, move `ver` to server-side session state, and add PostgreSQL
   session plus Redis active-JTI checks. The current adapter only passes JTI
   through and does not provide per-token revocation.
3. Add business-resource queries and compose ownership or row policy after the
   capability decision.

Do not ask the user to choose basic table topology, multi-role semantics,
hierarchy direction, the three system roles, default-user assignment,
delegation meaning, default denial, public administration routes, lock order, or
ordinary self-management behavior unless the existing application explicitly
contradicts this baseline.
