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
| Identity | Greenfield contract chosen explicitly; bundled fallback stores nullable `email`/`user_name`, requires at least one, and reserves both globally |
| Authorization | One application-wide RBAC control plane |
| System roles | Immutable `super_admin`, `admin`, and `user` roles |
| Grants | Positive, exact `resource:action` permission keys |
| Multiple roles | Permission union and maximum management tier; no more than 10 live bindings per user |
| Delegation | `role_permissions.can_delegate`; never inferred from possession |
| Hierarchy | Larger tier is higher; ordinary management requires strict `>` |
| Protected authority | The `super_admin` identity is outside ordinary administration |
| Production token target | Exact default `sub`/`jti`/`iat`/`exp`/`token_type`; consented optional `iss`/`aud` pair; no profile or authorization data |
| Current `Unreleased` token adapter | Default five-claim or explicitly approved seven-claim profile, configurable 3600-second default, and required Redis active-JTI validation; no individual PostgreSQL Token table |
| Permission cache | None; versions remain available for a later versioned cache |
| Authorization writes | Global guard first, canonical row locks, reload, policy decision, mutation, version bump, audit |
| Public API | Neutral `/api/v1` GET/POST routes with the standard numeric-code envelope |
| Operational logs | Safe one-line JSON to stdout with server request correlation and one completion event |
| Audit storage | Append-only `rbac_audit_events` with bounded safe state and database enforcement |
| Runtime lifecycle rule | Every exposed delete/unbind uses tombstones and every rebind creates a new episode; the asset directly implements custom-role deletion and both RBAC unbinds |

Do not add explicit deny, wildcards, role inheritance, ad hoc resource-scope
languages, or an authorization cache merely because they are common elsewhere.
Each changes policy algebra and needs its own precedence, invalidation, and
concurrency tests. A Redis active-JTI registry is per-Token authentication state,
not a permission cache; use [JWT access-token security](jwt-session-security.md)
when per-Token revocation is in scope.

## Public Surface Does Not Reveal The Engine

RBAC is an internal implementation detail. Public paths, OpenAPI tags,
`operation_id` values, application titles, response fields, and error codes must
not contain `rbac`. Use resource names such as `permissions`, `roles`, `users`,
and `system`; use the neutral numeric denial code `403001`. Do not retain
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
- [`app/observability.py`](../assets/postgresql-rbac/app/observability.py)
  configures safe structured process/request logging, context propagation, and
  defensive redaction.
- [`app/audit.py`](../assets/postgresql-rbac/app/audit.py) validates stable audit
  labels and converts bounded allowlisted before/after state to safe JSON.
- [`app/rbac/domain.py`](../assets/postgresql-rbac/app/rbac/domain.py) defines
  immutable principals, the permission catalog, system-role specifications, and
  complete multi-role authority snapshots.
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py) resolves
  effective and delegable permissions and implements canonical locking queries.
- [`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) contains
  strict manageability, system-role, and anti-self-elevation decisions.
- [`app/rbac/dependencies.py`](../assets/postgresql-rbac/app/rbac/dependencies.py)
  validates bearer claims, requires the Redis active-JTI record, loads current
  PostgreSQL user and RBAC authority, compares `users.token_version`, and
  centralizes exact permission checks.
- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py) implements
  user status changes, custom-role lifecycle, role creation and update,
  permission and role bind/unbind commands, delegation, super-admin transfer,
  rollback-before-denial-audit, and the common locking protocol.
- [`app/rbac/api.py`](../assets/postgresql-rbac/app/rbac/api.py) exposes neutral
  application-level resource endpoints with privileged fields excluded from
  bodies.
- [`sql/bootstrap_super_admin.sql`](../assets/postgresql-rbac/sql/bootstrap_super_admin.sql)
  is the operator-run, one-time first-super-admin transaction.
- [`alembic/versions/0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py)
  creates the core RBAC schema and the database-enforced 10-live-role limit;
  [`0002_system_roles.py`](../assets/postgresql-rbac/alembic/versions/0002_system_roles.py)
  installs the system-role/API contract;
  [`0003_business_audit.py`](../assets/postgresql-rbac/alembic/versions/0003_business_audit.py)
  adds generic append-only business audit.
- [`0004_password_auth.py`](../assets/postgresql-rbac/alembic/versions/0004_password_auth.py)
  adds password credential episodes, account-security audit, and the dedicated
  administrator-reset capability.
- [`tests`](../assets/postgresql-rbac/tests/) exercises PostgreSQL behavior,
  including the public contract, system roles, multi-role union, strict
  hierarchy, delegation ceilings, direct and indirect self-elevation,
  assignment constraints, the 10-live-role limit, optimistic concurrency, and
  locking.

Every Python name referenced by an example is implemented in the asset. The app
now includes the concrete username/password baseline described in
[Local password authentication](local-password-authentication.md), while other
identity providers remain product-specific. For greenfield use, settle the full login identifier contract in
[Identity and soft-delete lifecycle](identity-soft-delete.md) before adapting
those integration points.

## Schema Contract

The authoritative relationships are:

```text
users *---* roles (through live user_roles episodes)
roles *---* permissions (through live role_permissions episodes)
rbac_state (exactly one global guard row)
users 1---* rbac_audit_events (actor and optional target)
```

The baseline fixes these seven tables:

| Table | Purpose and enforced boundary |
| --- | --- |
| `users` | Selected login identifiers, lifecycle, protection, token revocation version, and authorization version |
| `rbac_state` | Fixed `scope='global'` row used as the first RBAC lock and shared epoch; not Token state |
| `permissions` | Stable capability catalog |
| `roles` | Immutable key, display data, tier, active/soft-delete lifecycle, version, and internal `is_system`/`is_protected`/`is_super_admin` flags |
| `role_permissions` | Non-sequentially identified grant episodes, explicit `can_delegate`, bind metadata, and soft-delete metadata; one live row per role/permission pair |
| `user_roles` | Non-sequentially identified assignment episodes with bind and soft-delete metadata; one live row per user/role pair and at most 10 live rows per user |
| `rbac_audit_events` | Allowed and denied RBAC administration decisions with trusted source, payload version, safe before/after summaries, request ID, and append-only enforcement |

`rbac_audit_events.source` is one of `http`, `service`, `job`, `operator`, or
`migration`; `schema_version` is currently `1`. The database validates action,
reason, correlation ID, decision, source, version, and JSON-object state. Indexed
review paths cover request ID, actor/time, target/time, and `(created_at, id)`.
A trigger rejects row updates and deletes. This does not protect against a
database owner and is not a claim of cryptographic immutability. Follow
[Audit module](audit-module.md) for event coverage, retention, access, and safe
state rules, and [Operational logging](operational-logging.md) for non-durable
request telemetry.

`rbac_state` is coordination metadata, not a business entity or Token table. It
has exactly two non-null columns and one seeded row:

| Column | PostgreSQL type | Contract |
| --- | --- | --- |
| `scope` | `varchar(16)` | Primary key constrained to the single value `global` |
| `epoch` | `bigint` | Defaults to `0`, remains non-negative, and increments only for an effective RBAC change |

The initial data is `scope='global', epoch=0`. Every RBAC writer locks this row
with `SELECT ... FOR UPDATE` before discovering affected assignments or locking
users and roles. Missing state fails closed; runtime code never recreates it.
There is no synthetic ID, creation timestamp, user identity, JWT, or session
data in this table. Runtime and production-maintenance roles cannot delete,
truncate, disable, or soft-delete it; database enforcement must reject those
operations.

This bundled asset selects the compliant PostgreSQL UUIDv4 profile for user,
role, permission, audit, and business entity IDs. New runtime entity IDs are
application-generated UUIDv4 values; public deterministic system-role and
permission seeds use the narrow UUIDv5 exception. There is no `SERIAL`,
`BIGSERIAL`, `IDENTITY`, integer autoincrement identifier, or sequential public
alias. A new project is not required to choose UUID: when it has no established
ID strategy, prefer registered business prefixes plus cryptographically random
uppercase suffixes sized by lifetime volume. Follow
[identifier policy](identifier-policy.md) before creating tables. The fixed
`rbac_state.scope` string is a control key, not a business or API ID.

For the bundled fallback identity profile, `email` and `user_name` are nullable,
at least one must be present, and each supplied canonical value remains globally
unique even after user soft deletion. The product's trusted provisioner owns
canonicalization, and login credential verification remains an adaptation point.
A greenfield implementation must still ask which identity fields `users` stores,
which are required on each creation path, what inputs login accepts, how values
normalize, and whether reuse is allowed; it may then remove an unused column or
replace these fallback constraints. An
existing application's choice remains unchanged unless migration is requested.
A shared untyped login input must also reject email/`user_name` cross-column
ambiguity through a canonical login-key constraint, disjoint syntax, or explicit
typed inputs; separate per-column unique constraints do not prevent it.
Regardless of that choice, immutable `users.id` is the JWT subject and bootstrap
target.

`user_roles` and `role_permissions` use non-sequential surrogate IDs so each bind
is a distinct episode. They carry trusted bind and soft-delete actor/timestamp
metadata. Non-null foreign keys plus partial unique indexes on each logical pair
where `deleted_at IS NULL` reject missing parents and concurrent duplicate live
bindings. Unbind sets tombstone metadata; a later bind inserts a new episode and
never clears the old row. Each user may have at most 10 live `user_roles` rows:
the mandatory `user` and any `super_admin` binding count, disabled roles still
count, and tombstones do not count. The service checks the complete final set
under `rbac_state`; PostgreSQL serializes assignment writes on that guard and
uses a deferred final-state constraint so direct SQL and concurrent requests
cannot exceed the limit.

`is_system` and `is_protected` are independent. `is_system` makes a role
application-defined and immutable at runtime; it must not automatically make
every holder protected. Only `super_admin` contributes protected
super-administrator authority. This distinction lets a higher actor manage an
ordinary user who holds the system `user` role.

Custom-role deletion is soft deletion: set `deleted_at`,
`deleted_by_user_id`, and `is_active=false`, and tombstone all of its live grants
and assignments in the same transaction. Exclude deleted/inactive roles and
tombstoned relations from every effective-authority query, never enable a
deleted role, and never reuse its key.
This fresh baseline has no legacy `owner` system role. `owner` may be used as an
ordinary custom-role key; its name alone grants no authority and does not bypass
the same tier, delegation, lifecycle, and soft-delete rules as other custom
roles.

The same lifecycle applies to every runtime-deletable parent, including users,
custom roles, and business entities: tombstone the parent and its live owned
relations atomically. Restore never revives relation tombstones. A restored user
receives only a new mandatory `user` binding; former custom, `admin`, or
`super_admin` assignments require explicit new decisions.
Append-only audit rows are not soft-deletable and cannot be updated, deleted, or
truncated. Follow
[Identity and soft-delete lifecycle](identity-soft-delete.md).

## System Roles

Migrations seed exactly these roles before users are provisioned:

| Key | Tier | Flags | Runtime policy |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | system, protected, active (`is_super_admin` internal compatibility flag) | Exactly one current holder after bootstrap; full explicit allowlist; only the transfer command changes its holder |
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
the live user and binds a new live `user` episode in the same PostgreSQL
transaction. The request body
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
- `rbac_state.epoch` changes after shared authorization changes.

The baseline reads PostgreSQL for each request, so these are not weak cache
checks. Preserve them when adding a versioned permission cache.

## Minimum Public API

The baseline has at least these thirteen protected endpoints:

| Method | Path | Required capability | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/permissions` | `permissions:read` | Permission list |
| `GET` | `/api/v1/permissions/{permission_id}` | `permissions:read` | Permission detail |
| `GET` | `/api/v1/roles` | `roles:read` | Strictly lower visible-role list; `super_admin` sees all |
| `GET` | `/api/v1/roles/{role_id}` | `roles:read` | Visible role detail including `version` |
| `POST` | `/api/v1/roles` | `roles:create` | Create an empty custom role |
| `POST` | `/api/v1/roles/{role_id}/update` | `roles:update` | Update mutable role information |
| `POST` | `/api/v1/roles/{role_id}/disable` | `roles:status:update` | Disable a custom role |
| `POST` | `/api/v1/roles/{role_id}/enable` | `roles:status:update` | Re-enable a non-deleted custom role |
| `POST` | `/api/v1/roles/{role_id}/delete` | `roles:delete` | Soft-delete a custom role |
| `POST` | `/api/v1/roles/{role_id}/permissions/bind` | `roles:permissions:bind` | Atomically add permission grants |
| `POST` | `/api/v1/roles/{role_id}/permissions/unbind` | `roles:permissions:unbind` | Atomically tombstone live permission grants |
| `POST` | `/api/v1/users/{user_id}/roles/bind` | `roles:assign` | Atomically add role assignments |
| `POST` | `/api/v1/users/{user_id}/roles/unbind` | `roles:revoke` | Atomically tombstone live role assignments |

Every endpoint requires a current bearer identity and server-side PostgreSQL
authority. Use the four-field JSON envelope, real HTTP status, numeric business
codes, server-generated request ID, and simple page data from
[API response standard](api-response-standard.md). Missing or invalid
authentication returns `401001`; a visible but forbidden action returns generic
`403001`; a missing or deliberately concealed target returns generic `404001`.
A normal `user` has none of the required capabilities. An `admin` can call only
its seeded capability subset, and every write still applies hierarchy,
delegation, protected-target, affected-user, and anti-self-elevation checks after
locking.

An early route capability gate is only a fast rejection. Record its denied
privileged `POST` decision without target secrets, and repeat the capability
decision from current PostgreSQL state inside the service transaction. The
service checks current capability before revealing target existence or a role
version, so a revoked or direct-service caller cannot probe with `403001`,
`404001`, or `409002` differences.

Administrative reads obey hierarchy as well as capability. The current
`super_admin` may list and inspect every non-deleted role and user. Every other
administrator may list or inspect only roles and users whose complete effective
management tier is strictly lower, and never itself, a peer, a higher target, or
a protected target. Apply the same predicate to list rows and `total`, then use
it again for detail lookup so a concealed ID is indistinguishable from a missing
one (`404001`). The caller reads its own effective authority only through
`GET /api/v1/me/access`. Assemble page authorities and role grants in bounded
batch queries rather than one query per row.

Use explicit operation IDs such as `list_permissions`, `get_role`, and
`bind_user_roles`, and neutral OpenAPI tags such as `Permissions`, `Roles`,
`User access`, and `System administration`.

Role creation accepts only `key`, `name`, `description`, and
`management_tier`. The key is permanently immutable; permission IDs, system
flags, active/deleted state, the internal `is_super_admin` flag, and delegation are
forbidden fields.
New roles start active and permissionless. Ordinary role information update
accepts `expected_version` plus at least one of `name` or `description`; tier
changes require a separate, `super_admin`-only policy if the product truly needs
them.

Permission bind/unbind requires a unique `permission_ids` array plus
`expected_version`; user-role bind/unbind requires a unique `role_ids` array.
Limit a permission array to 100 IDs and a role array to 10 IDs. The role request
limit is only input bounding, not enforcement of the per-user total; a user may
already hold other roles. After locking, require the complete proposed live set
to contain no more than 10 bindings. Then
reject duplicate, unknown, or unmanageable objects, validate the complete
proposed result, and commit the whole request or none of it. Binding an existing
live relation or unbinding a pair with no live relation is an idempotent success
with `changed=false`. A successful unbind tombstones the live episode; a later
bind inserts a new episode with a new ID rather than clearing the tombstone.
Ordinary binding can never grant `super_admin`; only the `super_admin` transfer
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

The delegation endpoints and `super_admin` transfer additionally require the
current `super_admin` identity after locks are held. No route accepts an
authority override from the request body.

## Optimistic Concurrency

`GET /api/v1/roles/{role_id}` returns `version` inside the role data. Role
update, disable, enable, delete, and permission/delegation bind or unbind require
that nonnegative value as a strict JSON integer `expected_version` in the body.
Role creation does not require it. Missing or malformed input returns HTTP `422`
with business code `422001`; a stale value returns HTTP `409` with business code
`409002` only after the caller passes the complete current policy decision.

Compare the expected role version only after acquiring canonical locks and
reloading current rows and then authorizing the full proposed change, before
mutation. An unauthorized caller receives `403001` regardless of whether its
version guess is stale, preventing a version oracle. Use `409001` for another
client-visible state conflict such as exhausted bounded affected-set retries. An
expected version never replaces the post-lock authorization decision. User role
bind/unbind is an incremental, idempotent, single-transaction command and does
not require a user version in this baseline; its post-lock hierarchy and authority
reload remains mandatory.

Construct the complete successful role representation and new version from one
immutable snapshot while the authoritative transaction still owns the locks.
Do not commit, requery grants through a request session, and combine that newer
state with an older role version; a delete response must not become `404001`
after the deletion already committed. A dynamic `request_id` in the JSON body
means this envelope cannot also claim a stable strong ETag; see the response
standard for the protocol rationale.

Apply the same rule to user-role bind/unbind, user disable/enable, and any other
administrative write returning user data. The service builds an immutable
`UserResponse` projection while the authorization transaction still owns the
global, user, role, and relation locks; the route returns that snapshot after
commit without loading the user again through its request `Session`. Nested
`assigned_role_ids` contains only roles visible to the actor. Keep the complete
unfiltered assignments for policy and audit, but never expose a disabled peer or
higher role ID to an ordinary administrator through the response projection.

## Administrative Decision

Role assignment and revocation calculate complete target authority before and
after the proposal. Allow only when all applicable conditions hold:

1. The actor is current and active. Assignment also requires an active target;
   revocation may tombstone live role episodes for a suspended target.
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
9. The target's final set contains at most 10 live role bindings. The required
   `user` and any `super_admin` binding count; disabled roles count; tombstoned
   history does not.

Shared custom-role updates expand every live assignment, including suspended
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

Do not promote the first registered user and do not tell an operator to improvise
a bare `user_roles` row. A naked insert omits the global lock, mandatory base
role check, uniqueness decision, version increments, and audit event.

The intended person must first create an account through the product's normal
trusted registration or provisioning flow. After that active account has the
mandatory `user` role, the user personally operates PostgreSQL from a trusted
host and runs the supplied script:

```powershell
$env:PSQL_DATABASE_URL = "postgresql://app_user:password@db.example/app"
psql $env:PSQL_DATABASE_URL `
  --set=super_admin_user_id=9bb60ae3-cad9-4e07-b072-7f4336044f18 `
  --file sql/bootstrap_super_admin.sql
```

The script locks `rbac_state(scope='global')` first, reloads and verifies
the existing user, system-role shapes, exact super-admin grants, and mandatory
`user` assignment, and confirms that adding `super_admin` leaves at most 10 live
bindings, then binds only the pre-seeded `super_admin`. When the binding
changes, it increments the affected user's authorization version and global
epoch. It writes an audit event and commits once. It never creates the identity,
changes a password, changes `users.token_version`, or marks the user protected.
Re-running for the same resulting identity leaves authority versions unchanged;
attempting to name a missing, inactive, deleted, protected, or different second
identity is refused and rolled back. The parameter is immutable `users.id`, not
an email or `user_name`. It is not an HTTP endpoint and never accepts a role
definition or arbitrary grants. Automated tests may execute the script against a
disposable test database; the user performs the target-database initialization.

The migration seeds `super_admin`, `admin`, and `user` directly and does not
rename, reserve, or interpret a custom role whose key is `owner`. A deferred
PostgreSQL constraint runs whenever a `super_admin` assignment changes and
requires the final transaction state to contain exactly one holder. This permits
the first bootstrap and an atomic remove-plus-add transfer, but rejects both a
second holder and removal of the final holder.
The fresh `0001_single_project_rbac` schema also serializes direct assignment
writes and enforces at most 10 live roles per user. This is a baseline invariant,
not a later compatibility migration.

After bootstrap, change the sole holder only through
`POST /api/v1/system/super-admin/transfer`. The transfer atomically inserts a new
`super_admin` episode for the target, tombstones the actor's live episode,
preserves `user` for
both, increments both users' authorization versions and the global epoch, and
writes the allowed audit. The next authorization reload observes the new
authority immediately. This baseline does not increment `users.token_version`
or revoke either user's Access Tokens merely because authority was transferred.
Exactly one active holder remains after commit.
Because `super_admin` counts toward the role limit, a target already holding 10
live roles must first have a non-mandatory role unbound; the failed transfer has
no partial assignment, version, epoch, or audit-success write.

## Locking Contract

Follow [atomic authorization consistency](atomic-consistency.md) for complete
failure semantics. Every authorization writer first locks the fixed global
guard, freezing assignment topology before any affected-user scan. It then uses:

```text
rbac_state(scope='global')
-> users, sorted by canonical ID
-> roles, sorted by canonical ID
-> role_permissions and user_roles for the changed authority
-> protected business rows when applicable
```

The engine uses PostgreSQL `READ COMMITTED`, and integration tests assert it.
Locking queries refresh existing ORM identities so a row loaded before waiting
cannot remain stale. The service-layer post-lock reload is the final decision for
privileged writes. All future user-status, token-version, ownership, role-state, and
protected-business writers must reuse this order.
The `user_roles` database trigger acquires the same global guard for direct SQL,
and its deferred constraint evaluates the transaction's final live count. This
is the database backstop for the service check and the concurrent tenth-slot race.

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
uvicorn app.main:app --reload
pytest
```

After the product's trusted identity flow has created the intended account, stop
the application setup and let the user run `sql/bootstrap_super_admin.sql` with
the `psql` command shown above. The application's SQLAlchemy URL commonly starts
with `postgresql+asyncpg://`; `psql` needs an ordinary `postgresql://` connection
URL instead.

Compose credentials are local-development values. Deployments supply separate
secrets and a managed PostgreSQL URL. Startup rejects empty, known-placeholder,
or shorter-than-32-byte JWT secrets; length alone does not prove entropy. The app
never uses runtime `metadata.create_all()` as a migration substitute.

The initializer creates a separate test database. Tests ignore the application's
`DATABASE_URL`, accept only `TEST_DATABASE_URL`, require its database name to end
in `_test`, and verify `current_database()` before destructive test cleanup. The
development port binds to `127.0.0.1`.

## Required Adaptation Points

The main product-specific decisions are:

1. For greenfield use, first ask whether `users` stores `email`, `user_name`, or
   both. Separately fix per-flow requiredness, accepted login inputs,
   normalization, database uniqueness, cross-field ambiguity, and post-deletion
   reuse. Preserve an existing product's choices unless their migration is
   requested. Follow
   [Identity and soft-delete lifecycle](identity-soft-delete.md).
2. Add stable business capabilities without weakening the fixed administration
   catalog or system-role invariants.
3. Connect the asset's issuance function, `get_current_principal`, and user
   provisioning to the product's trusted login or identity provider. The current
   `Unreleased` adapter implements the default exact five claims, an optional
   `iss`/`aud` pair, Redis registration and
   validation, user-version comparison, and logout; the product still owns
   credential verification and the point that calls issuance. Follow
   [JWT access-token security](jwt-session-security.md): require the canonical
   selected user ID as `sub` and a UUIDv4 `jti`, remove `ver` from JWT, bind the current
   `users.token_version` in the Redis value, and require the exact active-JTI
   record before the existing PostgreSQL user and RBAC reload. Do not add a
   PostgreSQL Token table. Leave `iss`/`aud` absent for a new project unless the
   user gives explicit consent after a plain-language explanation of their
   cross-service scoping benefit and configuration cost; no reply is not consent.
   Preserve an existing configured pair by default. Explicitly tell the user that
   the one-hour default must be reviewed for business risk and login experience.
4. Add business-resource queries and compose ownership or row policy after the
   capability decision.
5. If the product exposes user deletion/restoration, mutable permission-catalog
   lifecycle, or business-entity lifecycle, add separate capabilities, hierarchy
   decisions, transaction services, audit actions, and negative/concurrency
   tests. Reuse the lifecycle columns and scenarios, but do not mistake them for
   already registered public endpoints.
6. Set `SERVICE_NAME` and immutable `SERVICE_VERSION` from deployment, connect
   stdout JSON to the product's log platform, and define operational-log and
   audit preservation/access policies. Keep exception details off until their
   content and readers are reviewed. Add domain-specific audit tables only for
   explicitly identified security or regulated business events; do not broaden
   `rbac_audit_events` into a generic activity dump.

Do not ask the user to choose basic table topology, multi-role semantics,
hierarchy direction, the three system roles, the 10-live-role limit,
default-user assignment,
delegation meaning, default denial, public administration routes, lock order, or
ordinary self-management behavior unless the existing application explicitly
contradicts this baseline.

The immutable `v0.3.0` tag predates the Redis adapter and still uses the older
`sub`/`ver`/`jti` shape. Do not describe that historical tag as containing the
current `Unreleased` behavior, and do not call the working tree production-ready
until its final Redis and PostgreSQL checks pass.
