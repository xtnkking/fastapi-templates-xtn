# PostgreSQL RBAC Reference Implementation

Read this reference when creating single-project authorization on PostgreSQL or
when concrete code is requested. The maintained example is in
[`assets/postgresql-rbac`](../assets/postgresql-rbac/). For a new application,
use [New-project delivery](new-project-delivery.md) to select application files
and starter tests; do not copy the whole asset. In an existing application,
adapt the relevant authorization, transaction and audit boundaries together,
following its established architecture.

The Skill delivers ORM models and code. The user generates, reviews, and
executes migrations, DDL, database-only protection, and initial data. No
migration history or initialization SQL is copied into a generated project;
generation, startup and ordinary tests never run schema creation or seeding.
The requirements below are model/service contracts plus an explicit
[database handoff](migrations.md), not a claim that custom PostgreSQL triggers
are installed by model metadata or Alembic autogeneration.

For a maintainer-facing Chinese map of how authentication, authorization,
rate limiting, logging, and audits fit together, read
[中文架构总览](architecture-overview.zh-CN.md). This English reference remains
the authoritative detailed implementation contract.

## Fixed Baseline

The example deliberately resolves choices that commonly produce security gaps:

| Concern | Baseline decision |
| --- | --- |
| Database | PostgreSQL with asyncpg |
| Persistence | SQLAlchemy 2 typed mappings; user-owned migrations and schema setup |
| Identity | Greenfield baseline requires `user_name` (trimmed, 3..32 ASCII), permanently reserved after deletion; ask only about case sensitivity |
| Authorization | One application-wide RBAC control plane |
| System roles | Immutable `super_admin`, `admin`, and `user` roles |
| Grants | Positive, exact `resource:action` permission keys |
| Multiple roles | Permission union and maximum management tier; no more than 10 live bindings per user |
| Granting | Current user must hold any permission it grants, while strict hierarchy and anti-self-elevation still apply; no independent delegation field/API |
| Hierarchy | Larger tier is higher; ordinary management requires strict `>` |
| Protected authority | The `super_admin` identity is outside ordinary administration |
| Production token target | Exact default `user_id`/`jti`/`iat`/`exp`/`token_type`; consented optional `iss`/`aud` pair; no profile or authorization data |
| Bundled token adapter | Default five-claim or explicitly approved seven-claim profile, configurable 86,400-second (24-hour) default, required Redis active-JTI validation and project-chosen simultaneous-login maximum; no individual PostgreSQL Token table |
| Permission cache | None; read current PostgreSQL authority on every request |
| Authorization writes | Global guard first, canonical row locks, reload, policy decision, mutation, edited-role version bump where needed, audit |
| Public API | Neutral `/api/v1` GET/POST routes with the standard numeric-code envelope |
| Operational logs | Safe one-line JSON to stdout with server request correlation and one completion event |
| Audit storage | Append-only `operation_audit_events` for account/permission operations with bounded safe state and redacted input/result summaries |
| Runtime lifecycle rule | Every exposed delete/unbind uses tombstones and every rebind creates a new episode; the asset directly implements custom-role deletion and both RBAC unbinds |

Do not add explicit deny, wildcards, role inheritance, ad hoc resource-scope
languages, or an authorization cache merely because they are common elsewhere.
Each changes policy algebra and needs its own precedence, invalidation, and
concurrency tests. A Redis active-JTI registry is per-Token authentication state,
not a permission cache; use [JWT access-token security](jwt-session-security.md)
when per-Token revocation is in scope.

## Public Surface Does Not Reveal The Engine

RBAC is an internal implementation detail. Public paths, application titles,
response fields, and error codes must not contain `rbac`. Use resource names such as `permissions`, `roles`, `users`,
and `system`; use the neutral numeric denial code `40301`. Do not retain
`/rbac` as a compatibility alias because an alias still exposes the mechanism.

The asset follows [Project structure](project-structure.md): access endpoints,
policy, repositories, models, and services live in their respective responsibility
directories. The `assets/postgresql-rbac` directory and database/audit internals
are not public API. Keep internal policy reason codes out of responses.

All business routes in this baseline use only `GET` and `POST`.
Do not introduce `PUT`, `PATCH`, or `DELETE` aliases. Action-specific `POST`
paths make lifecycle and relationship commands explicit; method choice does not
weaken authentication, authorization, idempotency, or concurrency requirements.
List and detail reads end in `/list` and `/detail`, with IDs in typed Query
parameters. Current-user information uses `GET /api/v1/me/user_info`.
POST targets belong in the closed Pydantic JSON command model,
alongside its other inputs; no business route contains a path-parameter ID.
This ID location does not prevent unauthorized access by itself. Follow
[the request contract](api-response-standard.md#methods-paths-and-request-parameters)
and preserve every object-policy check described below.

## Included Code

- [`app/models/postgres/`](../assets/postgresql-rbac/app/models/postgres/) groups
  declarations into `user.py` (including user-role assignments), `role.py`
  (including role grants), `permission.py`, `rbac_state.py` and
  `operation_audit.py`. Its package registers the seven default application models;
  moving declarations does not change their tables, constraints or relationships.
- [`app/core/logging/events.py`](../assets/postgresql-rbac/app/core/logging/events.py)
  configures safe structured process/request logging, context propagation, and
  defensive redaction.
- [`app/core/audit.py`](../assets/postgresql-rbac/app/core/audit.py) validates stable audit
  labels and converts bounded allowlisted before/after state to safe JSON.
- [`app/core/i18n/messages.py`](../assets/postgresql-rbac/app/core/i18n/messages.py) defines closed
  `MessageKey` values, validates catalogs, and translates messages.
  [`app/core/i18n/language.py`](../assets/postgresql-rbac/app/core/i18n/language.py) selects
  bounded request languages and applies response headers;
  [`app/core/i18n/validation_messages.py`](../assets/postgresql-rbac/app/core/i18n/validation_messages.py)
  maps validation errors without reflecting untrusted input.
- [`app/assets/locales/zh-CN.json`](../assets/postgresql-rbac/app/assets/locales/zh-CN.json) and
  [`app/assets/locales/en.json`](../assets/postgresql-rbac/app/assets/locales/en.json) provide
  complete, equal-key Simplified Chinese and English runtime message catalogs.
  [`app/core/middleware/request_logging.py`](../assets/postgresql-rbac/app/core/middleware/request_logging.py)
  resolves a request-local language and
  [`app/core/exception_handlers.py`](../assets/postgresql-rbac/app/core/exception_handlers.py)
  localizes framework errors, while
  [`app/core/response.py`](../assets/postgresql-rbac/app/core/response.py) renders
  route, service, and error `MessageKey` values into the standard envelope.
- [`tests/test_i18n.py`](../assets/postgresql-rbac/tests/test_i18n.py) verifies
  catalog parity, language negotiation, localized success/error/validation
  responses, headers, hostile input, and concurrent request isolation. The
  complete call flow and extension rules are in
  [API internationalization](api-internationalization.md).
- [`app/core/access/permissions.py`](../assets/postgresql-rbac/app/core/access/permissions.py) defines
  business-grouped `PermissionKey` and `PERMISSION_CATALOG`. Its values are
  description `MessageKey` values; `get_permission_description()` resolves them
  through the existing locale catalogs, defaulting to Chinese for initialization.
- [`app/core/access/roles.py`](../assets/postgresql-rbac/app/core/access/roles.py) defines
  system-role keys, specifications, fixed tiers, role limits and explicit grant allowlists.
- [`app/core/access/authorization.py`](../assets/postgresql-rbac/app/core/access/authorization.py) defines
  immutable `LoginInfo`, `UserInfo` and `AuthorizationContext`. `UserInfo`
  contains account state, roles, role level and permissions, without passwords;
  it is neither the ORM `User` nor an HTTP response schema.
- [`app/repositories/postgres/user_repository.py`](../assets/postgresql-rbac/app/repositories/postgres/user_repository.py)
  owns `get_user` with ID/username/state filters, current account/permission
  loading, user visibility SQL and `UserDetails`. Its `check_current_user`
  checks missing/deleted/disabled accounts and `token_version` before loading
  permissions. `get_user_permissions(session, users=users)` reuses loaded users
  and always returns a user-ID mapping. For one user, use `users=(user,)` and
  read the result by `user.user_id`. One role/permission query
  builds `UserPermissions.user_info` from enabled roles and
  `.user_info_with_disabled_roles` including disabled roles for management checks.
  Both are `UserInfo`; only the enabled-role
  result may supply current permissions, while the result containing disabled
  roles preserves management protection. The private `_load_user_permissions`
  combines the query and assembly: collect each role's permissions once, then
  compose each user's results from their bound role IDs. Both repositories use
  `RolePermissions` with an already loaded `Role`; conversion to immutable
  role fields stays in `to_role_info`, without another query.
  `get_users_info` also uses it to add usernames, bound roles and permitted
  permissions to already loaded users, returning `dict[str, UserDetails]`.
  Viewer-filtered `UserDetails.user_info` is separate from complete authorization
  data and must not authorize operations.
  `_build_user_info` copies the shared account fields for enabled, all or empty
  role sets; it performs no query. `_build_user_query` shares SQL for `list_users`
  and `get_user_detail`; both only read users the current caller may view.
  Their `current_user` argument and comments state this filter, while `get_user`
  remains the identity/state lookup without caller-specific display filtering.
  `_is_super_admin` retains the system-role identity check.
  Locked target users are reused; the current-user
  rechecks around role locks remain.
  [`role_repository.py`](../assets/postgresql-rbac/app/repositories/postgres/role_repository.py)
  owns `list_roles` and `get_role_detail`, sharing `_build_role_query` for SQL
  visibility. `get_role_permissions(session, roles=roles)` reuses loaded roles
  and always returns `dict[str, RoleGrant]`; for one role, pass `roles=(role,)`
  and read the result by `role.id`. `unbind_permissions` tombstones bindings;
  `lock_permission_bindings` selects only binding IDs to acquire ordered row
  locks and returns `None`; it does not load binding objects or build an unused
  mapping. Keep its permission join, live-row filters and `FOR UPDATE OF`
  relationship-table target. Ordinary permission aggregation uses unordered
  sets, with response sorting in the Service; lock queries keep their fixed
  ordering. Unique role-key lookups use `session.scalar`, while the locked
  lookup retains `populate_existing=True` to refresh an already loaded role.
  [`user_role_repository.py`](../assets/postgresql-rbac/app/repositories/postgres/user_role_repository.py)
  uses `get_role_ids` for the combined role IDs of supplied users, `get_user_ids`
  for a role's non-deleted users, and `count_roles` for one user's role count.
  These queries exclude unbound relationships but keep disabled roles/users;
  disabled roles still occupy a role slot. `unbind_roles` only writes tombstones:
  pass `user_id` to unbind one user, or omit it when deleting a role to unbind
  that role from all users. Empty target sets do not query or update the database.
  Services retain authorization, lock ordering, audit and transaction ownership.
  Permission and global-state repositories retain their concrete SQL and canonical lock queries;
  there is no separate authority Repository.
- [`app/core/access/authorization_policy.py`](../assets/postgresql-rbac/app/core/access/authorization_policy.py) contains
  shared permission and authority-ceiling checks. The
  [`role_policy.py`](../assets/postgresql-rbac/app/core/access/role_policy.py)
  module decides role visibility and role changes; the
  [`user_policy.py`](../assets/postgresql-rbac/app/core/access/user_policy.py)
  module decides user visibility, user administration and user-role assignment.
  Each user-administration entry point fixes its capability before calling its
  shared user decision.
- Role and user Services build their own shared read/write response snapshots
  from already-authorized data without querying or changing visibility. Their
  public contracts live in `schemas/role.py` and `schemas/user.py`;
  `schemas/permission.py` owns the permission catalog contract.
  RoleService keeps `_lock_role`, `_check_role_change`, `_check_role_version`
  and response/audit converters before its public methods. Its `_LockedRole`
  holds the current user, target role, `role_info`, `bound_users` and
  `bound_user_ids`. Permission bindings are still locked, but binding deduplication
  reuses `role_info.permissions` rather than retaining another map of those keys.
  `delete_role` preserves soft deletion of the role and both relationship kinds.
  Role creation/update take the validated request model as `body`.
- `schemas/auth.py` owns registration/login/password-change requests and Token
  data. `schemas/captcha.py` owns CAPTCHA contracts, while `schemas/common.py`
  owns shared request fields and operation results. Administrative session
  statistics use `ActiveSessionsResponse` in `schemas/user.py`; consumers import
  definitions directly from their business owner, without copied validators.
- [`app/dependencies/auth.py`](../assets/postgresql-rbac/app/dependencies/auth.py)
  validates bearer claims and requires the Redis active-JTI record, then counts
  the selected business/user-ID window exactly once before loading PostgreSQL
  user/RBAC authority. Excess requests stop before PostgreSQL. It compares
  `users.token_version` and removes an exact JTI rejected by current database
  state on a best-effort basis; a later database denial retains that count.
- [`app/dependencies/permission.py`](../assets/postgresql-rbac/app/dependencies/permission.py)
  checks the route's exact capability after authentication and the current user
  quota. Permission checks default to ordinary user quotas; built-in business
  management routes explicitly pass `management=True` to select management
  settings, independent of the caller's role. A denied POST uses `AuditService.audit_denied`;
  target visibility remains in business Services.
- [`app/services/role_service.py`](../assets/postgresql-rbac/app/services/role_service.py)
  implements role reads, creation, lifecycle and permission binding;
  [`app/services/user_service.py`](../assets/postgresql-rbac/app/services/user_service.py)
  implements administrator user reads, creation, password reset, status, role
  binding and session revocation. Self-registration, login and own-password
  changes remain in `auth_service.py`; shared account-event handling
  lives in the shared `audit_service.py`.
  Both use the explicit transaction/audit context in
  [`app/services/user_role_transaction.py`](../assets/postgresql-rbac/app/services/user_role_transaction.py).
- [`app/api/v1/endpoints/auth.py`](../assets/postgresql-rbac/app/api/v1/endpoints/auth.py)
  makes authentication ordering visible: a named per-business dependency in
  [`dependencies/rate_limit.py`](../assets/postgresql-rbac/app/dependencies/rate_limit.py),
  one-time CAPTCHA verification and consumption, then
  [`AuthService`](../assets/postgresql-rbac/app/services/auth_service.py).
  CAPTCHA issuance/consumption has one
  [`CaptchaService`](../assets/postgresql-rbac/app/services/captcha_service.py)
  and shared user insertion with the initial password hash, default-role binding
  and creation audit live in
  [`UserService.create_user`](../assets/postgresql-rbac/app/services/user_service.py).
  Registration and `UserService.admin_create_user` hash the password outside
  database locks, pass it to `create_user`, and keep their own checks and
  outer transaction ownership while calling this shared method.
  These classes own real work; there is no callback-based authentication facade.
- [`app/services/permission_service.py`](../assets/postgresql-rbac/app/services/permission_service.py)
  owns permission pagination, detail-not-found semantics and public results;
  its Repository reuses the same live-permission filter for list and count.
  Both reads use `_build_permission_response` for the same field selection and
  locale handling; it converts an already loaded permission without a query.
- [`app/api/v1/router.py`](../assets/postgresql-rbac/app/api/v1/router.py) assembles
  neutral resource endpoints and adds `/api/v1` once. Business routers declare
  only their resource prefix. The endpoints
  contain no SQL and exclude privileged fields from request bodies.
- [`app/api/v1/route_validation.py`](../assets/postgresql-rbac/app/api/v1/route_validation.py)
  owns the version-specific anonymous and special authentication route rules;
  the router assembly above contains only business mounts.
- [`sql/bootstrap_super_admin.sql`](../assets/postgresql-rbac/sql/bootstrap_super_admin.sql)
  is historical first-super-admin transaction reference, excluded from new projects.
- [`sql/handover_super_admin.sql`](../assets/postgresql-rbac/sql/handover_super_admin.sql)
  is historical guarded offline handover reference, excluded from new projects.
- [`alembic/versions/0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py)
  historically created the core RBAC schema and database-enforced 10-live-role limit;
  [`0002_system_roles.py`](../assets/postgresql-rbac/alembic/versions/0002_system_roles.py)
  installs the system-role/API contract;
  [`0003_business_audit.py`](../assets/postgresql-rbac/alembic/versions/0003_business_audit.py)
  adds generic append-only business audit.
- [`0004_password_auth.py`](../assets/postgresql-rbac/alembic/versions/0004_password_auth.py)
  historically added password fields on `users`, the persisted public-registration switch,
  account-security audit, and the dedicated administrator-reset capability.
- [`tests`](../assets/postgresql-rbac/tests/) is the full maintainer regression suite for PostgreSQL behavior,
  including the public contract, system roles, multi-role union, strict
  hierarchy, bounded permission grants, direct and indirect self-elevation,
  assignment constraints, the 10-live-role limit, optimistic concurrency, and
  locking. Historical Alembic/SQL files, database-mutating fixtures, topology and
  load helpers remain maintenance reference and are not default starter output.

Every Python name referenced by an example is implemented in the asset. The app
now includes the concrete username/password baseline described in
[Local password authentication](local-password-authentication.md), while other
identity providers remain product-specific. For greenfield use, settle username case sensitivity in
[Identity and soft-delete lifecycle](identity-soft-delete.md) before adapting
those integration points.

## Schema Contract

The authoritative relationships are:

```text
users *---* roles (through live user_roles episodes)
roles *---* permissions (through live role_permissions episodes)
rbac_state (exactly one global guard row)
users 1---* operation_audit_events (optional operation user and target)
```

The baseline models these seven core tables. The user creates the actual
schema and installs the described database-only enforcement:

| Table | Purpose and enforced boundary |
| --- | --- |
| `users` | Required username, lifecycle, protection, and token revocation version |
| `rbac_state` | Fixed `scope='global'` row used as the first RBAC write lock; no version counter or Token state |
| `permissions` | Stable capability catalog |
| `roles` | Immutable key, display data, tier, active/soft-delete lifecycle, version, and internal `is_system`/`is_protected`/`is_super_admin` flags |
| `role_permissions` | Non-sequentially identified grant episodes, bind metadata, and soft-delete metadata; one live row per role/permission pair |
| `user_roles` | Non-sequentially identified assignment episodes with bind and soft-delete metadata; one live row per user/role pair and at most 10 live rows per user |
| `operation_audit_events` | Account/permission operations, safe request/result and state summaries, outcome, source, correlation and append-only enforcement |

`operation_audit_events.source` is one of `http`, `service`, `job`, `operator`, or
`migration`. The database validates action, optional reason, correlation ID,
category, outcome, source, fingerprint and JSON-object summaries/state. Indexed
review paths cover request ID, current user/time, target/time, and `(created_at, id)`.
The user's database setup must install a trigger or equivalent runtime database
role protection rejecting row updates and deletes. The ORM does not install
that protection automatically. This does not protect against a
database owner and is not a claim of cryptographic immutability. Follow
[Audit module](audit-module.md) for event coverage, retention, access, and safe
state rules, and [Operational logging](operational-logging.md) for non-durable
request telemetry.

`rbac_state` is coordination metadata, not a business entity or Token table. At
the model level it has only one non-null column. The user must separately
initialize one row:

| Column | PostgreSQL type | Contract |
| --- | --- | --- |
| `scope` | `varchar(16)` | Primary key constrained to the single value `global` |

The required user-owned initial data is `scope='global'`.
Every RBAC writer locks this row with
`SELECT ... FOR UPDATE` before discovering affected assignments or locking
users and roles. Registration also locks this row while creating the default
`user` assignment; there is no registration switch. Missing state fails closed; runtime
code never recreates it. There is no synthetic ID, creation timestamp, user
identity, JWT, or session data in this table. Runtime and
production-maintenance roles cannot delete, truncate, or soft-delete it;
database enforcement must reject those operations.

The bundled default uses 15-character prefixed string IDs for users, roles,
permissions and relationship rows, and 22-character time-prefixed IDs for the
three durable audit tables. The random parts use `secrets`; exact formats and
prefixes are in [identifier policy](identifier-policy.md). There is no `SERIAL`,
`BIGSERIAL`, `IDENTITY` or sequential public alias. JWT JTI and request IDs
remain UUIDv4. The fixed `rbac_state.scope` string is a control key, not a
business or API ID. Existing projects need not replace a sound established
non-sequential ID scheme merely to follow the new-project default.

The bundled new-project profile has a required, globally unique `user_name`:
trim edges and require 3..32 ASCII letters/digits/underscores. Deleted names
remain reserved. Ask whether case matters and apply the chosen normalization
at every write and login lookup. Email login and verified email recovery are
outside this baseline. Preserve an existing application's different identity
contract unless changing it is requested. Immutable `users.user_id`, never the
username, is the JWT subject and operator-bootstrap target.

The bundled profile currently compares usernames case-sensitively: normalization
trims both ends but preserves ASCII letter casing. The management user-list
`user_name` query runs that same normalization before its exact database match,
so surrounding whitespace is ignored while `Alice` and `alice` remain distinct.
If a project selects case-insensitive identity instead, change creation, login,
management lookup, and PostgreSQL uniqueness together rather than lowercasing
only one route.

`user_roles` and `role_permissions` use non-sequential surrogate IDs so each bind
is a distinct episode. They carry trusted bind and soft-delete current user/timestamp
metadata. Non-null foreign keys plus partial unique indexes on each logical pair
where `deleted_at IS NULL` reject missing parents and concurrent duplicate live
bindings. Unbind sets tombstone metadata; a later bind inserts a new episode and
never clears the old row. Each user may have at most 10 live `user_roles` rows:
the mandatory `user` and any `super_admin` binding count, disabled roles still
count, and tombstones do not count. The service checks the complete final set
under `rbac_state`. The user's database setup must also serialize direct
assignment writes on that guard and install a deferred final-state constraint.
Only that verified database protection provides the direct-SQL backstop;
importing these ORM models alone does not install it.

`is_system` and `is_protected` are independent. `is_system` makes a role
application-defined and immutable at runtime; it must not automatically make
every holder protected. Only `super_admin` contributes protected
super-administrator authority. This distinction lets a higher current user manage an
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

The user initializes exactly these roles before users are created:

| Key | Tier | Flags | Runtime policy |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | system, protected, active (`is_super_admin` internal flag) | Exactly one holder after bootstrap; only guarded offline SQL changes its holder |
| `admin` | `500` | system, active | Manages only strictly lower users and custom roles using currently held capabilities |
| `user` | `0` | system, active | Mandatory base role; `account:read` and `account:change_password` only, without management permissions |

All three keys, tiers, system flags, lifecycle state, and permission
composition are immutable through public APIs, including for `super_admin`.
They cannot be disabled, soft-deleted, or recreated. Change a system-role seed
only through a user-prepared, reviewed data change with the same impact analysis,
role-version increments and audit expectations as any other authority
change.

The control-plane portion of the seeded `admin` permission set is deliberately
incomplete and fixed to:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:bind
roles:unbind
roles:permissions:bind
roles:permissions:unbind
users:read
users:status:update
```

It does not include `roles:delete` or an online super-admin transfer capability.
Possessing a capability is only the first gate: an
`admin` still cannot manage itself, another `admin`, a `super_admin`, any system
role, a custom role at tier `500` or above, or permissions it does not hold.
The included `USER_PERMISSION_KEYS` explicitly grants `account:read` for current-user
information and `account:change_password` for changing one's own password.
The `admin` and `super_admin` allowlists also include both keys. The corresponding
`me.py` routes enforce them through `require_permission`, using ordinary user
quotas; possession of a basic permission grants no user-management capability.
A generated project must not include example permissions for nonexistent businesses. For an actual new
business, update its code catalog and hand the initial-data differences to the
user; they prepare, review and execute that database change. It must not
broaden the fixed control-plane set above.

Every public signup and trusted user-creation path creates or synchronizes
the live user and binds a new live `user` episode in the same PostgreSQL
transaction. The request body
cannot choose an initial role. A user keeps `user` after receiving another role,
and the role-unbind service always rejects removal of `user`. Direct database
imports must use the same user-creation boundary or a database safeguard that
enforces this invariant.

## Permission Catalog

Deliver stable descriptions for at least these administration capabilities,
and tell the user to initialize them in their database:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:delete
roles:bind
roles:unbind
roles:permissions:bind
roles:permissions:unbind
users:read
users:status:update
```

There is no `can_delegate` field or independent delegation-management API.
Granting requires possession of the permission, the exact operation capability,
strict lower-target hierarchy, and complete affected-user anti-escalation checks.
New custom roles start with no permissions; `POST /api/v1/roles/create` cannot smuggle
grants into creation. This preserves the independent bind and unbind
capabilities.

The `super_admin` receives permissions from an explicit
`SUPER_ADMIN_PERMISSION_KEYS` allowlist, not every permission-table row. Adding
a platform-internal or break-glass key therefore does not silently grant it.

The model maintains these change counters:

- `users.token_version` invalidates access tokens after identity-wide changes;
- `roles.version` changes after role information, lifecycle, or grant changes.

`rbac_state` supplies the shared write lock only. Ordinary authentication does
not query it, and authorization responses carry no global change counter.

The baseline reads PostgreSQL for each request and checks current authority
again under the write locks. It has no permission cache or separate per-user
authorization version; the retained counters do not replace those checks.

## Minimum Public API

The baseline has at least these thirteen protected endpoints:

| Method | Path | Required capability | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/permissions/list` | `permissions:read` | Permission list |
| `GET` | `/api/v1/permissions/detail?permission_id=<id>` | `permissions:read` | Permission detail |
| `GET` | `/api/v1/roles/list` | `roles:read` | Filtered visible-role list; `super_admin` sees all in the selected deletion state |
| `GET` | `/api/v1/roles/detail?role_id=<id>` | `roles:read` | Visible role detail including `version` |
| `POST` | `/api/v1/roles/create` | `roles:create` | Create an empty custom role |
| `POST` | `/api/v1/roles/update` | `roles:update` | Update mutable role information; JSON `role_id` |
| `POST` | `/api/v1/roles/disable` | `roles:status:update` | Disable a custom role; JSON `role_id` |
| `POST` | `/api/v1/roles/enable` | `roles:status:update` | Re-enable a non-deleted custom role; JSON `role_id` |
| `POST` | `/api/v1/roles/delete` | `roles:delete` | Soft-delete a custom role; JSON `role_id` |
| `POST` | `/api/v1/roles/permissions/bind` | `roles:permissions:bind` | Atomically add permission grants; JSON `role_id` |
| `POST` | `/api/v1/roles/permissions/unbind` | `roles:permissions:unbind` | Atomically tombstone live permission grants; JSON `role_id` |
| `POST` | `/api/v1/users/roles/bind` | `roles:bind` | Atomically add role assignments; JSON `user_id` |
| `POST` | `/api/v1/users/roles/unbind` | `roles:unbind` | Atomically tombstone live role assignments; JSON `user_id` |

Every endpoint requires a current bearer identity and server-side PostgreSQL
authority. Use the four-field JSON envelope, real HTTP status, numeric business
codes, server-generated request ID, and simple page data from
[API response standard](api-response-standard.md). Missing or invalid
authentication returns `40110`; a visible but forbidden action returns generic
`40301`; a missing or deliberately concealed target returns generic `40401`.
A normal `user` has none of the required capabilities. An `admin` can call only
its seeded capability subset, and every write still applies hierarchy,
granted-permission, protected-target, affected-user, and anti-self-elevation checks after
locking.

An early route capability gate is only a fast rejection. Record its denied
privileged `POST` decision without target secrets, and repeat the capability
decision from current PostgreSQL state inside the service transaction. The
service checks current capability before revealing target existence or a role
version, so a revoked or direct-service caller cannot probe with `40301`,
`40401`, or `40931` differences.

Administrative reads obey hierarchy as well as capability. The current
`super_admin` may inspect every non-deleted role and user, and list all targets
in the deletion state selected by the explicit list filters below. Every other
administrator may list or inspect only roles and users whose complete effective
management tier is strictly lower, and never itself, a peer, a higher target, or
a protected target. Apply the same predicate to list rows and `total`, then use
it again for detail lookup so a concealed ID is indistinguishable from a missing
one (`40401`). The caller reads its own effective authority only through
`GET /api/v1/me/user_info`. Assemble page authorities and role grants in bounded
batch queries rather than one query per row.

The shared user visibility query directly excludes a target when any live
assignment to an active, non-deleted role is protected or has a level at least
as high as the caller's. No effective roles means level `0`, so a non-super-admin
caller at level `0` has no lower users to inspect. Keep this SQL predicate shared
by list, count, search and detail; do not fetch users and filter them in Python.

`GET /api/v1/roles/list` keeps the existing `roles:read` capability and accepts
optional exact `role_id` and `key` filters, plus a `name` substring filter.
Treat `%` and `_` in `name` as literal characters, not SQL wildcards. Optional
`is_active` and `is_system` default to `None`: omitted means either state, while
`true` and `false` select that exact state. `is_deleted` defaults to `false`
(only non-deleted roles); `true` selects only soft-deleted roles. Combine supplied
conditions with AND in the shared SQL used for page rows and `total`. Ordinary
callers still see only strictly lower roles that are neither protected nor
super-administrator roles; the super administrator sees every role in the
selected deletion state. For example,
`/api/v1/roles/list?name=audit&is_active=true&is_system=false` selects enabled
non-system roles whose names contain `audit`, within that visibility range.

Deleted-role list entries contain basic role information and `permissions=[]`;
do not load old grants. Role detail and ordinary role operations continue to
exclude deleted roles. This filter adds no restoration/deletion endpoint, model
field or capability.

`GET /api/v1/users/list` keeps the existing `users:read` capability and accepts
optional exact `user_id` and normalized exact `user_name` filters. Optional
`is_active` defaults to `None` (either enabled state); `true` selects enabled
accounts and `false` selects disabled accounts. `is_deleted` defaults to `false`
(only non-deleted accounts); `true` explicitly selects only soft-deleted accounts.
Combine supplied conditions with AND, and use the same SQL visibility and filter
conditions for page rows and `total`. These filters never bypass hierarchy,
self or protected-user restrictions.

Deleted-user listing is a management query only. Its user projection has empty
role/permission collections and `role_level=0`; it does not restore previous
grants or become authentication data. User detail, login, authentication and
ordinary user operations continue to exclude deleted accounts. This filter adds
no deletion/restoration command, model field or capability.

Use clear, unique handler names such as `list_permissions`, `get_role_detail`,
and `bind_user_roles`. They remain server-side names used for maintenance,
auditing, and independent per-business rate-limit keys; no explicit
`operation_id` or documentation tag is required.

Role creation accepts only `key`, `name`, `description`, and
`level`. Role models and role responses use the same field; a user's authority
and user responses use `role_level` for the highest effective role level, or `0`
when there are no effective roles. The key is permanently immutable; permission IDs, system
flags, active/deleted state, and the internal `is_super_admin` flag are
forbidden fields.
New roles start active and permissionless. Ordinary role information update
accepts `role_id`, `expected_version` plus at least one of `name` or `description`; level
changes require a separate, `super_admin`-only policy if the product truly needs
them.

Permission bind/unbind requires JSON `role_id`, a unique `permission_ids` array
and `expected_version`; user-role bind/unbind requires JSON `user_id` and a
unique `role_ids` array. These models reject unknown fields. The body target is
untrusted input and must pass the same locked object-policy checks as before.
Limit a permission array to 100 IDs and a role array to 10 IDs. The role request
limit is only input bounding, not enforcement of the per-user total; a user may
already hold other roles. After locking, require the complete proposed live set
to contain no more than 10 bindings. Then
reject duplicate, unknown, or unmanageable objects, validate the complete
proposed result, and commit the whole request or none of it. Binding an existing
live relation or unbinding a pair with no live relation is an idempotent success
returning the final user or role state, without a public `changed` field.
Authorization and role `expected_version` checks still apply. A successful
unbind tombstones the live episode; a later
bind inserts a new episode with a new ID rather than clearing the tombstone.
Ordinary binding can never grant `super_admin`; only guarded offline SQL changes
its holder. Only `super_admin` can bind or unbind `admin`, while `user`
cannot be unbound from any user.

The baseline also exposes these neutral companion operations for the existing
user lifecycle and administrator session-revocation capabilities:

```text
GET  /api/v1/me/user_info
GET  /api/v1/users/list
GET  /api/v1/users/detail?user_id=<id>
GET  /api/v1/users/sessions/list?user_id=<id>
POST /api/v1/users/disable             JSON: {"user_id": "<id>"}
POST /api/v1/users/enable              JSON: {"user_id": "<id>"}
POST /api/v1/users/sessions/logout-all JSON: {"user_id": "<id>"}
```

No online route transfers `super_admin` or edits a separate delegation subset.
The session list uses `users:read` and the same target visibility as user detail;
ordinary users have no default self-session-list route. The logout-all command
rechecks exact capability and strictly lower target
inside the authoritative transaction. No route accepts an authority override.

## Optimistic Concurrency

`GET /api/v1/roles/detail?role_id=<id>` returns `version` inside the role data. Role
update, disable, enable, delete, and permission bind or unbind require
that nonnegative value as a strict JSON integer `expected_version` alongside
the target `role_id` in the body.
Role creation does not require it. Missing or malformed input returns HTTP `422`
with business code `42201`; a stale value returns HTTP `409` with business code
`40931` only after the caller passes the complete current policy decision.

Compare the expected role version only after acquiring canonical locks and
reloading current rows and then authorizing the full proposed change, before
mutation. An unauthorized caller receives `40301` regardless of whether its
version guess is stale, preventing a version oracle. Use `40901` for another
client-visible state conflict such as exhausted bounded affected-set retries. An
expected version never replaces the post-lock authorization decision. User role
bind/unbind is an incremental, idempotent, single-transaction command and does
not require a user version in this baseline; its post-lock hierarchy and authority
reload remains mandatory.

Construct the complete successful role representation and new version from one
immutable snapshot while the authoritative transaction still owns the locks.
Do not commit, requery grants through a request session, and combine that newer
state with an older role version; a delete response must not become `40401`
after the deletion already committed. A dynamic `request_id` in the JSON body
means this envelope cannot also claim a stable strong ETag; see the response
standard for the protocol rationale.

Apply the same rule to user-role bind/unbind, user disable/enable, and any other
administrative write returning user data. The service builds an immutable
`UserResponse` projection while the authorization transaction still owns the
global, user, role, and relation locks; the route returns that snapshot after
commit without loading the user again through its request `Session`. Nested
`bound_role_ids` contains only roles visible to the current user. Keep the complete
unfiltered assignments for policy and audit, but never expose a disabled peer or
higher role ID to an ordinary administrator through the response projection.

## Administrative Decision

Role assignment and revocation calculate complete target authority before and
after the proposal. Allow only when all applicable conditions hold:

1. The current user is current and active. Assignment also requires an active target;
   revocation may tombstone live role episodes for a suspended target.
2. The current user has the exact operation permission after locks are held.
3. Current user and target are different users.
4. No affected identity or role is protected or an immutable system role.
5. Current user tier is strictly greater than target-before, target-after, and every
   changed role tier.
6. The current user holds each newly granted permission, and affected users' current
   and proposed authority remains strictly manageable by the current user.
7. The current user's own authority is unchanged by the proposal.
8. Mandatory `user`, sole-`super_admin`, soft-delete, and audit invariants remain
   valid.
9. The target's final set contains at most 10 live role bindings. The required
   `user` and any `super_admin` binding count; disabled roles count; tombstoned
   history does not.

Shared custom-role updates expand every live assignment, including suspended
users. Reject the whole operation when the current user holds the role or an affected
user is protected, peer, higher, or outside the current user's manageable authority. This blocks
indirect self-elevation and partial bulk writes.

User suspension and reactivation deny self-management, protected users, peers,
higher users, and retained authority outside the current user's manageable authority.
Reactivation revalidates every retained role before restoring access.

## First Super Admin And Offline Handover

Do not promote the first registered user and do not tell an operator to improvise
a bare `user_roles` row. A naked insert omits the global lock, mandatory base
role check, uniqueness decision, and audit event.

The intended person first creates an account through the normal trusted
registration or user-creation flow after the user completes schema and initial
role setup. Once that active account has `user`, the user prepares, reviews,
and executes their own offline transaction against its immutable `users.user_id`.
The Skill supplies this contract, not a bootstrap SQL file or execution step.

That transaction locks `rbac_state(scope='global')` first, reloads and verifies
the existing user, system-role shapes, exact super-admin grants, and mandatory
`user` assignment, and confirms that adding `super_admin` leaves at most 10 live
bindings, then binds only the pre-seeded `super_admin`. It writes an audit event
and commits once. It never creates the identity,
changes a password, changes `users.token_version`, or marks the user protected.
Re-running for the same resulting identity does not add another binding;
attempting to name a missing, inactive, deleted, protected, or different second
identity is refused and rolled back. The parameter is immutable `users.user_id`, not
the username. It is not an HTTP endpoint and never accepts a role
definition or arbitrary grants. The retained historical SQL and its isolated
maintenance tests illustrate this contract; they are excluded from generated
projects and are not executed by the ordinary Skill workflow.

The user's initialization creates `super_admin`, `admin`, and `user` directly and does not
rename, reserve, or interpret a custom role whose key is `owner`. A deferred
PostgreSQL constraint must be installed by the user's database setup, run
whenever a `super_admin` assignment changes, and
requires the final transaction state to contain exactly one holder. This permits
the first bootstrap and an atomic remove-plus-add transfer, but rejects both a
second holder and removal of the final holder.
The historical `0001_single_project_rbac` demonstrates direct-assignment
serialization and the 10-role backstop. New projects hand these requirements
to the user rather than inheriting that old migration history.

After bootstrap, the user changes the sole holder only through their reviewed,
guarded offline transaction from a trusted host. It atomically inserts a new
`super_admin` episode for the target, tombstones the current user's live episode,
preserves `user` for both, and writes the allowed audit. The next authorization reload observes the new
authority immediately. This baseline does not increment `users.token_version`
or revoke either user's Access Tokens merely because authority was transferred.
Exactly one active holder remains after commit.
Because `super_admin` counts toward the role limit, a target already holding 10
live roles must first have a non-mandatory role unbound; the failed transfer has
no partial assignment or audit-success write.

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
The user's database-only protection must make `user_roles` direct SQL acquire
the same global guard and evaluate the final live count with a deferred
constraint. This is the backstop for the service check and concurrent tenth-slot
race; model delivery alone does not establish that it has been installed.

## Running The Selected Application

Use the selected output and Chinese quick start from
[New-project delivery](new-project-delivery.md). The asset is reference source,
not a complete-directory copy entry point. Its own `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md` remain in the maintained asset; the generated project
preserves necessary copied-code copyright/permission text in a collapsed README
appendix instead of exporting these files. Do not apply that license to the
user's whole business application. Copy the environment
file and generate two independent random secrets before startup: `JWT_SECRET`
signs Tokens, while `RATE_LIMIT_HMAC_KEY` protects identities embedded in Redis
rate-limit keys. Both are mandatory, must be different, and must never reuse
example, test, or documentation values.

The official verification profile is Python 3.12, PostgreSQL 17, and Redis 7.
Other versions require project-owned validation and must not be described as
verified by this Skill until that validation passes.

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

From the generated project, create a virtual environment and install runtime
dependencies. Install the test extra separately only for development checks:

```powershell
python -B -m venv .venv
.\.venv\Scripts\Activate.ps1
python -B -m pip install -e .
```

The generated quick start also shows POSIX shell activation when needed.
Configure endpoints and settings, then let the
user generate, review and execute their migrations, database protection and
initial data. After that setup, `uvicorn app.main:app --reload` starts the
development service. First-super-admin binding remains the user-owned offline
transaction described above. The Skill does not execute it.

Retained Compose files are maintenance reference, not starter setup. Deployments supply separate
secrets and a managed PostgreSQL URL. Startup rejects empty, known-placeholder,
or shorter-than-32-byte JWT secrets; length alone does not prove entropy. The app
never uses runtime `metadata.create_all()` as a migration substitute.

Generated-project checks use isolated dependencies and model metadata without
database initialization. Historical integration fixtures may create, migrate,
or clear disposable databases and are excluded from output; their separate
maintenance use follows [Testing](testing.md). No such run is implied by
successfully generating or importing the application.

## Required Adaptation Points

The main product-specific decisions are:

1. For greenfield use, start with required username and password, trim edges,
   validate 3..32 ASCII characters and the reserved-name list, and ask only
   whether username case matters. Deleted names stay reserved. Preserve an
   existing product's other identity contract unless a change is requested. Follow
   [Identity and soft-delete lifecycle](identity-soft-delete.md).
2. Add stable business capabilities without weakening the fixed administration
   catalog or system-role invariants.
3. Preserve the asset's connected local-password login, issuance function,
   `check_token`, and user-creation boundary. If the product
   deliberately replaces local passwords with another identity provider,
   connect that trusted verifier at the same issuance boundary. The bundled
   adapter implements the default exact five claims, an optional `iss`/`aud`
   pair, Redis registration and validation, user-version comparison, and
   logout. Follow
   [JWT access-token security](jwt-session-security.md): require the canonical
   selected user ID as `user_id` and a UUIDv4 `jti`, remove `ver` from JWT, bind the current
   `users.token_version` in the Redis value, and require the exact active-JTI
   record before the existing PostgreSQL user and RBAC reload. Do not add a
   PostgreSQL Token table. Leave `iss`/`aud` absent for a new project unless the
   user gives explicit consent after a plain-language explanation of their
   cross-service scoping benefit and configuration cost; no reply is not consent.
   Preserve an existing configured pair by default. Explicitly tell the user that
   the 24-hour default must be reviewed and shortened for high-risk surfaces.
4. Add business-resource queries and compose ownership or row policy after the
   capability decision.
5. If the product exposes user deletion/restoration, mutable permission-catalog
   lifecycle, or business-entity lifecycle, add separate capabilities, hierarchy
   decisions, transaction services, audit actions, and negative/concurrency
   tests. Reuse the lifecycle columns and scenarios, but do not mistake them for
   already registered public endpoints.
6. Set `SERVICE_NAME` and immutable `SERVICE_VERSION` through configuration.
   Preserve safe structured stdout and transactional audit behavior; reuse any
   existing logging integration. Log platforms and retention/access policy are
   owner/operations choices, not required additions to ordinary code generation.
   Keep exception details off until their content and readers are reviewed.
   Add domain-specific audit tables only for explicitly identified security or
   regulated business events; do not broaden `operation_audit_events` into a generic
   activity dump.

Do not ask the user to choose basic table topology, multi-role semantics,
hierarchy direction, the three system roles, the 10-live-role limit,
default-user assignment,
grant bounds, default denial, public administration routes, lock order, or
ordinary self-management behavior unless the existing application explicitly
contradicts this baseline.

Report relevant code tests without treating them as production certification.
