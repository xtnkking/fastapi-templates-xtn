# RBAC Design And Authorization Flow

Read this reference for role, permission, or authorization policy work. RBAC
answers whether a principal has a named capability. Ownership, object state,
relationships, and other row-level conditions remain separate policy inputs.

For executable PostgreSQL code, use
[postgresql-rbac-implementation.md](postgresql-rbac-implementation.md) and the
curated [new-project workflow](new-project-delivery.md). Deliver models and
connected application code; the user owns migration generation/execution and
initial-data preparation. Do not copy the full maintenance asset, its historical
migrations, initialization SQL or regression suite into a new project.

## Define The Policy First

Before writing models, list:

- principals and their active or disabled states;
- for greenfield authentication, the username/password contract from
  [Identity and soft-delete lifecycle](identity-soft-delete.md);
- protected resources and any ownership or row-level boundaries;
- actions such as `read`, `create`, `update`, `delete`, `approve`, or `manage`;
- stable permission keys in `resource:action` form;
- which roles bundle those permissions;
- grant bounds, offline bootstrap, revocation, and audit requirements.

Do not infer sensitive policy from route names. Record a small permission matrix
and turn it into tests.

## Fixed Data Model

Use this normalized single-project model:

- `users` store the required `user_name`, identity lifecycle, protection,
  and token revocation version;
- `roles` have a globally unique stable key, explicit status, management tier,
  version, and protected/system/super-admin flags;
- `permissions` form the stable capability catalog;
- `user_roles` are non-sequentially identified binding episodes; only one live
  episode may exist for `(user_id, role_id)`, and each user may have at most 10
  live episodes in total;
- `role_permissions` are non-sequentially identified grant episodes; only one
  live episode may exist for `(role_id, permission_id)`;
- `rbac_state` contains exactly one global guard row with only `scope='global'`;
  it coordinates authorization write locks, not Token state or change counting;
- `operation_audit_events` capture the operation user, targets, category, action,
  outcome/reason, trusted source, safe request/result and before/after summaries,
  new-password fingerprint where applicable, request ID and timestamp.

`operation_audit_events` combines account security and RBAC administration,
distinguished by `category`. It is not a JWT, Token-session, login or general
application activity log. Ordinary queries use file logs; material product
events use the optional business-audit resources only when requested.
Follow [Audit module](audit-module.md) for its complete schema, payload safety,
append-only, access, and retention contract.

Use positive grants. An active user's effective permissions are the union of
permissions from all live grants on active, non-deleted roles through live
assignments; the effective management tier is the maximum such role tier.
Disabled or deleted users/roles and tombstoned relation episodes grant nothing.
Start without explicit deny,
wildcard permissions, or role inheritance. Add them only with a documented
precedence model and tests for conflicts and cycles.

The per-user cap counts live assignment rows, not only currently effective
permissions: the mandatory `user` role and any `super_admin` role count, and a
live assignment to a disabled role still occupies one of the 10 slots. A
tombstoned historical assignment does not count. This stable definition prevents
temporarily disabling roles and later enabling them from exceeding the cap.

Document the user-owned initial immutable `super_admin` and `user`
system roles at tiers `1000` and `0`. Only `super_admin` supplies the protected
super-administrator authority; `is_system` must not make every `user` holder protected.
Every normally created user receives the mandatory `user` assignment in its
creation transaction. Runtime
APIs cannot change either role definition or its grants, cannot disable or delete
them, cannot grant `super_admin` outside guarded offline SQL, and cannot
unbind `user`.
Its explicit basic grants are `account:read` and `account:change_password`.
The super-administrator allowlist also contains these keys; the base role
provides no management permissions. No `admin` role is preconfigured. Create
ordinary custom roles at tiers `1..999` and bind exact permissions as needed;
`admin` is available as a custom key and tier `500` is not reserved.

## Identity And Deletion Lifecycle

For a new service use required `user_name` and password, trim edges, validate
3..32 ASCII letters/digits/underscores, and reserve deleted usernames forever.
Ask whether username case matters. Existing services retain their chosen contract
unless the user requests a change. JWT `user_id` and the
first-super-admin bootstrap always use immutable `users.user_id`, never a login
identifier.

Every mutable row that may be removed at runtime uses soft deletion, including
users, custom roles, business entities, and relationship unbinds. Unbind
tombstones the live relation episode; an authorized rebind inserts a new episode
and leaves history untouched. Deleting a parent and tombstoning every live owned
relation commit atomically. Restoring an entity never restores old authority;
each wanted relation must pass a fresh bind decision. System roles and the fixed
permission catalog have no runtime delete command. Append-only audit rows are not
soft-deleted, and the singleton `rbac_state` is never deleted. Follow
[Identity and soft-delete lifecycle](identity-soft-delete.md) for the complete
storage, purge-exception, restore, and test contract.

## Permission Keys And Roles

- Define permission keys as stable code constants, for example
  `projects:read`, `projects:update`, and `roles:bind`.
- Endpoint checks depend on permission keys, not display names such as `admin`.
- Separate administrative effects. `roles:bind` may attach an existing role;
  `roles:create`, `roles:update`, `roles:delete`, and
  `roles:permissions:bind` or `roles:permissions:unbind` govern distinct role
  definition effects.
- Grant only permissions the current user currently holds, and only to strictly lower
  manageable users/roles; enforce all affected-user and no-self-elevation rules.
  Do not add a separate `can_delegate` subsystem or online management API.
- Treat the sole `super_admin` as an explicit trust
  boundaries. Do not hide a universal bypass behind an ordinary role name.
- Treat permission-key renames as data migrations; never silently reinterpret an
  existing key.

## Authorization Pipeline

Use one consistent chain:

```text
Bearer credential
  -> verify JWT and require the exact Redis active-JTI record
  -> load the existing active PostgreSQL user and compare users.token_version
  -> load a current immutable permission snapshot
  -> enforce required permissions
  -> query the protected resource
  -> apply ownership or other row-level policy
```

Keep request contexts narrow:

- `AccessTokenInfo` / `token_info` contains the user ID, JTI and times parsed
  from the signed JWT; Redis has not yet confirmed that login remains active.
- `LoginInfo` contains the verified user ID, JTI, and minimal Token metadata.
- `AuthorizationContext.login_info` holds those verified login facts; its
  `user_info` holds the current account state, roles, role level and permissions
  from PostgreSQL.

Keep the authentication and permission steps visible:

1. `check_token` in `dependencies/auth.py` verifies JWT and the exact Redis
   active-JTI record, returning `LoginInfo`.
2. A route needing login and account checks without a named permission declares
   `context: AuthorizationContext = Depends(get_current_user)` directly.
   This dependency receives `Depends(check_token)`, counts the own-account quota
   and calls `_load_current_user` once. The result contains login and live
   database authority, not an ORM `User`.
3. The callback returned by `require_permission` in `dependencies/permission.py`
   receives `Depends(check_token)`, calls `rate_limit_user(..., management=management)`,
   then `_load_current_user`, then checks the exact permission. Its
   `management=False` default selects ordinary user quotas; users/roles/permissions
   management routes explicitly pass `management=True`. Permission possession
   does not imply an administrator role. It does not depend on `get_current_user`,
   which would count another quota.
   The built-in current-user information and own-password routes use
   `require_permission(PermissionKey.ACCOUNT_READ)` and
   `require_permission(PermissionKey.ACCOUNT_CHANGE_PASSWORD)` respectively,
   with the default ordinary quotas.
   The private CAPTCHA route uses `get_captcha_user`: the same Token check,
   its scene quota, then the shared account load.
4. Current-session logout uses `Depends(check_token)` directly and revokes
   only that JTI, without a quota, PostgreSQL query or business-permission check.

`_load_current_user` calls `UserRepository.check_current_user`: it first rejects
missing, deleted, disabled or `token_version`-mismatched accounts, then reads the
current roles and permissions. Invalid accounts do not need permission queries.
The HTTP dependency owns invalid-login cleanup and HTTP error conversion; the
Repository owns account/permission SQL. Reusing this loader keeps account checks
consistent without a separate management-context dependency.

`get_user_permissions(session, users=users)` reuses users already loaded in the
transaction and always returns a user-ID mapping. For one user, pass
`users=(user,)` and read the result by `user.user_id`; no separate batch method
is needed. Each `UserPermissions.user_info` is the complete authority from enabled roles;
`user_info_with_disabled_roles` also includes disabled roles for management
restrictions and must not grant access. A single
role read builds both results. The private `_load_user_permissions` keeps that
query and assembly together. `get_users_info` calls it with the
viewer's role filters to add usernames, bound roles and permitted permissions
to already loaded users, returning `dict[str, UserDetails]`. Its `user_info`
contains only displayable roles and permissions, so it cannot replace complete
authority in a permission decision. Retain the
current-user checks before and after role locks, even when target reads reuse
already locked users.

Do not hide these operations behind `CurrentPrincipal`, `MyAccountContext` or
`MyCaptchaContext` aliases, or add dependencies that only forward an unchanged
result. Each ordinary protected business request spends one relevant quota and
loads current account authority once. The existing write-lock checks inside
Services remain required.

A permission-protected route declares one exact `PermissionKey` through
`require_permission(key)`, using ordinary user quotas by default. A management
business explicitly uses `require_permission(key, management=True)`; the flag
selects its rate configuration and never checks or grants an administrator role.
The maintained implementation is
[`app/dependencies/permission.py`](../assets/postgresql-rbac/app/dependencies/permission.py):
its FastAPI dependency receives the verified login, counts the selected quota,
loads the current account and checks that key. It returns the checked context. A denied POST attempts a
separate best-effort audit before returning HTTP `403` and business code `40301`.
The key is fixed by the route, never supplied by the client. Add a
multi-permission policy only when a real route needs one and its exact semantics
are specified.

The check answers whether the action is allowed, not whether a particular
target may be seen. For example, `GET /api/v1/roles/detail?role_id=...` checks
`roles:read` first; `RoleService.get_role_detail` then asks `RoleRepository`
for a role within the current user's visible range and loads that role's
permissions separately. An unknown or deliberately hidden role returns the
same `404`. Follow the complete
[`roles.py` endpoint](../assets/postgresql-rbac/app/api/v1/endpoints/roles.py),
[`RoleService`](../assets/postgresql-rbac/app/services/role_service.py) and
[`RoleRepository`](../assets/postgresql-rbac/app/repositories/postgres/role_repository.py)
chain when adding a new business route. User account/permission and visible-user
queries belong to
[`UserRepository`](../assets/postgresql-rbac/app/repositories/postgres/user_repository.py).
Keep target decisions in the Service
and SQL filters in named Repositories, not directly in the endpoint.

Lists, counts, search, export, bulk operations, and nested-resource queries need
equivalent SQL visibility predicates. Filtering only detail endpoints leaves
IDOR and data-disclosure paths.

The role list's exact `role_id`/`key`, substring `name` (literal `%` and `_`),
optional `is_active`/`is_system` and boolean `is_deleted` filters combine with AND in
the same SQL as visibility for both rows and `total`. Omitted active/system
filters accept either state; `is_deleted=false` is the default and `true`
selects only deleted roles. Filtering never widens the strictly lower,
unprotected, non-super role range for ordinary callers; the super administrator
may list all roles in the selected deletion state. Deleted entries expose only
basic role information with `permissions=[]`, without loading old grants.
Detail still excludes deleted roles. See the
[role-list contract](postgresql-rbac-implementation.md#minimum-public-api).

## Status Codes

- Return `401` with `WWW-Authenticate: Bearer` for missing, invalid, expired, or
  revoked credentials, and normally for a disabled user.
- Return `403` when authentication is valid and the action is visible but the
  required capability is absent.
- Return `404` for a missing resource or one deliberately concealed by row
  policy. Keep lookup and response ordering consistent so differences do not
  become an enumeration signal.
- Return `503` when a required authentication or authorization authority is
  unavailable; never turn infrastructure failure into allow.

## Authorization Cache Consistency

JWT active-JTI validation and an RBAC permission cache are different security
boundaries. Follow [JWT access-token security](jwt-session-security.md) for
claims, JTI registration, and Token revocation. Never treat roles, permissions, tiers,
or versions from a token as authoritative.

The baseline reads current users, assignments, roles, and grants from PostgreSQL
on every request; it does not maintain a permission cache or a per-user
authorization-version field. Ordinary authentication does not read `rbac_state`
or return a global authorization version. Mutations lock its global row and
update `roles.version` when editing a role. The role version does not replace
the current-state reload or the transaction-local checks below.

If a project later adds a permission cache, design and test its invalidation and
revocation guarantee explicitly. Cached or Token-supplied state is not proof of
current authority; on cache failure, reload PostgreSQL or fail closed.

## Atomic Writes And Immediate Revocation

A short cache TTL only bounds staleness; it does not provide immediate
revocation. Every authorization control-plane write, and every high-risk business
write promising immediate revocation, follows
[atomic authorization consistency](atomic-consistency.md). That protocol defines
the transaction owner, global guard, canonical lock order, post-lock reload,
affected-set validation, audit outcomes, external effects, and deterministic tests. A
route-level check cannot replace the transaction-local decision.

## Privileged Mutations

- Apply [administrative hierarchy](administrative-hierarchy.md) to identity
  administration, role changes, and offline super-admin handover; no online
  transfer route is permitted. Enforce strict anti-self-elevation checks.
- Use dedicated request models with `extra="forbid"` and an allowlist of mutable
  fields.
- Require the exact operation capability. Assignment, role lifecycle, permission
  binding, and permission unbinding are separate effects.
- For assignment or permission changes, calculate complete proposed
  authority and require every newly granted permission to be currently held
  by the current user, with strict hierarchy and no affected-user escalation.
- For every role bind, bootstrap, and offline super-admin handover, calculate the target's
  complete proposed live assignment set after the global guard and row locks are
  held. Reject a final total above 10 as one atomic conflict. Enforce the same
  invariant in PostgreSQL so direct SQL and concurrent service writers cannot
  bypass it; an idempotent bind of an already-live pair does not consume a slot.
- Protect the immutable `super_admin` and `user` role definitions, the
  mandatory `user` assignment, and the sole `super_admin` holder from ordinary
  rename, disablement, deletion, grant changes, or revocation.
- Bootstrap the first `super_admin` through the explicit offline transaction in
  the PostgreSQL implementation, targeting an existing immutable `users.user_id`;
  never promote the first registered user, select the holder by
  `user_name`, or insert a bare assignment implicitly. Later changes use the
  guarded audited offline handover script, never an HTTP command.
- Keep the public authorization API on neutral `/api/v1` resource paths. Do not
  expose `rbac` in public paths, schemas or response metadata, and use only `GET` and
  action-specific `POST` for the baseline administration contract. Internal code
  follows [Project structure](project-structure.md); database and audit names
  are outside the public naming rule.
- Follow the [request parameter convention](api-response-standard.md#methods-paths-and-request-parameters):
  `/list` and `/detail` for reads, target IDs in GET Query or POST JSON,
  never business-ID path segments. Changing parameter location must not change
  authentication, object visibility, capability, hierarchy or audit semantics.

## Avoid Authorization Bypasses

Route dependencies are insufficient if jobs, WebSockets, CLI tools, or direct
service entry points can perform the same privileged operation. Call the shared
authorization service at every boundary handling untrusted intent. Keep truly
trusted system jobs explicit and auditable instead of manufacturing a fake role.
