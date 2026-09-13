# RBAC Design And Authorization Flow

Read this reference for role, permission, or authorization policy work. RBAC
answers whether a principal has a named capability. Ownership, object state,
relationships, and other row-level conditions remain separate policy inputs.

For executable PostgreSQL code, use
[postgresql-rbac-implementation.md](postgresql-rbac-implementation.md) and copy
the linked asset as one coherent unit. It includes tables, dependencies, user and
role administration, `super_admin`-only delegation control, migrations, and
negative and concurrency tests.

## Define The Policy First

Before writing models, list:

- principals and their active or disabled states;
- for greenfield authentication, the selected `users` storage fields and the
  separately selected login-input contract from
  [Identity and soft-delete lifecycle](identity-soft-delete.md);
- protected resources and any ownership or row-level boundaries;
- actions such as `read`, `create`, `update`, `delete`, `approve`, or `manage`;
- stable permission keys in `resource:action` form;
- which roles bundle those permissions;
- delegation, bootstrap, revocation, and audit requirements.

Do not infer sensitive policy from route names. Record a small permission matrix
and turn it into tests.

## Fixed Data Model

Use this normalized single-project model:

- `users` store the selected identity fields, identity lifecycle, protection,
  token revocation version, and the per-user authorization version;
- `roles` have a globally unique stable key, explicit status, management tier,
  version, and protected/system/super-admin flags;
- `permissions` form the stable capability catalog;
- `user_roles` are non-sequentially identified binding episodes; only one live
  episode may exist for `(user_id, role_id)`, and each user may have at most 10
  live episodes in total;
- `role_permissions` are non-sequentially identified grant episodes; only one
  live episode may exist for `(role_id, permission_id)`, and it records the
  explicit `can_delegate` subset;
- `rbac_state` contains exactly one global guard row and the shared
  authorization epoch; it is RBAC coordination metadata, not Token state;
- `rbac_audit_events` capture actor, target, action, decision, reason, trusted
  source, schema version, safe before/after state, request ID, and timestamp for
  privileged mutations.

`rbac_audit_events` is deliberately limited to RBAC administration and its
authorization decisions: role lifecycle, role-permission bindings, user-role
bindings, protected user status changes, and super-admin transfer or bootstrap.
It is not a JWT, Token-session, login, or general application activity log. Add
separately named audit models when the product needs those different event types.
Follow [Audit module](audit-module.md) for its complete schema, payload safety,
append-only, access, and retention contract.

Use positive grants. An active user's effective permissions are the union of
permissions from all live grants on active, non-deleted roles through live
assignments; the effective management tier is the maximum such role tier.
Disabled or deleted users/roles and tombstoned relation episodes grant nothing
and must update the relevant authorization version. Start without explicit deny,
wildcard permissions, or role inheritance. Add them only with a documented
precedence model and tests for conflicts and cycles.

The per-user cap counts live assignment rows, not only currently effective
permissions: the mandatory `user` role and any `super_admin` role count, and a
live assignment to a disabled role still occupies one of the 10 slots. A
tombstoned historical assignment does not count. This stable definition prevents
temporarily disabling roles and later enabling them from exceeding the cap.

Seed immutable `super_admin`, `admin`, and `user` system roles at tiers `1000`,
`500`, and `0`. Only `super_admin` supplies the protected super-administrator
authority; `is_system` must not make every `admin` or `user` holder protected.
Every normally created user receives the mandatory `user` assignment in its
creation transaction. Runtime
APIs cannot change the three role definitions or grants, cannot disable or delete
them, cannot grant `super_admin` outside the dedicated transfer, and cannot
unbind `user`.

## Identity And Deletion Lifecycle

For a greenfield service, first ask whether `users` stores `email`, `user_name`,
or both. Then separately resolve per-flow requiredness, login input,
normalization, database uniqueness, cross-field ambiguity, and whether a deleted
identity's value may be reused. Existing services retain their chosen contract
unless the user requests a migration. JWT `sub` and the
first-super-admin bootstrap always use immutable `users.id`, never a login
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
  `projects:read`, `projects:update`, and `roles:assign`.
- Endpoint checks depend on permission keys, not display names such as `admin`.
- Separate administrative effects. `roles:assign` may attach an existing role;
  `roles:create`, `roles:update`, `roles:delete`, and
  `roles:permissions:bind` or `roles:permissions:unbind` govern distinct role
  definition effects.
- Define delegable permissions explicitly. Possessing or assigning a permission
  does not imply authority to grant it. A role being assigned or changed must not
  contain authority outside the actor's delegable set.
- Treat the sole `super_admin` and break-glass operations as explicit trust
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

- `Principal` contains the verified user ID, JTI, and minimal Token metadata.
- `AuthorizationContext` contains the principal and immutable current authority
  used for the request.

A permission dependency can follow this shape:

```python
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated, Literal

from fastapi import Depends

from app.errors import forbidden


class PermissionKey(StrEnum):
    PROJECTS_READ = "projects:read"
    PROJECTS_UPDATE = "projects:update"
    ROLES_ASSIGN = "roles:assign"


def require_permissions(
    *required: PermissionKey,
    mode: Literal["all", "any"] = "all",
) -> Callable[..., Awaitable[AuthorizationContext]]:
    if not required:
        raise ValueError("at least one permission is required")
    if mode not in ("all", "any"):
        raise ValueError("mode must be 'all' or 'any'")

    required_set = frozenset(required)

    async def dependency(
        context: Annotated[
            AuthorizationContext,
            Depends(get_authorization_context),
        ],
    ) -> AuthorizationContext:
        granted = context.permissions
        allowed = (
            required_set <= granted
            if mode == "all"
            else bool(required_set & granted)
        )
        if not allowed:
            raise forbidden("missing_required_permission")
        return context

    return dependency
```

Adapt names to the repository and map the internal denial to public HTTP `403`
with numeric business code `403001` under
[API response standard](api-response-standard.md). Never let an empty permission
configuration become an implicit allow. Centralize ALL versus ANY semantics and
test both.

Apply row policy after the capability check. Here `ProjectId` is the project's
entity-specific validated type under [identifier policy](identifier-policy.md),
whether prefixed or UUIDv4:

```python
from fastapi import Request

from app.api_contract import ApiResponse, BusinessCode, api_response
from app.errors import not_found


ProjectReadAccess = Annotated[
    AuthorizationContext,
    Depends(require_permissions(PermissionKey.PROJECTS_READ)),
]


@router.get("/{project_id}", response_model=ApiResponse[ProjectResponse])
async def read_project(
    request: Request,
    project_id: ProjectId,
    access: ProjectReadAccess,
    session: SessionDependency,
) -> ApiResponse[ProjectResponse]:
    project = await project_repository.get_by_id(session, project_id=project_id)
    if project is None or not project_policy.can_read(access, project):
        raise not_found("project_not_found")
    return api_response(
        request,
        code=BusinessCode.OK,
        message="查询成功",
        data=ProjectResponse.model_validate(project),
    )
```

Lists, counts, search, export, bulk operations, and nested-resource queries need
equivalent SQL visibility predicates. Filtering only detail endpoints leaves
IDOR and data-disclosure paths.

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

Prefer PostgreSQL reads or a versioned permission cache. A cache key includes at
least:

```text
user_id:user_token_version:authorization_epoch:user_authz_version
```

- Increment `users.authz_version` when that user's status or assignments change,
  and increment `rbac_state.epoch` when a shared role changes.
- Resolve the current version tuple from PostgreSQL or a strongly consistent
  version store before choosing a cache entry. Token or old-cache values are not
  proof that a version is current.
- On cache miss or outage, reload from the authority or fail closed.
- Define and test the maximum revocation delay. High-risk operations may require
  a database or strong-version check on every request.

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
  administration, role changes, delegation, super-admin transfer, and
  self-elevation.
- Use dedicated request models with `extra="forbid"` and an allowlist of mutable
  fields.
- Require the exact operation capability. Assignment, role lifecycle, permission
  binding, permission unbinding, delegation, and transfer are separate effects.
- For assignment or permission changes, calculate complete proposed
  authority and require it to remain within the actor's delegable authority.
- For every role bind, bootstrap, and super-admin transfer, calculate the target's
  complete proposed live assignment set after the global guard and row locks are
  held. Reject a final total above 10 as one atomic conflict. Enforce the same
  invariant in PostgreSQL so direct SQL and concurrent service writers cannot
  bypass it; an idempotent bind of an already-live pair does not consume a slot.
- Protect the immutable `super_admin`, `admin`, and `user` role definitions, the
  mandatory `user` assignment, and the sole `super_admin` holder from ordinary
  rename, disablement, deletion, grant changes, or revocation.
- Bootstrap the first `super_admin` through the explicit offline transaction in
  the PostgreSQL implementation, targeting an existing immutable `users.id`;
  never promote the first registered user, select the holder by email or
  `user_name`, or insert a bare assignment implicitly.
- Keep the public authorization API on neutral `/api/v1` resource paths. Do not
  expose `rbac` in public paths or OpenAPI metadata, and use only `GET` and
  action-specific `POST` for the baseline administration contract. Internal
  packages may retain `app.rbac`.

## Avoid Authorization Bypasses

Route dependencies are insufficient if jobs, WebSockets, CLI tools, or direct
service entry points can perform the same privileged operation. Call the shared
authorization service at every boundary handling untrusted intent. Keep truly
trusted system jobs explicit and auditable instead of manufacturing a fake role.
