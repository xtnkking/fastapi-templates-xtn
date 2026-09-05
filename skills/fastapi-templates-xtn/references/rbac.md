# RBAC Design And Authorization Flow

Read this reference for any role, permission, tenant, or authorization task.
RBAC answers whether a principal has a named capability. Ownership, object state,
relationships, and other row-level conditions are separate policy inputs.

For an executable PostgreSQL version of these rules, use
[postgresql-rbac-implementation.md](postgresql-rbac-implementation.md) and copy
the linked asset as one coherent unit. It includes the tables, dependencies,
member lifecycle, role services, owner-only delegation control, migrations, and
negative/concurrency tests described here.

## Define The Policy First

Before writing models, list:

- principals and their active or disabled states;
- resources and tenant boundaries;
- actions such as `read`, `create`, `update`, `delete`, `approve`, or `manage`;
- stable permission keys in `resource:action` form;
- which roles bundle those permissions;
- ownership or row-level conditions that RBAC alone cannot express;
- delegation, bootstrap, revocation, and audit requirements.

Do not infer sensitive policy from route names. Record a small permission matrix
and turn it into tests.

## Data Model

For a single-tenant application, the minimum normalized model is:

- `users`;
- `roles`, with a unique stable key;
- `permissions`, with a unique stable permission key;
- `user_roles`, unique on `(user_id, role_id)`;
- `role_permissions`, unique on `(role_id, permission_id)`.

If the product has organizations or tenants, model the boundary from the start:

- `users` are global identities and include status plus a token version when
  immediate account revocation is required.
- `tenants` include status and, when caching authorization, an authorization
  epoch.
- `memberships` join users to tenants and include status plus a membership
  authorization version. Enforce uniqueness on `(tenant_id, user_id)`.
- `roles` belong to exactly one tenant and have an explicit active or disabled
  state (or an equally explicit deletion model). Enforce uniqueness on
  `(tenant_id, role_key)` and a key suitable for tenant-safe references.
- `permissions` form a global catalog of stable capability keys.
- `role_permissions` join roles to permissions.
- `membership_roles` join memberships to roles and carry `tenant_id`. Give
  `memberships` a unique `(id, tenant_id)` key and `roles` a unique
  `(id, tenant_id)` key. Reference both pairs from `membership_roles`, so one row
  cannot combine a membership from one tenant with a role from another tenant.
- `authorization_audit_events` capture actor, target, tenant, action, before and
  after state, request ID, and timestamp for privileged mutations.

Use positive grants and union the permissions from active roles attached to an
active membership. Disabled or deleted roles grant nothing and must invalidate
the relevant authorization version. Start without explicit deny, wildcard
permissions, or role inheritance. Add them only with a documented precedence
model and tests for conflicts and cycles.

## Permission Keys And Roles

- Define permission keys as stable code constants, for example
  `projects:read`, `projects:update`, and `roles:assign`.
- A role is administrative data. Ordinary endpoint checks should depend on
  permission keys so that role composition can change without code changes.
- Define separate capabilities for separate administrative effects. For example,
  `roles:assign` may attach or detach an existing role, while `roles:create`,
  `roles:update`, `roles:delete`, and `roles:permissions:update` govern role
  definitions. Do not let `roles:assign` modify a role's permission set.
- Define the actor's delegable permission set explicitly, either in authorization
  data or a version-controlled policy. It is not implied by `roles:assign` and
  need not equal every permission the actor can personally exercise. A role being
  assigned or updated must not contain permissions outside that set.
- Treat platform-level administration as a separate, explicit trust boundary.
  Do not hide a universal bypass behind a common role name such as `admin`.
- Permission renames are data migrations. Do not silently reinterpret an existing
  key.

## Authorization Pipeline

Use one consistent chain:

```text
Bearer credential
  -> authenticate principal
  -> resolve candidate tenant
  -> validate active user, tenant, and membership
  -> load a permission snapshot
  -> enforce required permissions
  -> query the resource within the tenant
  -> apply ownership or other row-level policy
```

Separate request contexts make the boundaries visible:

- `Principal` contains verified identity and authentication/session metadata.
- `TenantContext` contains the resolved, visible tenant and membership.
- `AuthorizationContext` contains the principal, tenant context, and immutable
  permission set used for the request.

A permission dependency can follow this shape:

```python
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, status


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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "permission_denied"},
            )
        return context

    return dependency
```

Adapt names and error envelopes to the repository. Never let an empty permission
configuration become an implicit allow. Centralize ALL versus ANY semantics and
test both.

Use the resulting context in a tenant-scoped query:

```python
ProjectReadAccess = Annotated[
    AuthorizationContext,
    Depends(require_permissions(PermissionKey.PROJECTS_READ)),
]


@router.get("/{project_id}", response_model=ProjectResponse)
async def read_project(
    project_id: UUID,
    access: ProjectReadAccess,
    session: SessionDependency,
) -> ProjectResponse:
    project = await project_repository.get_for_tenant(
        session,
        tenant_id=access.tenant.id,
        project_id=project_id,
    )
    if project is None:
        raise HTTPException(status_code=404, detail={"code": "not_found"})
    return ProjectResponse.model_validate(project)
```

Lists, counts, search, export, bulk operations, and nested-resource queries need
the same database-level tenant predicate. Filtering only detail endpoints is not
tenant isolation.

## Tenant Resolution

A path value, trusted subdomain, header, or token claim may identify a candidate
tenant. It is never sufficient by itself. Validate it against the authenticated
principal's active membership and, when a token is tenant-bound, the token tenant.

- Do not accept `tenant_id` from an ordinary body model as authorization context.
- Prefer tenant-bound access tokens when users can switch between organizations.
- Make cross-tenant objects indistinguishable from missing objects to callers who
  cannot see them.
- If PostgreSQL row-level security is used as defense in depth, still keep
  application authorization explicit and set database session context safely for
  every transaction.

## Status Codes

- Return `401` with `WWW-Authenticate: Bearer` for a missing, invalid, expired,
  revoked, or wrong-type bearer token, and normally for a disabled identity.
- Return `403` when authentication and tenant visibility are valid but the
  required action is not permitted.
- Return `404` for a missing resource or a cross-tenant resource whose existence
  must not be disclosed. An unknown or invisible tenant should normally behave
  the same way.
- Authenticate and resolve tenant context before performing a protected resource
  lookup. Keep ordering consistent so response differences do not become an
  enumeration signal.

## Authorization Cache Consistency

JWT session validation and an RBAC permission cache are different security
boundaries. Follow [JWT session security](jwt-session-security.md) for token
claims, JTI registration, and session revocation. Never treat roles, permissions,
tiers, versions, or other authorization state from a token as authoritative.

Prefer loading current permissions from PostgreSQL or a versioned authorization
cache. A multi-tenant permission-cache key should include at least:

```text
tenant_id:user_id:user_token_version:tenant_authz_epoch:membership_authz_version
```

- Change the tenant epoch when shared role authority changes, the membership
  version when that member's roles or status changes, and the user token version
  when the identity is disabled. For write ordering, atomic version increments,
  and post-commit invalidation, follow
  [atomic authorization consistency](atomic-consistency.md).
- Resolve the current version tuple from the authoritative database or a strongly
  consistent version store before selecting a permission-cache entry. Values from
  the presented token or an old permission entry are not proof that a version is
  current.
- On cache miss or outage, reload from the authority or fail closed. Never convert
  an authorization infrastructure failure into allow.
- Define and test the maximum permitted revocation delay. High-risk operations may
  require a database or strong-version check on every request even when normal
  reads use a cache.

## Atomic Writes And Immediate Revocation

A versioned cache with a short TTL provides bounded staleness; it does not provide
immediate revocation. Every authorization control-plane write, and every
high-risk business write that promises immediate revocation, must follow
[atomic authorization consistency](atomic-consistency.md). That protocol defines
the transaction owner, canonical lock order, authoritative post-lock reload,
discover-lock-requery behavior, audit outcomes, external effects, isolation, and
deterministic concurrency tests. A route-level permission check cannot replace
the transaction-local decision.

## Privileged Mutations

- For identity administration, authority levels, shared-role changes, and direct
  or indirect self-escalation, apply
  [administrative-hierarchy.md](administrative-hierarchy.md).
- Use dedicated request models with `extra="forbid"` and an allowlist of mutable
  fields.
- Require the permission for the exact operation. Assignment, role lifecycle, and
  permission-set replacement are separate effects.
- When assigning a role or replacing its permissions, calculate the target
  effective permission set and require it to be a subset of the actor's explicit
  delegable set. Validate tenant scope and protected-role policy in the same
  transaction.
- Protect system roles from ordinary rename, deletion, or permission replacement.
- Lock and validate changes that could remove the last owner or administrator.
- Do not make the first registered user an administrator implicitly. Bootstrap an
  initial administrator through an explicit, one-time, auditable operation.
- Apply the mandatory allowed, denied, retry, and audit outcomes from
  [atomic authorization consistency](atomic-consistency.md).

## Avoid Authorization Bypasses

Route dependencies are not sufficient if background jobs, WebSockets, CLI tools,
or internal service entry points can perform the same privileged operation.
Pass an authorization context or call a shared policy service at every boundary
that handles untrusted intent. Keep truly trusted system jobs explicit and
auditable rather than manufacturing a fake user role.
