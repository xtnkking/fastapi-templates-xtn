# RBAC Design And Authorization Flow

Read this reference for role, permission, or authorization policy work. RBAC
answers whether a principal has a named capability. Ownership, object state,
relationships, and other row-level conditions remain separate policy inputs.

For executable PostgreSQL code, use
[postgresql-rbac-implementation.md](postgresql-rbac-implementation.md) and copy
the linked asset as one coherent unit. It includes tables, dependencies, user and
role administration, Owner-only delegation control, migrations, and negative and
concurrency tests.

## Define The Policy First

Before writing models, list:

- principals and their active or disabled states;
- protected resources and any ownership or row-level boundaries;
- actions such as `read`, `create`, `update`, `delete`, `approve`, or `manage`;
- stable permission keys in `resource:action` form;
- which roles bundle those permissions;
- delegation, bootstrap, revocation, and audit requirements.

Do not infer sensitive policy from route names. Record a small permission matrix
and turn it into tests.

## Fixed Data Model

Use this normalized single-project model:

- `users` store identity status, protection, token revocation version, and the
  per-user authorization version;
- `roles` have a globally unique stable key, explicit status, management tier,
  version, and protected/system/Owner flags;
- `permissions` form the stable capability catalog;
- `user_roles` join users to roles and are unique on `(user_id, role_id)`;
- `role_permissions` join roles to permissions and record the explicit
  `can_delegate` subset;
- `authorization_state` contains exactly one global guard row and the shared
  authorization epoch;
- `authorization_audit_events` capture actor, target, action, decision, safe
  before/after state, request ID, and timestamp for privileged mutations.

Use positive grants. An active user's effective permissions are the union of
permissions from all active assigned roles; the effective management tier is the
maximum active role tier. Disabled or deleted roles grant nothing and must update
the relevant authorization version. Start without explicit deny, wildcard
permissions, or role inheritance. Add them only with a documented precedence
model and tests for conflicts and cycles.

## Permission Keys And Roles

- Define permission keys as stable code constants, for example
  `projects:read`, `projects:update`, and `roles:assign`.
- Endpoint checks depend on permission keys, not display names such as `admin`.
- Separate administrative effects. `roles:assign` may attach an existing role;
  `roles:create`, `roles:update`, `roles:delete`, and
  `roles:permissions:update` govern role definitions.
- Define delegable permissions explicitly. Possessing or assigning a permission
  does not imply authority to grant it. A role being assigned or changed must not
  contain authority outside the actor's delegable set.
- Treat system Owner and break-glass operations as explicit trust boundaries. Do
  not hide a universal bypass behind an ordinary role name.
- Treat permission-key renames as data migrations; never silently reinterpret an
  existing key.

## Authorization Pipeline

Use one consistent chain:

```text
Bearer credential
  -> verify token and active JTI
  -> load the active PostgreSQL session and user
  -> load a current immutable permission snapshot
  -> enforce required permissions
  -> query the protected resource
  -> apply ownership or other row-level policy
```

Keep request contexts narrow:

- `Principal` contains verified user and authentication/session metadata.
- `AuthorizationContext` contains the principal and immutable current authority
  used for the request.

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

Apply row policy after the capability check:

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
    project = await project_repository.get_by_id(session, project_id=project_id)
    if project is None or not project_policy.can_read(access, project):
        raise HTTPException(status_code=404, detail={"code": "not_found"})
    return ProjectResponse.model_validate(project)
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

JWT session validation and an RBAC permission cache are different security
boundaries. Follow [JWT session security](jwt-session-security.md) for claims,
JTI registration, and session revocation. Never treat roles, permissions, tiers,
or versions from a token as authoritative.

Prefer PostgreSQL reads or a versioned permission cache. A cache key includes at
least:

```text
user_id:user_token_version:authorization_epoch:user_authz_version
```

- Increment `users.authz_version` when that user's status or assignments change,
  and increment `authorization_state.epoch` when a shared role changes.
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
  administration, role changes, delegation, system ownership, and self-elevation.
- Use dedicated request models with `extra="forbid"` and an allowlist of mutable
  fields.
- Require the exact operation capability. Assignment, role lifecycle, permission
  replacement, delegation, and ownership transfer are separate effects.
- For assignment or permission replacement, calculate complete proposed
  authority and require it to remain within the actor's delegable authority.
- Protect system roles and the final Owner from ordinary rename, deletion,
  replacement, or revocation.
- Bootstrap the first Owner through an explicit one-time auditable operation;
  never promote the first registered user implicitly.

## Avoid Authorization Bypasses

Route dependencies are insufficient if jobs, WebSockets, CLI tools, or direct
service entry points can perform the same privileged operation. Call the shared
authorization service at every boundary handling untrusted intent. Keep truly
trusted system jobs explicit and auditable instead of manufacturing a fake role.
