from collections.abc import Iterable

from app.models.access import Role
from app.repositories.access import UserAccessView
from app.schemas.access import RoleResponse, UserResponse


def role_response(role: Role, permissions: Iterable[str]) -> RoleResponse:
    """Freeze already-authorized role data without performing another query."""
    return RoleResponse(
        id=role.id,
        key=role.key,
        name=role.name,
        description=role.description,
        management_tier=role.management_tier,
        is_active=role.is_active,
        is_system=role.is_system,
        is_protected=role.is_protected,
        permissions=tuple(sorted(permissions)),
        version=role.version,
        deleted_at=role.deleted_at,
    )


def user_response(access: UserAccessView) -> UserResponse:
    """Freeze a view whose assigned roles were filtered for the current actor."""
    authority = access.authority
    return UserResponse(
        id=authority.user_id,
        user_name=access.user_name,
        is_active=authority.user_is_active,
        assigned_role_ids=access.assigned_role_ids,
        effective_role_ids=tuple(role.role_id for role in authority.roles),
        effective_management_tier=authority.management_tier,
        effective_permissions=tuple(sorted(authority.permissions)),
        authz_version=authority.authz_version,
    )
