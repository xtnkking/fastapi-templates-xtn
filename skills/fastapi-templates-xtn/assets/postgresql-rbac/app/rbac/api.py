import uuid
from collections.abc import Iterable
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select

from app.rbac.dependencies import (
    SessionDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import OWNER_PERMISSION_KEYS, AuthorizationContext, PermissionKey
from app.rbac.models import Permission, Role, User
from app.rbac.queries import load_authority_snapshot, load_role_grant
from app.rbac.schemas import (
    AuthorityResponse,
    PermissionResponse,
    RoleCreateRequest,
    RoleDelegationReplaceRequest,
    RolePermissionsReplaceRequest,
    RoleResponse,
    UserResponse,
    UserStatusUpdateRequest,
)
from app.rbac.service import RbacService, get_rbac_service

router = APIRouter(prefix="/rbac", tags=["rbac"])
RbacServiceDependency = Annotated[RbacService, Depends(get_rbac_service)]


def _role_response(
    role: Role,
    permissions: Iterable[str],
    delegable_permissions: Iterable[str],
) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        key=role.key,
        name=role.name,
        management_tier=role.management_tier,
        is_active=role.is_active,
        is_system=role.is_system,
        is_protected=role.is_protected,
        is_owner=role.is_owner,
        permissions=sorted(permissions),
        delegable_permissions=sorted(delegable_permissions),
        version=role.version,
    )


async def _user_response(
    session: SessionDependency,
    *,
    user: User,
) -> UserResponse:
    authority = await load_authority_snapshot(
        session,
        user_id=user.id,
        include_disabled_roles=True,
    )
    return UserResponse(
        id=user.id,
        is_active=authority.user_is_active,
        management_tier=authority.management_tier,
        role_ids=[role.role_id for role in authority.roles],
        permissions=sorted(authority.permissions),
        delegable_permissions=sorted(authority.delegable_permissions),
        authz_version=authority.authz_version,
    )


@router.get("/me", response_model=AuthorityResponse)
async def read_my_authority(
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
) -> AuthorityResponse:
    authority = context.authority
    return AuthorityResponse(
        user_id=authority.user_id,
        management_tier=authority.management_tier,
        permissions=sorted(authority.permissions),
        delegable_permissions=sorted(authority.delegable_permissions),
        authz_version=authority.authz_version,
        authorization_epoch=context.authorization_epoch,
    )


@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> list[RoleResponse]:
    roles = (await session.scalars(select(Role).order_by(Role.key, Role.id))).all()
    responses: list[RoleResponse] = []
    for role in roles:
        grant = await load_role_grant(
            session,
            role_id=role.id,
            include_disabled=True,
        )
        responses.append(
            _role_response(role, grant.permissions, grant.delegable_permissions)
        )
    return responses


@router.get("/permissions", response_model=list[PermissionResponse])
async def list_permissions(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> list[PermissionResponse]:
    permissions = (
        await session.scalars(
            select(Permission)
            .where(Permission.key.in_(OWNER_PERMISSION_KEYS))
            .order_by(Permission.key)
        )
    ).all()
    return [
        PermissionResponse(key=permission.key, description=permission.description)
        for permission in permissions
    ]


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_READ)),
    ],
    session: SessionDependency,
) -> list[UserResponse]:
    users = (await session.scalars(select(User).order_by(User.id))).all()
    return [await _user_response(session, user=user) for user in users]


@router.patch("/users/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: uuid.UUID,
    body: UserStatusUpdateRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> UserResponse:
    user = await service.update_user_status(
        context=context,
        target_user_id=user_id,
        request=body,
    )
    return await _user_response(session, user=user)


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreateRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> RoleResponse:
    role = await service.create_role(context=context, request=body)
    grant = await load_role_grant(session, role_id=role.id)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.put(
    "/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def assign_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.assign_role(
        context=context,
        target_user_id=user_id,
        role_id=role_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.revoke_role(
        context=context,
        target_user_id=user_id,
        role_id=role_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/roles/{role_id}/permissions", response_model=RoleResponse)
async def replace_role_permissions(
    role_id: uuid.UUID,
    body: RolePermissionsReplaceRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> RoleResponse:
    role = await service.replace_role_permissions(
        context=context,
        role_id=role_id,
        request=body,
    )
    grant = await load_role_grant(session, role_id=role.id)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.put("/roles/{role_id}/delegable-permissions", response_model=RoleResponse)
async def replace_role_delegation(
    role_id: uuid.UUID,
    body: RoleDelegationReplaceRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> RoleResponse:
    role = await service.replace_role_delegation(
        context=context,
        role_id=role_id,
        request=body,
    )
    grant = await load_role_grant(session, role_id=role.id)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.post(
    "/ownership/transfer/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def transfer_ownership(
    user_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.transfer_ownership(
        context=context,
        target_user_id=user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
