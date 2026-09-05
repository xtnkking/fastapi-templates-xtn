import uuid
from collections.abc import Iterable
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select

from app.rbac.dependencies import (
    SessionDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import (
    TENANT_OWNER_PERMISSION_KEYS,
    AuthorizationContext,
    PermissionKey,
)
from app.rbac.models import Membership, Permission, Role
from app.rbac.queries import load_authority_snapshot, load_role_grant
from app.rbac.schemas import (
    AuthorityResponse,
    MembershipCreateRequest,
    MembershipResponse,
    MembershipStatusUpdateRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleDelegationReplaceRequest,
    RolePermissionsReplaceRequest,
    RoleResponse,
)
from app.rbac.service import RbacService, get_rbac_service

router = APIRouter(prefix="/tenants/{tenant_id}/rbac", tags=["rbac"])
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


async def _membership_response(
    session: SessionDependency,
    *,
    tenant_id: uuid.UUID,
    membership: Membership,
) -> MembershipResponse:
    authority = await load_authority_snapshot(
        session,
        tenant_id=tenant_id,
        membership_id=membership.id,
        include_disabled_roles=True,
    )
    return MembershipResponse(
        id=membership.id,
        user_id=membership.user_id,
        status=cast(Literal["active", "suspended"], authority.membership_status),
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
        tenant_id=context.tenant_id,
        membership_id=authority.membership_id,
        management_tier=authority.management_tier,
        permissions=sorted(authority.permissions),
        delegable_permissions=sorted(authority.delegable_permissions),
        authz_version=authority.authz_version,
        tenant_authz_epoch=context.tenant_authz_epoch,
    )


@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> list[RoleResponse]:
    roles = (
        await session.scalars(
            select(Role)
            .where(Role.tenant_id == context.tenant_id)
            .order_by(Role.key, Role.id)
        )
    ).all()
    responses: list[RoleResponse] = []
    for role in roles:
        grant = await load_role_grant(
            session,
            tenant_id=context.tenant_id,
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
            .where(Permission.key.in_(TENANT_OWNER_PERMISSION_KEYS))
            .order_by(Permission.key)
        )
    ).all()
    return [
        PermissionResponse(key=permission.key, description=permission.description)
        for permission in permissions
    ]


@router.get("/memberships", response_model=list[MembershipResponse])
async def list_memberships(
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.MEMBERSHIPS_READ)),
    ],
    session: SessionDependency,
) -> list[MembershipResponse]:
    memberships = (
        await session.scalars(
            select(Membership)
            .where(Membership.tenant_id == context.tenant_id)
            .order_by(Membership.id)
        )
    ).all()
    return [
        await _membership_response(
            session,
            tenant_id=context.tenant_id,
            membership=membership,
        )
        for membership in memberships
    ]


@router.post(
    "/memberships",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_membership(
    body: MembershipCreateRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> MembershipResponse:
    membership = await service.create_membership(context=context, request=body)
    return await _membership_response(
        session,
        tenant_id=context.tenant_id,
        membership=membership,
    )


@router.patch(
    "/memberships/{membership_id}/status",
    response_model=MembershipResponse,
)
async def update_membership_status(
    membership_id: uuid.UUID,
    body: MembershipStatusUpdateRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> MembershipResponse:
    membership = await service.update_membership_status(
        context=context,
        target_membership_id=membership_id,
        request=body,
    )
    return await _membership_response(
        session,
        tenant_id=context.tenant_id,
        membership=membership,
    )


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreateRequest,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> RoleResponse:
    role = await service.create_role(context=context, request=body)
    grant = await load_role_grant(session, tenant_id=context.tenant_id, role_id=role.id)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.put(
    "/memberships/{membership_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def assign_role(
    membership_id: uuid.UUID,
    role_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.assign_role(
        context=context,
        target_membership_id=membership_id,
        role_id=role_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/memberships/{membership_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_role(
    membership_id: uuid.UUID,
    role_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.revoke_role(
        context=context,
        target_membership_id=membership_id,
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
    grant = await load_role_grant(session, tenant_id=context.tenant_id, role_id=role.id)
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
    grant = await load_role_grant(session, tenant_id=context.tenant_id, role_id=role.id)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.post(
    "/ownership/transfer/{membership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def transfer_ownership(
    membership_id: uuid.UUID,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: RbacServiceDependency,
) -> Response:
    await service.transfer_ownership(
        context=context,
        target_membership_id=membership_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
