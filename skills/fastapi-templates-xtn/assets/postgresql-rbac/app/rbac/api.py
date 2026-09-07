import re
import uuid
from collections.abc import Iterable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, Response, status
from sqlalchemy import select

from app.rbac.dependencies import (
    SessionDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import AuthorizationContext, PermissionKey
from app.rbac.errors import invalid_request, not_found, precondition_required
from app.rbac.models import Permission, Role, User
from app.rbac.queries import load_authority_snapshot, load_role_grant
from app.rbac.schemas import (
    AuthorityResponse,
    OperationResponse,
    OwnershipTransferRequest,
    PermissionIdsRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleIdsRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
    UserResponse,
    UserRoleMutationResponse,
    UserStatusUpdateRequest,
)
from app.rbac.service import RbacService, get_rbac_service

router = APIRouter(prefix="/api/v1")
RbacServiceDependency = Annotated[RbacService, Depends(get_rbac_service)]
IfMatchHeader = Annotated[str, Header(alias="If-Match")]

PERMISSION_TAG = "Permission management"
ROLE_TAG = "Role management"
USER_TAG = "User access"
SYSTEM_TAG = "System ownership"

_ROLE_ETAG_PATTERN = re.compile(
    r'^"role:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-'
    r'[0-9a-f]{12}):v(0|[1-9][0-9]*)"$'
)


def _role_etag(role: Role | RoleResponse) -> str:
    return f'"role:{role.id}:v{role.version}"'


def _expected_role_version(
    *,
    role_id: uuid.UUID,
    if_match: str | None,
) -> int:
    if if_match is None:
        raise precondition_required("if_match_required")
    match = _ROLE_ETAG_PATTERN.fullmatch(if_match)
    if match is None:
        raise invalid_request("invalid_if_match")

    etag_role_id = uuid.UUID(match.group(1))
    if etag_role_id != role_id:
        raise invalid_request("if_match_resource_mismatch")
    return int(match.group(2))


def _role_response(
    role: Role,
    permissions: Iterable[str],
    delegable_permissions: Iterable[str],
) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        key=role.key,
        name=role.name,
        description=role.description,
        management_tier=role.management_tier,
        is_active=role.is_active,
        is_system=role.is_system,
        is_protected=role.is_protected,
        is_owner=role.is_owner,
        permissions=tuple(sorted(permissions)),
        delegable_permissions=tuple(sorted(delegable_permissions)),
        version=role.version,
        deleted_at=role.deleted_at,
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


async def _get_user(session: SessionDependency, *, user_id: uuid.UUID) -> User:
    user = await session.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise not_found("user_not_found")
    return user


@router.get(
    "/me/access",
    response_model=AuthorityResponse,
    tags=[USER_TAG],
    operation_id="get_my_access",
)
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


@router.get(
    "/permissions",
    response_model=list[PermissionResponse],
    tags=[PERMISSION_TAG],
    operation_id="list_permissions",
)
async def list_permissions(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.PERMISSIONS_READ)),
    ],
    session: SessionDependency,
) -> list[PermissionResponse]:
    permissions = (
        await session.scalars(
            select(Permission).order_by(Permission.key, Permission.id)
        )
    ).all()
    return [
        PermissionResponse(
            id=permission.id,
            key=permission.key,
            description=permission.description,
        )
        for permission in permissions
    ]


@router.get(
    "/permissions/{permission_id}",
    response_model=PermissionResponse,
    tags=[PERMISSION_TAG],
    operation_id="get_permission",
)
async def get_permission(
    permission_id: uuid.UUID,
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.PERMISSIONS_READ)),
    ],
    session: SessionDependency,
) -> PermissionResponse:
    permission = await session.scalar(
        select(Permission).where(Permission.id == permission_id)
    )
    if permission is None:
        raise not_found("permission_not_found")
    return PermissionResponse(
        id=permission.id,
        key=permission.key,
        description=permission.description,
    )


@router.get(
    "/roles",
    response_model=list[RoleResponse],
    tags=[ROLE_TAG],
    operation_id="list_roles",
)
async def list_roles(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> list[RoleResponse]:
    roles = (
        await session.scalars(
            select(Role).where(Role.deleted_at.is_(None)).order_by(Role.key, Role.id)
        )
    ).all()
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


@router.get(
    "/roles/{role_id}",
    response_model=RoleResponse,
    tags=[ROLE_TAG],
    operation_id="get_role",
)
async def get_role(
    role_id: uuid.UUID,
    response: Response,
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> RoleResponse:
    role = await session.scalar(
        select(Role).where(Role.id == role_id, Role.deleted_at.is_(None))
    )
    if role is None:
        raise not_found("role_not_found")
    grant = await load_role_grant(
        session,
        role_id=role.id,
        include_disabled=True,
    )
    response.headers["ETag"] = _role_etag(role)
    return _role_response(role, grant.permissions, grant.delegable_permissions)


@router.post(
    "/roles",
    response_model=RoleMutationResponse,
    status_code=status.HTTP_201_CREATED,
    tags=[ROLE_TAG],
    operation_id="create_role",
)
async def create_role(
    body: RoleCreateRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_CREATE)),
    ],
    service: RbacServiceDependency,
) -> RoleMutationResponse:
    result = await service.create_role(context=context, request=body)
    response.headers["ETag"] = _role_etag(result.role)
    return result


@router.post(
    "/roles/{role_id}/update",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="update_role",
)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdateRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_UPDATE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    expected_version = _expected_role_version(role_id=role_id, if_match=if_match)
    result = await service.update_role(
        context=context,
        role_id=role_id,
        request=body,
        expected_version=expected_version,
    )
    response.headers["ETag"] = _role_etag(result.role)
    return result


async def _set_role_active(
    *,
    role_id: uuid.UUID,
    is_active: bool,
    if_match: str | None,
    response: Response,
    context: AuthorizationContext,
    service: RbacService,
) -> RoleMutationResponse:
    expected_version = _expected_role_version(role_id=role_id, if_match=if_match)
    result = await service.set_role_active(
        context=context,
        role_id=role_id,
        is_active=is_active,
        expected_version=expected_version,
    )
    response.headers["ETag"] = _role_etag(result.role)
    return result


@router.post(
    "/roles/{role_id}/disable",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="disable_role",
)
async def disable_role(
    role_id: uuid.UUID,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _set_role_active(
        role_id=role_id,
        is_active=False,
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


@router.post(
    "/roles/{role_id}/enable",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="enable_role",
)
async def enable_role(
    role_id: uuid.UUID,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _set_role_active(
        role_id=role_id,
        is_active=True,
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


@router.post(
    "/roles/{role_id}/delete",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="delete_role",
)
async def delete_role(
    role_id: uuid.UUID,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_DELETE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    expected_version = _expected_role_version(role_id=role_id, if_match=if_match)
    result = await service.soft_delete_role(
        context=context,
        role_id=role_id,
        expected_version=expected_version,
    )
    response.headers["ETag"] = _role_etag(result.role)
    return result


async def _change_role_permissions(
    *,
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    operation: Literal["bind", "unbind"],
    if_match: str | None,
    response: Response,
    context: AuthorizationContext,
    service: RbacService,
) -> RoleMutationResponse:
    expected_version = _expected_role_version(role_id=role_id, if_match=if_match)
    result = await service.change_role_permissions(
        context=context,
        role_id=role_id,
        permission_ids=body.permission_ids,
        operation=operation,
        expected_version=expected_version,
    )
    response.headers["ETag"] = _role_etag(result.role)
    return result


@router.post(
    "/roles/{role_id}/permissions/bind",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="bind_role_permissions",
)
async def bind_role_permissions(
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_PERMISSIONS_BIND)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _change_role_permissions(
        role_id=role_id,
        body=body,
        operation="bind",
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


@router.post(
    "/roles/{role_id}/permissions/unbind",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="unbind_role_permissions",
)
async def unbind_role_permissions(
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_PERMISSIONS_UNBIND)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _change_role_permissions(
        role_id=role_id,
        body=body,
        operation="unbind",
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


async def _change_role_delegation(
    *,
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    operation: Literal["bind", "unbind"],
    if_match: str | None,
    response: Response,
    context: AuthorizationContext,
    service: RbacService,
) -> RoleMutationResponse:
    expected_version = _expected_role_version(role_id=role_id, if_match=if_match)
    result = await service.change_role_delegation(
        context=context,
        role_id=role_id,
        permission_ids=body.permission_ids,
        operation=operation,
        expected_version=expected_version,
    )
    response.headers["ETag"] = _role_etag(result.role)
    return result


@router.post(
    "/roles/{role_id}/delegable-permissions/bind",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="bind_role_delegable_permissions",
)
async def bind_role_delegable_permissions(
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_DELEGATION_UPDATE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _change_role_delegation(
        role_id=role_id,
        body=body,
        operation="bind",
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


@router.post(
    "/roles/{role_id}/delegable-permissions/unbind",
    response_model=RoleMutationResponse,
    tags=[ROLE_TAG],
    operation_id="unbind_role_delegable_permissions",
)
async def unbind_role_delegable_permissions(
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_DELEGATION_UPDATE)),
    ],
    service: RbacServiceDependency,
    if_match: IfMatchHeader,
) -> RoleMutationResponse:
    return await _change_role_delegation(
        role_id=role_id,
        body=body,
        operation="unbind",
        if_match=if_match,
        response=response,
        context=context,
        service=service,
    )


@router.get(
    "/users",
    response_model=list[UserResponse],
    tags=[USER_TAG],
    operation_id="list_users",
)
async def list_users(
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_READ)),
    ],
    session: SessionDependency,
) -> list[UserResponse]:
    users = (await session.scalars(select(User).order_by(User.id))).all()
    return [await _user_response(session, user=user) for user in users]


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    tags=[USER_TAG],
    operation_id="get_user",
)
async def get_user(
    user_id: uuid.UUID,
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_READ)),
    ],
    session: SessionDependency,
) -> UserResponse:
    user = await _get_user(session, user_id=user_id)
    return await _user_response(session, user=user)


async def _change_user_roles(
    *,
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    operation: Literal["bind", "unbind"],
    context: AuthorizationContext,
    session: SessionDependency,
    service: RbacService,
) -> UserRoleMutationResponse:
    changed = await service.change_user_roles(
        context=context,
        target_user_id=user_id,
        role_ids=body.role_ids,
        operation=operation,
    )
    user = await _get_user(session, user_id=user_id)
    return UserRoleMutationResponse(
        changed=changed,
        user=await _user_response(session, user=user),
    )


@router.post(
    "/users/{user_id}/roles/bind",
    response_model=UserRoleMutationResponse,
    tags=[USER_TAG],
    operation_id="bind_user_roles",
)
async def bind_user_roles(
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_ASSIGN)),
    ],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> UserRoleMutationResponse:
    return await _change_user_roles(
        user_id=user_id,
        body=body,
        operation="bind",
        context=context,
        session=session,
        service=service,
    )


@router.post(
    "/users/{user_id}/roles/unbind",
    response_model=UserRoleMutationResponse,
    tags=[USER_TAG],
    operation_id="unbind_user_roles",
)
async def unbind_user_roles(
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_REVOKE)),
    ],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> UserRoleMutationResponse:
    return await _change_user_roles(
        user_id=user_id,
        body=body,
        operation="unbind",
        context=context,
        session=session,
        service=service,
    )


async def _set_user_active(
    *,
    user_id: uuid.UUID,
    is_active: bool,
    context: AuthorizationContext,
    session: SessionDependency,
    service: RbacService,
) -> UserResponse:
    user = await service.update_user_status(
        context=context,
        target_user_id=user_id,
        request=UserStatusUpdateRequest(is_active=is_active),
    )
    return await _user_response(session, user=user)


@router.post(
    "/users/{user_id}/disable",
    response_model=UserResponse,
    tags=[USER_TAG],
    operation_id="disable_user",
)
async def disable_user(
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_STATUS_UPDATE)),
    ],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> UserResponse:
    return await _set_user_active(
        user_id=user_id,
        is_active=False,
        context=context,
        session=session,
        service=service,
    )


@router.post(
    "/users/{user_id}/enable",
    response_model=UserResponse,
    tags=[USER_TAG],
    operation_id="enable_user",
)
async def enable_user(
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_STATUS_UPDATE)),
    ],
    session: SessionDependency,
    service: RbacServiceDependency,
) -> UserResponse:
    return await _set_user_active(
        user_id=user_id,
        is_active=True,
        context=context,
        session=session,
        service=service,
    )


@router.post(
    "/system/super-admin/transfer",
    response_model=OperationResponse,
    tags=[SYSTEM_TAG],
    operation_id="transfer_system_ownership",
)
async def transfer_system_ownership(
    body: OwnershipTransferRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.SUPER_ADMIN_TRANSFER)),
    ],
    service: RbacServiceDependency,
) -> OperationResponse:
    await service.transfer_ownership(
        context=context,
        target_user_id=body.target_user_id,
    )
    return OperationResponse(changed=True)
