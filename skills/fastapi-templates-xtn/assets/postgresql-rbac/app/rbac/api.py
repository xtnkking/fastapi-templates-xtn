import uuid
from collections.abc import Iterable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BeforeValidator
from sqlalchemy import func, select

from app.api_contract import (
    RATE_LIMIT_ERROR_RESPONSES,
    STANDARD_ERROR_RESPONSES,
    ApiResponse,
    BusinessCode,
    PageData,
    RequestIdRoute,
    api_response,
)
from app.i18n import MessageKey
from app.rate_limit_dependencies import enforce_principal_rate_limit
from app.rbac.dependencies import (
    PrincipalDependency,
    SessionDependency,
    SettingsDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import AuthorizationContext, PermissionKey
from app.rbac.errors import not_found
from app.rbac.models import Permission, Role, User
from app.rbac.provisioning import normalize_identity
from app.rbac.queries import (
    UserAccessView,
    list_visible_roles_page,
    list_visible_users_page,
    load_role_grant,
    load_role_grants_for_roles,
    load_user_access_views,
    load_visible_role,
    load_visible_user,
)
from app.rbac.schemas import (
    AuthorityResponse,
    OperationResponse,
    PermissionIdsRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleIdsRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
    RoleVersionRequest,
    UserResponse,
    UserRoleMutationResponse,
    UserStatusUpdateRequest,
)
from app.rbac.security import AccessTokenClaims, revoke_active_jti
from app.rbac.service import RbacService, get_rbac_service
from app.redis_client import get_redis

router = APIRouter(
    prefix="/api/v1",
    responses={**STANDARD_ERROR_RESPONSES, **RATE_LIMIT_ERROR_RESPONSES},
    route_class=RequestIdRoute,
)
RbacServiceDependency = Annotated[RbacService, Depends(get_rbac_service)]

PERMISSION_TAG = "Permission management"
ROLE_TAG = "Role management"
USER_TAG = "User access"
AUTHENTICATION_TAG = "Authentication"


def _normalize_user_name_query(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("user_name must be a string")
    return normalize_identity(value, field="user_name")


def _role_response(
    role: Role,
    permissions: Iterable[str],
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
        permissions=tuple(sorted(permissions)),
        version=role.version,
        deleted_at=role.deleted_at,
    )


def _user_response(access: UserAccessView) -> UserResponse:
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


async def _load_user_response(
    session: SessionDependency,
    *,
    user: User,
    actor: AuthorizationContext,
) -> UserResponse:
    access_by_user_id = await load_user_access_views(
        session,
        users=(user,),
        actor=actor.authority,
    )
    return _user_response(access_by_user_id[user.id])


@router.post(
    "/auth/logout",
    response_model=ApiResponse[OperationResponse],
    tags=[AUTHENTICATION_TAG],
    operation_id="logout_current_access_token",
)
async def logout_current_access_token(
    request: Request,
    principal: PrincipalDependency,
    settings: SettingsDependency,
) -> ApiResponse[OperationResponse]:
    await enforce_principal_rate_limit(request, principal, settings)
    await revoke_active_jti(
        get_redis(request),
        claims=AccessTokenClaims(
            user_id=principal.user_id,
            token_id=principal.token_id,
            issued_at=principal.issued_at,
            expires_at=principal.expires_at,
        ),
        user_token_version=principal.token_version,
        settings=settings,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.AUTH_LOGOUT_SUCCEEDED,
        data=OperationResponse(changed=True),
    )


@router.get(
    "/me/access",
    response_model=ApiResponse[AuthorityResponse],
    tags=[USER_TAG],
    operation_id="get_my_access",
)
async def read_my_authority(
    request: Request,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
) -> ApiResponse[AuthorityResponse]:
    authority = context.authority
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=AuthorityResponse(
            user_id=authority.user_id,
            management_tier=authority.management_tier,
            permissions=sorted(authority.permissions),
            authz_version=authority.authz_version,
            authorization_epoch=context.authorization_epoch,
        ),
    )


@router.get(
    "/permissions",
    response_model=ApiResponse[PageData[PermissionResponse]],
    tags=[PERMISSION_TAG],
    operation_id="list_permissions",
)
async def list_permissions(
    request: Request,
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.PERMISSIONS_READ)),
    ],
    session: SessionDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
) -> ApiResponse[PageData[PermissionResponse]]:
    total = int(
        await session.scalar(
            select(func.count())
            .select_from(Permission)
            .where(Permission.deleted_at.is_(None))
        )
        or 0
    )
    permissions = (
        await session.scalars(
            select(Permission)
            .where(Permission.deleted_at.is_(None))
            .order_by(Permission.key, Permission.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    items = [
        PermissionResponse(
            id=permission.id,
            key=permission.key,
            description=permission.description,
        )
        for permission in permissions
    ]
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=PageData(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        ),
    )


@router.get(
    "/permissions/{permission_id}",
    response_model=ApiResponse[PermissionResponse],
    tags=[PERMISSION_TAG],
    operation_id="get_permission",
)
async def get_permission(
    request: Request,
    permission_id: uuid.UUID,
    _context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.PERMISSIONS_READ)),
    ],
    session: SessionDependency,
) -> ApiResponse[PermissionResponse]:
    permission = await session.scalar(
        select(Permission).where(
            Permission.id == permission_id,
            Permission.deleted_at.is_(None),
        )
    )
    if permission is None:
        raise not_found("permission_not_found")
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=PermissionResponse(
            id=permission.id,
            key=permission.key,
            description=permission.description,
        ),
    )


@router.get(
    "/roles",
    response_model=ApiResponse[PageData[RoleResponse]],
    tags=[ROLE_TAG],
    operation_id="list_roles",
)
async def list_roles(
    request: Request,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
) -> ApiResponse[PageData[RoleResponse]]:
    roles, total = await list_visible_roles_page(
        session,
        actor=context.authority,
        page=page,
        page_size=page_size,
    )
    grants = await load_role_grants_for_roles(session, roles=roles)
    responses = [
        _role_response(
            role,
            grants[role.id].permissions,
        )
        for role in roles
    ]
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=PageData(
            items=responses,
            page=page,
            page_size=page_size,
            total=total,
        ),
    )


@router.get(
    "/roles/{role_id}",
    response_model=ApiResponse[RoleResponse],
    tags=[ROLE_TAG],
    operation_id="get_role",
)
async def get_role(
    request: Request,
    role_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_READ)),
    ],
    session: SessionDependency,
) -> ApiResponse[RoleResponse]:
    role = await load_visible_role(
        session,
        actor=context.authority,
        role_id=role_id,
    )
    if role is None:
        raise not_found("role_not_found")
    grant = await load_role_grant(
        session,
        role_id=role.id,
        include_disabled=True,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=_role_response(role, grant.permissions),
    )


@router.post(
    "/roles",
    response_model=ApiResponse[RoleMutationResponse],
    status_code=status.HTTP_201_CREATED,
    tags=[ROLE_TAG],
    operation_id="create_role",
)
async def create_role(
    request: Request,
    body: RoleCreateRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_CREATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await service.create_role(context=context, request=body)
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.COMMON_CREATED,
        data=result,
    )


@router.post(
    "/roles/{role_id}/update",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="update_role",
)
async def update_role(
    request: Request,
    role_id: uuid.UUID,
    body: RoleUpdateRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_UPDATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await service.update_role(
        context=context,
        role_id=role_id,
        request=body,
        expected_version=body.expected_version,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


async def _set_role_active(
    *,
    role_id: uuid.UUID,
    is_active: bool,
    expected_version: int,
    context: AuthorizationContext,
    service: RbacService,
) -> RoleMutationResponse:
    return await service.set_role_active(
        context=context,
        role_id=role_id,
        is_active=is_active,
        expected_version=expected_version,
    )


@router.post(
    "/roles/{role_id}/disable",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="disable_role",
)
async def disable_role(
    request: Request,
    role_id: uuid.UUID,
    body: RoleVersionRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await _set_role_active(
        role_id=role_id,
        is_active=False,
        expected_version=body.expected_version,
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/roles/{role_id}/enable",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="enable_role",
)
async def enable_role(
    request: Request,
    role_id: uuid.UUID,
    body: RoleVersionRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await _set_role_active(
        role_id=role_id,
        is_active=True,
        expected_version=body.expected_version,
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/roles/{role_id}/delete",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="delete_role",
)
async def delete_role(
    request: Request,
    role_id: uuid.UUID,
    body: RoleVersionRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_DELETE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await service.soft_delete_role(
        context=context,
        role_id=role_id,
        expected_version=body.expected_version,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


async def _change_role_permissions(
    *,
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    operation: Literal["bind", "unbind"],
    context: AuthorizationContext,
    service: RbacService,
) -> RoleMutationResponse:
    return await service.change_role_permissions(
        context=context,
        role_id=role_id,
        permission_ids=body.permission_ids,
        operation=operation,
        expected_version=body.expected_version,
    )


@router.post(
    "/roles/{role_id}/permissions/bind",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="bind_role_permissions",
)
async def bind_role_permissions(
    request: Request,
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_PERMISSIONS_BIND)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await _change_role_permissions(
        role_id=role_id,
        body=body,
        operation="bind",
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/roles/{role_id}/permissions/unbind",
    response_model=ApiResponse[RoleMutationResponse],
    tags=[ROLE_TAG],
    operation_id="unbind_role_permissions",
)
async def unbind_role_permissions(
    request: Request,
    role_id: uuid.UUID,
    body: PermissionIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_PERMISSIONS_UNBIND)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[RoleMutationResponse]:
    result = await _change_role_permissions(
        role_id=role_id,
        body=body,
        operation="unbind",
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.get(
    "/users",
    response_model=ApiResponse[PageData[UserResponse]],
    tags=[USER_TAG],
    operation_id="list_users",
)
async def list_users(
    request: Request,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_READ)),
    ],
    session: SessionDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
    user_name: Annotated[
        str | None,
        BeforeValidator(_normalize_user_name_query),
        Query(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$"),
    ] = None,
) -> ApiResponse[PageData[UserResponse]]:
    users, total = await list_visible_users_page(
        session,
        actor=context.authority,
        page=page,
        page_size=page_size,
        user_name=user_name,
    )
    access_by_user_id = await load_user_access_views(
        session,
        users=users,
        actor=context.authority,
    )
    items = [_user_response(access_by_user_id[user.id]) for user in users]
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=PageData(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        ),
    )


@router.get(
    "/users/{user_id}",
    response_model=ApiResponse[UserResponse],
    tags=[USER_TAG],
    operation_id="get_user",
)
async def get_user(
    request: Request,
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_READ)),
    ],
    session: SessionDependency,
) -> ApiResponse[UserResponse]:
    user = await load_visible_user(
        session,
        actor=context.authority,
        user_id=user_id,
    )
    if user is None:
        raise not_found("user_not_found")
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=await _load_user_response(session, user=user, actor=context),
    )


async def _change_user_roles(
    *,
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    operation: Literal["bind", "unbind"],
    context: AuthorizationContext,
    service: RbacService,
) -> UserRoleMutationResponse:
    return await service.change_user_roles(
        context=context,
        target_user_id=user_id,
        role_ids=body.role_ids,
        operation=operation,
    )


@router.post(
    "/users/{user_id}/roles/bind",
    response_model=ApiResponse[UserRoleMutationResponse],
    tags=[USER_TAG],
    operation_id="bind_user_roles",
)
async def bind_user_roles(
    request: Request,
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_ASSIGN)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[UserRoleMutationResponse]:
    result = await _change_user_roles(
        user_id=user_id,
        body=body,
        operation="bind",
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/users/{user_id}/roles/unbind",
    response_model=ApiResponse[UserRoleMutationResponse],
    tags=[USER_TAG],
    operation_id="unbind_user_roles",
)
async def unbind_user_roles(
    request: Request,
    user_id: uuid.UUID,
    body: RoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.ROLES_REVOKE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[UserRoleMutationResponse]:
    result = await _change_user_roles(
        user_id=user_id,
        body=body,
        operation="unbind",
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


async def _set_user_active(
    *,
    user_id: uuid.UUID,
    is_active: bool,
    context: AuthorizationContext,
    service: RbacService,
) -> UserResponse:
    return await service.update_user_status(
        context=context,
        target_user_id=user_id,
        request=UserStatusUpdateRequest(is_active=is_active),
    )


@router.post(
    "/users/{user_id}/disable",
    response_model=ApiResponse[UserResponse],
    tags=[USER_TAG],
    operation_id="disable_user",
)
async def disable_user(
    request: Request,
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[UserResponse]:
    result = await _set_user_active(
        user_id=user_id,
        is_active=False,
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/users/{user_id}/enable",
    response_model=ApiResponse[UserResponse],
    tags=[USER_TAG],
    operation_id="enable_user",
)
async def enable_user(
    request: Request,
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_STATUS_UPDATE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[UserResponse]:
    result = await _set_user_active(
        user_id=user_id,
        is_active=True,
        context=context,
        service=service,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post(
    "/users/{user_id}/sessions/revoke",
    response_model=ApiResponse[OperationResponse],
    tags=[USER_TAG],
    operation_id="revoke_user_sessions",
)
async def revoke_user_sessions(
    request: Request,
    user_id: uuid.UUID,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_SESSIONS_REVOKE)),
    ],
    service: RbacServiceDependency,
) -> ApiResponse[OperationResponse]:
    await service.revoke_user_sessions(
        context=context,
        target_user_id=user_id,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=OperationResponse(changed=True),
    )
