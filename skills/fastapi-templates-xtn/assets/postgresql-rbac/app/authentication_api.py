import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.abuse_flow import IdentityAbuseFlow, build_identity_abuse_flow
from app.api_contract import (
    STANDARD_ERROR_RESPONSES,
    ApiResponse,
    BusinessCode,
    RequestIdRoute,
    api_response,
    request_id_for,
)
from app.authentication_schemas import (
    AccessTokenData,
    AdminPasswordResetRequest,
    LoginRequest,
    PasswordChangeRequest,
    PasswordMutationData,
    PasswordResetCompletionRequest,
    RegistrationData,
    RegistrationRequest,
)
from app.authentication_service import (
    LocalAuthenticationService,
    get_local_authentication_service,
)
from app.rate_limit_middleware import trusted_client_ip
from app.rbac.dependencies import (
    SettingsDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import AuthorizationContext, PermissionKey
from app.rbac.errors import password_change_required
from app.rbac.security import issue_access_token
from app.redis_client import get_rate_limit_redis, get_redis

router = APIRouter(
    prefix="/api/v1",
    responses=STANDARD_ERROR_RESPONSES,
    route_class=RequestIdRoute,
)
registration_router = APIRouter(
    prefix="/api/v1",
    responses=STANDARD_ERROR_RESPONSES,
    route_class=RequestIdRoute,
)
AUTHENTICATION_TAG = "Authentication"
ACCOUNT_SECURITY_TAG = "Account security"

LocalAuthenticationServiceDependency = Annotated[
    LocalAuthenticationService,
    Depends(get_local_authentication_service),
]


def authentication_routers(
    *,
    public_registration_enabled: bool,
) -> tuple[APIRouter, ...]:
    """Return only the authentication surfaces selected by product policy."""
    if public_registration_enabled:
        return registration_router, router
    return (router,)


def _identity_abuse_flow(
    request: Request,
    settings: SettingsDependency,
) -> IdentityAbuseFlow | None:
    if not settings.rate_limit_enabled:
        return None
    return build_identity_abuse_flow(
        get_rate_limit_redis(request),
        settings=settings,
    )


@registration_router.post(
    "/auth/register",
    status_code=status.HTTP_201_CREATED,
    response_model=ApiResponse[RegistrationData],
    tags=[AUTHENTICATION_TAG],
    operation_id="register_local_account",
)
async def register_local_account(
    body: RegistrationRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[RegistrationData]:
    response.headers["Cache-Control"] = "no-store"
    user_id = await service.register(
        abuse_flow=_identity_abuse_flow(request, settings),
        client_ip=trusted_client_ip(request.scope),
        user_name=body.user_name,
        password=body.password.get_secret_value(),
        request_id=request_id_for(request),
    )
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message="注册成功",
        data=RegistrationData(user_id=user_id),
    )


@router.post(
    "/auth/login",
    response_model=ApiResponse[AccessTokenData],
    tags=[AUTHENTICATION_TAG],
    operation_id="login_with_local_password",
)
async def login_with_local_password(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[AccessTokenData]:
    response.headers["Cache-Control"] = "no-store"
    identity = await service.authenticate(
        abuse_flow=_identity_abuse_flow(request, settings),
        client_ip=trusted_client_ip(request.scope),
        user_name=body.user_name,
        password=body.password.get_secret_value(),
    )
    if identity.must_change_password:
        raise password_change_required("temporary_password_must_be_changed")

    access_token = await issue_access_token(
        get_redis(request),
        user_id=identity.user_id,
        user_token_version=identity.token_version,
        settings=settings,
    )
    request.state.actor_user_id = str(identity.user_id)
    return api_response(
        request,
        code=BusinessCode.OK,
        message="登录成功",
        data=AccessTokenData(
            access_token=access_token,
            expires_in=settings.jwt_access_token_ttl_seconds,
        ),
    )


@router.post(
    "/me/password/change",
    response_model=ApiResponse[PasswordMutationData],
    tags=[ACCOUNT_SECURITY_TAG],
    operation_id="change_my_password",
)
async def change_my_password(
    body: PasswordChangeRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[PasswordMutationData]:
    response.headers["Cache-Control"] = "no-store"
    changed = await service.change_password(
        abuse_flow=_identity_abuse_flow(request, settings),
        client_ip=trusted_client_ip(request.scope),
        context=context,
        current_password=body.current_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message="密码修改成功，请重新登录",
        data=PasswordMutationData(changed=changed),
    )


@router.post(
    "/users/{user_id}/password/reset",
    response_model=ApiResponse[PasswordMutationData],
    tags=[ACCOUNT_SECURITY_TAG],
    operation_id="reset_user_password",
)
async def reset_user_password(
    user_id: uuid.UUID,
    body: AdminPasswordResetRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_PASSWORD_RESET)),
    ],
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[PasswordMutationData]:
    response.headers["Cache-Control"] = "no-store"
    changed = await service.reset_user_password(
        abuse_flow=_identity_abuse_flow(request, settings),
        client_ip=trusted_client_ip(request.scope),
        context=context,
        target_user_id=user_id,
        current_password=body.current_password.get_secret_value(),
        temporary_password=body.temporary_password.get_secret_value(),
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message="临时密码已设置",
        data=PasswordMutationData(changed=changed),
    )


@router.post(
    "/auth/password/reset/complete",
    response_model=ApiResponse[PasswordMutationData],
    tags=[AUTHENTICATION_TAG],
    operation_id="complete_temporary_password_reset",
)
async def complete_temporary_password_reset(
    body: PasswordResetCompletionRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[PasswordMutationData]:
    response.headers["Cache-Control"] = "no-store"
    changed = await service.complete_password_reset(
        abuse_flow=_identity_abuse_flow(request, settings),
        client_ip=trusted_client_ip(request.scope),
        user_name=body.user_name,
        temporary_password=body.temporary_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
        request_id=request_id_for(request),
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message="密码设置成功，请重新登录",
        data=PasswordMutationData(changed=changed),
    )
