import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.abuse_defense import AbuseDefenseService
from app.abuse_flow import IdentityAbuseFlow, build_identity_abuse_flow
from app.api_contract import (
    RATE_LIMIT_ERROR_RESPONSES,
    STANDARD_ERROR_RESPONSES,
    ApiResponse,
    BusinessCode,
    RequestIdRoute,
    api_response,
    request_id_for,
)
from app.authentication_schemas import (
    AccessTokenData,
    ActiveSessionsData,
    AdminPasswordResetRequest,
    AdminUserCreateRequest,
    CaptchaCreateRequest,
    CaptchaData,
    LoginRequest,
    PasswordChangeRequest,
    PasswordMutationData,
    PasswordResetCompletionRequest,
    RegistrationData,
    RegistrationRequest,
    RegistrationStatusData,
    RegistrationStatusUpdateRequest,
)
from app.authentication_service import (
    LocalAuthenticationService,
    get_local_authentication_service,
)
from app.captcha import CaptchaService
from app.captcha_request import parse_captcha_create_request
from app.i18n import MessageKey
from app.rate_limit_middleware import trusted_client_ip
from app.rbac.dependencies import (
    SettingsDependency,
    get_authorization_context,
    require_permissions,
)
from app.rbac.domain import AuthorizationContext, PermissionKey
from app.rbac.errors import invalid_request, password_change_required
from app.rbac.security import issue_access_token, list_active_sessions
from app.redis_client import get_rate_limit_redis, get_redis

router = APIRouter(
    prefix="/api/v1",
    responses={**STANDARD_ERROR_RESPONSES, **RATE_LIMIT_ERROR_RESPONSES},
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


def authentication_routers() -> tuple[APIRouter, ...]:
    """The server-side registration switch does not remove the public route."""
    return registration_router, router


def _identity_abuse_flow(
    request: Request,
    settings: SettingsDependency,
    *,
    post_admission_check: Callable[[], Awaitable[None]] | None = None,
) -> IdentityAbuseFlow | None:
    if not settings.rate_limit_enabled:
        return None
    return build_identity_abuse_flow(
        get_rate_limit_redis(request),
        settings=settings,
        post_admission_check=post_admission_check,
    )


async def _consume_captcha(
    request: Request,
    settings: SettingsDependency,
    *,
    captcha_id: uuid.UUID,
    answer: str,
    scene: str,
    owner_id: uuid.UUID | None = None,
) -> None:
    await CaptchaService(get_redis(request), settings).consume(
        captcha_id=captcha_id, answer=answer, scene=scene, owner_id=owner_id
    )


async def _issue_captcha(
    request: Request,
    settings: SettingsDependency,
    *,
    body: CaptchaCreateRequest,
    owner_id: uuid.UUID | None,
) -> ApiResponse[CaptchaData]:
    if settings.rate_limit_enabled:
        defense = AbuseDefenseService(get_rate_limit_redis(request), settings)
        await defense.check_captcha_create(
            scene=body.scene,
            user_id=str(owner_id) if owner_id else None,
            client_ip=trusted_client_ip(request.scope) if owner_id is None else None,
        )
    captcha_id, image_base64 = await CaptchaService(get_redis(request), settings).issue(
        scene=body.scene,
        owner_id=owner_id,
        previous_captcha_id=body.previous_captcha_id,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.AUTH_CAPTCHA_CREATED,
        data=CaptchaData(captcha_id=captcha_id, image_base64=image_base64),
    )


async def _admit_rejected_captcha_scene(
    request: Request,
    settings: SettingsDependency,
    *,
    owner_id: uuid.UUID | None,
) -> None:
    if not settings.rate_limit_enabled:
        return
    await AbuseDefenseService(
        get_rate_limit_redis(request), settings
    ).check_rejected_captcha_scene(
        user_id=str(owner_id) if owner_id is not None else None,
        client_ip=trusted_client_ip(request.scope) if owner_id is None else None,
    )


async def _precheck_captcha_body(
    request: Request,
    settings: SettingsDependency,
    *,
    owner_id: uuid.UUID | None,
) -> None:
    if await parse_captcha_create_request(request) is not None:
        return
    await _admit_rejected_captcha_scene(request, settings, owner_id=owner_id)


async def _precheck_public_captcha_body(
    request: Request, settings: SettingsDependency
) -> None:
    await _precheck_captcha_body(request, settings, owner_id=None)


async def _precheck_authenticated_captcha_body(
    request: Request,
    settings: SettingsDependency,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
) -> None:
    await _precheck_captcha_body(
        request,
        settings,
        owner_id=context.principal.user_id,
    )


@registration_router.post(
    "/auth/captcha",
    response_model=ApiResponse[CaptchaData],
    tags=[AUTHENTICATION_TAG],
    operation_id="create_public_captcha",
    dependencies=[Depends(_precheck_public_captcha_body)],
    responses=RATE_LIMIT_ERROR_RESPONSES,
)
async def create_public_captcha(
    body: CaptchaCreateRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
) -> ApiResponse[CaptchaData]:
    response.headers["Cache-Control"] = "no-store"
    if body.scene not in {"login", "register"}:
        await _admit_rejected_captcha_scene(request, settings, owner_id=None)
        raise invalid_request("captcha_scene_requires_authentication")
    return await _issue_captcha(request, settings, body=body, owner_id=None)


@router.post(
    "/me/captcha",
    response_model=ApiResponse[CaptchaData],
    tags=[ACCOUNT_SECURITY_TAG],
    operation_id="create_authenticated_captcha",
    dependencies=[Depends(_precheck_authenticated_captcha_body)],
)
async def create_authenticated_captcha(
    body: CaptchaCreateRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
) -> ApiResponse[CaptchaData]:
    response.headers["Cache-Control"] = "no-store"
    if body.scene not in {"admin_create", "admin_reset", "self_change"}:
        await _admit_rejected_captcha_scene(
            request, settings, owner_id=context.principal.user_id
        )
        raise invalid_request("captcha_scene_is_public")
    return await _issue_captcha(
        request, settings, body=body, owner_id=context.principal.user_id
    )


@registration_router.get(
    "/auth/registration/status",
    response_model=ApiResponse[RegistrationStatusData],
    tags=[AUTHENTICATION_TAG],
    operation_id="read_registration_status",
)
async def read_registration_status(
    request: Request,
    response: Response,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[RegistrationStatusData]:
    response.headers["Cache-Control"] = "no-store"
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_SUCCESS,
        data=RegistrationStatusData(
            registration_enabled=await service.registration_enabled()
        ),
    )


@router.post(
    "/auth/registration/status",
    response_model=ApiResponse[RegistrationStatusData],
    tags=[ACCOUNT_SECURITY_TAG],
    operation_id="update_registration_policy",
)
async def update_registration_status(
    body: RegistrationStatusUpdateRequest,
    request: Request,
    response: Response,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.REGISTRATION_CONFIGURE)),
    ],
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[RegistrationStatusData]:
    response.headers["Cache-Control"] = "no-store"
    enabled = await service.set_registration_enabled(
        context=context, enabled=body.registration_enabled
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.AUTH_REGISTRATION_SETTINGS_UPDATED,
        data=RegistrationStatusData(registration_enabled=enabled),
    )


@registration_router.post(
    "/auth/register",
    status_code=status.HTTP_201_CREATED,
    response_model=ApiResponse[RegistrationData],
    tags=[AUTHENTICATION_TAG],
    operation_id="register_local_account",
    responses=RATE_LIMIT_ERROR_RESPONSES,
)
async def register_local_account(
    body: RegistrationRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[RegistrationData]:
    response.headers["Cache-Control"] = "no-store"

    async def check_captcha() -> None:
        await _consume_captcha(
            request,
            settings,
            captcha_id=body.captcha_id,
            answer=body.captcha_answer,
            scene="register",
        )

    abuse_flow = _identity_abuse_flow(
        request,
        settings,
        post_admission_check=check_captcha,
    )
    if abuse_flow is None:
        await check_captcha()
    user_id = await service.register(
        abuse_flow=abuse_flow,
        client_ip=trusted_client_ip(request.scope),
        user_name=body.user_name,
        password=body.password.get_secret_value(),
        request_id=request_id_for(request),
    )
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.AUTH_REGISTRATION_SUCCEEDED,
        data=RegistrationData(user_id=user_id),
    )


@router.post(
    "/auth/login",
    response_model=ApiResponse[AccessTokenData],
    tags=[AUTHENTICATION_TAG],
    operation_id="login_with_local_password",
    responses=RATE_LIMIT_ERROR_RESPONSES,
)
async def login_with_local_password(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[AccessTokenData]:
    response.headers["Cache-Control"] = "no-store"

    async def check_captcha() -> None:
        await _consume_captcha(
            request,
            settings,
            captcha_id=body.captcha_id,
            answer=body.captcha_answer,
            scene="login",
        )

    abuse_flow = _identity_abuse_flow(
        request,
        settings,
        post_admission_check=check_captcha,
    )
    if abuse_flow is None:
        await check_captcha()
    identity = await service.authenticate(
        abuse_flow=abuse_flow,
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
        message_key=MessageKey.AUTH_LOGIN_SUCCEEDED,
        data=AccessTokenData(
            access_token=access_token,
            expires_in=settings.jwt_access_token_ttl_seconds,
        ),
    )


@router.get(
    "/me/sessions",
    response_model=ApiResponse[ActiveSessionsData],
    tags=[AUTHENTICATION_TAG],
    operation_id="my_active_sessions",
)
async def my_active_sessions(
    request: Request,
    response: Response,
    settings: SettingsDependency,
    context: Annotated[AuthorizationContext, Depends(get_authorization_context)],
) -> ApiResponse[ActiveSessionsData]:
    response.headers["Cache-Control"] = "no-store"
    timestamps = await list_active_sessions(
        get_redis(request),
        user_id=context.principal.user_id,
        token_version=context.principal.token_version,
        settings=settings,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.COMMON_SUCCESS,
        data=ActiveSessionsData(
            active_count=len(timestamps),
            login_times=tuple(
                datetime.fromtimestamp(value, UTC).isoformat() for value in timestamps
            ),
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
    await _consume_captcha(
        request,
        settings,
        captcha_id=body.captcha_id,
        answer=body.captcha_answer,
        scene="self_change",
        owner_id=context.principal.user_id,
    )
    changed = await service.change_password(
        context=context,
        current_password=body.current_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.AUTH_PASSWORD_CHANGED_RELOGIN,
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
    await _consume_captcha(
        request,
        settings,
        captcha_id=body.captcha_id,
        answer=body.captcha_answer,
        scene="admin_reset",
        owner_id=context.principal.user_id,
    )
    changed = await service.reset_user_password(
        context=context,
        target_user_id=user_id,
        new_password=body.new_password.get_secret_value(),
        reset_mode=settings.admin_password_reset_mode,
    )
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=(
            MessageKey.AUTH_TEMPORARY_PASSWORD_SET
            if settings.admin_password_reset_mode == "temporary"
            else MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED
        ),
        data=PasswordMutationData(changed=changed),
    )


@router.post(
    "/users",
    status_code=status.HTTP_201_CREATED,
    response_model=ApiResponse[RegistrationData],
    tags=[ACCOUNT_SECURITY_TAG],
    operation_id="create_user",
)
async def create_user_with_temporary_password(
    body: AdminUserCreateRequest,
    request: Request,
    response: Response,
    settings: SettingsDependency,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permissions(PermissionKey.USERS_CREATE)),
    ],
    service: LocalAuthenticationServiceDependency,
) -> ApiResponse[RegistrationData]:
    response.headers["Cache-Control"] = "no-store"
    await _consume_captcha(
        request,
        settings,
        captcha_id=body.captcha_id,
        answer=body.captcha_answer,
        scene="admin_create",
        owner_id=context.principal.user_id,
    )
    user_id = await service.create_user_by_administrator(
        context=context,
        user_name=body.user_name,
        temporary_password=body.temporary_password.get_secret_value(),
    )
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.AUTH_USER_CREATED,
        data=RegistrationData(user_id=user_id),
    )


@router.post(
    "/auth/password/reset/complete",
    response_model=ApiResponse[PasswordMutationData],
    tags=[AUTHENTICATION_TAG],
    operation_id="complete_temporary_password_reset",
    responses=RATE_LIMIT_ERROR_RESPONSES,
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
        message_key=MessageKey.AUTH_PASSWORD_SETUP_RELOGIN,
        data=PasswordMutationData(changed=changed),
    )
