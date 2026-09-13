import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.authentication_api as authentication_api
from app.abuse_defense import AbuseDefenseService
from app.api_contract import BusinessCode
from app.authentication_service import (
    AuthenticatedPasswordUser,
    get_local_authentication_service,
)
from app.captcha import CaptchaService
from app.main import app
from app.rate_limit import RateLimitResult
from app.rate_limit_dependencies import RateLimitExceeded
from app.rbac.dependencies import get_authorization_context, get_current_principal
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)
from app.settings import get_settings

VALID_PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "new correct horse battery staple"


def _context(*, password_reset: bool = False) -> AuthorizationContext:
    user_id = uuid.uuid4()
    permissions = (
        frozenset({PermissionKey.USERS_PASSWORD_RESET.value})
        if password_reset
        else frozenset()
    )
    role = RoleGrant(
        role_id=uuid.uuid4(),
        key="test-actor",
        management_tier=500 if password_reset else 0,
        permissions=permissions,
        is_system=False,
        is_protected=False,
        is_super_admin=False,
    )
    return AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_version=4,
            token_id=uuid.uuid4(),
            issued_at=1,
            expires_at=2,
        ),
        authorization_epoch=3,
        authority=AuthoritySnapshot.build(
            user_id=user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=4,
            authz_version=2,
            roles=(role,),
        ),
        request_id=str(uuid.uuid4()),
    )


def _assert_envelope(response_status: int, body: dict[str, object]) -> None:
    assert body.keys() == {"code", "message", "data", "request_id"}
    code = body["code"]
    assert isinstance(code, int) and not isinstance(code, bool)
    assert code // 1000 == response_status
    request_id = uuid.UUID(str(body["request_id"]))
    assert request_id.version == 4


@pytest.fixture(autouse=True)
def fake_captcha(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authentication_api, "_consume_captcha", AsyncMock())


CAPTCHA = {"captcha_id": str(uuid.uuid4()), "captcha_answer": "AB234"}


def _authentication_app() -> FastAPI:
    isolated_app = FastAPI()
    for selected_router in authentication_api.authentication_routers():
        isolated_app.include_router(selected_router)
    return isolated_app


async def test_public_registration_route_remains_present_for_runtime_switch() -> None:
    isolated_app = _authentication_app()

    async with AsyncClient(
        transport=ASGITransport(app=isolated_app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/auth/register", json={})

    assert response.status_code == 422
    assert set(isolated_app.openapi()["paths"]["/api/v1/auth/register"]) == {"post"}


async def test_captcha_is_required_before_public_registration_calls_service() -> None:
    service = AsyncMock()
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/register",
                json={"user_name": "Alice", "password": VALID_PASSWORD},
            )
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 422
    service.register.assert_not_awaited()


async def test_registration_status_public_read_exposes_only_boolean() -> None:
    service = AsyncMock()
    service.registration_enabled.return_value = False
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.get("/api/v1/auth/registration/status")
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 200
    assert result.json()["data"] == {"registration_enabled": False}
    assert result.headers["Cache-Control"] == "no-store"


async def test_three_authenticated_captcha_scenes_are_separately_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context()
    quota_check = AsyncMock()
    issue = AsyncMock(return_value=(uuid.uuid4(), "data:image/png;base64,AA=="))
    monkeypatch.setattr(authentication_api, "get_redis", lambda _request: object())
    monkeypatch.setattr(
        authentication_api, "get_rate_limit_redis", lambda _request: object()
    )
    monkeypatch.setattr(CaptchaService, "issue", issue)
    monkeypatch.setattr(AbuseDefenseService, "check_captcha_create", quota_check)

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_current_principal] = lambda: context.principal
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            for scene in ("admin_create", "admin_reset", "self_change"):
                response = await client.post(
                    "/api/v1/me/captcha", json={"scene": scene}
                )
                assert response.status_code == 200, response.text
    finally:
        app.dependency_overrides.clear()
    assert [call.kwargs["scene"] for call in quota_check.await_args_list] == [
        "admin_create",
        "admin_reset",
        "self_change",
    ]
    assert all(
        call.kwargs["user_id"] == str(context.principal.user_id)
        for call in quota_check.await_args_list
    )
    assert all(
        call.kwargs["owner_id"] == context.principal.user_id
        for call in issue.await_args_list
    )


async def test_wrong_captcha_endpoint_is_metered_without_creating_an_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context()
    check = AsyncMock()
    issue = AsyncMock()
    monkeypatch.setattr(authentication_api, "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(AbuseDefenseService, "check_rejected_captcha_scene", check)
    monkeypatch.setattr(CaptchaService, "issue", issue)
    app.dependency_overrides[get_authorization_context] = lambda: context
    app.dependency_overrides[get_current_principal] = lambda: context.principal
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            public = await client.post(
                "/api/v1/auth/captcha", json={"scene": "admin_reset"}
            )
            private = await client.post("/api/v1/me/captcha", json={"scene": "login"})
    finally:
        app.dependency_overrides.clear()
    assert public.status_code == 400
    assert private.status_code == 400
    assert check.await_count == 2
    assert check.await_args_list[0].kwargs == {
        "user_id": None,
        "client_ip": "127.0.0.1",
    }
    assert check.await_args_list[1].kwargs == {
        "user_id": str(context.principal.user_id),
        "client_ip": None,
    }
    issue.assert_not_awaited()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"scene": "unknown"},
        {"scene": "admin_reset", "previous_captcha_id": "not-a-uuid"},
    ],
)
async def test_invalid_private_captcha_body_is_metered_and_then_checks_authority(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, str]
) -> None:
    context = _context()
    check = AsyncMock()
    authority_lookup = AsyncMock(return_value=context)
    issue = AsyncMock()

    async def current_context() -> AuthorizationContext:
        await authority_lookup()
        return context

    monkeypatch.setattr(authentication_api, "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(AbuseDefenseService, "check_rejected_captcha_scene", check)
    monkeypatch.setattr(CaptchaService, "issue", issue)
    app.dependency_overrides[get_current_principal] = lambda: context.principal
    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/me/captcha", json=payload)
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert response.json()["code"] == int(BusinessCode.VALIDATION_FAILED)
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    check.assert_awaited_once_with(
        user_id=str(context.principal.user_id), client_ip=None
    )
    authority_lookup.assert_awaited_once()
    issue.assert_not_awaited()


async def test_invalid_private_captcha_body_over_quota_returns_429_before_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context()
    denied = RateLimitExceeded(
        "captcha_rejected_scene", RateLimitResult(False, 10, 0, 2100, 2100)
    )
    check = AsyncMock(side_effect=denied)
    authority_lookup = AsyncMock(side_effect=AssertionError("authority was loaded"))

    async def current_context() -> AuthorizationContext:
        await authority_lookup()
        return context

    monkeypatch.setattr(authentication_api, "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(AbuseDefenseService, "check_rejected_captcha_scene", check)
    app.dependency_overrides[get_current_principal] = lambda: context.principal
    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/me/captcha", json={"scene": "nope"})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 429
    assert response.json()["code"] == int(BusinessCode.RATE_LIMITED)
    assert response.headers["Retry-After"] == "3"
    check.assert_awaited_once()
    authority_lookup.assert_not_awaited()


async def test_invalid_public_captcha_body_is_metered_by_trusted_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock()
    issue = AsyncMock()
    monkeypatch.setattr(authentication_api, "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(AbuseDefenseService, "check_rejected_captcha_scene", check)
    monkeypatch.setattr(CaptchaService, "issue", issue)
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/auth/captcha", json={})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    check.assert_awaited_once_with(user_id=None, client_ip="127.0.0.1")
    issue.assert_not_awaited()


async def test_wrong_captcha_endpoint_over_quota_returns_429(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denied = RateLimitExceeded(
        "captcha_rejected_scene", RateLimitResult(False, 10, 0, 2100, 2100)
    )
    check = AsyncMock(side_effect=denied)
    issue = AsyncMock()
    monkeypatch.setattr(authentication_api, "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(AbuseDefenseService, "check_rejected_captcha_scene", check)
    monkeypatch.setattr(CaptchaService, "issue", issue)
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"rate_limit_enabled": True}
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/captcha", json={"scene": "admin_reset"}
            )
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 429
    assert result.json()["code"] == int(BusinessCode.RATE_LIMITED)
    assert result.headers["Retry-After"] == "3"
    assert result.headers["Cache-Control"] == "no-store"
    assert result.json()["request_id"] == result.headers["X-Request-ID"]
    check.assert_awaited_once()
    issue.assert_not_awaited()


async def test_registration_normalizes_username_and_returns_only_user_id() -> None:
    user_id = uuid.uuid4()
    service = AsyncMock()
    service.register.return_value = user_id
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={"user_name": "  Alice  ", "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 201
    assert body["code"] == int(BusinessCode.CREATED)
    assert body["data"] == {"user_id": str(user_id)}
    assert response.headers["Cache-Control"] == "no-store"
    _assert_envelope(response.status_code, body)
    assert service.register.await_args.kwargs["user_name"] == "Alice"
    assert service.register.await_args.kwargs["password"] == VALID_PASSWORD


async def test_login_issues_access_token_only_after_password_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = AuthenticatedPasswordUser(
        user_id=uuid.uuid4(),
        token_version=8,
        must_change_password=False,
    )
    service = AsyncMock()
    service.authenticate.return_value = identity
    issue_token = AsyncMock(return_value="signed-access-token")
    monkeypatch.setattr(authentication_api, "issue_access_token", issue_token)
    monkeypatch.setattr(authentication_api, "get_redis", lambda _request: object())
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={"user_name": "Alice", "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 200
    assert body["data"] == {
        "access_token": "signed-access-token",
        "token_type": "bearer",
        "expires_in": 3600,
        "password_change_required": False,
    }
    assert response.headers["Cache-Control"] == "no-store"
    issue_token.assert_awaited_once()
    assert service.authenticate.await_count == 1


async def test_temporary_password_login_returns_403002_without_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = AsyncMock()
    service.authenticate.return_value = AuthenticatedPasswordUser(
        user_id=uuid.uuid4(),
        token_version=8,
        must_change_password=True,
    )
    issue_token = AsyncMock(return_value="must-not-be-issued")
    monkeypatch.setattr(authentication_api, "issue_access_token", issue_token)
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={"user_name": "alice", "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 403
    assert body["code"] == int(BusinessCode.PASSWORD_CHANGE_REQUIRED)
    assert body["data"] is None
    assert "token" not in response.text.casefold()
    assert response.headers["Cache-Control"] == "no-store"
    issue_token.assert_not_awaited()


async def test_self_change_reauthenticates_and_returns_relogin_message() -> None:
    context = _context()
    service = AsyncMock()
    service.change_password.return_value = True

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/me/password/change",
                json={
                    "current_password": VALID_PASSWORD,
                    "new_password": NEW_PASSWORD,
                    **CAPTCHA,
                },
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 200
    assert body["data"] == {"changed": True}
    assert "重新登录" in body["message"]
    assert service.change_password.await_args.kwargs["context"] is context
    assert (
        service.change_password.await_args.kwargs["current_password"] == VALID_PASSWORD
    )


async def test_admin_reset_and_temporary_completion_are_separate_commands() -> None:
    context = _context(password_reset=True)
    target_id = uuid.uuid4()
    service = AsyncMock()
    service.reset_user_password.return_value = True
    service.complete_password_reset.return_value = True

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_local_authentication_service] = lambda: service
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            reset = await client.post(
                f"/api/v1/users/{target_id}/password/reset",
                json={
                    "temporary_password": NEW_PASSWORD,
                    **CAPTCHA,
                },
            )
            complete = await client.post(
                "/api/v1/auth/password/reset/complete",
                json={
                    "user_name": "Alice",
                    "temporary_password": NEW_PASSWORD,
                    "new_password": "final correct horse battery staple",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert reset.status_code == 200
    assert reset.json()["data"] == {"changed": True}
    assert complete.status_code == 200
    assert complete.json()["data"] == {"changed": True}
    assert "access_token" not in complete.text
    assert service.reset_user_password.await_args.kwargs["target_user_id"] == target_id
    assert service.complete_password_reset.await_args.kwargs["user_name"] == "Alice"


async def test_password_requests_reject_unknown_fields_without_echoing_secrets() -> (
    None
):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "alice",
                "password": VALID_PASSWORD,
                "role": "super_admin",
                **CAPTCHA,
            },
        )

    body = response.json()
    assert response.status_code == 422
    assert body["code"] == int(BusinessCode.VALIDATION_FAILED)
    assert VALID_PASSWORD not in response.text


def test_password_routes_are_post_only_and_do_not_expose_the_mechanism() -> None:
    schema = app.openapi()
    paths = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/me/password/change",
        "/api/v1/users/{user_id}/password/reset",
        "/api/v1/auth/password/reset/complete",
        "/api/v1/auth/captcha",
        "/api/v1/me/captcha",
        "/api/v1/auth/registration/status",
        "/api/v1/users",
    }
    for path in paths:
        assert "post" in schema["paths"][path]
        operation = schema["paths"][path]["post"]
        assert "rbac" not in str(operation).casefold()
        for response in operation["responses"].values():
            assert "X-Request-ID" in response["headers"]
