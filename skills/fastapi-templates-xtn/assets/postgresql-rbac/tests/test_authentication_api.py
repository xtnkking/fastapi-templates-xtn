import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.authentication_api as authentication_api
from app.api_contract import BusinessCode
from app.authentication_service import (
    AuthenticatedPasswordUser,
    get_local_authentication_service,
)
from app.main import app
from app.rbac.dependencies import get_authorization_context
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)

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
        delegable_permissions=frozenset(),
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


def _authentication_app(*, public_registration_enabled: bool) -> FastAPI:
    isolated_app = FastAPI()
    for selected_router in authentication_api.authentication_routers(
        public_registration_enabled=public_registration_enabled
    ):
        isolated_app.include_router(selected_router)
    return isolated_app


async def test_public_registration_route_is_not_registered_when_disabled() -> None:
    isolated_app = _authentication_app(public_registration_enabled=False)

    async with AsyncClient(
        transport=ASGITransport(app=isolated_app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/auth/register", json={})

    assert response.status_code == 404
    assert "/api/v1/auth/register" not in isolated_app.openapi()["paths"]


async def test_public_registration_route_is_registered_only_when_enabled() -> None:
    isolated_app = _authentication_app(public_registration_enabled=True)

    async with AsyncClient(
        transport=ASGITransport(app=isolated_app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/auth/register", json={})

    assert response.status_code == 422
    assert set(isolated_app.openapi()["paths"]["/api/v1/auth/register"]) == {"post"}


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
                json={"user_name": "  Alice  ", "password": VALID_PASSWORD},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 201
    assert body["code"] == int(BusinessCode.CREATED)
    assert body["data"] == {"user_id": str(user_id)}
    assert response.headers["Cache-Control"] == "no-store"
    _assert_envelope(response.status_code, body)
    assert service.register.await_args.kwargs["user_name"] == "alice"
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
                json={"user_name": "Alice", "password": VALID_PASSWORD},
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
                json={"user_name": "alice", "password": VALID_PASSWORD},
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
                    "current_password": VALID_PASSWORD,
                    "temporary_password": NEW_PASSWORD,
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
    assert service.complete_password_reset.await_args.kwargs["user_name"] == "alice"


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
    }
    for path in paths:
        assert set(schema["paths"][path]) == {"post"}
        operation = schema["paths"][path]["post"]
        assert "rbac" not in str(operation).casefold()
        for response in operation["responses"].values():
            assert "X-Request-ID" in response["headers"]
