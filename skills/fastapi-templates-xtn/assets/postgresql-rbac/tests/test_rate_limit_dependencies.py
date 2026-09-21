import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.routing import APIRoute
from starlette.requests import Request

import app.dependencies.rate_limit as dependency_module
from app.api.access import router as access_router
from app.api.authentication import authentication_routers
from app.core.api_contract import BusinessCode
from app.core.config import Settings, get_settings
from app.core.errors import RbacError
from app.core.security.domain import Principal
from app.core.security.rate_limit import (
    RateLimitExceeded,
    RateLimitResult,
    RateLimitUnavailable,
)
from app.dependencies.rate_limit import (
    AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS,
    AUTHENTICATED_RATE_LIMIT_RULES,
    actor_policy_for,
    enforce_principal_rate_limit,
    precheck_principal_rate_limit,
)


def enabled_settings() -> Settings:
    return get_settings().model_copy(update={"rate_limit_enabled": True})


def principal() -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


def request_for(
    *,
    method: str,
    operation_id: str,
    rate_limit_redis: object | None = None,
) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=rate_limit_redis))
    return Request(
        {
            "type": "http",
            "method": method,
            "headers": [],
            "app": app,
            "route": SimpleNamespace(operation_id=operation_id),
        }
    )


def json_request_for(
    *,
    operation_id: str,
    payload: object,
    content_type: str = "application/json",
) -> Request:
    body = json.dumps(payload).encode("utf-8")
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    app = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=object()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", content_type.encode("ascii"))],
            "app": app,
            "route": SimpleNamespace(operation_id=operation_id),
        },
        receive,
    )


@pytest.mark.parametrize(
    ("method", "operation_id", "limit"),
    [
        ("GET", "list_roles", 300),
        ("GET", "get_permission", 300),
        ("GET", "get_my_access", 600),
        ("POST", "create_role", 60),
        ("POST", "reset_user_password", 60),
        ("POST", "create_user", 60),
        ("POST", "update_registration_policy", 60),
        ("POST", "revoke_user_sessions", 60),
        ("POST", "logout_current_access_token", 120),
        ("POST", "change_my_password", 120),
    ],
)
def test_each_operation_gets_its_own_key_and_class_quota(
    method: str,
    operation_id: str,
    limit: int,
) -> None:
    policy = actor_policy_for(
        request_for(method=method, operation_id=operation_id),
        enabled_settings(),
    )
    assert policy.name == operation_id
    assert policy.limit == limit
    assert policy.window_seconds == 60


def test_registered_session_revocation_route_uses_authorization_write_quota() -> None:
    route = next(
        route
        for route in access_router.routes
        if getattr(route, "path", None) == "/api/v1/users/{user_id}/sessions/revoke"
        and "POST" in (getattr(route, "methods", None) or set())
    )
    application = SimpleNamespace(state=SimpleNamespace())
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [],
            "app": application,
            "route": route,
        }
    )

    policy = actor_policy_for(request, enabled_settings())

    assert policy.name == "revoke_user_sessions"
    assert policy.limit == 60
    assert policy.window_seconds == 60


def test_every_registered_operation_has_an_explicit_admission_class() -> None:
    anonymous_operation_ids = {
        "create_public_captcha",
        "read_registration_status",
        "register_local_account",
        "login_with_local_password",
        "complete_temporary_password_reset",
    }
    registered: dict[str, tuple[str, str]] = {}
    for current_router in (*authentication_routers(), access_router):
        for route in current_router.routes:
            if not isinstance(route, APIRoute) or route.operation_id is None:
                continue
            methods = route.methods or set()
            assert len(methods) == 1
            method = next(iter(methods))
            assert route.operation_id not in registered
            registered[route.operation_id] = (method, route.path)

    classified = set(AUTHENTICATED_RATE_LIMIT_RULES)
    exempt = set(AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS)
    assert classified.isdisjoint(exempt)
    assert set(registered) == anonymous_operation_ids | classified | exempt
    for operation_id, (
        expected_method,
        _quota_name,
    ) in AUTHENTICATED_RATE_LIMIT_RULES.items():
        assert registered[operation_id][0] == expected_method
    for (
        operation_id,
        expected_method,
    ) in AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS.items():
        assert registered[operation_id][0] == expected_method


@pytest.mark.asyncio
async def test_allowed_actor_check_hides_user_id_in_redis_key() -> None:
    actor = principal()
    settings = enabled_settings()
    redis_mock = AsyncMock()
    redis_mock.eval.return_value = [1, 60000]
    request = request_for(
        method="GET",
        operation_id="get_my_access",
        rate_limit_redis=redis_mock,
    )
    await enforce_principal_rate_limit(request, actor, settings)
    key = redis_mock.eval.await_args.args[2]
    assert key.startswith(f"rl:v2:{settings.rate_limit_namespace}:get_my_access:actor:")
    assert str(actor.user_id) not in key
    assert request.state.actor_rate_limit_result.remaining == 599


@pytest.mark.asyncio
async def test_denied_actor_check_raises_rate_limit_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denied = RateLimitResult(False, 60, 0, 750, 750)
    check = AsyncMock(return_value=denied)
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(
        method="POST",
        operation_id="bind_role_permissions",
        rate_limit_redis=object(),
    )
    with pytest.raises(RateLimitExceeded) as caught:
        await enforce_principal_rate_limit(request, principal(), enabled_settings())
    assert caught.value.policy_name == "bind_role_permissions"
    assert caught.value.result is denied


@pytest.mark.asyncio
async def test_exhausted_precheck_does_not_increment_the_actor_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denied = RateLimitResult(False, 60, 0, 750, 750)
    inspect = AsyncMock(return_value=denied)
    increment = AsyncMock()
    monkeypatch.setattr(dependency_module, "inspect_bucket", inspect)
    monkeypatch.setattr(dependency_module, "check_bucket", increment)
    request = request_for(
        method="POST",
        operation_id="bind_role_permissions",
        rate_limit_redis=object(),
    )

    with pytest.raises(RateLimitExceeded) as caught:
        await precheck_principal_rate_limit(request, principal(), enabled_settings())

    assert caught.value.result is denied
    inspect.assert_awaited_once()
    increment.assert_not_awaited()


@pytest.mark.asyncio
async def test_open_precheck_does_not_charge_the_actor_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = RateLimitResult(True, 60, 60, 0, 0)
    inspect = AsyncMock(return_value=allowed)
    increment = AsyncMock()
    monkeypatch.setattr(dependency_module, "inspect_bucket", inspect)
    monkeypatch.setattr(dependency_module, "check_bucket", increment)
    request = request_for(
        method="POST",
        operation_id="bind_role_permissions",
        rate_limit_redis=object(),
    )

    await precheck_principal_rate_limit(request, principal(), enabled_settings())

    inspect.assert_awaited_once()
    increment.assert_not_awaited()


@pytest.mark.parametrize(
    ("payload", "expected_policy"),
    [
        ({"scene": "admin_create"}, "captcha_create_admin_create"),
        ({"scene": "admin_reset"}, "captcha_create_admin_reset"),
        ({"scene": "self_change"}, "captcha_create_self_change"),
        ({"scene": "login"}, "captcha_rejected_scene"),
        ({"scene": "register"}, "captcha_rejected_scene"),
        ({"scene": "unknown"}, "captcha_rejected_scene"),
        ({}, "captcha_rejected_scene"),
        (
            {"scene": "admin_reset", "previous_captcha_id": "not-a-uuid"},
            "captcha_rejected_scene",
        ),
    ],
)
@pytest.mark.asyncio
async def test_authenticated_captcha_precheck_inspects_its_exact_window(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    expected_policy: str,
) -> None:
    inspect = AsyncMock(return_value=RateLimitResult(True, 10, 10, 0, 0))
    increment = AsyncMock()
    monkeypatch.setattr(dependency_module, "inspect_bucket", inspect)
    monkeypatch.setattr(dependency_module, "check_bucket", increment)
    request = json_request_for(
        operation_id="create_authenticated_captcha",
        payload=payload,
    )

    await precheck_principal_rate_limit(request, principal(), enabled_settings())

    inspect_call = inspect.await_args
    assert inspect_call is not None
    policy = inspect_call.kwargs["policy"]
    assert policy.name == expected_policy
    assert policy.limit == 10
    assert policy.window_seconds == 300
    increment.assert_not_awaited()


@pytest.mark.asyncio
async def test_authenticated_captcha_precheck_rejects_json_body_sent_as_text_plain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect = AsyncMock(return_value=RateLimitResult(True, 10, 10, 0, 0))
    monkeypatch.setattr(dependency_module, "inspect_bucket", inspect)
    request = json_request_for(
        operation_id="create_authenticated_captcha",
        payload={"scene": "admin_reset"},
        content_type="text/plain",
    )

    await precheck_principal_rate_limit(request, principal(), enabled_settings())

    inspect_call = inspect.await_args
    assert inspect_call is not None
    assert inspect_call.kwargs["policy"].name == "captcha_rejected_scene"


@pytest.mark.asyncio
async def test_authenticated_captcha_precheck_accepts_vendor_json_media_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect = AsyncMock(return_value=RateLimitResult(True, 10, 10, 0, 0))
    monkeypatch.setattr(dependency_module, "inspect_bucket", inspect)
    request = json_request_for(
        operation_id="create_authenticated_captcha",
        payload={"scene": "admin_reset"},
        content_type="application/vnd.xtn+json; charset=utf-8",
    )

    await precheck_principal_rate_limit(request, principal(), enabled_settings())

    inspect_call = inspect.await_args
    assert inspect_call is not None
    assert inspect_call.kwargs["policy"].name == "captcha_create_admin_reset"


@pytest.mark.asyncio
async def test_rate_limit_store_failure_fails_closed_as_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock(side_effect=RateLimitUnavailable("private Redis endpoint"))
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(
        method="POST",
        operation_id="bind_role_permissions",
        rate_limit_redis=object(),
    )
    with pytest.raises(RbacError) as caught:
        await enforce_principal_rate_limit(request, principal(), enabled_settings())
    assert caught.value.status_code == 503
    assert caught.value.business_code == BusinessCode.SERVICE_UNAVAILABLE
    assert "private Redis endpoint" not in str(caught.value)


@pytest.mark.asyncio
async def test_missing_operation_id_fails_closed() -> None:
    request = request_for(method="POST", operation_id="", rate_limit_redis=object())
    with pytest.raises(RbacError) as caught:
        await enforce_principal_rate_limit(request, principal(), enabled_settings())
    assert caught.value.status_code == 503


def test_unknown_or_renamed_operation_does_not_fall_back_to_ordinary_write() -> None:
    request = request_for(method="POST", operation_id="renamed_operation")

    with pytest.raises(RateLimitUnavailable):
        actor_policy_for(request, enabled_settings())


@pytest.mark.asyncio
async def test_captcha_private_scenes_do_not_share_generic_write_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock()
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(method="POST", operation_id="create_authenticated_captcha")
    await enforce_principal_rate_limit(request, principal(), enabled_settings())
    check.assert_not_awaited()
