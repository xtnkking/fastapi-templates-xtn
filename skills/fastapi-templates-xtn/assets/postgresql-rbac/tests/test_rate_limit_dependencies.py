import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

import app.rate_limit_dependencies as dependency_module
from app.api_contract import BusinessCode
from app.rate_limit import RateLimitResult, RateLimitUnavailable
from app.rate_limit_dependencies import (
    RateLimitExceeded,
    actor_policy_for,
    enforce_principal_rate_limit,
)
from app.rbac.domain import Principal
from app.rbac.errors import RbacError
from app.settings import Settings, get_settings


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
        ("POST", "force_logout_user", 60),
        ("POST", "logout_current_access_token", 120),
        ("POST", "create_invoice", 120),
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
    assert key.startswith(
        f"rl:v2:{{{settings.rate_limit_namespace}}}:get_my_access:actor:"
    )
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


@pytest.mark.asyncio
async def test_captcha_private_scenes_do_not_share_generic_write_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock()
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(method="POST", operation_id="create_authenticated_captcha")
    await enforce_principal_rate_limit(request, principal(), enabled_settings())
    check.assert_not_awaited()
