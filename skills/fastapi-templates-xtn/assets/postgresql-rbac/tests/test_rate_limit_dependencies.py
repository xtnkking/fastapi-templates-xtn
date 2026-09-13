import uuid
from types import SimpleNamespace
from typing import cast
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
    ("method", "operation_id", "expected_policy"),
    [
        ("GET", "list_roles", "management_read"),
        ("GET", "get_permission", "management_read"),
        ("GET", "get_my_access", "authenticated_read"),
        ("POST", "create_role", "authorization_write"),
        ("POST", "update_role", "authorization_write"),
        ("POST", "disable_role", "authorization_write"),
        ("POST", "enable_role", "authorization_write"),
        ("POST", "delete_role", "authorization_write"),
        ("POST", "bind_role_permissions", "authorization_write"),
        ("POST", "unbind_role_permissions", "authorization_write"),
        ("POST", "bind_role_delegable_permissions", "authorization_write"),
        ("POST", "unbind_role_delegable_permissions", "authorization_write"),
        ("POST", "bind_user_roles", "authorization_write"),
        ("POST", "unbind_user_roles", "authorization_write"),
        ("POST", "disable_user", "authorization_write"),
        ("POST", "enable_user", "authorization_write"),
        ("POST", "reset_user_password", "authorization_write"),
        ("POST", "logout_all_access_tokens", "logout_all"),
        ("POST", "transfer_super_admin", "super_admin_transfer"),
        ("POST", "logout_current_access_token", None),
        ("POST", "create_invoice", "ordinary_write"),
        ("PUT", "replace_profile", "ordinary_write"),
    ],
)
def test_actor_policy_classifies_route_operations(
    method: str,
    operation_id: str,
    expected_policy: str | None,
) -> None:
    policy = actor_policy_for(
        request_for(method=method, operation_id=operation_id),
        enabled_settings(),
    )

    assert (None if policy is None else policy.name) == expected_policy


async def test_allowed_actor_check_hides_user_id_in_redis_key() -> None:
    actor = principal()
    settings = enabled_settings()
    redis_mock = AsyncMock()
    redis_mock.eval.return_value = [1, 0, 1, 299, 0, 1_000]
    request = request_for(
        method="GET",
        operation_id="get_my_access",
        rate_limit_redis=redis_mock,
    )

    await enforce_principal_rate_limit(request, actor, settings)

    redis_mock.eval.assert_awaited_once()
    awaited = redis_mock.eval.await_args
    assert awaited is not None
    redis_key = awaited.args[2]
    assert isinstance(redis_key, str)
    assert redis_key.startswith(
        f"rl:v1:{{{settings.rate_limit_namespace}}}:authenticated_read:actor:"
    )
    assert str(actor.user_id) not in redis_key
    stored_result = cast(RateLimitResult, request.state.actor_rate_limit_result)
    assert stored_result.allowed is True
    assert stored_result.remaining == 299


async def test_denied_actor_check_raises_rate_limit_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denied = RateLimitResult(
        allowed=False,
        limit=30,
        remaining=0,
        retry_after_ms=750,
        reset_after_ms=60_000,
    )
    check = AsyncMock(return_value=denied)
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(
        method="POST",
        operation_id="bind_role_permissions",
        rate_limit_redis=object(),
    )

    with pytest.raises(RateLimitExceeded) as caught:
        await enforce_principal_rate_limit(
            request,
            principal(),
            enabled_settings(),
        )

    assert caught.value.policy_name == "authorization_write"
    assert caught.value.result is denied
    assert getattr(request.state, "actor_rate_limit_result", None) is None
    check.assert_awaited_once()


async def test_rate_limit_store_failure_fails_closed_as_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock(
        side_effect=RateLimitUnavailable("private Redis endpoint is unavailable")
    )
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(
        method="POST",
        operation_id="transfer_super_admin",
        rate_limit_redis=object(),
    )

    with pytest.raises(RbacError) as caught:
        await enforce_principal_rate_limit(
            request,
            principal(),
            enabled_settings(),
        )

    assert caught.value.status_code == 503
    assert caught.value.business_code == BusinessCode.SERVICE_UNAVAILABLE
    assert caught.value.reason_code == "rate_limit_registry_unavailable"
    assert "private Redis endpoint" not in str(caught.value)
    assert getattr(request.state, "actor_rate_limit_result", None) is None
    check.assert_awaited_once()


async def test_current_token_logout_skips_actor_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = AsyncMock()
    monkeypatch.setattr(dependency_module, "check_bucket", check)
    request = request_for(
        method="POST",
        operation_id="logout_current_access_token",
    )

    await enforce_principal_rate_limit(request, principal(), enabled_settings())

    check.assert_not_awaited()
