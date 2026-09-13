import uuid
from unittest.mock import AsyncMock, Mock

import pytest
from httpx import ASGITransport, AsyncClient, Response
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

import app.rate_limit_middleware as middleware_module
from app.api_contract import BusinessCode
from app.rate_limit import (
    RateLimitBatchDecision,
    RateLimitCheck,
    RateLimitResult,
    RateLimitUnavailable,
)
from app.rate_limit_middleware import ApiRateLimitMiddleware
from app.settings import Settings, get_settings


def enabled_settings() -> Settings:
    return get_settings().model_copy(update={"rate_limit_enabled": True})


def result(
    *,
    allowed: bool,
    limit: int,
    remaining: int,
    retry_after_ms: int = 0,
    reset_after_ms: int = 1_000,
) -> RateLimitResult:
    return RateLimitResult(
        allowed=allowed,
        limit=limit,
        remaining=remaining,
        retry_after_ms=retry_after_ms,
        reset_after_ms=reset_after_ms,
    )


def decision(*results: RateLimitResult) -> RateLimitBatchDecision:
    return RateLimitBatchDecision(
        allowed=all(item.allowed for item in results),
        results=results,
        retry_after_ms=max((item.retry_after_ms for item in results), default=0),
    )


def build_test_app(downstream: AsyncMock) -> Starlette:
    async def endpoint(_: Request) -> JSONResponse:
        await downstream()
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[
            Route("/api/items", endpoint, methods=["GET", "OPTIONS"]),
            Route("/health/live", endpoint, methods=["GET"]),
        ]
    )
    app.state.rate_limit_redis = object()
    app.add_middleware(ApiRateLimitMiddleware)
    return app


def assert_standard_error(response: Response, code: BusinessCode) -> None:
    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(code)
    assert body["data"] is None
    request_id = uuid.UUID(body["request_id"])
    assert request_id.version == 4
    assert response.headers["X-Request-ID"] == body["request_id"]


async def test_uses_scope_client_and_ignores_spoofed_forwarding_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream = AsyncMock()
    check = AsyncMock(
        return_value=decision(
            result(allowed=True, limit=1_000, remaining=999),
            result(allowed=True, limit=200, remaining=199),
        )
    )
    monkeypatch.setattr(middleware_module, "get_settings", enabled_settings)
    monkeypatch.setattr(middleware_module, "check_rate_limits", check)
    transport = ASGITransport(
        app=build_test_app(downstream),
        client=("203.0.113.42", 49152),
    )

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/items",
            headers={
                "X-Forwarded-For": "198.51.100.8, 198.51.100.9",
                "X-Real-IP": "192.0.2.10",
                "Forwarded": "for=192.0.2.11",
            },
        )

    assert response.status_code == 200
    downstream.assert_awaited_once()
    check.assert_awaited_once()
    awaited = check.await_args
    assert awaited is not None
    checks = awaited.kwargs["checks"]
    assert isinstance(checks, tuple)
    assert all(isinstance(item, RateLimitCheck) for item in checks)
    assert [(item.subject_type, item.subject) for item in checks] == [
        ("global", "all"),
        ("ip", "203.0.113.42"),
    ]
    assert "198.51.100.8" not in repr(awaited)
    assert "192.0.2.10" not in repr(awaited)
    assert "192.0.2.11" not in repr(awaited)


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/health/live"), ("OPTIONS", "/api/items")],
)
async def test_health_and_options_skip_rate_limiting(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
) -> None:
    downstream = AsyncMock()
    settings_lookup = Mock(side_effect=AssertionError("settings must not be loaded"))
    check = AsyncMock()
    monkeypatch.setattr(middleware_module, "get_settings", settings_lookup)
    monkeypatch.setattr(middleware_module, "check_rate_limits", check)
    transport = ASGITransport(app=build_test_app(downstream))

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.request(method, path)

    assert response.status_code == 200
    downstream.assert_awaited_once()
    settings_lookup.assert_not_called()
    check.assert_not_awaited()


async def test_denial_returns_standard_429_without_calling_downstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream = AsyncMock()
    denied = result(
        allowed=False,
        limit=1_000,
        remaining=0,
        retry_after_ms=1_001,
        reset_after_ms=2_001,
    )
    allowed_ip = result(allowed=True, limit=200, remaining=199)
    check = AsyncMock(return_value=decision(denied, allowed_ip))
    monkeypatch.setattr(middleware_module, "get_settings", enabled_settings)
    monkeypatch.setattr(middleware_module, "check_rate_limits", check)
    transport = ASGITransport(app=build_test_app(downstream))

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/items")

    assert response.status_code == 429
    assert_standard_error(response, BusinessCode.RATE_LIMITED)
    assert response.headers["Retry-After"] == "2"
    assert response.headers["RateLimit-Limit"] == "1000"
    assert response.headers["RateLimit-Remaining"] == "0"
    assert response.headers["RateLimit-Reset"] == "3"
    assert response.headers["Cache-Control"] == "no-store"
    check.assert_awaited_once()
    downstream.assert_not_awaited()


async def test_redis_failure_returns_503_without_calling_downstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream = AsyncMock()
    check = AsyncMock(
        side_effect=RateLimitUnavailable("private Redis endpoint is unavailable")
    )
    monkeypatch.setattr(middleware_module, "get_settings", enabled_settings)
    monkeypatch.setattr(middleware_module, "check_rate_limits", check)
    transport = ASGITransport(app=build_test_app(downstream))

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/items")

    assert response.status_code == 503
    assert_standard_error(response, BusinessCode.SERVICE_UNAVAILABLE)
    assert response.headers["Cache-Control"] == "no-store"
    assert "Retry-After" not in response.headers
    assert "private Redis endpoint" not in response.text
    check.assert_awaited_once()
    downstream.assert_not_awaited()


async def test_allowed_response_includes_deciding_bucket_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream = AsyncMock()
    global_result = result(allowed=True, limit=1_000, remaining=995)
    ip_result = result(
        allowed=True,
        limit=200,
        remaining=173,
        reset_after_ms=1_001,
    )
    check = AsyncMock(return_value=decision(global_result, ip_result))
    monkeypatch.setattr(middleware_module, "get_settings", enabled_settings)
    monkeypatch.setattr(middleware_module, "check_rate_limits", check)
    transport = ASGITransport(app=build_test_app(downstream))

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/items")

    assert response.status_code == 200
    assert response.headers["RateLimit-Limit"] == "200"
    assert response.headers["RateLimit-Remaining"] == "173"
    assert response.headers["RateLimit-Reset"] == "2"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Retry-After" not in response.headers
    downstream.assert_awaited_once()
