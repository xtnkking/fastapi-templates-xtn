import ipaddress
import logging
import math
from collections.abc import Mapping
from typing import cast

from fastapi import Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api_contract import BusinessCode, error_content, request_id_headers
from app.observability import safe_exception_metadata, safe_log
from app.rate_limit import (
    RateLimitCheck,
    RateLimitPolicy,
    RateLimitResult,
    RateLimitUnavailable,
    check_rate_limits,
)
from app.security_policies import SecurityPolicies
from app.settings import get_settings

logger = logging.getLogger(__name__)


def trusted_client_ip(scope: Scope) -> str:
    """Use only the client address already trusted by the ASGI server."""
    client = scope.get("client")
    host = client[0] if isinstance(client, tuple) and client else ""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        # One conservative shared bucket is safer than trusting a spoofable header.
        return "unknown"


def rate_limit_headers(
    result: RateLimitResult,
    *,
    include_retry_after: bool,
) -> dict[str, str]:
    headers = {
        "RateLimit-Limit": str(result.limit),
        "RateLimit-Remaining": str(result.remaining),
        "RateLimit-Reset": str(math.ceil(result.reset_after_ms / 1000)),
        "Cache-Control": "no-store",
    }
    if include_retry_after:
        headers["Retry-After"] = str(max(1, math.ceil(result.retry_after_ms / 1000)))
    return headers


def semantic_rate_limit_headers(result: RateLimitResult) -> dict[str, str]:
    """Expose the deciding result without revealing its subject or policy name."""
    return rate_limit_headers(result, include_retry_after=True)


def _merge_response_headers(message: Message, headers: Mapping[str, str]) -> None:
    raw_headers = list(message.get("headers", []))
    present = {item[0].lower() for item in raw_headers}
    raw_headers.extend(
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in headers.items()
        if name.lower().encode("latin-1") not in present
    )
    message["headers"] = raw_headers


class ApiRateLimitMiddleware:
    """Apply global and trusted-client-IP protection before application work."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") == "OPTIONS"
            or scope.get("path") == "/health/live"
            or not str(scope.get("path", "")).startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        if not settings.rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        redis = getattr(request.app.state, "rate_limit_redis", None)
        if redis is None:
            await self._send_unavailable(request, send, RuntimeError("missing client"))
            return

        policies = SecurityPolicies.from_settings(settings)
        key_secret = settings.rate_limit_hmac_key.get_secret_value().encode("utf-8")
        client_ip = trusted_client_ip(scope)

        allowed_result: RateLimitResult | None = None
        try:
            checks = (
                RateLimitCheck(policies.api_global, "global", "all"),
                RateLimitCheck(policies.api_ip, "ip", client_ip),
            )
            decision = await check_rate_limits(
                cast(Redis, redis),
                namespace=settings.rate_limit_namespace,
                checks=checks,
                key_secret=key_secret,
            )
            if not decision.allowed:
                denied = [
                    (check.policy, result)
                    for check, result in zip(checks, decision.results, strict=True)
                    if not result.allowed
                ]
                policy, result = max(denied, key=lambda item: item[1].retry_after_ms)
                await self._send_denied(request, send, policy, result)
                return
            allowed_result = decision.results[-1]
        except RateLimitUnavailable as exc:
            await self._send_unavailable(request, send, exc)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start" and allowed_result is not None:
                result = getattr(
                    request.state,
                    "actor_rate_limit_result",
                    allowed_result,
                )
                _merge_response_headers(
                    message,
                    rate_limit_headers(result, include_retry_after=False),
                )
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _send_denied(
        request: Request,
        send: Send,
        policy: RateLimitPolicy,
        result: RateLimitResult,
    ) -> None:
        safe_log(
            logger,
            logging.WARNING,
            "rate_limit.denied",
            extra={
                "rate_limit_policy": policy.name,
                "http_status_code": 429,
                "business_code": int(BusinessCode.RATE_LIMITED),
            },
        )
        response = JSONResponse(
            status_code=429,
            content=error_content(
                request,
                code=BusinessCode.RATE_LIMITED,
                message="请求过于频繁，请稍后重试",
            ),
            headers=request_id_headers(
                request,
                rate_limit_headers(result, include_retry_after=True),
            ),
        )
        await response(request.scope, request.receive, send)

    @staticmethod
    async def _send_unavailable(
        request: Request,
        send: Send,
        exc: BaseException,
    ) -> None:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.rate_limit.unavailable",
            extra={
                "dependency": "rate_limit_redis",
                "dependency_operation": "api_admission",
                "http_status_code": 503,
                "business_code": int(BusinessCode.SERVICE_UNAVAILABLE),
                **safe_exception_metadata(exc),
            },
        )
        response = JSONResponse(
            status_code=503,
            content=error_content(
                request,
                code=BusinessCode.SERVICE_UNAVAILABLE,
                message="服务暂时不可用",
            ),
            headers=request_id_headers(request, {"Cache-Control": "no-store"}),
        )
        await response(request.scope, request.receive, send)
