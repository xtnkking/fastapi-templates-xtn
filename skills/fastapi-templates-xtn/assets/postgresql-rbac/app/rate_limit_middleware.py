import ipaddress
import math

from starlette.types import Scope

from app.rate_limit import RateLimitResult


def trusted_client_ip(scope: Scope) -> str:
    """Only use a peer address already trusted by the ASGI server, never headers."""
    client = scope.get("client")
    host = client[0] if isinstance(client, tuple) and client else ""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        # Admission fails closed when a trustworthy address is unavailable.
        return ""


def rate_limit_headers(
    result: RateLimitResult,
    *,
    include_retry_after: bool,
) -> dict[str, str]:
    headers = {
        "RateLimit-Limit": str(result.limit),
        "RateLimit-Remaining": str(result.remaining),
        "RateLimit-Reset": str(max(1, math.ceil(result.reset_after_ms / 1000))),
        "Cache-Control": "no-store",
    }
    if include_retry_after:
        headers["Retry-After"] = str(max(1, math.ceil(result.retry_after_ms / 1000)))
    return headers


def semantic_rate_limit_headers(result: RateLimitResult) -> dict[str, str]:
    """Expose the denied window without revealing the subject or policy name."""
    return rate_limit_headers(result, include_retry_after=True)
