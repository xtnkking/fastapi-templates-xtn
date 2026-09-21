from app.core.middleware.rate_limit import (
    rate_limit_headers,
    semantic_rate_limit_headers,
    trusted_client_ip,
)
from app.core.security.rate_limit import RateLimitResult


def test_only_asgi_peer_is_used_for_anonymous_rate_limit() -> None:
    assert (
        trusted_client_ip(
            {
                "type": "http",
                "client": ("2001:0db8::1", 5000),
                "headers": [(b"x-forwarded-for", b"198.51.100.7")],
            }
        )
        == "2001:db8::1"
    )
    assert trusted_client_ip({"type": "http", "headers": []}) == ""
    assert trusted_client_ip({"type": "http", "client": ("unknown", 5000)}) == ""


def test_429_headers_round_retry_up_and_hide_subject() -> None:
    result = RateLimitResult(False, 10, 0, 1001, 1001)
    assert semantic_rate_limit_headers(result) == {
        "RateLimit-Limit": "10",
        "RateLimit-Remaining": "0",
        "RateLimit-Reset": "2",
        "Retry-After": "2",
        "Cache-Control": "no-store",
    }
    assert "Retry-After" not in rate_limit_headers(result, include_retry_after=False)
