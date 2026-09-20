from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ConnectionError

from app.rate_limit import (
    FIXED_WINDOW_SCRIPT,
    INSPECT_FIXED_WINDOW_SCRIPT,
    RateLimitPolicy,
    RateLimitUnavailable,
    build_rate_limit_key,
    check_rate_limit,
    inspect_rate_limit,
)

POLICY = RateLimitPolicy(name="login", limit=2, window_seconds=300)
KEY_SECRET = b"D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "Login", "limit": 2, "window_seconds": 300},
        {"name": "login", "limit": 0, "window_seconds": 300},
        {"name": "login", "limit": True, "window_seconds": 300},
        {"name": "login", "limit": 2, "window_seconds": 0},
        {"name": "login", "limit": 2, "window_seconds": 30 * 86400 + 1},
    ],
)
def test_policy_rejects_unbounded_or_disabled_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RateLimitPolicy(**kwargs)  # type: ignore[arg-type]


def test_key_is_private_and_separated_by_business() -> None:
    first = build_rate_limit_key(
        namespace="example",
        policy=POLICY,
        subject_type="ip",
        subject="203.0.113.9",
        key_secret=KEY_SECRET,
    )
    second = build_rate_limit_key(
        namespace="example",
        policy=RateLimitPolicy("register", 5, 3600),
        subject_type="ip",
        subject="203.0.113.9",
        key_secret=KEY_SECRET,
    )
    assert first.startswith("rl:v2:{example}:login:ip:")
    assert first != second
    assert "203.0.113.9" not in first
    assert len(first.rsplit(":", maxsplit=1)[-1]) == 64


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        [True, 1000],
        [1, 0],
        [1, -1],
        [0, 1000],
        [1, 300001],
        ["1", 1000],
        [1, 1000, 2],
    ],
)
@pytest.mark.asyncio
async def test_invalid_redis_result_fails_closed(raw: object) -> None:
    redis = AsyncMock()
    redis.eval.return_value = raw
    with pytest.raises(RateLimitUnavailable):
        await check_rate_limit(
            redis,
            namespace="example",
            policy=POLICY,
            subject_type="ip",
            subject="203.0.113.9",
            key_secret=KEY_SECRET,
        )


@pytest.mark.asyncio
async def test_first_window_and_denial_share_original_ttl() -> None:
    redis = AsyncMock()
    redis.eval.side_effect = ([1, 300000], [2, 200000], [3, 100001])
    results = [
        await check_rate_limit(
            redis,
            namespace="example",
            policy=POLICY,
            subject_type="ip",
            subject="203.0.113.9",
            key_secret=KEY_SECRET,
        )
        for _ in range(3)
    ]
    assert [result.allowed for result in results] == [True, True, False]
    assert [result.remaining for result in results] == [1, 0, 0]
    assert results[2].retry_after_ms == 100001
    assert "redis.call('INCR', KEYS[1])" in FIXED_WINDOW_SCRIPT
    assert "redis.call('EXPIRE', KEYS[1], window)" in FIXED_WINDOW_SCRIPT
    assert redis.eval.call_args.args[1] == 1
    assert redis.eval.call_args.args[-2:] == ("2", "300")


@pytest.mark.asyncio
async def test_redis_failure_denies_before_protected_work() -> None:
    redis = AsyncMock()
    redis.eval.side_effect = ConnectionError("secret Redis URL")
    with pytest.raises(RateLimitUnavailable, match="store is unavailable"):
        await check_rate_limit(
            redis,
            namespace="example",
            policy=POLICY,
            subject_type="ip",
            subject="203.0.113.9",
            key_secret=KEY_SECRET,
        )


@pytest.mark.asyncio
async def test_inspection_does_not_create_or_increment_a_missing_window() -> None:
    redis = AsyncMock()
    redis.eval.return_value = [0, -2]

    result = await inspect_rate_limit(
        redis,
        namespace="example",
        policy=POLICY,
        subject_type="actor",
        subject="UABC1234567",
        key_secret=KEY_SECRET,
    )

    assert result.allowed is True
    assert result.remaining == POLICY.limit
    assert result.reset_after_ms == 0
    assert "INCR" not in INSPECT_FIXED_WINDOW_SCRIPT
    assert redis.eval.await_args.args[1] == 1
    assert len(redis.eval.await_args.args) == 3


@pytest.mark.asyncio
async def test_inspection_reports_an_existing_exhausted_window() -> None:
    redis = AsyncMock()
    redis.eval.return_value = [2, 2500]

    result = await inspect_rate_limit(
        redis,
        namespace="example",
        policy=POLICY,
        subject_type="actor",
        subject="UABC1234567",
        key_secret=KEY_SECRET,
    )

    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after_ms == 2500


@pytest.mark.parametrize("raw", ([0, 1000], [1, -2], [3, 300001], ["1", 1000]))
@pytest.mark.asyncio
async def test_invalid_inspection_result_fails_closed(raw: object) -> None:
    redis = AsyncMock()
    redis.eval.return_value = raw

    with pytest.raises(RateLimitUnavailable):
        await inspect_rate_limit(
            redis,
            namespace="example",
            policy=POLICY,
            subject_type="actor",
            subject="UABC1234567",
            key_secret=KEY_SECRET,
        )
