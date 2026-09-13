from typing import cast
from unittest.mock import AsyncMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.rate_limit import (
    MICROTOKENS_PER_TOKEN,
    TOKEN_BUCKET_SCRIPT,
    RateLimitCheck,
    RateLimitPolicy,
    RateLimitUnavailable,
    build_rate_limit_key,
    check_rate_limit,
    check_rate_limits,
)

KEY_SECRET = b"rate-limit-tests-have-a-separate-secret"
POLICY = RateLimitPolicy(
    name="authenticated_read",
    burst_capacity=20,
    refill_tokens=120,
    refill_period_seconds=60,
)
SECOND_POLICY = RateLimitPolicy(
    name="login_ip",
    burst_capacity=5,
    refill_tokens=30,
    refill_period_seconds=60,
)


def test_policy_keeps_burst_and_sustained_rate_independent() -> None:
    assert POLICY.burst_microtokens == 20 * MICROTOKENS_PER_TOKEN
    assert POLICY.refill_microtokens == 120 * MICROTOKENS_PER_TOKEN
    assert POLICY.refill_period_ms == 60_000
    assert POLICY.full_refill_ms == 10_000


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "name": "dynamic/path",
            "burst_capacity": 1,
            "refill_tokens": 1,
            "refill_period_seconds": 1,
        },
        {
            "name": "valid",
            "burst_capacity": 0,
            "refill_tokens": 1,
            "refill_period_seconds": 1,
        },
        {
            "name": "valid",
            "burst_capacity": 1,
            "refill_tokens": True,
            "refill_period_seconds": 1,
        },
        {
            "name": "valid",
            "burst_capacity": 1,
            "refill_tokens": 1,
            "refill_period_seconds": 0,
        },
        {
            "name": "valid",
            "burst_capacity": 1_000_000,
            "refill_tokens": 1,
            "refill_period_seconds": 86_400,
        },
    ],
)
def test_policy_rejects_dynamic_names_and_invalid_numbers(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        RateLimitPolicy(**kwargs)  # type: ignore[arg-type]


def test_key_is_stable_bounded_and_hides_the_subject() -> None:
    subject = "203.0.113.42"
    key = build_rate_limit_key(
        namespace="test_service",
        policy=POLICY,
        subject_type="ip",
        subject=subject,
        key_secret=KEY_SECRET,
    )

    assert key == build_rate_limit_key(
        namespace="test_service",
        policy=POLICY,
        subject_type="ip",
        subject=subject,
        key_secret=KEY_SECRET,
    )
    assert key.startswith("rl:v1:{test_service}:authenticated_read:ip:")
    assert subject not in key
    assert len(key) < 160
    second_key = build_rate_limit_key(
        namespace="test_service",
        policy=SECOND_POLICY,
        subject_type="ip",
        subject="203.0.113.43",
        key_secret=KEY_SECRET,
    )
    assert key != second_key
    assert "{test_service}" in key
    assert "{test_service}" in second_key


@pytest.mark.parametrize(
    ("namespace", "subject_type"),
    [
        ("BadName", "ip"),
        ("route/path", "ip"),
        ("service", "with:colon"),
        ("service", ""),
    ],
)
def test_key_rejects_non_static_namespace_and_subject_type(
    namespace: str,
    subject_type: str,
) -> None:
    with pytest.raises(ValueError, match="static lowercase ASCII identifier"):
        build_rate_limit_key(
            namespace=namespace,
            policy=POLICY,
            subject_type=subject_type,
            subject="203.0.113.42",
            key_secret=KEY_SECRET,
        )


async def test_check_parses_allowed_and_denied_results() -> None:
    redis_mock = AsyncMock()
    redis_mock.eval.side_effect = (
        [1, 0, 1, 19, 0, 500],
        [0, 250, 0, 0, 250, 10_000],
    )
    redis = cast(Redis, redis_mock)

    allowed = await check_rate_limit(
        redis,
        namespace="test_service",
        policy=POLICY,
        subject_type="actor",
        subject="U0000000001",
        key_secret=KEY_SECRET,
    )
    denied = await check_rate_limit(
        redis,
        namespace="test_service",
        policy=POLICY,
        subject_type="actor",
        subject="U0000000001",
        key_secret=KEY_SECRET,
    )

    assert allowed.allowed is True
    assert allowed.limit == 20
    assert allowed.remaining == 19
    assert allowed.retry_after_ms == 0
    assert allowed.reset_after_ms == 500
    assert denied.allowed is False
    assert denied.remaining == 0
    assert denied.retry_after_ms == 250
    assert denied.reset_after_ms == 10_000
    first_call = redis_mock.eval.await_args_list[0].args
    assert first_call[0] == TOKEN_BUCKET_SCRIPT
    assert "redis.call('TIME')" in TOKEN_BUCKET_SCRIPT
    assert first_call[1] == 1
    assert "U0000000001" not in first_call[2]
    assert first_call[3:] == ("20000000", "120000000", "60000")


async def test_batch_parses_each_bucket_and_longest_retry() -> None:
    redis_mock = AsyncMock()
    redis_mock.eval.return_value = [
        0,
        400,
        1,
        19,
        0,
        500,
        0,
        0,
        400,
        10_000,
    ]
    checks = (
        RateLimitCheck(
            policy=POLICY,
            subject_type="global",
            subject="all",
        ),
        RateLimitCheck(
            policy=SECOND_POLICY,
            subject_type="ip",
            subject="203.0.113.42",
        ),
    )

    decision = await check_rate_limits(
        cast(Redis, redis_mock),
        namespace="test_service",
        checks=checks,
        key_secret=KEY_SECRET,
    )

    assert decision.allowed is False
    assert decision.retry_after_ms == 400
    assert tuple(result.allowed for result in decision.results) == (True, False)
    assert tuple(result.remaining for result in decision.results) == (19, 0)
    call = redis_mock.eval.await_args.args
    assert call[0] == TOKEN_BUCKET_SCRIPT
    assert call[1] == 2
    assert all("{test_service}" in key for key in call[2:4])
    assert "all" not in call[2]
    assert "203.0.113.42" not in call[3]
    assert call[4:] == (
        "20000000",
        "120000000",
        "60000",
        "5000000",
        "30000000",
        "60000",
    )


async def test_batch_rejects_duplicate_keys_before_redis() -> None:
    redis_mock = AsyncMock()
    check = RateLimitCheck(
        policy=POLICY,
        subject_type="actor",
        subject="U0000000001",
    )

    with pytest.raises(ValueError, match="unique keys"):
        await check_rate_limits(
            cast(Redis, redis_mock),
            namespace="test_service",
            checks=(check, check),
            key_secret=KEY_SECRET,
        )

    redis_mock.eval.assert_not_awaited()


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [1, 2, 3],
        [2, 0, 1, 19, 0, 1],
        [True, 0, 1, 19, 0, 1],
        [1, 0, 1, 21, 0, 1],
        [1, 0, 1, 19, 1, 1],
        [0, 0, 0, 0, 0, 1],
        [1, 0, 1, 19, 0, -1],
        [0, 250, 1, 19, 0, 500],
        [0, 200, 0, 0, 250, 10_000],
    ],
)
async def test_check_rejects_untrustworthy_script_results(raw: object) -> None:
    redis_mock = AsyncMock()
    redis_mock.eval.return_value = raw

    with pytest.raises(
        RateLimitUnavailable,
        match="rate-limit store returned an invalid result",
    ):
        await check_rate_limit(
            cast(Redis, redis_mock),
            namespace="test_service",
            policy=POLICY,
            subject_type="actor",
            subject="U0000000001",
            key_secret=KEY_SECRET,
        )


async def test_redis_error_becomes_rate_limit_unavailable() -> None:
    redis_mock = AsyncMock()
    redis_mock.eval.side_effect = RedisConnectionError("secret endpoint unavailable")

    with pytest.raises(
        RateLimitUnavailable,
        match="rate-limit store is unavailable",
    ) as caught:
        await check_rate_limit(
            cast(Redis, redis_mock),
            namespace="test_service",
            policy=POLICY,
            subject_type="actor",
            subject="U0000000001",
            key_secret=KEY_SECRET,
        )

    assert "secret endpoint" not in str(caught.value)
