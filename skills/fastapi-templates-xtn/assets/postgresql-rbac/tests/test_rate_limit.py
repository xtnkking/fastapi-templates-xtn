#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证 Redis 固定窗口限流的私有键、错误回包和计数窗口边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充共同回包校验和原错误文案的回归覆盖
# 2026/10/10    XTN       V1.001        删除只读预查测试，保留原子计数和错误回包覆盖
# 2026/10/13    XTN       V1.002        验证简化限流键的精确摘要、稳定性及业务和主体隔离
# --------------------------------------------------------------------------------------------------

import hashlib
import hmac
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ConnectionError

from app.core.rate_limit.limiter import (
    FIXED_WINDOW_SCRIPT,
    RateLimitPolicy,
    RateLimitUnavailable,
    build_rate_limit_key,
    check_rate_limit,
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


@pytest.mark.parametrize(
    ("subject_type", "subject", "message"),
    [
        ("ip", "203.0.113.9", b"login\x00ip\x00203.0.113.9"),
        (
            "user_id",
            "U00000000000000000000000000",
            b"login\x00user_id\x00U00000000000000000000000000",
        ),
    ],
)
def test_key_has_exact_hmac_format_and_is_stable(subject_type: str, subject: str, message: bytes) -> None:
    first = build_rate_limit_key(
        policy=POLICY,
        subject_type=subject_type,
        subject=subject,
        key_secret=KEY_SECRET,
    )
    second = build_rate_limit_key(
        policy=POLICY,
        subject_type=subject_type,
        subject=subject,
        key_secret=KEY_SECRET,
    )
    expected_digest = hmac.new(KEY_SECRET, message, hashlib.sha256).hexdigest()
    assert first == f"rate_limit:login:{subject_type}:{expected_digest}"
    assert first == second
    assert subject not in first


@pytest.mark.parametrize(
    ("subject_type", "subject", "other_business", "other_subject_type", "other_subject"),
    [
        ("ip", "203.0.113.9", "register", "ip", "203.0.113.9"),
        ("ip", "203.0.113.9", "login", "ip", "203.0.113.10"),
        ("ip", "203.0.113.9", "login", "user_id", "203.0.113.9"),
        (
            "user_id",
            "U00000000000000000000000001",
            "login",
            "user_id",
            "U00000000000000000000000002",
        ),
    ],
)
def test_key_separates_business_subject_type_and_subject(
    subject_type: str, subject: str, other_business: str, other_subject_type: str, other_subject: str
) -> None:
    first = build_rate_limit_key(
        policy=POLICY,
        subject_type=subject_type,
        subject=subject,
        key_secret=KEY_SECRET,
    )
    second = build_rate_limit_key(
        policy=RateLimitPolicy(name=other_business, limit=5, window_seconds=3600),
        subject_type=other_subject_type,
        subject=other_subject,
        key_secret=KEY_SECRET,
    )
    assert first != second
    assert first.rsplit(":", maxsplit=1)[-1] != second.rsplit(":", maxsplit=1)[-1]
    assert subject not in first
    assert other_subject not in second


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
    with pytest.raises(RateLimitUnavailable, match="invalid result"):
        await check_rate_limit(
            redis,
            policy=POLICY,
            subject_type="ip",
            subject="203.0.113.9",
            key_secret=KEY_SECRET,
        )


@pytest.mark.asyncio
async def test_first_window_and_denial_share_original_ttl() -> None:
    redis = AsyncMock()
    redis.eval.side_effect = ([1, 300000], [2, 20000], [3, 100001])
    results = [
        await check_rate_limit(
            redis,
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
            policy=POLICY,
            subject_type="ip",
            subject="203.0.113.9",
            key_secret=KEY_SECRET,
        )
