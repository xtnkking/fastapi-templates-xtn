#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    使用隔离 Redis 验证限流的原子计数、独立业务窗口和过期边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        对齐简化限流键并用唯一业务名隔离每轮 Redis 计数
# --------------------------------------------------------------------------------------------------

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.rate_limit.limiter import (
    RateLimitPolicy,
    RateLimitUnavailable,
    build_rate_limit_key,
    check_rate_limit,
)

pytestmark = pytest.mark.postgresql
KEY_SECRET = b"integration-rate-limit-secret-is-isolated"


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """Only the disposable limiter Redis is exercised in this module."""


@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncIterator[None]:
    yield


async def test_fixed_window_enforces_concurrent_limit_without_plaintext_keys() -> None:
    redis = Redis.from_url(
        get_settings().effective_rate_limit_redis_url, decode_responses=True
    )
    policy = RateLimitPolicy(name=f"captcha_login_{uuid.uuid4().hex}", limit=7, window_seconds=60)
    subject = "198.51.100.10"
    key = build_rate_limit_key(
        policy=policy,
        subject_type="ip",
        subject=subject,
        key_secret=KEY_SECRET,
    )
    try:
        results = await asyncio.gather(
            *(
                check_rate_limit(
                    redis,
                    policy=policy,
                    subject_type="ip",
                    subject=subject,
                    key_secret=KEY_SECRET,
                )
                for _ in range(40)
            )
        )
        assert sum(result.allowed for result in results) == 7
        assert all(result.limit == 7 for result in results)
        assert all(
            result.retry_after_ms > 0 for result in results if not result.allowed
        )
        assert 0 < await redis.pttl(key) <= 60_000
        assert int(await redis.get(key)) == 40
        assert subject not in key
    finally:
        await redis.delete(key)
        await redis.aclose()


async def test_business_keys_are_independent_even_for_same_ip() -> None:
    redis = Redis.from_url(
        get_settings().effective_rate_limit_redis_url, decode_responses=True
    )
    business_suffix = uuid.uuid4().hex
    login = RateLimitPolicy(name=f"login_{business_suffix}", limit=1, window_seconds=60)
    register = RateLimitPolicy(name=f"register_{business_suffix}", limit=1, window_seconds=60)
    subject = "198.51.100.11"
    keys = [
        build_rate_limit_key(
            policy=policy,
            subject_type="ip",
            subject=subject,
            key_secret=KEY_SECRET,
        )
        for policy in (login, register)
    ]
    try:
        for policy in (login, register):
            assert (
                await check_rate_limit(
                    redis,
                    policy=policy,
                    subject_type="ip",
                    subject=subject,
                    key_secret=KEY_SECRET,
                )
            ).allowed
        assert not (
            await check_rate_limit(
                redis,
                policy=login,
                subject_type="ip",
                subject=subject,
                key_secret=KEY_SECRET,
            )
        ).allowed
        assert int(await redis.get(keys[0])) == 2
        assert int(await redis.get(keys[1])) == 1
    finally:
        await redis.delete(*keys)
        await redis.aclose()


async def test_fixed_window_does_not_extend_ttl_on_denial_then_resets() -> None:
    redis = Redis.from_url(
        get_settings().effective_rate_limit_redis_url, decode_responses=True
    )
    policy = RateLimitPolicy(name=f"login_{uuid.uuid4().hex}", limit=1, window_seconds=1)
    key = build_rate_limit_key(
        policy=policy,
        subject_type="ip",
        subject="198.51.100.12",
        key_secret=KEY_SECRET,
    )

    async def attempt() -> bool:
        """
            对本轮唯一业务窗口执行一次真实 Redis 计数。

        :return: 当前请求是否仍在该固定窗口的额度内。
        """
        return (
            await check_rate_limit(
                redis,
                policy=policy,
                subject_type="ip",
                subject="198.51.100.12",
                key_secret=KEY_SECRET,
            )
        ).allowed

    try:
        assert await attempt()
        original_ttl = await redis.pttl(key)
        assert not await attempt()
        assert 0 < await redis.pttl(key) <= original_ttl
        await asyncio.sleep(1.1)
        assert await attempt()
        assert int(await redis.get(key)) == 1
    finally:
        await redis.delete(key)
        await redis.aclose()


async def test_missing_expiry_is_unavailable_not_permanent_counter() -> None:
    redis = Redis.from_url(
        get_settings().effective_rate_limit_redis_url, decode_responses=True
    )
    policy = RateLimitPolicy(name=f"register_{uuid.uuid4().hex}", limit=1, window_seconds=60)
    key = build_rate_limit_key(
        policy=policy,
        subject_type="ip",
        subject="198.51.100.13",
        key_secret=KEY_SECRET,
    )
    try:
        await redis.set(key, "1")
        with pytest.raises(RateLimitUnavailable):
            await check_rate_limit(
                redis,
                policy=policy,
                subject_type="ip",
                subject="198.51.100.13",
                key_secret=KEY_SECRET,
            )
        assert await redis.get(key) == "1"
    finally:
        await redis.delete(key)
        await redis.aclose()
