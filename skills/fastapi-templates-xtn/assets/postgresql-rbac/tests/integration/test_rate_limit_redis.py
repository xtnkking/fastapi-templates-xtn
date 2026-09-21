import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.security.rate_limit import (
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
    namespace = f"test_{uuid.uuid4().hex}"
    policy = RateLimitPolicy("captcha_create_login", 7, 60)
    subject = "198.51.100.10"
    key = build_rate_limit_key(
        namespace=namespace,
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
                    namespace=namespace,
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
    namespace = f"test_{uuid.uuid4().hex}"
    login = RateLimitPolicy("login", 1, 60)
    register = RateLimitPolicy("register", 1, 60)
    subject = "198.51.100.11"
    keys = [
        build_rate_limit_key(
            namespace=namespace,
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
                    namespace=namespace,
                    policy=policy,
                    subject_type="ip",
                    subject=subject,
                    key_secret=KEY_SECRET,
                )
            ).allowed
        assert not (
            await check_rate_limit(
                redis,
                namespace=namespace,
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
    namespace = f"test_{uuid.uuid4().hex}"
    policy = RateLimitPolicy("login", 1, 1)
    key = build_rate_limit_key(
        namespace=namespace,
        policy=policy,
        subject_type="ip",
        subject="198.51.100.12",
        key_secret=KEY_SECRET,
    )

    async def attempt() -> bool:
        return (
            await check_rate_limit(
                redis,
                namespace=namespace,
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
    namespace = f"test_{uuid.uuid4().hex}"
    policy = RateLimitPolicy("register", 1, 60)
    key = build_rate_limit_key(
        namespace=namespace,
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
                namespace=namespace,
                policy=policy,
                subject_type="ip",
                subject="198.51.100.13",
                key_secret=KEY_SECRET,
            )
        assert await redis.get(key) == "1"
    finally:
        await redis.delete(key)
        await redis.aclose()
