import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.rate_limit import (
    RateLimitCheck,
    RateLimitPolicy,
    build_rate_limit_key,
    check_rate_limit,
    check_rate_limits,
)
from app.settings import get_settings

pytestmark = pytest.mark.postgresql
KEY_SECRET = b"integration-rate-limit-secret-is-isolated"


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """This module exercises the isolated limiter Redis only."""


@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncIterator[None]:
    """Shadow the PostgreSQL integration cleanup for this Redis-only module."""
    yield


async def test_real_redis_enforces_concurrent_burst_and_sets_ttl() -> None:
    settings = get_settings()
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    namespace = f"test_{uuid.uuid4().hex}"
    policy = RateLimitPolicy(
        name="concurrent_burst",
        burst_capacity=7,
        refill_tokens=1,
        refill_period_seconds=60,
    )
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

        assert sum(result.allowed for result in results) == policy.burst_capacity
        assert all(result.limit == policy.burst_capacity for result in results)
        assert any(not result.allowed for result in results)
        assert all(
            result.retry_after_ms > 0 for result in results if not result.allowed
        )
        ttl_ms = await redis.pttl(key)
        assert 0 < ttl_ms <= policy.burst_capacity * 60_000
        stored = await redis.hgetall(key)
        assert set(stored) == {"tokens_micro", "updated_at_ms"}
        assert subject not in key
        assert subject not in repr(stored)
    finally:
        await redis.delete(key)
        await redis.aclose()


async def test_rejected_batch_does_not_consume_another_bucket() -> None:
    settings = get_settings()
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    namespace = f"test_{uuid.uuid4().hex}"
    exhausted_policy = RateLimitPolicy(
        name="exhausted",
        burst_capacity=1,
        refill_tokens=1,
        refill_period_seconds=60,
    )
    spare_policy = RateLimitPolicy(
        name="spare",
        burst_capacity=2,
        refill_tokens=1,
        refill_period_seconds=60,
    )
    checks = (
        RateLimitCheck(exhausted_policy, "global", "all"),
        RateLimitCheck(spare_policy, "ip", "203.0.113.20"),
    )
    keys = tuple(
        build_rate_limit_key(
            namespace=namespace,
            policy=check.policy,
            subject_type=check.subject_type,
            subject=check.subject,
            key_secret=KEY_SECRET,
        )
        for check in checks
    )
    try:
        consumed = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=exhausted_policy,
            subject_type="global",
            subject="all",
            key_secret=KEY_SECRET,
        )
        assert consumed.allowed is True

        denied = await check_rate_limits(
            redis,
            namespace=namespace,
            checks=checks,
            key_secret=KEY_SECRET,
        )

        assert denied.allowed is False
        assert tuple(result.allowed for result in denied.results) == (False, True)
        assert denied.retry_after_ms == denied.results[0].retry_after_ms
        assert await redis.exists(keys[1]) == 0

        spare = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=spare_policy,
            subject_type="ip",
            subject="203.0.113.20",
            key_secret=KEY_SECRET,
        )
        assert spare.allowed is True
        assert spare.remaining == 1
        assert all(f"{{{namespace}}}" in key for key in keys)
    finally:
        await redis.delete(*keys)
        await redis.aclose()


async def test_concurrent_batches_do_not_overconsume_any_dimension() -> None:
    settings = get_settings()
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    namespace = f"test_{uuid.uuid4().hex}"
    wider_policy = RateLimitPolicy(
        name="wider",
        burst_capacity=5,
        refill_tokens=1,
        refill_period_seconds=60,
    )
    narrower_policy = RateLimitPolicy(
        name="narrower",
        burst_capacity=3,
        refill_tokens=1,
        refill_period_seconds=60,
    )
    checks = (
        RateLimitCheck(wider_policy, "global", "all"),
        RateLimitCheck(narrower_policy, "actor", "U0000000002"),
    )
    keys = tuple(
        build_rate_limit_key(
            namespace=namespace,
            policy=check.policy,
            subject_type=check.subject_type,
            subject=check.subject,
            key_secret=KEY_SECRET,
        )
        for check in checks
    )
    try:
        decisions = await asyncio.gather(
            *(
                check_rate_limits(
                    redis,
                    namespace=namespace,
                    checks=checks,
                    key_secret=KEY_SECRET,
                )
                for _ in range(20)
            )
        )

        assert sum(decision.allowed for decision in decisions) == 3
        assert all(
            decision.retry_after_ms > 0
            for decision in decisions
            if not decision.allowed
        )
        wider_followups = [
            await check_rate_limit(
                redis,
                namespace=namespace,
                policy=wider_policy,
                subject_type="global",
                subject="all",
                key_secret=KEY_SECRET,
            )
            for _ in range(3)
        ]
        assert [result.allowed for result in wider_followups] == [True, True, False]

        narrower_followup = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=narrower_policy,
            subject_type="actor",
            subject="U0000000002",
            key_secret=KEY_SECRET,
        )
        assert narrower_followup.allowed is False
    finally:
        await redis.delete(*keys)
        await redis.aclose()


async def test_real_redis_refills_tokens_using_redis_time() -> None:
    settings = get_settings()
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    namespace = f"test_{uuid.uuid4().hex}"
    policy = RateLimitPolicy(
        name="refill",
        burst_capacity=2,
        refill_tokens=2,
        refill_period_seconds=1,
    )
    subject = "U0000000001"
    key = build_rate_limit_key(
        namespace=namespace,
        policy=policy,
        subject_type="actor",
        subject=subject,
        key_secret=KEY_SECRET,
    )
    try:
        first = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=policy,
            subject_type="actor",
            subject=subject,
            key_secret=KEY_SECRET,
        )
        second = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=policy,
            subject_type="actor",
            subject=subject,
            key_secret=KEY_SECRET,
        )
        denied = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=policy,
            subject_type="actor",
            subject=subject,
            key_secret=KEY_SECRET,
        )

        assert (first.allowed, second.allowed, denied.allowed) == (True, True, False)
        assert 0 < await redis.pttl(key) <= 1_000
        await asyncio.sleep(0.6)

        refilled = await check_rate_limit(
            redis,
            namespace=namespace,
            policy=policy,
            subject_type="actor",
            subject=subject,
            key_secret=KEY_SECRET,
        )

        assert refilled.allowed is True
        assert refilled.remaining == 0
        assert 0 < await redis.pttl(key) <= 1_000
    finally:
        await redis.delete(key)
        await redis.aclose()
