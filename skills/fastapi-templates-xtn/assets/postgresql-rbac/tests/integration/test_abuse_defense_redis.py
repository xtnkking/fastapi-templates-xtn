import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.settings import Settings, get_settings

pytestmark = pytest.mark.postgresql


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """This module exercises the isolated security Redis only."""


@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncIterator[None]:
    """Shadow the PostgreSQL integration cleanup for this Redis-only module."""
    yield


@pytest_asyncio.fixture
async def rate_redis() -> AsyncIterator[Redis]:
    settings = get_settings()
    client = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    try:
        yield client
    finally:
        await client.aclose()


def isolated_settings(**updates: object) -> Settings:
    namespace = f"test_{uuid.uuid4().hex}"
    return get_settings().model_copy(
        update={"rate_limit_namespace": namespace, **updates}
    )


async def delete_namespace(redis: Redis, namespace: str) -> None:
    patterns = (
        f"abuse:v1:{namespace}:*",
        f"rl:v1:{{{namespace}}}:*",
    )
    keys: list[str] = []
    for pattern in patterns:
        keys.extend([key async for key in redis.scan_iter(match=pattern)])
    if keys:
        await redis.delete(*keys)


async def test_concurrent_login_failures_do_not_lose_increments(
    rate_redis: Redis,
) -> None:
    settings = isolated_settings(login_failure_state_retention_seconds=60)
    service = AbuseDefenseService(rate_redis, settings)
    identifier = "private.person@example.test"
    try:
        await asyncio.gather(
            *(service.record_login_failure(identifier) for _ in range(20))
        )
        state = await service.login_failure_state(identifier)

        assert state.consecutive_failures == 20
        keys = [
            key
            async for key in rate_redis.scan_iter(
                match=f"abuse:v1:{settings.rate_limit_namespace}:*"
            )
        ]
        assert len(keys) == 1
        assert identifier not in keys[0]
    finally:
        await delete_namespace(rate_redis, settings.rate_limit_namespace)


async def test_failure_count_has_finite_ttl_and_success_clears_state(
    rate_redis: Redis,
) -> None:
    settings = isolated_settings(login_failure_state_retention_seconds=2)
    service = AbuseDefenseService(rate_redis, settings)
    identifier = "person@example.test"
    try:
        states = [await service.record_login_failure(identifier) for _ in range(3)]
        assert states[-1].consecutive_failures == 3
        keys = [
            key
            async for key in rate_redis.scan_iter(
                match=f"abuse:v1:{settings.rate_limit_namespace}:*"
            )
        ]
        assert len(keys) == 1
        assert 1 <= await rate_redis.ttl(keys[0]) <= 2

        await service.record_login_success(identifier)
        cleared = await service.login_failure_state(identifier)
        assert cleared.consecutive_failures == 0
    finally:
        await delete_namespace(rate_redis, settings.rate_limit_namespace)


async def test_failure_signal_expires_and_never_blocks_correct_credentials(
    rate_redis: Redis,
) -> None:
    settings = isolated_settings(login_failure_state_retention_seconds=1)
    service = AbuseDefenseService(rate_redis, settings)
    identifier = "person@example.test"
    try:
        states = [await service.record_login_failure(identifier) for _ in range(5)]

        assert states[-1].consecutive_failures == 5
        await service.check_login_attempt(
            client_ip="198.51.100.80",
            normalized_identifier=identifier,
        )
        await asyncio.sleep(1.1)
        assert (await service.login_failure_state(identifier)).consecutive_failures == 0
    finally:
        await delete_namespace(rate_redis, settings.rate_limit_namespace)
