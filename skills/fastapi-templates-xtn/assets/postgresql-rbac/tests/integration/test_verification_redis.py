import asyncio
from collections.abc import AsyncIterator, Awaitable
from typing import cast

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.settings import get_settings
from app.verification import (
    VerificationChannel,
    VerificationDeliveryPayload,
    VerificationExpiredError,
    VerificationInvalidError,
    VerificationPolicy,
    VerificationPurpose,
    VerificationService,
)

pytestmark = pytest.mark.postgresql
SECRET = "integration-verification-hmac-secret-32-bytes"
NAMESPACE = "verification:test:v1"
ALL_PURPOSES = frozenset(VerificationPurpose)
ALL_CHANNELS = frozenset(VerificationChannel)


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """This module exercises Redis only and does not need an Alembic upgrade."""


@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncIterator[None]:
    """Shadow the PostgreSQL integration cleanup for this Redis-only module."""

    yield


@pytest_asyncio.fixture
async def verification_redis() -> AsyncIterator[Redis]:
    redis = Redis.from_url(
        get_settings().effective_rate_limit_redis_url,
        decode_responses=True,
    )
    keys = [key async for key in redis.scan_iter(match=f"{NAMESPACE}:*")]
    if keys:
        await redis.delete(*keys)
    try:
        yield redis
    finally:
        keys = [key async for key in redis.scan_iter(match=f"{NAMESPACE}:*")]
        if keys:
            await redis.delete(*keys)
        await redis.aclose()


async def test_real_redis_never_stores_plaintext_target_or_code(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )
    target = "private.person@example.test"
    delivery = await service.issue_challenge(
        purpose=VerificationPurpose.REGISTRATION,
        channel=VerificationChannel.EMAIL,
        target=target,
    )

    keys = [key async for key in verification_redis.scan_iter(match=f"{NAMESPACE}:*")]
    assert len(keys) == 3
    assert all(target not in key for key in keys)
    assert all(str(delivery.challenge_id) not in key for key in keys)
    hash_tags = {key.split("{", 1)[1].split("}", 1)[0] for key in keys}
    assert len(hash_tags) == 1
    stored_fragments: list[str] = []
    for key in keys:
        key_type = await verification_redis.type(key)
        if key_type == "hash":
            hash_command = verification_redis.hgetall(key)
            stored_hash = await cast(Awaitable[dict[str, str]], hash_command)
            stored_fragments.extend(stored_hash.values())
        elif key_type == "string":
            value = await verification_redis.get(key)
            assert value is not None
            stored_fragments.append(value)
    assert target not in stored_fragments
    assert delivery.plaintext_code not in stored_fragments
    assert str(delivery.challenge_id) not in stored_fragments


async def test_resend_atomically_invalidates_old_challenge(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )

    async def issue(target: str) -> VerificationDeliveryPayload:
        return await service.issue_challenge(
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.EMAIL,
            target=target,
        )

    old_delivery = await issue("Person@Example.Test")
    new_delivery = await issue(" person@example.test ")
    keys = [key async for key in verification_redis.scan_iter(match=f"{NAMESPACE}:*")]
    assert len(keys) == 3

    with pytest.raises(VerificationInvalidError):
        await service.verify_challenge(
            challenge_id=old_delivery.challenge_id,
            purpose=old_delivery.purpose,
            channel=old_delivery.channel,
            target=old_delivery.delivery_target,
            code=old_delivery.plaintext_code,
        )
    verified = await service.verify_challenge(
        challenge_id=new_delivery.challenge_id,
        purpose=new_delivery.purpose,
        channel=new_delivery.channel,
        target=new_delivery.delivery_target,
        code=new_delivery.plaintext_code,
    )
    assert verified.challenge_id == new_delivery.challenge_id


async def test_cancel_only_removes_the_matching_active_challenge(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )
    old_delivery = await service.issue_challenge(
        purpose=VerificationPurpose.REGISTRATION,
        channel=VerificationChannel.SMS,
        target="+15551234567",
    )
    current_delivery = await service.issue_challenge(
        purpose=old_delivery.purpose,
        channel=old_delivery.channel,
        target=old_delivery.delivery_target,
    )

    assert (
        await service.cancel_challenge(
            challenge_id=old_delivery.challenge_id,
            purpose=old_delivery.purpose,
            channel=old_delivery.channel,
            target=old_delivery.delivery_target,
        )
        is False
    )
    verified = await service.verify_challenge(
        challenge_id=current_delivery.challenge_id,
        purpose=current_delivery.purpose,
        channel=current_delivery.channel,
        target=current_delivery.delivery_target,
        code=current_delivery.plaintext_code,
    )
    assert verified.challenge_id == current_delivery.challenge_id

    cancelled_delivery = await service.issue_challenge(
        purpose=old_delivery.purpose,
        channel=old_delivery.channel,
        target=old_delivery.delivery_target,
    )
    assert await service.cancel_challenge(
        challenge_id=cancelled_delivery.challenge_id,
        purpose=cancelled_delivery.purpose,
        channel=cancelled_delivery.channel,
        target=cancelled_delivery.delivery_target,
    )
    with pytest.raises(VerificationInvalidError):
        await service.verify_challenge(
            challenge_id=cancelled_delivery.challenge_id,
            purpose=cancelled_delivery.purpose,
            channel=cancelled_delivery.channel,
            target=cancelled_delivery.delivery_target,
            code=cancelled_delivery.plaintext_code,
        )
    keys = [key async for key in verification_redis.scan_iter(match=f"{NAMESPACE}:*")]
    assert keys
    assert all(key.endswith(":state") for key in keys)


async def test_cancel_resend_race_never_deletes_new_challenge(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )
    old_delivery = await service.issue_challenge(
        purpose=VerificationPurpose.LOGIN,
        channel=VerificationChannel.EMAIL,
        target="person@example.test",
    )

    cancel_result, new_delivery = await asyncio.gather(
        service.cancel_challenge(
            challenge_id=old_delivery.challenge_id,
            purpose=old_delivery.purpose,
            channel=old_delivery.channel,
            target=old_delivery.delivery_target,
        ),
        service.issue_challenge(
            purpose=old_delivery.purpose,
            channel=old_delivery.channel,
            target=old_delivery.delivery_target,
        ),
    )

    assert isinstance(cancel_result, bool)
    verified = await service.verify_challenge(
        challenge_id=new_delivery.challenge_id,
        purpose=new_delivery.purpose,
        channel=new_delivery.channel,
        target=new_delivery.delivery_target,
        code=new_delivery.plaintext_code,
    )
    assert verified.challenge_id == new_delivery.challenge_id


async def test_fifth_wrong_attempt_consumes_challenge(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )
    delivery = await service.issue_challenge(
        purpose=VerificationPurpose.LOGIN,
        channel=VerificationChannel.SMS,
        target="+15551234567",
    )

    for _ in range(5):
        with pytest.raises(VerificationInvalidError):
            await service.verify_challenge(
                challenge_id=delivery.challenge_id,
                purpose=delivery.purpose,
                channel=delivery.channel,
                target=delivery.delivery_target,
                code="000000" if delivery.plaintext_code != "000000" else "111111",
            )

    with pytest.raises(VerificationInvalidError):
        await service.verify_challenge(
            challenge_id=delivery.challenge_id,
            purpose=delivery.purpose,
            channel=delivery.channel,
            target=delivery.delivery_target,
            code=delivery.plaintext_code,
        )
    keys = [key async for key in verification_redis.scan_iter(match=f"{NAMESPACE}:*")]
    assert keys
    assert all(key.endswith(":state") for key in keys)


async def test_expiration_is_distinct_from_unknown_challenge(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
        policy=VerificationPolicy(challenge_ttl_seconds=1),
    )
    delivery = await service.issue_challenge(
        purpose=VerificationPurpose.PASSWORD_RESET,
        channel=VerificationChannel.EMAIL,
        target="person@example.test",
    )
    await asyncio.sleep(1.1)

    with pytest.raises(VerificationExpiredError):
        await service.verify_challenge(
            challenge_id=delivery.challenge_id,
            purpose=delivery.purpose,
            channel=delivery.channel,
            target=delivery.delivery_target,
            code=delivery.plaintext_code,
        )


async def test_success_is_single_use_under_concurrency(
    verification_redis: Redis,
) -> None:
    service = VerificationService(
        verification_redis,
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
        namespace=NAMESPACE,
    )
    delivery = await service.issue_challenge(
        purpose=VerificationPurpose.SENSITIVE_ACTION,
        channel=VerificationChannel.EMAIL,
        target="person@example.test",
    )

    async def verify_once() -> bool:
        try:
            await service.verify_challenge(
                challenge_id=delivery.challenge_id,
                purpose=delivery.purpose,
                channel=delivery.channel,
                target=delivery.delivery_target,
                code=delivery.plaintext_code,
            )
        except VerificationInvalidError:
            return False
        return True

    results = await asyncio.gather(*(verify_once() for _ in range(20)))

    assert results.count(True) == 1
    assert results.count(False) == 19
    keys = [key async for key in verification_redis.scan_iter(match=f"{NAMESPACE}:*")]
    assert keys
    assert all(key.endswith(":state") for key in keys)
