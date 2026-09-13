import asyncio
import uuid
from collections.abc import Iterable
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.encoders import jsonable_encoder
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.verification import (
    VerificationChannel,
    VerificationDeliveryPayload,
    VerificationExpiredError,
    VerificationInvalidError,
    VerificationPolicy,
    VerificationPurpose,
    VerificationService,
    VerificationUnavailableError,
    VerifiedChallenge,
)

SECRET = "s3parate-verification-hmac-secret-32-bytes"
ALL_PURPOSES = frozenset(VerificationPurpose)
ALL_CHANNELS = frozenset(VerificationChannel)


def make_service(*results: object) -> tuple[VerificationService, AsyncMock]:
    redis = MagicMock(spec=Redis)
    eval_mock = AsyncMock(side_effect=results)
    redis.eval = eval_mock
    return (
        VerificationService(
            cast(Redis, redis),
            hmac_secret=SECRET,
            allowed_purposes=ALL_PURPOSES,
            allowed_channels=ALL_CHANNELS,
        ),
        eval_mock,
    )


def flattened_calls(eval_mock: AsyncMock) -> Iterable[object]:
    for call in eval_mock.await_args_list:
        yield from call.args


async def test_issue_stores_only_digests_and_returns_separate_public_result() -> None:
    service, eval_mock = make_service(1)
    target = "Person@Example.Test"

    delivery = await service.issue_challenge(
        purpose=VerificationPurpose.REGISTRATION,
        channel=VerificationChannel.EMAIL,
        target=target,
    )

    assert isinstance(delivery, VerificationDeliveryPayload)
    assert delivery.challenge_id.version == 4
    assert delivery.plaintext_code.isascii()
    assert delivery.plaintext_code.isdigit()
    assert len(delivery.plaintext_code) == 6
    assert delivery.delivery_target == target.casefold()
    assert "plaintext_code" not in delivery.model_dump()
    assert "delivery_target" not in delivery.model_dump()
    assert delivery.plaintext_code not in repr(delivery)
    assert delivery.plaintext_code not in delivery.model_dump_json()
    encoded_delivery = jsonable_encoder(delivery)
    assert "plaintext_code" not in encoded_delivery
    assert "delivery_target" not in encoded_delivery
    assert delivery.plaintext_code not in tuple(flattened_calls(eval_mock))
    assert target not in tuple(flattened_calls(eval_mock))
    assert target.casefold() not in tuple(flattened_calls(eval_mock))
    public = delivery.to_public_result()
    assert public.model_dump() == {
        "challenge_id": delivery.challenge_id,
        "expires_in_seconds": 300,
    }

    assert eval_mock.await_args is not None
    issue_args = eval_mock.await_args.args
    assert issue_args[1] == 3
    assert all(isinstance(value, str) for value in issue_args[2:])
    keys = issue_args[2:5]
    assert all("person" not in str(key).casefold() for key in keys)
    assert all("example" not in str(key).casefold() for key in keys)
    assert all(str(delivery.challenge_id) not in str(key) for key in keys)
    hash_tags = {str(key).split("{", 1)[1].split("}", 1)[0] for key in keys}
    assert len(hash_tags) == 1


async def test_wrong_candidates_always_reach_atomic_attempt_counter() -> None:
    service, eval_mock = make_service(*([[0, attempt] for attempt in range(1, 6)]))
    challenge_id = uuid.uuid4()

    for attempt in range(5):
        with pytest.raises(VerificationInvalidError):
            await service.verify_challenge(
                challenge_id=challenge_id,
                purpose=VerificationPurpose.LOGIN,
                channel=VerificationChannel.EMAIL,
                target="not an email" if attempt == 0 else "person@example.test",
                code="wrong" if attempt == 1 else "000000",
            )

    assert eval_mock.await_count == 5
    assert all(call.args[10] == "5" for call in eval_mock.await_args_list)


async def test_expired_challenge_has_distinct_safe_error() -> None:
    service, _redis = make_service([-1, 0])

    with pytest.raises(VerificationExpiredError) as caught:
        await service.verify_challenge(
            challenge_id=uuid.uuid4(),
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.SMS,
            target="+15551234567",
            code="123456",
        )

    assert caught.value.reason == "verification_expired"


async def test_success_then_replay_is_invalid() -> None:
    service, _redis = make_service([1, 0], [0, 0])
    challenge_id = uuid.uuid4()

    async def verify() -> VerifiedChallenge:
        return await service.verify_challenge(
            challenge_id=challenge_id,
            purpose=VerificationPurpose.SENSITIVE_ACTION,
            channel=VerificationChannel.EMAIL,
            target="person@example.test",
            code="123456",
        )

    verified = await verify()
    assert verified.challenge_id == challenge_id
    with pytest.raises(VerificationInvalidError):
        await verify()


async def test_resend_invalidates_old_challenge_and_keeps_latest() -> None:
    service, eval_mock = make_service(1, 1, [0, 0], [1, 0])

    async def issue(target: str) -> VerificationDeliveryPayload:
        return await service.issue_challenge(
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.EMAIL,
            target=target,
        )

    old_delivery = await issue("Person@Example.Test")
    new_delivery = await issue(" person@example.test ")
    first_scope_keys = eval_mock.await_args_list[0].args[2:5]
    second_scope_keys = eval_mock.await_args_list[1].args[2:5]
    assert first_scope_keys[0] == second_scope_keys[0]
    assert first_scope_keys[1] != second_scope_keys[1]
    assert first_scope_keys[2] == second_scope_keys[2]
    hash_tags = {
        str(key).split("{", 1)[1].split("}", 1)[0]
        for key in first_scope_keys + second_scope_keys
    }
    assert len(hash_tags) == 1

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


async def test_cancel_is_idempotent_and_has_no_plaintext_arguments() -> None:
    service, eval_mock = make_service(1, 0)
    challenge_id = uuid.uuid4()

    async def cancel() -> bool:
        return await service.cancel_challenge(
            challenge_id=challenge_id,
            purpose=VerificationPurpose.REGISTRATION,
            channel=VerificationChannel.EMAIL,
            target="person@example.test",
        )

    assert await cancel() is True
    assert await cancel() is False
    assert all(
        "person@example.test" not in str(value) for value in flattened_calls(eval_mock)
    )
    assert all(
        str(challenge_id) not in str(value) for value in flattened_calls(eval_mock)
    )
    assert all(call.args[1] == 3 for call in eval_mock.await_args_list)


async def test_concurrent_verification_exposes_only_one_success() -> None:
    redis = MagicMock(spec=Redis)
    lock = asyncio.Lock()
    consumed = False

    async def atomic_eval(*_args: object) -> list[int]:
        nonlocal consumed
        async with lock:
            if consumed:
                return [0, 0]
            consumed = True
            return [1, 0]

    redis.eval = AsyncMock(side_effect=atomic_eval)
    service = VerificationService(
        cast(Redis, redis),
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
    )
    challenge_id = uuid.uuid4()

    async def verify_once() -> bool:
        try:
            await service.verify_challenge(
                challenge_id=challenge_id,
                purpose=VerificationPurpose.LOGIN,
                channel=VerificationChannel.EMAIL,
                target="person@example.test",
                code="123456",
            )
        except VerificationInvalidError:
            return False
        return True

    results = await asyncio.gather(*(verify_once() for _ in range(20)))
    assert results.count(True) == 1
    assert results.count(False) == 19


async def test_redis_failure_is_fail_closed_as_unavailable() -> None:
    redis = MagicMock(spec=Redis)
    redis.eval = AsyncMock(side_effect=RedisConnectionError("secret endpoint omitted"))
    service = VerificationService(
        cast(Redis, redis),
        hmac_secret=SECRET,
        allowed_purposes=ALL_PURPOSES,
        allowed_channels=ALL_CHANNELS,
    )

    with pytest.raises(VerificationUnavailableError) as caught:
        await service.issue_challenge(
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.EMAIL,
            target="person@example.test",
        )

    assert caught.value.reason == "verification_authority_unavailable"
    assert "endpoint" not in str(caught.value)


async def test_policy_and_target_constraints_are_server_owned() -> None:
    with pytest.raises(ValueError):
        VerificationPolicy(challenge_ttl_seconds=0)
    service, eval_mock = make_service(1)

    with pytest.raises(VerificationInvalidError):
        await service.issue_challenge(
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.SMS,
            target="5551234567",
        )
    eval_mock.assert_not_awaited()


async def test_purpose_rejects_wrong_delivery_channel() -> None:
    service, eval_mock = make_service()

    with pytest.raises(VerificationInvalidError) as caught:
        await service.issue_challenge(
            purpose=VerificationPurpose.EMAIL_CHANGE,
            channel=VerificationChannel.SMS,
            target="+15551234567",
        )

    assert caught.value.reason == "verification_channel_not_allowed"
    eval_mock.assert_not_awaited()


async def test_disabled_purpose_or_channel_is_rejected_before_redis() -> None:
    redis = MagicMock(spec=Redis)
    redis.eval = AsyncMock()
    service = VerificationService(
        cast(Redis, redis),
        hmac_secret=SECRET,
        allowed_purposes=frozenset({VerificationPurpose.REGISTRATION}),
        allowed_channels=frozenset({VerificationChannel.EMAIL}),
    )

    with pytest.raises(VerificationInvalidError, match="verification_flow_not_enabled"):
        await service.issue_challenge(
            purpose=VerificationPurpose.LOGIN,
            channel=VerificationChannel.EMAIL,
            target="person@example.test",
        )
    with pytest.raises(VerificationInvalidError, match="verification_flow_not_enabled"):
        await service.issue_challenge(
            purpose=VerificationPurpose.REGISTRATION,
            channel=VerificationChannel.SMS,
            target="+15551234567",
        )

    redis.eval.assert_not_awaited()


def test_service_rejects_empty_or_incompatible_flow_allowlists() -> None:
    redis = cast(Redis, MagicMock(spec=Redis))

    with pytest.raises(ValueError, match="allowed_purposes"):
        VerificationService(
            redis,
            hmac_secret=SECRET,
            allowed_purposes=frozenset(),
            allowed_channels=ALL_CHANNELS,
        )
    with pytest.raises(ValueError, match="requires an enabled channel"):
        VerificationService(
            redis,
            hmac_secret=SECRET,
            allowed_purposes=frozenset({VerificationPurpose.PHONE_CHANGE}),
            allowed_channels=frozenset({VerificationChannel.EMAIL}),
        )
