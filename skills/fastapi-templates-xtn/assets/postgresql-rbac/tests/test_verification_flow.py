import uuid
from types import SimpleNamespace
from typing import cast
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr
from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.settings import Settings
from app.verification import (
    VerificationChannel,
    VerificationDeliveryPayload,
    VerificationPurpose,
    VerificationService,
    VerifiedChallenge,
)
from app.verification_flow import (
    VerificationDeliveryAdapter,
    VerificationDeliveryUnavailableError,
    VerificationFlowConfigurationError,
    VerificationFlowService,
    build_verification_flow,
)

VERIFICATION_SECRET = "V5nL8rQ2xM7kT4pC9sD1fH6jB3yW0uGz"


class CapturingDelivery:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[VerificationChannel, str, VerificationPurpose, str]] = []

    async def send(
        self,
        *,
        channel: VerificationChannel,
        normalized_target: str,
        purpose: VerificationPurpose,
        code: str,
    ) -> None:
        self.calls.append((channel, normalized_target, purpose, code))
        if self.fail:
            raise RuntimeError("provider secret response")


def flow_with_payload(
    *,
    fail_delivery: bool = False,
) -> tuple[VerificationFlowService, AsyncMock, AsyncMock, CapturingDelivery]:
    challenge_id = uuid.uuid4()
    payload = VerificationDeliveryPayload.create(
        challenge_id=challenge_id,
        purpose=VerificationPurpose.REGISTRATION,
        channel=VerificationChannel.EMAIL,
        expires_in_seconds=300,
        delivery_target="person@example.test",
        plaintext_code="012345",
    )
    defense = AsyncMock(spec=AbuseDefenseService)
    defense.check_verification_send.return_value = "person@example.test"
    verification = AsyncMock(spec=VerificationService)
    verification.issue_challenge.return_value = payload
    verification.cancel_challenge.return_value = True
    delivery = CapturingDelivery(fail=fail_delivery)
    flow = VerificationFlowService(
        abuse_defense=cast(AbuseDefenseService, defense),
        verification=cast(VerificationService, verification),
        delivery=cast(VerificationDeliveryAdapter, delivery),
    )
    return flow, defense, verification, delivery


async def test_issue_sends_internally_but_returns_only_public_fields() -> None:
    flow, defense, verification, delivery = flow_with_payload()

    result = await flow.issue_and_send(
        client_ip="198.51.100.20",
        purpose=VerificationPurpose.REGISTRATION,
        channel=VerificationChannel.EMAIL,
        target="Person@Example.Test",
    )

    assert result.expires_in_seconds == 300
    assert set(result.model_dump()) == {"challenge_id", "expires_in_seconds"}
    assert delivery.calls == [
        (
            VerificationChannel.EMAIL,
            "person@example.test",
            VerificationPurpose.REGISTRATION,
            "012345",
        )
    ]
    defense.check_verification_send.assert_awaited_once()
    verification.cancel_challenge.assert_not_awaited()


async def test_delivery_failure_cancels_challenge_without_leaking_provider_error() -> (
    None
):
    flow, _defense, verification, _delivery = flow_with_payload(fail_delivery=True)

    with pytest.raises(VerificationDeliveryUnavailableError) as caught:
        await flow.issue_and_send(
            client_ip="198.51.100.21",
            purpose=VerificationPurpose.REGISTRATION,
            channel=VerificationChannel.EMAIL,
            target="person@example.test",
        )

    assert str(caught.value) == "verification_delivery_unavailable"
    assert "provider" not in str(caught.value)
    verification.cancel_challenge.assert_awaited_once()


async def test_verify_checks_submission_limits_before_consuming_code() -> None:
    flow, defense, verification, _delivery = flow_with_payload()
    challenge_id = uuid.uuid4()
    verified = VerifiedChallenge(
        challenge_id=challenge_id,
        purpose=VerificationPurpose.LOGIN,
        channel=VerificationChannel.SMS,
    )
    defense.check_verification_attempt.return_value = "+15551234567"
    verification.verify_challenge.return_value = verified

    result = await flow.verify(
        client_ip="198.51.100.22",
        challenge_id=challenge_id,
        purpose=VerificationPurpose.LOGIN,
        channel=VerificationChannel.SMS,
        target="+15551234567",
        code="123456",
    )

    assert result == verified
    defense.check_verification_attempt.assert_awaited_once()
    verification.verify_challenge.assert_awaited_once_with(
        challenge_id=challenge_id,
        purpose=VerificationPurpose.LOGIN,
        channel=VerificationChannel.SMS,
        target="+15551234567",
        code="123456",
    )


def optional_verification_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "verification_enabled": True,
        "verification_code_hmac_key": SecretStr(VERIFICATION_SECRET),
        "verification_enabled_purposes": "registration,login",
        "verification_enabled_channels": "email,sms",
        "rate_limit_namespace": "test",
        "verification_code_length": 6,
        "verification_code_ttl_seconds": 300,
        "verification_max_attempts": 5,
    }
    values.update(overrides)
    return cast(Settings, SimpleNamespace(**values))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"verification_enabled": False},
            "verification is disabled; set VERIFICATION_ENABLED=true",
        ),
        (
            {"verification_code_hmac_key": None},
            "VERIFICATION_CODE_HMAC_KEY is required",
        ),
        (
            {"verification_enabled_purposes": ""},
            "VERIFICATION_ENABLED_PURPOSES must contain at least one purpose",
        ),
        (
            {"verification_enabled_channels": ""},
            "VERIFICATION_ENABLED_CHANNELS must contain at least one channel",
        ),
    ],
)
def test_builder_rejects_disabled_or_incomplete_optional_verification(
    overrides: dict[str, object],
    message: str,
) -> None:
    redis = cast(Redis, MagicMock(spec=Redis))
    delivery = cast(VerificationDeliveryAdapter, CapturingDelivery())

    with pytest.raises(VerificationFlowConfigurationError, match=message):
        build_verification_flow(
            redis,
            settings=optional_verification_settings(**overrides),
            delivery=delivery,
        )


def test_builder_keeps_configured_verification_behavior() -> None:
    redis = cast(Redis, MagicMock(spec=Redis))
    delivery = cast(VerificationDeliveryAdapter, CapturingDelivery())
    settings = optional_verification_settings()
    verification = MagicMock(spec=VerificationService)
    defense = MagicMock(spec=AbuseDefenseService)

    with (
        patch(
            "app.verification_flow.VerificationService",
            return_value=verification,
        ) as verification_type,
        patch(
            "app.verification_flow.AbuseDefenseService",
            return_value=defense,
        ) as defense_type,
    ):
        flow = build_verification_flow(
            redis,
            settings=settings,
            delivery=delivery,
        )

    assert isinstance(flow, VerificationFlowService)
    assert flow._verification is verification
    assert flow._abuse_defense is defense
    defense_type.assert_called_once_with(redis, settings)
    verification_type.assert_called_once_with(
        redis,
        hmac_secret=VERIFICATION_SECRET,
        allowed_purposes=frozenset(
            {VerificationPurpose.REGISTRATION, VerificationPurpose.LOGIN}
        ),
        allowed_channels=frozenset(
            {VerificationChannel.EMAIL, VerificationChannel.SMS}
        ),
        namespace="verification:challenge:v1:test",
        policy=ANY,
    )
