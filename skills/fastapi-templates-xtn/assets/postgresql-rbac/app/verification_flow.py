from __future__ import annotations

import asyncio
import uuid
from typing import Protocol

from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.settings import Settings
from app.verification import (
    VerificationChannel,
    VerificationDeliveryPayload,
    VerificationPolicy,
    VerificationPublicResult,
    VerificationPurpose,
    VerificationService,
    VerifiedChallenge,
)


class VerificationDeliveryAdapter(Protocol):
    async def send(
        self,
        *,
        channel: VerificationChannel,
        normalized_target: str,
        purpose: VerificationPurpose,
        code: str,
    ) -> None: ...


class VerificationDeliveryUnavailableError(RuntimeError):
    """A provider failed without exposing its response or credentials."""

    def __init__(self) -> None:
        super().__init__("verification_delivery_unavailable")


class VerificationFlowConfigurationError(RuntimeError):
    """The optional verification flow is disabled or incompletely configured."""


class VerificationFlowService:
    """Compose abuse checks, challenge state, and an application-owned provider."""

    def __init__(
        self,
        *,
        abuse_defense: AbuseDefenseService,
        verification: VerificationService,
        delivery: VerificationDeliveryAdapter,
    ) -> None:
        self._abuse_defense = abuse_defense
        self._verification = verification
        self._delivery = delivery

    async def issue_and_send(
        self,
        *,
        client_ip: str,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target: str,
    ) -> VerificationPublicResult:
        normalized_target = await self._abuse_defense.check_verification_send(
            client_ip=client_ip,
            channel=channel,
            target=target,
        )
        payload = await self._verification.issue_challenge(
            purpose=purpose,
            channel=channel,
            target=normalized_target,
        )
        try:
            await self._deliver(payload)
        except asyncio.CancelledError:
            await self._cancel_after_failed_delivery(payload)
            raise
        except Exception:
            await self._cancel_after_failed_delivery(payload)
            raise VerificationDeliveryUnavailableError() from None
        return payload.to_public_result()

    async def verify(
        self,
        *,
        client_ip: str,
        challenge_id: uuid.UUID,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target: str,
        code: str,
    ) -> VerifiedChallenge:
        normalized_target = await self._abuse_defense.check_verification_attempt(
            client_ip=client_ip,
            channel=channel,
            target=target,
        )
        return await self._verification.verify_challenge(
            challenge_id=challenge_id,
            purpose=purpose,
            channel=channel,
            target=normalized_target,
            code=code,
        )

    async def _deliver(self, payload: VerificationDeliveryPayload) -> None:
        await self._delivery.send(
            channel=payload.channel,
            normalized_target=payload.delivery_target,
            purpose=payload.purpose,
            code=payload.plaintext_code,
        )

    async def _cancel_after_failed_delivery(
        self,
        payload: VerificationDeliveryPayload,
    ) -> None:
        try:
            await asyncio.shield(
                self._verification.cancel_challenge(
                    challenge_id=payload.challenge_id,
                    purpose=payload.purpose,
                    channel=payload.channel,
                    target=payload.delivery_target,
                )
            )
        except Exception:
            # The challenge remains bounded by its short TTL. Never expose cleanup
            # or provider details, and never refund the independent send quota.
            return


def build_verification_flow(
    redis: Redis,
    *,
    settings: Settings,
    delivery: VerificationDeliveryAdapter,
) -> VerificationFlowService:
    if not settings.verification_enabled:
        raise VerificationFlowConfigurationError(
            "verification is disabled; set VERIFICATION_ENABLED=true before "
            "building the verification flow"
        )

    hmac_key = settings.verification_code_hmac_key
    if hmac_key is None or not hmac_key.get_secret_value():
        raise VerificationFlowConfigurationError(
            "VERIFICATION_CODE_HMAC_KEY is required when verification is enabled"
        )

    purpose_names = tuple(
        item.strip()
        for item in settings.verification_enabled_purposes.split(",")
        if item.strip()
    )
    if not purpose_names:
        raise VerificationFlowConfigurationError(
            "VERIFICATION_ENABLED_PURPOSES must contain at least one purpose "
            "when verification is enabled"
        )

    channel_names = tuple(
        item.strip()
        for item in settings.verification_enabled_channels.split(",")
        if item.strip()
    )
    if not channel_names:
        raise VerificationFlowConfigurationError(
            "VERIFICATION_ENABLED_CHANNELS must contain at least one channel "
            "when verification is enabled"
        )

    allowed_purposes = frozenset(VerificationPurpose(item) for item in purpose_names)
    allowed_channels = frozenset(VerificationChannel(item) for item in channel_names)
    verification = VerificationService(
        redis,
        hmac_secret=hmac_key.get_secret_value(),
        allowed_purposes=allowed_purposes,
        allowed_channels=allowed_channels,
        namespace=(f"verification:challenge:v1:{settings.rate_limit_namespace}"),
        policy=VerificationPolicy(
            code_digits=settings.verification_code_length,
            challenge_ttl_seconds=settings.verification_code_ttl_seconds,
            max_attempts=settings.verification_max_attempts,
            expired_status_retention_seconds=settings.verification_code_ttl_seconds,
        ),
    )
    return VerificationFlowService(
        abuse_defense=AbuseDefenseService(redis, settings),
        verification=verification,
        delivery=delivery,
    )
