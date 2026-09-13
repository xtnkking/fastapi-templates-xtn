from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.settings import Settings

_ResultT = TypeVar("_ResultT")


class InvalidLoginCredentialsError(RuntimeError):
    """One public-safe login rejection for every invalid credential state."""

    def __init__(self) -> None:
        super().__init__("invalid_login_credentials")


class IdentityAbuseFlow:
    """Apply admission limits while keeping account failures non-blocking."""

    def __init__(self, abuse_defense: AbuseDefenseService) -> None:
        self._abuse_defense = abuse_defense

    async def authenticate(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        """Return the verified value; ``None`` is the only invalid result.

        The callback owns real-versus-dummy password hashing but must not issue a
        token. Account failure counts are risk signals only: admission never rejects
        a correct password based solely on prior attempts for that identifier.
        Token issuance starts only after this method returns successfully.
        """

        await self._abuse_defense.check_login_attempt(
            client_ip=client_ip,
            normalized_identifier=normalized_identifier,
        )
        result = await verify_real_or_dummy_credentials()
        if result is None:
            await self._abuse_defense.record_login_failure(normalized_identifier)
            raise InvalidLoginCredentialsError()
        await self._abuse_defense.record_login_success(normalized_identifier)
        return result

    async def register(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
        registration_action: Callable[[], Awaitable[_ResultT]],
    ) -> _ResultT:
        """Run product registration only after all admission buckets allow it."""

        await self._abuse_defense.check_registration_attempt(
            client_ip=client_ip,
            normalized_identifier=normalized_identifier,
        )
        return await registration_action()


def build_identity_abuse_flow(
    redis: Redis,
    *,
    settings: Settings,
) -> IdentityAbuseFlow:
    return IdentityAbuseFlow(AbuseDefenseService(redis, settings))
