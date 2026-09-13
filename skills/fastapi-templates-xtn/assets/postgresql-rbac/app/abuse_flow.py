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
    """Admit requests before running credential or registration callbacks."""

    def __init__(self, abuse_defense: AbuseDefenseService) -> None:
        self._abuse_defense = abuse_defense

    async def authenticate(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        """The callback does real-or-dummy work and never issues a token."""

        await self._abuse_defense.check_login_attempt(
            client_ip=client_ip,
            normalized_identifier=normalized_identifier,
        )
        result = await verify_real_or_dummy_credentials()
        if result is None:
            raise InvalidLoginCredentialsError()
        return result

    async def complete_temporary_password_reset(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        """Use a separate anonymous quota for completing temporary credentials."""
        await self._abuse_defense.check_temporary_password_completion(
            client_ip=client_ip
        )
        result = await verify_real_or_dummy_credentials()
        if result is None:
            raise InvalidLoginCredentialsError()
        return result

    async def register(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
        registration_action: Callable[[], Awaitable[_ResultT]],
    ) -> _ResultT:
        """Run product registration only after the named IP quota allows it."""

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
