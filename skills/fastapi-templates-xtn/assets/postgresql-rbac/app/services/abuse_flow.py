from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from app.core.config import Settings
from app.core.security.abuse_defense import AbuseDefenseService
from app.db.redis import RedisClient

_ResultT = TypeVar("_ResultT")


class InvalidLoginCredentialsError(RuntimeError):
    """One public-safe login rejection for every invalid credential state."""

    def __init__(self) -> None:
        super().__init__("invalid_login_credentials")


class IdentityAbuseFlow:
    """Admit requests before running credential or registration callbacks."""

    def __init__(
        self,
        abuse_defense: AbuseDefenseService,
        *,
        post_admission_check: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._abuse_defense = abuse_defense
        self._post_admission_check = post_admission_check

    async def _check_admitted_request(self) -> None:
        if self._post_admission_check is not None:
            await self._post_admission_check()

    async def authenticate(
        self,
        *,
        client_ip: str,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        """The callback does real-or-dummy work and never issues a token."""

        await self._abuse_defense.check_login_attempt(
            client_ip=client_ip,
        )
        return await self._verify_admitted_credentials(verify_real_or_dummy_credentials)

    async def complete_temporary_password_reset(
        self,
        *,
        client_ip: str,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        """Use a separate anonymous quota for completing temporary credentials."""
        await self._abuse_defense.check_temporary_password_completion(
            client_ip=client_ip
        )
        return await self._verify_admitted_credentials(verify_real_or_dummy_credentials)

    async def _verify_admitted_credentials(
        self,
        verify_real_or_dummy_credentials: Callable[[], Awaitable[_ResultT | None]],
    ) -> _ResultT:
        await self._check_admitted_request()
        result = await verify_real_or_dummy_credentials()
        if result is None:
            raise InvalidLoginCredentialsError()
        return result

    async def register(
        self,
        *,
        client_ip: str,
        registration_action: Callable[[], Awaitable[_ResultT]],
    ) -> _ResultT:
        """Run product registration only after the named IP quota allows it."""

        await self._abuse_defense.check_registration_attempt(
            client_ip=client_ip,
        )
        await self._check_admitted_request()
        return await registration_action()


def build_identity_abuse_flow(
    redis: RedisClient,
    *,
    settings: Settings,
    post_admission_check: Callable[[], Awaitable[None]] | None = None,
) -> IdentityAbuseFlow:
    return IdentityAbuseFlow(
        AbuseDefenseService(redis, settings),
        post_admission_check=post_admission_check,
    )
