from __future__ import annotations

import ipaddress

from app.core.config import Settings
from app.core.security.policies import SecurityPolicies
from app.core.security.rate_limit import (
    RateLimitExceeded,
    RateLimitPolicy,
    RateLimitUnavailable,
    check_rate_limit,
)
from app.db.redis import RedisClient

_PUBLIC_CAPTCHA_SCENES = frozenset({"login", "register"})
_PRIVATE_CAPTCHA_SCENES = frozenset({"admin_create", "admin_reset", "self_change"})


def canonical_client_ip(value: str) -> str:
    """A missing/invalid trusted IP must not collapse users into one quota."""
    try:
        return ipaddress.ip_address(value).compressed
    except (TypeError, ValueError):
        raise RateLimitUnavailable("trusted client address is unavailable") from None


class AbuseDefenseService:
    """One fixed-window quota per business and server-owned subject."""

    def __init__(self, redis: RedisClient, settings: Settings) -> None:
        self._redis = redis
        self._settings = settings
        self._policies = SecurityPolicies.from_settings(settings)
        self._key_secret = settings.rate_limit_hmac_key.get_secret_value().encode(
            "utf-8"
        )

    async def check_login_attempt(
        self,
        *,
        client_ip: str,
    ) -> None:
        await self._check(self._policies.login, "ip", canonical_client_ip(client_ip))

    async def check_registration_attempt(
        self,
        *,
        client_ip: str,
    ) -> None:
        await self._check(
            self._policies.registration,
            "ip",
            canonical_client_ip(client_ip),
        )

    async def check_temporary_password_completion(self, *, client_ip: str) -> None:
        await self._check(
            self._policies.temporary_complete,
            "ip",
            canonical_client_ip(client_ip),
        )

    async def check_captcha_create(
        self,
        *,
        scene: str,
        client_ip: str | None = None,
        user_id: str | None = None,
    ) -> None:
        if (
            scene in _PUBLIC_CAPTCHA_SCENES
            and user_id is None
            and client_ip is not None
        ):
            subject_type, subject = "ip", canonical_client_ip(client_ip)
        elif (
            scene in _PRIVATE_CAPTCHA_SCENES
            and client_ip is None
            and isinstance(user_id, str)
            and user_id
            and len(user_id.encode("utf-8")) <= 1024
        ):
            subject_type, subject = "actor", user_id
        else:
            raise ValueError("captcha scene and authenticated subject do not match")
        await self._check(
            RateLimitPolicy(
                name=f"captcha_create_{scene}",
                limit=self._policies.captcha_create.limit,
                window_seconds=self._policies.captcha_create.window_seconds,
            ),
            subject_type,
            subject,
        )

    async def check_rejected_captcha_scene(
        self,
        *,
        client_ip: str | None = None,
        user_id: str | None = None,
    ) -> None:
        if client_ip is not None and user_id is None:
            subject_type, subject = "ip", canonical_client_ip(client_ip)
        elif (
            user_id is not None
            and client_ip is None
            and len(user_id.encode("utf-8")) <= 1024
            and user_id
        ):
            subject_type, subject = "actor", user_id
        else:
            raise ValueError("rejected captcha needs one trusted subject")
        await self._check(
            RateLimitPolicy(
                name="captcha_rejected_scene",
                limit=self._policies.captcha_create.limit,
                window_seconds=self._policies.captcha_create.window_seconds,
            ),
            subject_type,
            subject,
        )

    async def _check(
        self,
        policy: RateLimitPolicy,
        subject_type: str,
        subject: str,
    ) -> None:
        result = await check_rate_limit(
            self._redis,
            namespace=self._settings.rate_limit_namespace,
            policy=policy,
            subject_type=subject_type,
            subject=subject,
            key_secret=self._key_secret,
        )
        if not result.allowed:
            raise RateLimitExceeded(policy_name=policy.name, result=result)
