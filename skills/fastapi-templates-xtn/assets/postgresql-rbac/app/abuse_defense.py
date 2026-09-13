from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass
from typing import Final, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.rate_limit import (
    RateLimitCheck,
    RateLimitPolicy,
    RateLimitResult,
    RateLimitUnavailable,
    check_rate_limits,
)
from app.rate_limit_dependencies import RateLimitExceeded
from app.security_policies import SecurityPolicies
from app.settings import Settings
from app.verification import VerificationChannel, normalize_verification_target

_LOGIN_FAILURE_PREFIX: Final = "abuse:v1"
_MAX_IDENTITY_BYTES: Final = 512

_READ_LOGIN_FAILURE_SCRIPT: Final = r"""
local key = KEYS[1]
local raw = redis.call('GET', key)
if raw == false then
    return 0
end
local failures = tonumber(raw)
if not failures or failures < 0 or failures ~= math.floor(failures) then
    return redis.error_reply('invalid login failure state')
end
return failures
"""

_RECORD_LOGIN_FAILURE_SCRIPT: Final = r"""
local key = KEYS[1]
local retention_seconds = tonumber(ARGV[1])
if not retention_seconds or retention_seconds < 1
    or retention_seconds ~= math.floor(retention_seconds) then
    return redis.error_reply('invalid login failure retention')
end
local failures = redis.call('INCR', key)
redis.call('EXPIRE', key, retention_seconds)
return failures
"""


@dataclass(frozen=True, slots=True)
class LoginFailureState:
    consecutive_failures: int


def require_canonical_identity(value: str) -> str:
    """Validate an identity already normalized by the product's login policy."""
    if not isinstance(value, str):
        raise ValueError("normalized identity must be a bounded non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            "normalized identity must be a bounded non-empty string"
        ) from None
    if (
        not value
        or value != value.strip()
        or len(encoded) > _MAX_IDENTITY_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("normalized identity must be a bounded non-empty string")
    return value


def canonical_client_ip(value: str) -> str:
    if value == "unknown":
        # The ASGI boundary deliberately maps an untrusted or missing address to
        # one shared conservative bucket instead of reading spoofable headers.
        return value
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        raise ValueError("client_ip must be a trusted IPv4 or IPv6 address") from None


class AbuseDefenseService:
    """Reusable admission checks for login, registration, and code delivery."""

    def __init__(self, redis: Redis, settings: Settings) -> None:
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
        normalized_identifier: str,
    ) -> None:
        identifier = require_canonical_identity(normalized_identifier)
        client_ip = canonical_client_ip(client_ip)
        await self._check_all(
            (
                (self._policies.login_ip, "ip", client_ip),
                (
                    self._policies.login_pair,
                    "ip_account",
                    self._pair(client_ip, identifier),
                ),
                (self._policies.login_global, "global", "all"),
            )
        )

    async def check_registration_attempt(
        self,
        *,
        client_ip: str,
        normalized_identifier: str,
    ) -> None:
        identifier = require_canonical_identity(normalized_identifier)
        client_ip = canonical_client_ip(client_ip)
        await self._check_all(
            (
                (self._policies.registration_ip, "ip", client_ip),
                (self._policies.registration_target, "account", identifier),
                (
                    self._policies.registration_pair,
                    "ip_account",
                    self._pair(client_ip, identifier),
                ),
                (self._policies.registration_global, "global", "all"),
            )
        )

    async def check_verification_send(
        self,
        *,
        client_ip: str,
        channel: VerificationChannel,
        target: str,
    ) -> str:
        client_ip = canonical_client_ip(client_ip)
        normalized_target = normalize_verification_target(channel, target)
        pair = self._pair(client_ip, normalized_target)
        await self._check_all(
            (
                (
                    self._policies.verification_target_cooldown,
                    "target",
                    normalized_target,
                ),
                (
                    self._policies.verification_target_average,
                    "target",
                    normalized_target,
                ),
                (self._policies.verification_ip, "ip", client_ip),
                (self._policies.verification_pair, "ip_target", pair),
                (
                    self._policies.verification_channel,
                    "channel",
                    channel.value,
                ),
                (self._policies.verification_global, "global", "all"),
            )
        )
        return normalized_target

    async def check_verification_attempt(
        self,
        *,
        client_ip: str,
        channel: VerificationChannel,
        target: str,
    ) -> str:
        client_ip = canonical_client_ip(client_ip)
        normalized_target = normalize_verification_target(channel, target)
        await self._check_all(
            (
                (self._policies.verification_submit_ip, "ip", client_ip),
                (
                    self._policies.verification_submit_target,
                    "target",
                    normalized_target,
                ),
                (
                    self._policies.verification_submit_pair,
                    "ip_target",
                    self._pair(client_ip, normalized_target),
                ),
                (self._policies.verification_submit_global, "global", "all"),
            )
        )
        return normalized_target

    async def login_failure_state(
        self,
        normalized_identifier: str,
    ) -> LoginFailureState:
        key = self._login_failure_key(normalized_identifier)
        raw = await self._eval(
            _READ_LOGIN_FAILURE_SCRIPT,
            key,
        )
        return self._parse_failure_state(raw)

    async def record_login_failure(
        self,
        normalized_identifier: str,
    ) -> LoginFailureState:
        key = self._login_failure_key(normalized_identifier)
        raw = await self._eval(
            _RECORD_LOGIN_FAILURE_SCRIPT,
            key,
            self._settings.login_failure_state_retention_seconds,
        )
        return self._parse_failure_state(raw)

    async def record_login_success(self, normalized_identifier: str) -> None:
        key = self._login_failure_key(normalized_identifier)
        try:
            await cast(Awaitable[int], self._redis.delete(key))
        except RedisError:
            raise RateLimitUnavailable("abuse-defense store is unavailable") from None

    async def _check_all(
        self,
        checks: Iterable[tuple[RateLimitPolicy, str, str]],
    ) -> tuple[RateLimitResult, ...]:
        rate_checks = tuple(
            RateLimitCheck(policy, subject_type, subject)
            for policy, subject_type, subject in checks
        )
        decision = await check_rate_limits(
            self._redis,
            namespace=self._settings.rate_limit_namespace,
            checks=rate_checks,
            key_secret=self._key_secret,
        )
        if not decision.allowed:
            denied = [
                (check.policy, result)
                for check, result in zip(
                    rate_checks,
                    decision.results,
                    strict=True,
                )
                if not result.allowed
            ]
            policy, result = max(denied, key=lambda item: item[1].retry_after_ms)
            raise RateLimitExceeded(policy_name=policy.name, result=result)
        return decision.results

    async def _eval(self, script: str, key: str, *arguments: int) -> object:
        try:
            return await cast(
                Awaitable[object],
                self._redis.eval(script, 1, key, *arguments),
            )
        except RedisError:
            raise RateLimitUnavailable("abuse-defense store is unavailable") from None

    def _login_failure_key(self, normalized_identifier: str) -> str:
        identifier = require_canonical_identity(normalized_identifier)
        digest = hmac.new(
            self._key_secret,
            f"login_failure\0{identifier}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return (
            f"{_LOGIN_FAILURE_PREFIX}:{self._settings.rate_limit_namespace}:"
            f"login_failure:{digest}"
        )

    @staticmethod
    def _pair(left: str, right: str) -> str:
        return f"{left}\0{right}"

    @staticmethod
    def _parse_failure_state(raw: object) -> LoginFailureState:
        if isinstance(raw, bool) or not isinstance(raw, (int, str, bytes)):
            raise RateLimitUnavailable("abuse-defense store returned invalid state")
        try:
            consecutive_failures = int(raw)
        except ValueError:
            raise RateLimitUnavailable(
                "abuse-defense store returned invalid state"
            ) from None
        if consecutive_failures < 0:
            raise RateLimitUnavailable("abuse-defense store returned invalid state")
        return LoginFailureState(consecutive_failures=consecutive_failures)
