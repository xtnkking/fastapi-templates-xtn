from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass
from enum import StrEnum
from string import digits
from types import MappingProxyType
from typing import Final, TypeVar, cast

from pydantic import BaseModel, ConfigDict, PrivateAttr
from redis.asyncio import Redis
from redis.exceptions import RedisError


class VerificationChannel(StrEnum):
    EMAIL = "email"
    SMS = "sms"


class VerificationPurpose(StrEnum):
    REGISTRATION = "registration"
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    EMAIL_CHANGE = "email_change"
    PHONE_CHANGE = "phone_change"
    SENSITIVE_ACTION = "sensitive_action"


PURPOSE_CHANNEL_POLICY: Final = MappingProxyType(
    {
        VerificationPurpose.REGISTRATION: frozenset(VerificationChannel),
        VerificationPurpose.LOGIN: frozenset(VerificationChannel),
        VerificationPurpose.PASSWORD_RESET: frozenset(VerificationChannel),
        VerificationPurpose.EMAIL_CHANGE: frozenset({VerificationChannel.EMAIL}),
        VerificationPurpose.PHONE_CHANGE: frozenset({VerificationChannel.SMS}),
        VerificationPurpose.SENSITIVE_ACTION: frozenset(VerificationChannel),
    }
)


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """Server-owned defaults; never accept these values from a request body."""

    code_digits: int = 6
    challenge_ttl_seconds: int = 300
    max_attempts: int = 5
    expired_status_retention_seconds: int = 300

    def __post_init__(self) -> None:
        if not 4 <= self.code_digits <= 10:
            raise ValueError("code_digits must be between 4 and 10")
        if not 1 <= self.challenge_ttl_seconds <= 1800:
            raise ValueError("challenge_ttl_seconds must be between 1 and 1800")
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if not 60 <= self.expired_status_retention_seconds <= 86400:
            raise ValueError(
                "expired_status_retention_seconds must be between 60 and 86400"
            )


DEFAULT_VERIFICATION_POLICY: Final = VerificationPolicy()


class VerificationError(RuntimeError):
    """Base error with a stable, non-sensitive reason for the API adapter."""

    default_reason = "verification_failed"

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason or self.default_reason
        super().__init__(self.reason)


class VerificationInvalidError(VerificationError):
    default_reason = "verification_invalid"


class VerificationExpiredError(VerificationError):
    default_reason = "verification_expired"


class VerificationUnavailableError(VerificationError):
    default_reason = "verification_authority_unavailable"


class VerificationPublicResult(BaseModel):
    """The only issuance object intended for an HTTP response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: uuid.UUID
    expires_in_seconds: int


class VerificationDeliveryPayload(BaseModel):
    """Internal-only payload for an email/SMS adapter.

    The plaintext target and code are Pydantic private attributes. Consequently,
    ``model_dump`` and FastAPI response serialization cannot expose them. Delivery
    adapters deliberately access the two explicit properties below.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: uuid.UUID
    purpose: VerificationPurpose
    channel: VerificationChannel
    expires_in_seconds: int
    _delivery_target: str = PrivateAttr()
    _plaintext_code: str = PrivateAttr()

    @classmethod
    def create(
        cls,
        *,
        challenge_id: uuid.UUID,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        expires_in_seconds: int,
        delivery_target: str,
        plaintext_code: str,
    ) -> VerificationDeliveryPayload:
        payload = cls(
            challenge_id=challenge_id,
            purpose=purpose,
            channel=channel,
            expires_in_seconds=expires_in_seconds,
        )
        payload._delivery_target = delivery_target
        payload._plaintext_code = plaintext_code
        return payload

    @property
    def delivery_target(self) -> str:
        return self._delivery_target

    @property
    def plaintext_code(self) -> str:
        return self._plaintext_code

    def to_public_result(self) -> VerificationPublicResult:
        return VerificationPublicResult(
            challenge_id=self.challenge_id,
            expires_in_seconds=self.expires_in_seconds,
        )


class VerifiedChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: uuid.UUID
    purpose: VerificationPurpose
    channel: VerificationChannel


_ISSUE_CHALLENGE_SCRIPT: Final = """
local pointer_key = KEYS[1]
local challenge_key = KEYS[2]
local state_key = KEYS[3]

local function secure_equals(left, right)
    if not left or not right or string.len(left) ~= string.len(right) then
        return false
    end
    local different = 0
    for index = 1, string.len(left) do
        different = different + math.abs(
            string.byte(left, index) - string.byte(right, index)
        )
    end
    return different == 0
end

local previous = redis.call('GET', pointer_key)
local state_challenge = redis.call('HGET', state_key, 'challenge_id_fingerprint')
if secure_equals(previous, ARGV[1]) or
   secure_equals(state_challenge, ARGV[1]) or
   redis.call('EXISTS', challenge_key) == 1 then
    return 0
end

if previous then
    if string.len(previous) ~= 64 or string.find(previous, '[^0-9a-f]') then
        return redis.error_reply('invalid verification state')
    end
    -- This derived key has the same target-HMAC hash tag as every KEYS entry.
    redis.call('DEL', ARGV[8] .. previous)
end

redis.call(
    'HSET', challenge_key,
    'challenge_id_fingerprint', ARGV[1],
    'code_digest', ARGV[2],
    'target_fingerprint', ARGV[3],
    'purpose', ARGV[4],
    'channel', ARGV[5],
    'attempts_used', 0
)
redis.call('EXPIRE', challenge_key, tonumber(ARGV[6]))
redis.call('SET', pointer_key, ARGV[1], 'EX', tonumber(ARGV[6]))
redis.call(
    'HSET', state_key,
    'challenge_id_fingerprint', ARGV[1],
    'state', 'issued'
)
redis.call('EXPIRE', state_key, tonumber(ARGV[7]))
return 1
"""


_VERIFY_CHALLENGE_SCRIPT: Final = """
local pointer_key = KEYS[1]
local challenge_key = KEYS[2]
local state_key = KEYS[3]

local function secure_equals(left, right)
    if not left or not right or string.len(left) ~= string.len(right) then
        return false
    end
    local different = 0
    for index = 1, string.len(left) do
        different = different + math.abs(
            string.byte(left, index) - string.byte(right, index)
        )
    end
    return different == 0
end

local function retain_state(value)
    local ttl = redis.call('TTL', state_key)
    if ttl < 1 then
        ttl = tonumber(ARGV[7])
    end
    redis.call(
        'HSET', state_key,
        'challenge_id_fingerprint', ARGV[1],
        'state', value
    )
    redis.call('EXPIRE', state_key, ttl)
end

local pointer = redis.call('GET', pointer_key)
local stored_state = redis.call(
    'HMGET', state_key, 'challenge_id_fingerprint', 'state'
)

if pointer == false then
    if secure_equals(stored_state[1], ARGV[1]) and
       (stored_state[2] == 'issued' or stored_state[2] == 'expired') then
        redis.call('DEL', challenge_key)
        retain_state('expired')
        return {-1, 0}
    end
    return {0, 0}
end

if not secure_equals(pointer, ARGV[1]) then
    return {0, 0}
end

if redis.call('EXISTS', challenge_key) == 0 then
    redis.call('DEL', pointer_key)
    if secure_equals(stored_state[1], ARGV[1]) and
       (stored_state[2] == 'issued' or stored_state[2] == 'expired') then
        retain_state('expired')
        return {-1, 0}
    end
    retain_state('consumed')
    return {-2, 0}
end

if not secure_equals(stored_state[1], ARGV[1]) or
   stored_state[2] ~= 'issued' then
    redis.call('DEL', pointer_key, challenge_key)
    retain_state('consumed')
    return {-2, 0}
end

local stored = redis.call(
    'HMGET', challenge_key,
    'challenge_id_fingerprint', 'code_digest', 'target_fingerprint',
    'purpose', 'channel', 'attempts_used'
)
for index = 1, 6 do
    if stored[index] == false then
        redis.call('DEL', pointer_key, challenge_key)
        retain_state('consumed')
        return {-2, 0}
    end
end

local attempts = tonumber(stored[6])
if attempts == nil then
    redis.call('DEL', pointer_key, challenge_key)
    retain_state('consumed')
    return {-2, 0}
end

local matches =
    secure_equals(stored[1], ARGV[1]) and
    secure_equals(stored[2], ARGV[2]) and
    secure_equals(stored[3], ARGV[3]) and
    stored[4] == ARGV[4] and
    stored[5] == ARGV[5]

if not matches then
    attempts = redis.call('HINCRBY', challenge_key, 'attempts_used', 1)
    if attempts >= tonumber(ARGV[6]) then
        redis.call('DEL', challenge_key)
        if secure_equals(redis.call('GET', pointer_key), ARGV[1]) then
            redis.call('DEL', pointer_key)
        end
        retain_state('consumed')
    end
    return {0, attempts}
end

redis.call('DEL', challenge_key)
if secure_equals(redis.call('GET', pointer_key), ARGV[1]) then
    redis.call('DEL', pointer_key)
end
retain_state('consumed')
return {1, attempts}
"""


_CANCEL_CHALLENGE_SCRIPT: Final = """
local pointer_key = KEYS[1]
local challenge_key = KEYS[2]
local state_key = KEYS[3]

local function secure_equals(left, right)
    if not left or not right or string.len(left) ~= string.len(right) then
        return false
    end
    local different = 0
    for index = 1, string.len(left) do
        different = different + math.abs(
            string.byte(left, index) - string.byte(right, index)
        )
    end
    return different == 0
end

if not secure_equals(redis.call('GET', pointer_key), ARGV[1]) then
    return 0
end

redis.call('DEL', pointer_key, challenge_key)
local ttl = redis.call('TTL', state_key)
if ttl < 1 then
    ttl = tonumber(ARGV[2])
end
redis.call(
    'HSET', state_key,
    'challenge_id_fingerprint', ARGV[1],
    'state', 'cancelled'
)
redis.call('EXPIRE', state_key, ttl)
return 1
"""


_EMAIL_PATTERN: Final = re.compile(r"^[^@\s]+@[^@\s]+$")
_SMS_PATTERN: Final = re.compile(r"^\+[1-9][0-9]{6,14}$")
_NAMESPACE_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9:_-]{0,79}$")
_EnumT = TypeVar("_EnumT", bound=StrEnum)
_RedisArgument = str | int


def normalize_verification_target(
    channel: VerificationChannel,
    target: str,
) -> str:
    """Return the canonical target used by both rate limits and challenges."""
    try:
        normalized_channel = VerificationChannel(channel)
    except (TypeError, ValueError):
        raise VerificationInvalidError() from None
    if not isinstance(target, str):
        raise VerificationInvalidError("verification_target_invalid")
    normalized = target.strip()
    if (
        not normalized
        or len(normalized) > 320
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise VerificationInvalidError("verification_target_invalid")
    if normalized_channel is VerificationChannel.EMAIL:
        normalized = normalized.casefold()
        if not _EMAIL_PATTERN.fullmatch(normalized):
            raise VerificationInvalidError("verification_target_invalid")
    elif not _SMS_PATTERN.fullmatch(normalized):
        raise VerificationInvalidError("verification_target_invalid")
    return normalized


class VerificationService:
    def __init__(
        self,
        redis: Redis,
        *,
        hmac_secret: str | bytes,
        allowed_purposes: frozenset[VerificationPurpose],
        allowed_channels: frozenset[VerificationChannel],
        namespace: str = "verification:challenge:v1",
        policy: VerificationPolicy = DEFAULT_VERIFICATION_POLICY,
    ) -> None:
        secret = (
            hmac_secret.encode("utf-8") if isinstance(hmac_secret, str) else hmac_secret
        )
        if len(secret) < 32:
            raise ValueError("verification HMAC secret must contain at least 32 bytes")
        if not _NAMESPACE_PATTERN.fullmatch(namespace):
            raise ValueError("verification namespace contains unsupported characters")
        if not allowed_purposes or any(
            not isinstance(purpose, VerificationPurpose) for purpose in allowed_purposes
        ):
            raise ValueError("allowed_purposes must contain supported purpose values")
        if not allowed_channels or any(
            not isinstance(channel, VerificationChannel) for channel in allowed_channels
        ):
            raise ValueError("allowed_channels must contain supported channel values")
        if any(
            not (PURPOSE_CHANNEL_POLICY[purpose] & allowed_channels)
            for purpose in allowed_purposes
        ):
            raise ValueError(
                "every enabled verification purpose requires an enabled channel"
            )
        self._redis = redis
        self._hmac_secret = secret
        self._namespace = namespace
        self._policy = policy
        self._allowed_purposes = allowed_purposes
        self._allowed_channels = allowed_channels

    async def issue_challenge(
        self,
        *,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target: str,
    ) -> VerificationDeliveryPayload:
        purpose = self._enum_value(VerificationPurpose, purpose)
        channel = self._enum_value(VerificationChannel, channel)
        self._require_enabled(purpose, channel)
        normalized_target = normalize_verification_target(channel, target)
        target_digest = self._target_digest(channel, normalized_target)

        for _ in range(3):
            challenge_id = uuid.uuid4()
            plaintext_code = "".join(
                secrets.choice(digits) for _ in range(self._policy.code_digits)
            )
            challenge_digest = self._digest("challenge", str(challenge_id))
            code_digest = self._code_digest(
                challenge_id=challenge_id,
                purpose=purpose,
                channel=channel,
                target_digest=target_digest,
                code=plaintext_code,
            )
            pointer_key, challenge_key, state_key, challenge_key_prefix = self._keys(
                target_digest,
                purpose,
                channel,
                challenge_digest,
            )
            result = await self._eval(
                _ISSUE_CHALLENGE_SCRIPT,
                3,
                pointer_key,
                challenge_key,
                state_key,
                challenge_digest,
                code_digest,
                target_digest,
                purpose.value,
                channel.value,
                self._policy.challenge_ttl_seconds,
                self._state_ttl_seconds,
                challenge_key_prefix,
            )
            if self._as_integer(result) == 1:
                return VerificationDeliveryPayload.create(
                    challenge_id=challenge_id,
                    purpose=purpose,
                    channel=channel,
                    expires_in_seconds=self._policy.challenge_ttl_seconds,
                    delivery_target=normalized_target,
                    plaintext_code=plaintext_code,
                )

        raise VerificationUnavailableError("verification_challenge_collision")

    async def verify_challenge(
        self,
        *,
        challenge_id: uuid.UUID,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target: str,
        code: str,
    ) -> VerifiedChallenge:
        if challenge_id.version != 4:
            raise VerificationInvalidError()
        purpose = self._enum_value(VerificationPurpose, purpose)
        channel = self._enum_value(VerificationChannel, channel)
        self._require_enabled(purpose, channel)
        normalized_target = self._normalize_candidate_target(channel, target)
        candidate_code = (
            code
            if isinstance(code, str)
            and len(code) == self._policy.code_digits
            and code.isascii()
            and code.isdigit()
            else "invalid-code"
        )
        challenge_digest = self._digest("challenge", str(challenge_id))
        target_digest = self._target_digest(channel, normalized_target)
        code_digest = self._code_digest(
            challenge_id=challenge_id,
            purpose=purpose,
            channel=channel,
            target_digest=target_digest,
            code=candidate_code,
        )
        pointer_key, challenge_key, state_key, _challenge_key_prefix = self._keys(
            target_digest,
            purpose,
            channel,
            challenge_digest,
        )
        raw_result = await self._eval(
            _VERIFY_CHALLENGE_SCRIPT,
            3,
            pointer_key,
            challenge_key,
            state_key,
            challenge_digest,
            code_digest,
            target_digest,
            purpose.value,
            channel.value,
            self._policy.max_attempts,
            self._state_ttl_seconds,
        )
        result = self._verification_result(raw_result)
        if result == 1:
            return VerifiedChallenge(
                challenge_id=challenge_id,
                purpose=purpose,
                channel=channel,
            )
        if result == -1:
            raise VerificationExpiredError()
        if result == 0:
            raise VerificationInvalidError()
        raise VerificationUnavailableError("verification_state_invalid")

    async def cancel_challenge(
        self,
        *,
        challenge_id: uuid.UUID,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target: str,
    ) -> bool:
        """Cancel a still-current challenge after delivery fails.

        This only changes verification keys. It deliberately does not touch or
        refund any independent send-rate-limit counters.
        """

        if challenge_id.version != 4:
            raise VerificationInvalidError()
        purpose = self._enum_value(VerificationPurpose, purpose)
        channel = self._enum_value(VerificationChannel, channel)
        self._require_enabled(purpose, channel)
        normalized_target = normalize_verification_target(channel, target)
        target_digest = self._target_digest(channel, normalized_target)
        challenge_digest = self._digest("challenge", str(challenge_id))
        pointer_key, challenge_key, state_key, _challenge_key_prefix = self._keys(
            target_digest,
            purpose,
            channel,
            challenge_digest,
        )
        result = self._as_integer(
            await self._eval(
                _CANCEL_CHALLENGE_SCRIPT,
                3,
                pointer_key,
                challenge_key,
                state_key,
                challenge_digest,
                self._state_ttl_seconds,
            )
        )
        if result in (0, 1):
            return result == 1
        raise VerificationUnavailableError("verification_state_invalid")

    @property
    def _state_ttl_seconds(self) -> int:
        return (
            self._policy.challenge_ttl_seconds
            + self._policy.expired_status_retention_seconds
        )

    async def _eval(
        self,
        script: str,
        number_of_keys: int,
        *values: _RedisArgument,
    ) -> object:
        try:
            command = self._redis.eval(
                script, number_of_keys, *(str(value) for value in values)
            )
            return await cast(Awaitable[object], command)
        except RedisError:
            # Redis exceptions can contain connection details; do not expose the cause.
            raise VerificationUnavailableError() from None

    def _keys(
        self,
        target_digest: str,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        challenge_digest: str,
    ) -> tuple[str, str, str, str]:
        # The target HMAC hash tag keeps every scope key in one Cluster slot.
        prefix = (
            f"{self._namespace}:{{{target_digest}}}:{purpose.value}:{channel.value}"
        )
        challenge_key_prefix = f"{prefix}:challenge:"
        return (
            f"{prefix}:active",
            f"{challenge_key_prefix}{challenge_digest}",
            f"{prefix}:state",
            challenge_key_prefix,
        )

    def _target_digest(
        self,
        channel: VerificationChannel,
        normalized_target: str,
    ) -> str:
        return self._digest("target", f"{channel.value}\0{normalized_target}")

    def _code_digest(
        self,
        *,
        challenge_id: uuid.UUID,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
        target_digest: str,
        code: str,
    ) -> str:
        return self._digest(
            "code",
            "\0".join(
                (
                    str(challenge_id),
                    purpose.value,
                    channel.value,
                    target_digest,
                    code,
                )
            ),
        )

    def _digest(self, domain: str, value: str) -> str:
        return hmac.new(
            self._hmac_secret,
            f"{domain}\0{value}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def _require_enabled(
        self,
        purpose: VerificationPurpose,
        channel: VerificationChannel,
    ) -> None:
        if (
            purpose not in self._allowed_purposes
            or channel not in self._allowed_channels
        ):
            raise VerificationInvalidError("verification_flow_not_enabled")
        if channel not in PURPOSE_CHANNEL_POLICY[purpose]:
            raise VerificationInvalidError("verification_channel_not_allowed")

    @staticmethod
    def _normalize_target(channel: VerificationChannel, target: str) -> str:
        return normalize_verification_target(channel, target)

    @classmethod
    def _normalize_candidate_target(
        cls,
        channel: VerificationChannel,
        target: str,
    ) -> str:
        try:
            return cls._normalize_target(channel, target)
        except VerificationInvalidError:
            # Invalid candidates use a non-sensitive, guaranteed-wrong scope.
            return "invalid-target"

    @staticmethod
    def _enum_value(enum_type: type[_EnumT], value: _EnumT) -> _EnumT:
        try:
            return enum_type(value)
        except (TypeError, ValueError):
            raise VerificationInvalidError() from None

    @staticmethod
    def _as_integer(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, (str, bytes, int)):
            raise VerificationUnavailableError("verification_state_invalid")
        try:
            return int(value)
        except (TypeError, ValueError):
            raise VerificationUnavailableError("verification_state_invalid") from None

    @classmethod
    def _verification_result(cls, value: object) -> int:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise VerificationUnavailableError("verification_state_invalid")
        return cls._as_integer(value[0])
