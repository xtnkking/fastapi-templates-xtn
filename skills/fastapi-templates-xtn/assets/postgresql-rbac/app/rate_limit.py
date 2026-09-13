import hashlib
import hmac
import re
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from typing import Final, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

RATE_LIMIT_KEY_PREFIX: Final = "rl:v2"
_MAX_LIMIT: Final = 1_000_000
_MAX_WINDOW_SECONDS: Final = 30 * 86_400
_MAX_SUBJECT_BYTES: Final = 1_024
_IDENTIFIER_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

FIXED_WINDOW_SCRIPT: Final = r"""
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
if not limit or not window or limit < 1 or window < 1
    or limit ~= math.floor(limit) or window ~= math.floor(window) then
    return redis.error_reply('invalid rate limit policy')
end

-- A pre-existing key without an expiry is corrupted state, not a valid quota.
if redis.call('PTTL', KEYS[1]) == -1 then
    return redis.error_reply('rate limit key has no expiry')
end
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], window)
end
local remaining_ms = redis.call('PTTL', KEYS[1])
if remaining_ms <= 0 then
    return redis.error_reply('rate limit key has invalid expiry')
end
return {count, remaining_ms}
"""


class RateLimitUnavailable(RuntimeError):
    """Redis did not produce a trustworthy admission decision."""


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """One named business and one fixed window per subject."""

    name: str
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        _require_identifier(self.name, field_name="policy name")
        _require_positive_integer(self.limit, field_name="limit", maximum=_MAX_LIMIT)
        _require_positive_integer(
            self.window_seconds,
            field_name="window_seconds",
            maximum=_MAX_WINDOW_SECONDS,
        )


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after_ms: int
    reset_after_ms: int


def _require_positive_integer(value: object, *, field_name: str, maximum: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ValueError(f"{field_name} must be an integer between 1 and {maximum}")


def _require_identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a static lowercase ASCII identifier")
    return value


def _subject_bytes(subject: object) -> bytes:
    if not isinstance(subject, str):
        raise ValueError("subject must be a non-empty bounded string")
    try:
        encoded = subject.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("subject must be a non-empty bounded string") from exc
    if not encoded or len(encoded) > _MAX_SUBJECT_BYTES:
        raise ValueError("subject must be a non-empty bounded string")
    return encoded


def build_rate_limit_key(
    *,
    namespace: str,
    policy: RateLimitPolicy,
    subject_type: str,
    subject: str,
    key_secret: bytes,
) -> str:
    """HMAC the subject; do not store raw IPs or user IDs in Redis keys."""
    safe_namespace = _require_identifier(namespace, field_name="namespace")
    safe_subject_type = _require_identifier(subject_type, field_name="subject type")
    subject_bytes = _subject_bytes(subject)
    if not isinstance(policy, RateLimitPolicy):
        raise ValueError("rate-limit policy must be validated")
    if not isinstance(key_secret, bytes) or len(key_secret) < 32:
        raise ValueError("rate-limit key secret must contain at least 32 bytes")
    message = b"\0".join(
        (
            RATE_LIMIT_KEY_PREFIX.encode("ascii"),
            safe_namespace.encode("ascii"),
            policy.name.encode("ascii"),
            safe_subject_type.encode("ascii"),
            subject_bytes,
        )
    )
    digest = hmac.new(key_secret, message, hashlib.sha256).hexdigest()
    return (
        f"{RATE_LIMIT_KEY_PREFIX}:{{{safe_namespace}}}:{policy.name}:"
        f"{safe_subject_type}:{digest}"
    )


def _parse_result(raw: object, *, policy: RateLimitPolicy) -> RateLimitResult:
    if (
        not isinstance(raw, Sequence)
        or isinstance(raw, (str, bytes))
        or len(raw) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) for value in raw)
    ):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    count, ttl_ms = cast(tuple[int, int], tuple(raw))
    if count < 1 or not 0 < ttl_ms <= policy.window_seconds * 1000:
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    allowed = count <= policy.limit
    return RateLimitResult(
        allowed=allowed,
        limit=policy.limit,
        remaining=max(0, policy.limit - count),
        retry_after_ms=0 if allowed else ttl_ms,
        reset_after_ms=ttl_ms,
    )


async def check_rate_limit(
    redis: Redis,
    *,
    namespace: str,
    policy: RateLimitPolicy,
    subject_type: str,
    subject: str,
    key_secret: bytes,
) -> RateLimitResult:
    """Atomically increment one business/subject key and preserve its first TTL."""
    key = build_rate_limit_key(
        namespace=namespace,
        policy=policy,
        subject_type=subject_type,
        subject=subject,
        key_secret=key_secret,
    )
    try:
        raw = await cast(
            Awaitable[object],
            redis.eval(
                FIXED_WINDOW_SCRIPT,
                1,
                key,
                str(policy.limit),
                str(policy.window_seconds),
            ),
        )
    except RedisError as exc:
        raise RateLimitUnavailable("rate-limit store is unavailable") from exc
    return _parse_result(raw, policy=policy)
