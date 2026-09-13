import hashlib
import hmac
import re
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from typing import Final, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

MICROTOKENS_PER_TOKEN: Final = 1_000_000
RATE_LIMIT_KEY_PREFIX: Final = "rl:v1"
_MAX_CAPACITY: Final = 1_000_000
_MAX_PERIOD_SECONDS: Final = 86_400
_MAX_FULL_REFILL_MILLISECONDS: Final = 30 * 86_400 * 1_000
_MAX_SUBJECT_BYTES: Final = 1_024
_MAX_BATCH_CHECKS: Final = 16
_IDENTIFIER_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

TOKEN_BUCKET_SCRIPT: Final = r"""
local token_micro = 1000000

if #KEYS < 1 or #ARGV ~= (#KEYS * 3) then
    return redis.error_reply('invalid token bucket batch')
end

local redis_time = redis.call('TIME')
local now_ms = (tonumber(redis_time[1]) * 1000)
    + math.floor(tonumber(redis_time[2]) / 1000)
local bucket_states = {}
local batch_allowed = 1
local maximum_retry_after_ms = 0

for index, key in ipairs(KEYS) do
    local argument_offset = (index - 1) * 3
    local burst_micro = tonumber(ARGV[argument_offset + 1])
    local refill_micro = tonumber(ARGV[argument_offset + 2])
    local period_ms = tonumber(ARGV[argument_offset + 3])
    if not burst_micro or not refill_micro or not period_ms
        or burst_micro < 1 or refill_micro < 1 or period_ms < 1
        or burst_micro ~= math.floor(burst_micro)
        or refill_micro ~= math.floor(refill_micro)
        or period_ms ~= math.floor(period_ms) then
        return redis.error_reply('invalid token bucket policy')
    end

    local state = redis.call('HMGET', key, 'tokens_micro', 'updated_at_ms')
    local tokens_micro
    local updated_at_ms
    if state[1] == false and state[2] == false then
        tokens_micro = burst_micro
        updated_at_ms = now_ms
    elseif state[1] == false or state[2] == false then
        return redis.error_reply('incomplete token bucket state')
    else
        tokens_micro = tonumber(state[1])
        updated_at_ms = tonumber(state[2])
        if not tokens_micro or not updated_at_ms
            or tokens_micro < 0
            or updated_at_ms < 0
            or tokens_micro ~= math.floor(tokens_micro)
            or updated_at_ms ~= math.floor(updated_at_ms) then
            return redis.error_reply('invalid token bucket state')
        end
        tokens_micro = math.min(tokens_micro, burst_micro)
    end

    local elapsed_ms = math.max(0, now_ms - updated_at_ms)
    local full_refill_ms = math.ceil((burst_micro / refill_micro) * period_ms)
    if elapsed_ms >= full_refill_ms then
        tokens_micro = burst_micro
    else
        local replenished = math.floor((elapsed_ms / period_ms) * refill_micro)
        tokens_micro = math.min(burst_micro, tokens_micro + replenished)
    end

    local allowed = 0
    local resulting_tokens_micro = tokens_micro
    if tokens_micro >= token_micro then
        allowed = 1
        resulting_tokens_micro = tokens_micro - token_micro
    else
        batch_allowed = 0
    end

    local remaining = math.floor(resulting_tokens_micro / token_micro)
    local retry_after_ms = 0
    if allowed == 0 then
        local deficit = token_micro - tokens_micro
        retry_after_ms = math.max(
            1,
            math.ceil((deficit / refill_micro) * period_ms)
        )
        maximum_retry_after_ms = math.max(
            maximum_retry_after_ms,
            retry_after_ms
        )
    end
    local reset_after_ms = math.max(
        1,
        math.ceil(
            ((burst_micro - resulting_tokens_micro) / refill_micro) * period_ms
        )
    )
    bucket_states[index] = {
        key = key,
        tokens_micro = resulting_tokens_micro,
        allowed = allowed,
        remaining = remaining,
        retry_after_ms = retry_after_ms,
        reset_after_ms = reset_after_ms
    }
end

if batch_allowed == 1 then
    for _, bucket in ipairs(bucket_states) do
        redis.call(
            'HSET',
            bucket.key,
            'tokens_micro',
            tostring(bucket.tokens_micro),
            'updated_at_ms',
            tostring(now_ms)
        )
        redis.call('PEXPIRE', bucket.key, math.max(1000, bucket.reset_after_ms))
    end
end

local result = {batch_allowed, maximum_retry_after_ms}
for _, bucket in ipairs(bucket_states) do
    table.insert(result, bucket.allowed)
    table.insert(result, bucket.remaining)
    table.insert(result, bucket.retry_after_ms)
    table.insert(result, bucket.reset_after_ms)
end
return result
"""


class RateLimitUnavailable(RuntimeError):
    """The rate-limit decision store could not produce a trustworthy result."""


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """A named token bucket whose sustained rate is independent of its burst."""

    name: str
    burst_capacity: int
    refill_tokens: int
    refill_period_seconds: int

    def __post_init__(self) -> None:
        _require_identifier(self.name, field_name="policy name")
        _require_bounded_integer(
            self.burst_capacity,
            field_name="burst_capacity",
            maximum=_MAX_CAPACITY,
        )
        _require_bounded_integer(
            self.refill_tokens,
            field_name="refill_tokens",
            maximum=_MAX_CAPACITY,
        )
        _require_bounded_integer(
            self.refill_period_seconds,
            field_name="refill_period_seconds",
            maximum=_MAX_PERIOD_SECONDS,
        )
        if self.full_refill_ms > _MAX_FULL_REFILL_MILLISECONDS:
            raise ValueError("token bucket full-refill time must not exceed 30 days")

    @property
    def burst_microtokens(self) -> int:
        return self.burst_capacity * MICROTOKENS_PER_TOKEN

    @property
    def refill_microtokens(self) -> int:
        return self.refill_tokens * MICROTOKENS_PER_TOKEN

    @property
    def refill_period_ms(self) -> int:
        return self.refill_period_seconds * 1_000

    @property
    def full_refill_ms(self) -> int:
        numerator = self.burst_capacity * self.refill_period_ms
        return (numerator + self.refill_tokens - 1) // self.refill_tokens


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after_ms: int
    reset_after_ms: int


@dataclass(frozen=True, slots=True)
class RateLimitCheck:
    policy: RateLimitPolicy
    subject_type: str
    subject: str

    def __post_init__(self) -> None:
        if not isinstance(self.policy, RateLimitPolicy):
            raise ValueError("rate-limit check requires a validated policy")
        _require_identifier(self.subject_type, field_name="subject type")
        _subject_bytes(self.subject)


@dataclass(frozen=True, slots=True)
class RateLimitBatchDecision:
    """One atomic outcome; per-bucket results preserve the input check order."""

    allowed: bool
    results: tuple[RateLimitResult, ...]
    retry_after_ms: int


def _require_bounded_integer(
    value: object,
    *,
    field_name: str,
    maximum: int,
) -> None:
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
    """Build a bounded key without exposing the rate-limited identity."""
    safe_namespace = _require_identifier(namespace, field_name="namespace")
    safe_subject_type = _require_identifier(subject_type, field_name="subject type")
    subject_bytes = _subject_bytes(subject)
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


def _parse_bucket_result(
    raw: Sequence[object],
    *,
    policy: RateLimitPolicy,
) -> RateLimitResult:
    if len(raw) != 4:
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    values = tuple(raw)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    allowed, remaining, retry_after_ms, reset_after_ms = cast(
        tuple[int, int, int, int], values
    )
    maximum_wait_ms = policy.full_refill_ms
    if (
        allowed not in (0, 1)
        or not 0 <= remaining <= policy.burst_capacity
        or retry_after_ms < 0
        or retry_after_ms > maximum_wait_ms
        or not 0 < reset_after_ms <= maximum_wait_ms
        or (allowed == 1 and retry_after_ms != 0)
        or (allowed == 0 and retry_after_ms == 0)
        or (allowed == 1 and remaining >= policy.burst_capacity)
        or (allowed == 0 and remaining != 0)
    ):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    return RateLimitResult(
        allowed=bool(allowed),
        limit=policy.burst_capacity,
        remaining=remaining,
        retry_after_ms=retry_after_ms,
        reset_after_ms=reset_after_ms,
    )


def _parse_batch_result(
    raw: object,
    *,
    checks: tuple[RateLimitCheck, ...],
) -> RateLimitBatchDecision:
    expected_length = 2 + (len(checks) * 4)
    if (
        not isinstance(raw, Sequence)
        or isinstance(raw, (str, bytes))
        or len(raw) != expected_length
    ):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    values = tuple(raw)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")

    batch_allowed = cast(int, values[0])
    maximum_retry_after_ms = cast(int, values[1])
    if batch_allowed not in (0, 1) or maximum_retry_after_ms < 0:
        raise RateLimitUnavailable("rate-limit store returned an invalid result")

    results = tuple(
        _parse_bucket_result(
            values[2 + (index * 4) : 6 + (index * 4)],
            policy=check.policy,
        )
        for index, check in enumerate(checks)
    )
    expected_allowed = all(result.allowed for result in results)
    expected_retry_after_ms = max(
        (result.retry_after_ms for result in results),
        default=0,
    )
    if (
        bool(batch_allowed) != expected_allowed
        or maximum_retry_after_ms != expected_retry_after_ms
    ):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    return RateLimitBatchDecision(
        allowed=bool(batch_allowed),
        results=results,
        retry_after_ms=maximum_retry_after_ms,
    )


async def check_rate_limits(
    redis: Redis,
    *,
    namespace: str,
    checks: Sequence[RateLimitCheck],
    key_secret: bytes,
) -> RateLimitBatchDecision:
    """Consume every bucket or none; rejected results are hypothetical only."""
    checks_tuple = tuple(checks)
    if not 1 <= len(checks_tuple) <= _MAX_BATCH_CHECKS:
        raise ValueError(
            f"rate-limit batch must contain between 1 and {_MAX_BATCH_CHECKS} checks"
        )
    if any(not isinstance(check, RateLimitCheck) for check in checks_tuple):
        raise ValueError("rate-limit batch contains an invalid check")

    keys = tuple(
        build_rate_limit_key(
            namespace=namespace,
            policy=check.policy,
            subject_type=check.subject_type,
            subject=check.subject,
            key_secret=key_secret,
        )
        for check in checks_tuple
    )
    if len(set(keys)) != len(keys):
        raise ValueError("rate-limit batch checks must resolve to unique keys")
    policy_arguments = tuple(
        str(value)
        for check in checks_tuple
        for value in (
            check.policy.burst_microtokens,
            check.policy.refill_microtokens,
            check.policy.refill_period_ms,
        )
    )
    try:
        raw = await cast(
            Awaitable[object],
            redis.eval(
                TOKEN_BUCKET_SCRIPT,
                len(keys),
                *keys,
                *policy_arguments,
            ),
        )
    except RedisError as exc:
        raise RateLimitUnavailable("rate-limit store is unavailable") from exc
    return _parse_batch_result(raw, checks=checks_tuple)


async def check_rate_limit(
    redis: Redis,
    *,
    namespace: str,
    policy: RateLimitPolicy,
    subject_type: str,
    subject: str,
    key_secret: bytes,
) -> RateLimitResult:
    decision = await check_rate_limits(
        redis,
        namespace=namespace,
        checks=(
            RateLimitCheck(
                policy=policy,
                subject_type=subject_type,
                subject=subject,
            ),
        ),
        key_secret=key_secret,
    )
    return decision.results[0]
