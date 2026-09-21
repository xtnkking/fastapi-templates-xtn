import hashlib
import json
import logging
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import jwt
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import unauthenticated, unavailable
from app.core.observability import (
    dependency_error_category,
    safe_exception_metadata,
    safe_log,
)
from app.db.redis import RedisClient

MAX_BEARER_TOKEN_BYTES = 4096
JWT_CLOCK_LEEWAY_SECONDS = 30
JTI_ISSUANCE_ATTEMPTS = 2
_SESSION_FUNCTIONS = """
local redis_time = redis.call('TIME')
local now = tonumber(redis_time[1])
local function remove_session(field)
    redis.call('HDEL', KEYS[1], field)
    redis.call('ZREM', KEYS[2], field)
    redis.call('ZREM', KEYS[3], field)
end
local function prune_expired()
    local expired = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now)
    for _, field in ipairs(expired) do remove_session(field) end
end
"""
_ACTIVATE_JTI = (
    _SESSION_FUNCTIONS
    + """
local expires_at = tonumber(ARGV[3])
local maximum = tonumber(ARGV[5])
local incoming_version = tonumber(ARGV[4])
if not expires_at or expires_at ~= math.floor(expires_at) then
    return -1
end
if not maximum or maximum < 1 or maximum ~= math.floor(maximum) then return -1 end
if not incoming_version or incoming_version < 0 or
    incoming_version ~= math.floor(incoming_version) then return -1 end
if expires_at <= now then return -1 end
local current_version = redis.call('HGET', KEYS[1], '_version')
if current_version then
    local parsed_version = tonumber(current_version)
    if not parsed_version or parsed_version < 0 or
        parsed_version ~= math.floor(parsed_version) then return -1 end
    if parsed_version > incoming_version then return -2 end
end
prune_expired()
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return 0 end
-- Preserve the version high-water mark until every previously issued deadline.
-- A shorter new login must not shorten another session or the version guard.
local deadline_ms = expires_at * 1000
local previous_deadline = redis.call('PEXPIRETIME', KEYS[1])
if previous_deadline > deadline_ms then deadline_ms = previous_deadline end
if current_version ~= ARGV[4] then
    redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
end
if redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2]) ~= 1 then return 0 end
redis.call('HSET', KEYS[1], '_version', ARGV[4])
local score = now * 1000000 + tonumber(redis_time[2])
local most_recent = redis.call('ZREVRANGE', KEYS[2], 0, 0, 'WITHSCORES')
if #most_recent == 2 and tonumber(most_recent[2]) >= score then
    score = tonumber(most_recent[2]) + 1
end
redis.call('ZADD', KEYS[2], score, ARGV[1])
redis.call('ZADD', KEYS[3], expires_at, ARGV[1])
while redis.call('ZCARD', KEYS[2]) > maximum do
    local oldest = redis.call('ZRANGE', KEYS[2], 0, 0)[1]
    remove_session(oldest)
end
for _, key in ipairs(KEYS) do redis.call('PEXPIREAT', key, deadline_ms) end
return 1
"""
)
_COMPARE_AND_DELETE = (
    _SESSION_FUNCTIONS
    + """
local expiry = tonumber(redis.call('ZSCORE', KEYS[3], ARGV[1]))
if not expiry or expiry <= now then
    remove_session(ARGV[1])
    return 0
end
local current = redis.call('HGET', KEYS[1], ARGV[1])
if not current then
    return 0
end
if current ~= ARGV[2] then
    return -1
end
remove_session(ARGV[1])
return 1
"""
)
_READ_ACTIVE_JTI = (
    _SESSION_FUNCTIONS
    + """
local expiry = tonumber(redis.call('ZSCORE', KEYS[3], ARGV[1]))
if not expiry or expiry <= now then
    remove_session(ARGV[1])
    return false
end
local value = redis.call('HGET', KEYS[1], ARGV[1])
if not value then return false end
local ok, record = pcall(cjson.decode, value)
if not ok or type(record) ~= 'table' or type(record.token_version) ~= 'number'
    then return false end
if record.exp ~= expiry then return false end
if redis.call('HGET', KEYS[1], '_version') ~= tostring(record.token_version)
    then return false end
if not redis.call('ZSCORE', KEYS[2], ARGV[1]) then return false end
return value
"""
)
_LIST_USER_SESSIONS = (
    _SESSION_FUNCTIONS
    + """
if redis.call('HGET', KEYS[1], '_version') ~= ARGV[1] then return {} end
prune_expired()
local entries = redis.call('ZRANGE', KEYS[2], 0, -1)
local result = {}
for _, field in ipairs(entries) do
    local raw = redis.call('HGET', KEYS[1], field)
    if raw then
        local ok, record = pcall(cjson.decode, raw)
        local expiry = tonumber(redis.call('ZSCORE', KEYS[3], field))
        if not ok or type(record) ~= 'table' or type(record.iat) ~= 'number'
            or record.iat ~= math.floor(record.iat) or record.iat < 0
            or record.exp ~= expiry or not expiry or expiry <= now
            or tostring(record.token_version) ~= ARGV[1] then
            return redis.error_reply('invalid active session')
        end
        result[#result + 1] = record.iat
    else
        remove_session(field)
    end
end
return result
"""
)
REQUIRED_ACCESS_CLAIMS = frozenset({"sub", "jti", "iat", "exp", "token_type"})
OPTIONAL_ACCESS_SCOPE_CLAIMS = frozenset({"iss", "aud"})
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    token_id: uuid.UUID
    issued_at: int
    expires_at: int


def _uuid4(value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise ValueError("claim must be a canonical UUIDv4 string")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("claim must be a canonical UUIDv4 string")
    return parsed


def _integer_numeric_date(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("NumericDate claims must be integers")
    return value


def _expected_access_claims(settings: Settings) -> frozenset[str]:
    if settings.jwt_issuer is None:
        return REQUIRED_ACCESS_CLAIMS
    return REQUIRED_ACCESS_CLAIMS | OPTIONAL_ACCESS_SCOPE_CLAIMS


def decode_access_token(token: str, settings: Settings) -> AccessTokenClaims:
    try:
        expected_claims = _expected_access_claims(settings)
        decode_kwargs: dict[str, Any] = {}
        if settings.jwt_issuer is not None and settings.jwt_audience is not None:
            decode_kwargs = {
                "audience": settings.jwt_audience,
                "issuer": settings.jwt_issuer,
            }
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            leeway=JWT_CLOCK_LEEWAY_SECONDS,
            options={
                "require": sorted(expected_claims),
                "strict_aud": True,
            },
            **decode_kwargs,
        )
        if set(payload) != expected_claims:
            raise ValueError("access token must contain only the configured claims")
        if payload["token_type"] != "access":
            raise ValueError("wrong token type")

        issued_at = _integer_numeric_date(payload["iat"])
        expires_at = _integer_numeric_date(payload["exp"])
        if (
            expires_at <= issued_at
            or expires_at - issued_at > settings.jwt_access_token_ttl_seconds
        ):
            raise ValueError("invalid access token lifetime")

        return AccessTokenClaims(
            user_id=_uuid4(payload["sub"]),
            token_id=_uuid4(payload["jti"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (jwt.PyJWTError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise unauthenticated("invalid_access_token") from exc


def _active_jti_field(*, settings: Settings, token_id: uuid.UUID) -> str:
    return hashlib.sha256(f"{settings.service_name}\0{token_id}".encode()).hexdigest()


def _user_session_keys(
    *, settings: Settings, user_id: uuid.UUID
) -> tuple[str, str, str]:
    digest = hashlib.sha256(f"{settings.service_name}\0{user_id}".encode()).hexdigest()
    prefix = f"auth:sessions:v2:{settings.app_environment}:{{{digest}}}"
    return f"{prefix}:records", f"{prefix}:order", f"{prefix}:expires"


def _active_jti_value(
    claims: AccessTokenClaims,
    *,
    user_token_version: int,
) -> str:
    return json.dumps(
        {
            "exp": claims.expires_at,
            "iat": claims.issued_at,
            "sub": str(claims.user_id),
            "token_version": user_token_version,
            "typ": "access",
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _parse_active_jti_value(value: str) -> tuple[uuid.UUID, int, int, int]:
    payload = json.loads(value)
    if not isinstance(payload, dict) or set(payload) != {
        "exp",
        "iat",
        "sub",
        "token_version",
        "typ",
    }:
        raise ValueError("invalid active JTI record")
    if payload["typ"] != "access":
        raise ValueError("invalid active JTI type")
    token_version = payload["token_version"]
    if (
        isinstance(token_version, bool)
        or not isinstance(token_version, int)
        or token_version < 0
    ):
        raise ValueError("invalid active JTI token version")
    expires_at = _integer_numeric_date(payload["exp"])
    issued_at = _integer_numeric_date(payload["iat"])
    return _uuid4(payload["sub"]), token_version, issued_at, expires_at


def _encode_access_token(
    *,
    user_id: uuid.UUID,
    token_id: uuid.UUID,
    settings: Settings,
) -> tuple[str, AccessTokenClaims]:
    now = int(datetime.now(UTC).timestamp())
    claims = AccessTokenClaims(
        user_id=user_id,
        token_id=token_id,
        issued_at=now,
        expires_at=now + settings.jwt_access_token_ttl_seconds,
    )
    payload: dict[str, object] = {
        "sub": str(claims.user_id),
        "jti": str(claims.token_id),
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "token_type": "access",
    }
    if settings.jwt_issuer is not None and settings.jwt_audience is not None:
        payload.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
    token = jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )
    if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
        raise ValueError("encoded access token exceeds the bearer token size limit")
    return token, claims


async def issue_access_token(
    redis: RedisClient,
    *,
    user_id: uuid.UUID,
    user_token_version: int,
    settings: Settings,
) -> str:
    if (
        user_id.version != 4
        or isinstance(user_token_version, bool)
        or not isinstance(user_token_version, int)
        or user_token_version < 0
    ):
        raise ValueError("the issuer requires a UUIDv4 user and valid token version")

    for _attempt in range(JTI_ISSUANCE_ATTEMPTS):
        token, claims = _encode_access_token(
            user_id=user_id,
            token_id=uuid.uuid4(),
            settings=settings,
        )
        try:
            session_keys = _user_session_keys(settings=settings, user_id=user_id)
            created = await cast(
                Awaitable[object],
                redis.eval(
                    _ACTIVATE_JTI,
                    3,
                    *session_keys,
                    _active_jti_field(settings=settings, token_id=claims.token_id),
                    _active_jti_value(
                        claims,
                        user_token_version=user_token_version,
                    ),
                    str(claims.expires_at),
                    str(user_token_version),
                    str(settings.max_active_sessions_per_user),
                ),
            )
        except RedisError as exc:
            safe_log(
                logger,
                logging.ERROR,
                "dependency.redis.unavailable",
                extra={
                    "dependency": "redis",
                    "dependency_operation": "register_active_jti",
                    "error_category": dependency_error_category(exc),
                    **safe_exception_metadata(exc),
                },
            )
            raise unavailable("active_token_registry_unavailable") from exc
        if type(created) is int and created == 1:
            return token
        if type(created) is int and created == -2:
            raise unauthenticated("token_version_changed")
        if type(created) is not int or created != 0:
            raise unavailable("active_token_registry_unavailable")

    raise unavailable("access_token_issuance_conflict")


async def require_active_jti(
    redis: RedisClient,
    *,
    claims: AccessTokenClaims,
    settings: Settings,
) -> int:
    try:
        session_keys = _user_session_keys(settings=settings, user_id=claims.user_id)
        value = await cast(
            Awaitable[object],
            redis.eval(
                _READ_ACTIVE_JTI,
                3,
                *session_keys,
                _active_jti_field(settings=settings, token_id=claims.token_id),
            ),
        )
    except RedisError as exc:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.redis.unavailable",
            extra={
                "dependency": "redis",
                "dependency_operation": "read_active_jti",
                "error_category": dependency_error_category(exc),
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable("active_token_registry_unavailable") from exc
    if not isinstance(value, str):
        raise unauthenticated("inactive_access_token")

    try:
        user_id, token_version, issued_at, expires_at = _parse_active_jti_value(value)
        if (
            user_id != claims.user_id
            or issued_at != claims.issued_at
            or expires_at != claims.expires_at
        ):
            raise ValueError("active JTI does not match the access token")
        if value != _active_jti_value(
            claims,
            user_token_version=token_version,
        ):
            raise ValueError("active JTI record is not canonical")
    except (KeyError, TypeError, ValueError) as exc:
        raise unauthenticated("active_token_record_mismatch") from exc
    return token_version


async def revoke_active_jti(
    redis: RedisClient,
    *,
    claims: AccessTokenClaims,
    user_token_version: int,
    settings: Settings,
) -> None:
    try:
        session_keys = _user_session_keys(settings=settings, user_id=claims.user_id)
        deleted = await cast(
            Awaitable[object],
            redis.eval(
                _COMPARE_AND_DELETE,
                3,
                *session_keys,
                _active_jti_field(settings=settings, token_id=claims.token_id),
                _active_jti_value(
                    claims,
                    user_token_version=user_token_version,
                ),
            ),
        )
    except RedisError as exc:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.redis.unavailable",
            extra={
                "dependency": "redis",
                "dependency_operation": "revoke_active_jti",
                "error_category": dependency_error_category(exc),
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable("active_token_registry_unavailable") from exc
    if deleted != 1:
        raise unauthenticated("inactive_access_token")


async def list_active_sessions(
    redis: RedisClient,
    *,
    user_id: uuid.UUID,
    token_version: int,
    settings: Settings,
) -> tuple[int, ...]:
    session_keys = _user_session_keys(settings=settings, user_id=user_id)
    try:
        values = await cast(
            Awaitable[object],
            redis.eval(_LIST_USER_SESSIONS, 3, *session_keys, str(token_version)),
        )
    except RedisError as exc:
        raise unavailable("active_token_registry_unavailable") from exc
    if not isinstance(values, list) or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        raise unavailable("active_token_registry_unavailable")
    return tuple(values)
