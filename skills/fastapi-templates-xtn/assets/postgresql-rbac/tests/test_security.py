import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import jwt
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api_contract import BusinessCode
from app.rbac.errors import RbacError
from app.rbac.security import (
    MAX_BEARER_TOKEN_BYTES,
    OPTIONAL_ACCESS_SCOPE_CLAIMS,
    REQUIRED_ACCESS_CLAIMS,
    AccessTokenClaims,
    _active_jti_key,
    decode_access_token,
    issue_access_token,
    require_active_jti,
    revoke_active_jti,
)
from app.settings import Settings, get_settings


def issuer_audience_settings() -> Settings:
    return get_settings().model_copy(
        update={
            "jwt_issuer": "https://identity.example.test",
            "jwt_audience": "fastapi-rbac-example",
        }
    )


def valid_payload(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    now = int(datetime.now(UTC).timestamp())
    payload: dict[str, Any] = {
        "sub": str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + settings.jwt_access_token_ttl_seconds,
        "token_type": "access",
    }
    if settings.jwt_issuer is not None and settings.jwt_audience is not None:
        payload.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
    return payload


def encode(
    payload: dict[str, Any],
    *,
    settings: Settings | None = None,
    algorithm: str = "HS256",
) -> str:
    settings = settings or get_settings()
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=algorithm,
    )


def redis_mock() -> tuple[Redis, AsyncMock]:
    mock = AsyncMock()
    return cast(Redis, mock), mock


def test_valid_access_token_resolves_only_fixed_claims() -> None:
    payload = valid_payload()

    claims = decode_access_token(encode(payload), get_settings())

    assert set(payload) == REQUIRED_ACCESS_CLAIMS
    assert claims.user_id == uuid.UUID(payload["sub"])
    assert claims.token_id == uuid.UUID(payload["jti"])
    assert claims.issued_at == payload["iat"]
    assert claims.expires_at == payload["exp"]


@pytest.mark.parametrize("claim", sorted(REQUIRED_ACCESS_CLAIMS))
def test_default_mode_rejects_each_missing_required_claim(claim: str) -> None:
    payload = valid_payload()
    payload.pop(claim)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401


@pytest.mark.parametrize(
    "extra_claims",
    [
        {"iss": "https://identity.example.test"},
        {"aud": "fastapi-rbac-example"},
        {
            "iss": "https://identity.example.test",
            "aud": "fastapi-rbac-example",
        },
    ],
)
def test_default_mode_rejects_optional_scope_claims(
    extra_claims: dict[str, str],
) -> None:
    payload = valid_payload()
    payload.update(extra_claims)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401


def test_configured_issuer_and_audience_mode_accepts_exact_seven_claims() -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)

    claims = decode_access_token(encode(payload, settings=settings), settings)

    assert set(payload) == REQUIRED_ACCESS_CLAIMS | OPTIONAL_ACCESS_SCOPE_CLAIMS
    assert claims.user_id == uuid.UUID(payload["sub"])
    assert claims.token_id == uuid.UUID(payload["jti"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(iss="https://wrong-issuer.example"),
        lambda payload: payload.update(aud="wrong-audience"),
        lambda payload: payload.update(aud=["fastapi-rbac-example"]),
        lambda payload: payload.update(username="example"),
    ],
)
def test_configured_issuer_and_audience_mode_rejects_invalid_scope(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)
    mutate(payload)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


@pytest.mark.parametrize(
    "claim",
    sorted(REQUIRED_ACCESS_CLAIMS | OPTIONAL_ACCESS_SCOPE_CLAIMS),
)
def test_configured_issuer_and_audience_mode_rejects_each_missing_claim(
    claim: str,
) -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)
    payload.pop(claim)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(token_type="other"),
        lambda payload: payload.update(exp=int(datetime.now(UTC).timestamp()) - 1),
        lambda payload: payload.update(iat=int(datetime.now(UTC).timestamp()) + 60),
        lambda payload: payload.update(sub="not-a-uuid"),
        lambda payload: payload.update(sub=str(uuid.uuid1())),
        lambda payload: payload.update(sub=str(uuid.uuid4()).upper()),
        lambda payload: payload.update(jti=str(uuid.uuid1())),
        lambda payload: payload.update(iat=True),
        lambda payload: payload.update(exp=1.5),
        lambda payload: payload.update(nbf=payload["iat"]),
        lambda payload: payload.update(username="example"),
        lambda payload: payload.pop("jti"),
    ],
)
def test_invalid_access_token_claims_fail_closed(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = valid_payload()
    mutate(payload)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401
    assert caught.value.business_code == BusinessCode.INVALID_AUTHENTICATION


def test_decoder_rejects_lifetime_longer_than_configured() -> None:
    settings = get_settings()
    payload = valid_payload(settings)
    payload["exp"] = payload["iat"] + settings.jwt_access_token_ttl_seconds + 1

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


def test_wrong_jwt_algorithm_fails_closed() -> None:
    with pytest.raises(RbacError):
        decode_access_token(encode(valid_payload(), algorithm="HS384"), get_settings())


async def test_issuer_registers_exact_minimal_token_before_returning() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    settings = get_settings()
    user_id = uuid.uuid4()

    token = await issue_access_token(
        redis,
        user_id=user_id,
        user_token_version=7,
        settings=settings,
    )
    claims = decode_access_token(token, settings)
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
    )

    assert set(payload) == REQUIRED_ACCESS_CLAIMS
    assert (
        payload["exp"] - payload["iat"]
        == settings.jwt_access_token_ttl_seconds
        == 86_400
    )
    assert payload["sub"] == str(user_id)
    mock.eval.assert_awaited_once()
    (
        script,
        key_count,
        key,
        index,
        version_key,
        value,
        expires_at,
        _,
        version,
        maximum,
    ) = mock.eval.await_args.args
    assert key_count == 3
    assert "redis.call('TIME')" in script
    assert "'NX', 'EX', ttl_seconds" in script
    assert "redis.call('PEXPIREAT', KEYS[1], expires_at * 1000)" in script
    assert str(claims.token_id) not in key
    assert str(user_id) not in index
    assert str(user_id) not in version_key
    assert json.loads(value) == {
        "exp": claims.expires_at,
        "iat": claims.issued_at,
        "sub": str(user_id),
        "token_version": 7,
        "typ": "access",
    }
    assert expires_at == str(claims.expires_at)
    assert version == "7"
    assert maximum == str(settings.max_active_sessions_per_user)
    assert mock.eval.await_args.kwargs == {}


async def test_issuer_uses_configured_access_token_lifetime() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    settings = get_settings().model_copy(update={"jwt_access_token_ttl_seconds": 900})

    token = await issue_access_token(
        redis,
        user_id=uuid.uuid4(),
        user_token_version=0,
        settings=settings,
    )
    claims = decode_access_token(token, settings)

    assert claims.expires_at - claims.issued_at == 900


def test_active_jti_key_does_not_depend_on_optional_issuer_or_audience() -> None:
    token_id = uuid.uuid4()
    default_settings = get_settings()
    configured_settings = issuer_audience_settings()

    default_key = _active_jti_key(settings=default_settings, token_id=token_id)
    configured_key = _active_jti_key(
        settings=configured_settings,
        token_id=token_id,
    )

    assert default_key == configured_key
    assert str(token_id) not in default_key
    assert configured_settings.jwt_issuer is not None
    assert configured_settings.jwt_issuer not in configured_key


async def test_configured_scope_uses_the_same_active_jti_lifecycle() -> None:
    settings = issuer_audience_settings()
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    user_id = uuid.uuid4()

    token = await issue_access_token(
        redis,
        user_id=user_id,
        user_token_version=9,
        settings=settings,
    )
    claims = decode_access_token(token, settings)
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"strict_aud": True},
    )
    key, record = mock.eval.await_args.args[2], mock.eval.await_args.args[5]
    mock.eval.return_value = record

    version = await require_active_jti(redis, claims=claims, settings=settings)
    mock.eval.return_value = 1
    await revoke_active_jti(
        redis,
        claims=claims,
        user_token_version=version,
        settings=settings,
    )

    assert set(payload) == REQUIRED_ACCESS_CLAIMS | OPTIONAL_ACCESS_SCOPE_CLAIMS
    assert payload["sub"] == str(user_id)
    assert mock.eval.await_args.args[2] == key
    assert mock.eval.await_count == 3


async def test_maximum_configured_scope_stays_within_bearer_limit() -> None:
    settings = get_settings().model_copy(
        update={
            "jwt_issuer": "i" * 256,
            "jwt_audience": "a" * 256,
        }
    )
    redis, mock = redis_mock()
    mock.eval.return_value = 1

    token = await issue_access_token(
        redis,
        user_id=uuid.uuid4(),
        user_token_version=0,
        settings=settings,
    )

    assert len(token.encode("utf-8")) <= MAX_BEARER_TOKEN_BYTES
    mock.eval.assert_awaited_once()


async def test_issuer_rejects_oversized_token_before_redis_registration() -> None:
    settings = get_settings().model_copy(
        update={
            "jwt_issuer": "issuer" * 1000,
            "jwt_audience": "audience" * 1000,
        }
    )
    redis, mock = redis_mock()

    with pytest.raises(ValueError, match="bearer token size limit"):
        await issue_access_token(
            redis,
            user_id=uuid.uuid4(),
            user_token_version=0,
            settings=settings,
        )

    mock.eval.assert_not_awaited()


async def test_issuer_retries_one_duplicate_jti_then_succeeds() -> None:
    redis, mock = redis_mock()
    mock.eval.side_effect = [0, 1]

    token = await issue_access_token(
        redis,
        user_id=uuid.uuid4(),
        user_token_version=0,
        settings=get_settings(),
    )

    assert token
    assert mock.eval.await_count == 2
    assert mock.eval.await_args_list[0].args[2] != mock.eval.await_args_list[1].args[2]


async def test_issuer_does_not_return_after_duplicate_retry_is_exhausted() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 0

    with pytest.raises(RbacError) as caught:
        await issue_access_token(
            redis,
            user_id=uuid.uuid4(),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503
    assert mock.eval.await_count == 2


async def test_issuer_rejects_a_stale_token_version_without_retry() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = -2

    with pytest.raises(RbacError) as caught:
        await issue_access_token(
            redis,
            user_id=uuid.uuid4(),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 401
    mock.eval.assert_awaited_once()
    script = mock.eval.await_args.args[0]
    assert script.index("parsed_version > incoming_version") < script.index(
        "'SET', KEYS[1]"
    )


async def test_issuer_maps_redis_failure_to_service_unavailable() -> None:
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("unavailable")

    with pytest.raises(RbacError) as caught:
        await issue_access_token(
            redis,
            user_id=uuid.uuid4(),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503


@pytest.mark.parametrize("result", [-1, None, True, "OK"])
async def test_issuer_fails_closed_for_invalid_or_expired_registry_result(
    result: object,
) -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = result

    with pytest.raises(RbacError) as caught:
        await issue_access_token(
            redis,
            user_id=uuid.uuid4(),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503
    mock.eval.assert_awaited_once()


async def _issued_claims_and_record() -> tuple[Settings, AccessTokenClaims, str]:
    settings = get_settings()
    issuer_redis, issuer_mock = redis_mock()
    issuer_mock.eval.return_value = 1
    token = await issue_access_token(
        issuer_redis,
        user_id=uuid.uuid4(),
        user_token_version=4,
        settings=settings,
    )
    return (
        settings,
        decode_access_token(token, settings),
        issuer_mock.eval.await_args.args[5],
    )


async def test_active_jti_returns_server_side_version_without_extending_ttl() -> None:
    settings, claims, record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = record

    version = await require_active_jti(redis, claims=claims, settings=settings)

    assert version == 4
    mock.eval.assert_awaited_once()
    mock.set.assert_not_awaited()
    mock.expire.assert_not_awaited()


@pytest.mark.parametrize("mutation", ["sub", "iat", "exp", "typ", "extra"])
async def test_missing_or_mismatched_active_jti_is_unauthenticated(
    mutation: str,
) -> None:
    settings, claims, record = await _issued_claims_and_record()
    payload = json.loads(record)
    if mutation == "sub":
        payload["sub"] = str(uuid.uuid4())
    elif mutation in {"iat", "exp"}:
        payload[mutation] += 1
    elif mutation == "typ":
        payload["typ"] = "other"
    else:
        payload["unexpected"] = True

    redis, mock = redis_mock()
    mock.eval.return_value = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    with pytest.raises(RbacError) as caught:
        await require_active_jti(redis, claims=claims, settings=settings)

    assert caught.value.status_code == 401


@pytest.mark.parametrize("value", [None, "not-json", "{}"])
async def test_active_jti_miss_or_malformed_record_is_unauthenticated(
    value: str | None,
) -> None:
    settings, claims, _record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = value

    with pytest.raises(RbacError) as caught:
        await require_active_jti(redis, claims=claims, settings=settings)

    assert caught.value.status_code == 401


async def test_active_jti_read_failure_is_service_unavailable() -> None:
    settings, claims, _record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("unavailable")

    with pytest.raises(RbacError) as caught:
        await require_active_jti(redis, claims=claims, settings=settings)

    assert caught.value.status_code == 503


async def test_logout_deletes_only_the_current_hashed_jti_key() -> None:
    settings, claims, record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = 1

    await revoke_active_jti(
        redis,
        claims=claims,
        user_token_version=4,
        settings=settings,
    )

    mock.eval.assert_awaited_once()
    _script, key_count, key, index, expected = mock.eval.await_args.args
    assert key_count == 2
    assert "auth:sessions:" in index
    assert str(claims.token_id) not in key
    assert expected == record


@pytest.mark.parametrize("result", [0, -1])
async def test_logout_rejects_a_missing_or_replaced_record(result: int) -> None:
    settings, claims, _record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = result

    with pytest.raises(RbacError) as caught:
        await revoke_active_jti(
            redis,
            claims=claims,
            user_token_version=4,
            settings=settings,
        )

    assert caught.value.status_code == 401


async def test_logout_does_not_report_success_when_redis_delete_fails() -> None:
    settings, claims, _record = await _issued_claims_and_record()
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("outcome unknown")

    with pytest.raises(RbacError) as caught:
        await revoke_active_jti(
            redis,
            claims=claims,
            user_token_version=4,
            settings=settings,
        )

    assert caught.value.status_code == 503
