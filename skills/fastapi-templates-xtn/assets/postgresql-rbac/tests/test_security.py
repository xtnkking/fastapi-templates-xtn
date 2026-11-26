#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证 JWT 字段、Redis 活跃会话登记及退出登录的错误边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        补充文件职责记录并覆盖异常 Redis 脚本返回值
# 2026/10/10    XTN       V1.001        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.002        会话摘要去除配置输入并同步活跃检查与退出调用
# 2026/10/13    XTN       V1.003        会话脚本边界同步为记录和登录顺序二键
# 2026/10/13    XTN       V1.004        登录字段准确使用完整 UUID 的 32 位形式
# 2026/10/20    XTN       V1.005        对齐登录会话入口并把 UUID 字段断言合入实际签发流程
# --------------------------------------------------------------------------------------------------

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.codes import BusinessCode
from app.core.config import Settings, get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import (
    MAX_BEARER_TOKEN_BYTES,
    OPTIONAL_ACCESS_TOKEN_FIELDS,
    REQUIRED_ACCESS_TOKEN_FIELDS,
    AccessTokenInfo,
    decode_access_token,
)
from app.repositories.redis.login_session_repository import (
    _user_session_keys,
    login_session_repository,
)
from app.services.auth_service import auth_service


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
        "user_id": new_entity_id("U"),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + settings.jwt_access_token_ttl_seconds,
        "token_type": "access",
    }
    if settings.jwt_issuer is not None and settings.jwt_audience is not None:
        payload.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
    return payload


def encode(payload: dict[str, Any], *, settings: Settings | None = None, algorithm: str = "HS256") -> str:
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

    token_info = decode_access_token(encode(payload), get_settings())

    assert set(payload) == REQUIRED_ACCESS_TOKEN_FIELDS
    assert token_info.user_id == payload["user_id"]
    assert token_info.token_id == uuid.UUID(payload["jti"])
    assert token_info.issued_at == payload["iat"]
    assert token_info.expires_at == payload["exp"]


@pytest.mark.parametrize("claim", sorted(REQUIRED_ACCESS_TOKEN_FIELDS))
def test_default_mode_rejects_each_missing_required_claim(claim: str) -> None:
    payload = valid_payload()
    payload.pop(claim)

    with pytest.raises(AppError) as caught:
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
def test_default_mode_rejects_optional_scope_claims(extra_claims: dict[str, str]) -> None:
    payload = valid_payload()
    payload.update(extra_claims)

    with pytest.raises(AppError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401


def test_configured_issuer_and_audience_mode_accepts_exact_seven_claims() -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)

    token_info = decode_access_token(encode(payload, settings=settings), settings)

    assert set(payload) == REQUIRED_ACCESS_TOKEN_FIELDS | OPTIONAL_ACCESS_TOKEN_FIELDS
    assert token_info.user_id == payload["user_id"]
    assert token_info.token_id == uuid.UUID(payload["jti"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(iss="https://wrong-issuer.example"),
        lambda payload: payload.update(aud="wrong-audience"),
        lambda payload: payload.update(aud=["fastapi-rbac-example"]),
        lambda payload: payload.update(username="example"),
    ],
)
def test_configured_issuer_and_audience_mode_rejects_invalid_scope(mutate: Callable[[dict[str, Any]], object]) -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)
    mutate(payload)

    with pytest.raises(AppError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


@pytest.mark.parametrize(
    "claim",
    sorted(REQUIRED_ACCESS_TOKEN_FIELDS | OPTIONAL_ACCESS_TOKEN_FIELDS),
)
def test_configured_issuer_and_audience_mode_rejects_each_missing_claim(claim: str) -> None:
    settings = issuer_audience_settings()
    payload = valid_payload(settings)
    payload.pop(claim)

    with pytest.raises(AppError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(token_type="other"),
        lambda payload: payload.update(exp=int(datetime.now(UTC).timestamp()) - 1),
        lambda payload: payload.update(iat=int(datetime.now(UTC).timestamp()) + 60),
        lambda payload: payload.update(user_id="not-a-user-id"),
        lambda payload: payload.update(user_id=str(uuid.uuid1())),
        lambda payload: payload.update(user_id=str(uuid.uuid4()).upper()),
        lambda payload: payload.update(sub=payload["user_id"]),
        lambda payload: payload.update(jti=str(uuid.uuid1())),
        lambda payload: payload.update(iat=True),
        lambda payload: payload.update(exp=1.5),
        lambda payload: payload.update(nbf=payload["iat"]),
        lambda payload: payload.update(username="example"),
        lambda payload: payload.pop("jti"),
    ],
)
def test_invalid_access_token_info_fail_closed(mutate: Callable[[dict[str, Any]], object]) -> None:
    payload = valid_payload()
    mutate(payload)

    with pytest.raises(AppError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401
    assert caught.value.business_code == BusinessCode.INVALID_AUTHENTICATION


def test_decoder_rejects_lifetime_longer_than_configured() -> None:
    settings = get_settings()
    payload = valid_payload(settings)
    payload["exp"] = payload["iat"] + settings.jwt_access_token_ttl_seconds + 1

    with pytest.raises(AppError) as caught:
        decode_access_token(encode(payload, settings=settings), settings)

    assert caught.value.status_code == 401


def test_wrong_jwt_algorithm_fails_closed() -> None:
    with pytest.raises(AppError):
        decode_access_token(encode(valid_payload(), algorithm="HS384"), get_settings())


@pytest.mark.parametrize(("script_result", "registered"), [(1, True), (0, False)])
async def test_repository_registers_supplied_token_info_without_signing(
    monkeypatch: pytest.MonkeyPatch, script_result: int, registered: bool,
) -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = script_result
    now = int(datetime.now(UTC).timestamp())
    token_info = AccessTokenInfo(new_entity_id("U"), uuid.uuid4(), now, now + 300)
    sign_token = Mock(side_effect=AssertionError("the repository must not sign Tokens"))
    monkeypatch.setattr("app.core.security.jwt_tokens.encode_access_token", sign_token)

    result = await login_session_repository.register_login_session(
        redis, token_info=token_info, user_token_version=7, max_active_sessions=2,
    )

    assert result is registered
    sign_token.assert_not_called()
    mock.eval.assert_awaited_once()
    assert mock.eval.await_args.args[4] == token_info.token_id.hex
    assert json.loads(mock.eval.await_args.args[5])["user_id"] == token_info.user_id


async def test_issuer_registers_exact_minimal_token_before_returning() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    settings = get_settings()
    user_id = new_entity_id("U")

    token = await auth_service.issue_access_token(
        redis,
        user_id=user_id,
        user_token_version=7,
        settings=settings,
    )
    token_info = decode_access_token(token, settings)
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
    )

    assert set(payload) == REQUIRED_ACCESS_TOKEN_FIELDS
    assert (
        payload["exp"] - payload["iat"]
        == settings.jwt_access_token_ttl_seconds
        == 86_400
    )
    assert payload["user_id"] == str(user_id)
    mock.eval.assert_awaited_once()
    (
        script,
        key_count,
        records_key,
        order_key,
        field,
        value,
        expires_at,
        version,
        maximum,
    ) = mock.eval.await_args.args
    assert key_count == 2
    assert "redis.call('TIME')" in script
    assert (records_key, order_key) == _user_session_keys(
        user_id=user_id
    )
    assert field == token_info.token_id.hex
    assert len(field) == 32
    assert uuid.UUID(hex=field) == token_info.token_id
    assert str(token_info.token_id) not in field
    assert (records_key, order_key) == (
        f"login:sessions:{user_id}",
        f"login:sequence:{user_id}",
    )
    assert json.loads(value) == {
        "exp": token_info.expires_at,
        "iat": token_info.issued_at,
        "user_id": str(user_id),
        "token_version": 7,
        "typ": "access",
    }
    assert expires_at == str(token_info.expires_at)
    assert version == "7"
    assert maximum == str(settings.max_active_sessions_per_user)
    assert mock.eval.await_args.kwargs == {}


async def test_issuer_uses_configured_access_token_lifetime() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    settings = get_settings().model_copy(update={"jwt_access_token_ttl_seconds": 900})

    token = await auth_service.issue_access_token(
        redis,
        user_id=new_entity_id("U"),
        user_token_version=0,
        settings=settings,
    )
    token_info = decode_access_token(token, settings)

    assert token_info.expires_at - token_info.issued_at == 900


async def test_configured_scope_uses_the_same_active_jti_lifecycle() -> None:
    settings = issuer_audience_settings()
    redis, mock = redis_mock()
    mock.eval.return_value = 1
    user_id = new_entity_id("U")

    token = await auth_service.issue_access_token(
        redis,
        user_id=user_id,
        user_token_version=9,
        settings=settings,
    )
    token_info = decode_access_token(token, settings)
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"strict_aud": True},
    )
    registration_args = mock.eval.await_args.args
    key, field, record = registration_args[2], registration_args[4], registration_args[5]
    assert field == token_info.token_id.hex
    mock.eval.return_value = record

    version = await login_session_repository.check_login_session(redis, token_info=token_info)
    assert mock.eval.await_args.args[4] == field
    mock.eval.return_value = 1
    await login_session_repository.delete_login_session(
        redis,
        token_info=token_info,
        user_token_version=version,
    )

    assert set(payload) == REQUIRED_ACCESS_TOKEN_FIELDS | OPTIONAL_ACCESS_TOKEN_FIELDS
    assert payload["user_id"] == str(user_id)
    assert mock.eval.await_args.args[2] == key
    assert mock.eval.await_args.args[4] == field
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

    token = await auth_service.issue_access_token(
        redis,
        user_id=new_entity_id("U"),
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
        await auth_service.issue_access_token(
            redis,
            user_id=new_entity_id("U"),
            user_token_version=0,
            settings=settings,
        )

    mock.eval.assert_not_awaited()


async def test_issuer_retries_one_duplicate_jti_then_succeeds() -> None:
    redis, mock = redis_mock()
    mock.eval.side_effect = [0, 1]

    token = await auth_service.issue_access_token(
        redis,
        user_id=new_entity_id("U"),
        user_token_version=0,
        settings=get_settings(),
    )

    assert token
    assert mock.eval.await_count == 2
    assert mock.eval.await_args_list[0].args[4] != mock.eval.await_args_list[1].args[4]


async def test_issuer_does_not_return_after_duplicate_retry_is_exhausted() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = 0

    with pytest.raises(AppError) as caught:
        await auth_service.issue_access_token(
            redis,
            user_id=new_entity_id("U"),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503
    assert mock.eval.await_count == 2


async def test_issuer_rejects_a_stale_token_version_without_retry() -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = -2

    with pytest.raises(AppError) as caught:
        await auth_service.issue_access_token(
            redis,
            user_id=new_entity_id("U"),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 401
    mock.eval.assert_awaited_once()


async def test_issuer_maps_redis_failure_to_service_unavailable() -> None:
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("unavailable")

    with pytest.raises(AppError) as caught:
        await auth_service.issue_access_token(
            redis,
            user_id=new_entity_id("U"),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503


@pytest.mark.parametrize("result", [-1, None, True, "OK"])
async def test_issuer_fails_closed_for_invalid_or_expired_registry_result(result: object) -> None:
    redis, mock = redis_mock()
    mock.eval.return_value = result

    with pytest.raises(AppError) as caught:
        await auth_service.issue_access_token(
            redis,
            user_id=new_entity_id("U"),
            user_token_version=0,
            settings=get_settings(),
        )

    assert caught.value.status_code == 503
    mock.eval.assert_awaited_once()


async def _issued_token_info_and_record() -> tuple[Settings, AccessTokenInfo, str]:
    settings = get_settings()
    issuer_redis, issuer_mock = redis_mock()
    issuer_mock.eval.return_value = 1
    token = await auth_service.issue_access_token(
        issuer_redis,
        user_id=new_entity_id("U"),
        user_token_version=4,
        settings=settings,
    )
    return (
        settings,
        decode_access_token(token, settings),
        issuer_mock.eval.await_args.args[5],
    )


async def test_active_jti_returns_server_side_version_without_extending_ttl() -> None:
    _settings, token_info, record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = record

    version = await login_session_repository.check_login_session(redis, token_info=token_info)

    assert version == 4
    mock.eval.assert_awaited_once()
    _script, key_count, records, order, field = mock.eval.await_args.args
    assert key_count == 2
    assert (records, order) == _user_session_keys(user_id=token_info.user_id)
    assert field == token_info.token_id.hex
    mock.set.assert_not_awaited()
    mock.expire.assert_not_awaited()


async def test_session_list_declares_only_record_and_login_order_keys() -> None:
    """
        会话列表脚本显式声明同一用户的二键，并传入数据库取得的当前版本。

    :return: 无返回值；列表结果和 Lua 输入契约一致时通过。
    """
    redis, mock = redis_mock()
    mock.eval.return_value = [10, 20]
    user_id = new_entity_id("U")

    assert await login_session_repository.list_active_sessions(
        redis, user_id=user_id, token_version=4
    ) == (10, 20)

    mock.eval.assert_awaited_once()
    _script, key_count, records, order, version = mock.eval.await_args.args
    assert key_count == 2
    assert (records, order) == _user_session_keys(user_id=user_id)
    assert version == "4"


@pytest.mark.parametrize("mutation", ["user_id", "iat", "exp", "typ", "extra"])
async def test_missing_or_mismatched_active_jti_is_unauthenticated(mutation: str) -> None:
    _settings, token_info, record = await _issued_token_info_and_record()
    payload = json.loads(record)
    if mutation == "user_id":
        payload["user_id"] = new_entity_id("U")
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

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=token_info)

    assert caught.value.status_code == 401


@pytest.mark.parametrize("value", [None, "not-json", "{}"])
async def test_active_jti_miss_or_malformed_record_is_unauthenticated(value: str | None) -> None:
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = value

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=token_info)

    assert caught.value.status_code == 401


@pytest.mark.parametrize("value", [False, 1, []])
async def test_active_jti_unexpected_script_reply_is_service_unavailable(value: object) -> None:
    """
        Redis 脚本返回协议外类型时报告服务故障，不误称客户端 Token 已失效。

    :param value: 脚本约定之外的返回值。
    :return: 无返回值；统一服务不可用状态由断言确认。
    """
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = value

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=token_info)

    assert caught.value.status_code == 503


async def test_active_jti_read_failure_is_service_unavailable() -> None:
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("unavailable")

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=token_info)

    assert caught.value.status_code == 503


async def test_logout_deletes_only_the_current_hashed_jti_field() -> None:
    _settings, token_info, record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = 1

    await login_session_repository.delete_login_session(
        redis,
        token_info=token_info,
        user_token_version=4,
    )

    mock.eval.assert_awaited_once()
    _script, key_count, records, order, field, expected = (
        mock.eval.await_args.args
    )
    assert key_count == 2
    assert (records, order) == _user_session_keys(
        user_id=token_info.user_id
    )
    assert field == token_info.token_id.hex
    assert str(token_info.token_id) not in field
    assert expected == record


@pytest.mark.parametrize("result", [0, -1])
async def test_logout_rejects_a_missing_or_replaced_record(result: int) -> None:
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = result

    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(
            redis,
            token_info=token_info,
            user_token_version=4,
        )

    assert caught.value.status_code == 401


@pytest.mark.parametrize("result", [None, True, 2, -2, "1"])
async def test_logout_unexpected_script_reply_is_service_unavailable(result: object) -> None:
    """
        退出结果不在脚本约定范围内时保留重试可能，不能误报普通凭据错误。

    :param result: 模拟 Redis 脚本的异常返回值。
    :return: 无返回值；统一服务不可用状态由断言确认。
    """
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.return_value = result

    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(
            redis,
            token_info=token_info,
            user_token_version=4,
        )

    assert caught.value.status_code == 503


async def test_logout_does_not_report_success_when_redis_delete_fails() -> None:
    _settings, token_info, _record = await _issued_token_info_and_record()
    redis, mock = redis_mock()
    mock.eval.side_effect = RedisConnectionError("outcome unknown")

    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(
            redis,
            token_info=token_info,
            user_token_version=4,
        )

    assert caught.value.status_code == 503
