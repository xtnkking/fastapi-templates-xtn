#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证退出登录的认证、精确撤销和拒绝边界，不访问限流或数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/10    XTN       V1.001        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.002        对齐退出限流键移除命名空间后的调用契约
# 2026/10/22    XTN       V1.003        删除退出额度要求，验证认证与精确撤销且不访问限流
# --------------------------------------------------------------------------------------------------

import json
import uuid
from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError

import app.api.v1.endpoints.auth as auth_api
import app.dependencies.auth as auth_dependencies
import app.dependencies.rate_limit as rate_limit_dependencies
from app.core.config import get_settings
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import encode_access_token
from app.main import app


@pytest.mark.parametrize("case,expected_status,session_calls", [
    ("success", 200, 2),
    ("revoked_token", 401, 1),
    ("session_unavailable", 503, 1),
    ("delete_unavailable", 503, 2),
    ("session_replaced", 401, 2),
    ("invalid_signature", 401, 0),
    ("expired_token", 401, 0),
    ("missing_token", 401, 0),
])
async def test_logout_verifies_then_revokes_without_quota_or_database(monkeypatch: pytest.MonkeyPatch,
                                                                      case: str,
                                                                      expected_status: int,
                                                                      session_calls: int
                                                                      ) -> None:
    """
        从真实 HTTP 路由验证退出先认证、再删除当前登录，完全不接触限流或数据库。
        保留真实 JWT 校验和 Redis 结果解析，只替换 Redis I/O。

    :param monkeypatch: 临时替换登录存储，并禁止访问数据库和限流后端。
    :param case: 正常退出或 Token、登录记录、Redis 故障的拒绝场景。
    :param expected_status: 该场景应返回的 HTTP 状态。
    :param session_calls: 首次退出应调用登录 Redis 的次数。
    :return: 无返回值；只允许有效登录精确退出，失败不得误报成功。
    """
    settings = get_settings()
    token, token_info = encode_access_token(
        user_id=new_entity_id("U"), token_id=uuid.uuid4(), settings=settings,
    )
    # Redis 中保存的版本只用于精确核对本次登录，不要求退出时再查询数据库权限。
    record = json.dumps(
        {"exp": token_info.expires_at, "iat": token_info.issued_at, "user_id": token_info.user_id,
         "token_version": 7, "typ": "access"},
        sort_keys=True, separators=(",", ":"),
    )
    session_results: list[object] = [record, 1, None]
    if case == "revoked_token":
        session_results = [None]
    elif case == "session_unavailable":
        session_results = [RedisConnectionError("test session store unavailable")]
    elif case == "delete_unavailable":
        session_results = [record, RedisConnectionError("test session deletion unavailable")]
    elif case == "session_replaced":
        session_results = [record, -1]
    elif case == "invalid_signature":
        # 保留真实签发的声明，破坏签名；应在访问任何 Redis 之前拒绝。
        token = token.rsplit(".", 1)[0] + ".invalid-signature"
    elif case == "expired_token":
        # 使用真实签名，但到期时间早于允许的时钟偏差；不能进入 Redis 登录校验。
        expired_at = token_info.issued_at - 60
        token_fields: dict[str, object] = {
            "user_id": token_info.user_id,
            "jti": str(token_info.token_id),
            "iat": expired_at - settings.jwt_access_token_ttl_seconds,
            "exp": expired_at,
            "token_type": "access",
        }
        if settings.jwt_issuer is not None:
            token_fields.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
        token = jwt.encode(token_fields, settings.jwt_secret.get_secret_value(), algorithm="HS256")

    session_redis = Mock()
    session_redis.eval = AsyncMock(side_effect=session_results)
    database_factory = Mock(side_effect=AssertionError("logout must not query PostgreSQL"))
    quota_factory = Mock(side_effect=AssertionError("logout must not access the rate-limit backend"))
    monkeypatch.setattr(auth_dependencies, "SessionFactory", database_factory)
    monkeypatch.setattr(auth_dependencies, "get_redis", lambda _request: session_redis)
    monkeypatch.setattr(auth_api, "get_redis", lambda _request: session_redis)
    monkeypatch.setattr(rate_limit_dependencies, "get_rate_limit_redis", quota_factory)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {} if case == "missing_token" else {"Authorization": f"Bearer {token}"}
        response = await client.post("/api/v1/auth/logout", headers=headers)
        assert response.status_code == expected_status, response.text
        assert session_redis.eval.await_count == session_calls
        if session_calls:
            # 第一次只查这张 Token；需要删除时再携带完整记录，不能误删其他登录。
            assert session_redis.eval.await_args_list[0].args[-1] == token_info.token_id.hex
        if session_calls == 2:
            assert session_redis.eval.await_args_list[1].args[-1] == record
        if case == "success":
            assert response.json()["data"] is None
            # 已经退出的 Token 再请求时认证失败，不得再次执行删除。
            repeated = await client.post("/api/v1/auth/logout", headers=headers)
            assert repeated.status_code == 401, repeated.text
            assert session_redis.eval.await_count == 3
    database_factory.assert_not_called()
    quota_factory.assert_not_called()
