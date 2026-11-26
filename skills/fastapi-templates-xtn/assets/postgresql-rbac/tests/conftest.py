#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    隔离测试配置，提供无管理权限的身份和仅在测试期间注册的成功响应路由。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        通过临时测试路由验证成功响应，不依赖默认健康入口
# 2026/09/30    XTN       V1.001        移除废弃的管理员密码模式环境配置
# 2026/10/09    XTN       V1.002        普通成功响应使用统一默认业务码
# 2026/10/14    XTN       V1.003        提供独立日志密码指纹测试密钥，不继承应用真实密钥
# 2026/10/15    XTN       V1.004        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V1.005        为直接审计测试提供显式启用的请求上下文
# 2026/10/16    XTN       V1.006        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/22    XTN       V1.007        新增管理测试隔离夹具，保留真实权限检查
# 2026/10/26    XTN       V1.008        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# --------------------------------------------------------------------------------------------------

import os
import uuid
from collections.abc import Callable, Iterator
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, Request
from sqlalchemy.engine import make_url

from app.core.access.authorization import AuthorizationContext, LoginInfo, UserInfo
from app.core.ids import new_entity_id
from app.core.logging.context import (
    bind_request_context,
    deactivate_request_context,
    reset_request_context,
)

test_database_url = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/rbac_example_test",
)
parsed_test_url = make_url(test_database_url)
if (
    parsed_test_url.drivername != "postgresql+asyncpg"
    or parsed_test_url.database is None
    or not parsed_test_url.database.endswith("_test")
):
    raise RuntimeError(
        "TEST_DATABASE_URL must use postgresql+asyncpg and a database name "
        "ending in '_test'"
    )

# Tests never inherit the application's DATABASE_URL.
os.environ["DATABASE_URL"] = test_database_url
os.environ["REDIS_URL"] = os.environ.get(
    "TEST_REDIS_URL",
    "redis://127.0.0.1:6379/15",
)
os.environ["RATE_LIMIT_REDIS_URL"] = os.environ.get(
    "TEST_RATE_LIMIT_REDIS_URL",
    "redis://127.0.0.1:6380/0",
)
os.environ["APP_ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz"
os.environ["RATE_LIMIT_HMAC_KEY"] = "vM8qD2kR7pX4cN9sH5wF1jL6tG3yB0uZ"
os.environ["LOG_HMAC_KEY"] = "N6wR2tY9qH4kF7vD1sL8cB3mJ5xP0uGa"
os.environ["MAX_ACTIVE_SESSIONS_PER_USER"] = "2"
os.environ["VERIFICATION_ENABLED"] = "false"
os.environ.pop("VERIFICATION_CODE_HMAC_KEY", None)
os.environ.pop("VERIFICATION_ENABLED_PURPOSES", None)
os.environ.pop("VERIFICATION_ENABLED_CHANNELS", None)
os.environ.pop("JWT_ISSUER", None)
os.environ.pop("JWT_AUDIENCE", None)
os.environ["JWT_ACCESS_TOKEN_TTL_SECONDS"] = "86400"


@pytest.fixture
def success_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """
        为响应和中间件测试临时注册不访问外部依赖的成功路由。
        复制路由表并隔离离线 schema 缓存，夹具结束后由 monkeypatch 恢复原值。

    :param monkeypatch: 管理路由表和 schema 缓存的临时替换及自动恢复。
    :return: 保留真实应用中间件、仅本次测试附加成功路由的应用。
    """
    from app.core.i18n.messages import MessageKey
    from app.core.response import ApiResponse, api_response
    from app.main import app

    monkeypatch.setattr(app.router, "routes", list(app.router.routes))
    monkeypatch.setattr(app, "openapi_schema", None)

    @app.get("/controlled-test/success", response_model=ApiResponse[dict[str, str]])
    async def controlled_success(request: Request) -> ApiResponse[dict[str, str]]:
        """
            返回固定成功数据，供语言协商和请求日志验证使用。
            不属于默认业务接口，也不访问数据库、Redis 或认证依赖。

        :param request: 当前测试请求，用于响应文案和服务端请求 ID。
        :return: 固定状态数据及统一成功响应。
        """
        return api_response(
            request,
            message_key=MessageKey.COMMON_OPERATION_SUCCESS,
            data={"status": "ok"},
        )

    return app


@pytest.fixture
def audit_request_context() -> Iterator[str]:
    """
        为明确启用此夹具的直接服务测试绑定操作入口的请求 ID。
        不自动应用，缺失上下文的拒绝用例仍能覆盖真实调用限制。

    :yield: 当前测试的请求 ID；结束后使复制上下文失效并恢复原上下文。
    """
    request_id = str(uuid.uuid4())
    token = bind_request_context(request_id)
    try:
        yield request_id
    finally:
        deactivate_request_context()
        reset_request_context(token)


@pytest.fixture
def unprivileged_authorization_context() -> AuthorizationContext:
    """Give each service-boundary test its own live identity without role grants."""
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=1,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    return AuthorizationContext(
        login_info=login_info,
        user_info=UserInfo.build(
            user_id=login_info.user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=login_info.token_version,
            roles=(),
        ),
    )


@pytest.fixture
def override_management(monkeypatch: pytest.MonkeyPatch) -> Callable[[AuthorizationContext], None]:
    """Isolate Token, quota and account I/O while keeping the real permission dependency."""
    from app.dependencies import auth, permission
    from app.main import app

    def use_context(context: AuthorizationContext) -> None:
        async def checked_token(request: Request) -> LoginInfo:
            request.state.user_id = context.login_info.user_id
            return context.login_info

        monkeypatch.setitem(app.dependency_overrides, auth.check_token, checked_token)
        monkeypatch.setattr(auth, "_load_current_user", AsyncMock(return_value=context))
        monkeypatch.setattr(permission, "rate_limit_user", AsyncMock())

    return use_context
