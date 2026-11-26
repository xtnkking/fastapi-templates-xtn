#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证依赖故障日志只记录安全元信息，不泄露连接凭据。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充会话列表 Redis 故障日志验证
# 2026/10/02    XTN       V1.001        核对 Redis 断连、超时及其他错误的安全分类
# 2026/10/09    XTN       V1.002        对齐用户限流预查与正式计数函数名称
# 2026/10/10    XTN       V1.003        验证单次限流计数先于数据库身份检查
# 2026/10/10    XTN       V1.004        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.005        会话读取、撤销和列表故障检查移除多余配置参数
# 2026/10/15    XTN       V1.006        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V1.007        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/20    XTN       V1.008        同步登录会话检查与删除入口，保留原有行为断言
# 2026/10/22    XTN       V1.009        对齐鉴权入口及管理权限拒绝的安全日志
# 2026/10/26    XTN       V1.010        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# --------------------------------------------------------------------------------------------------

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import ResponseError as RedisResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.access.authorization import AuthorizationContext, LoginInfo, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import AccessTokenInfo
from app.dependencies import auth as dependencies
from app.dependencies import permission as permission_dependency
from app.models.postgres.user import User
from app.repositories.postgres.user_repository import user_repository
from app.repositories.redis import login_session_repository as session_repository_module
from app.repositories.redis.login_session_repository import login_session_repository
from app.services import audit_service as audit_module
from app.services.audit_service import AuditService
from app.services.auth_service import auth_service


def request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/test", "headers": []})


def login_info(*, token_version: int = 3) -> LoginInfo:
    return LoginInfo(
        user_id=new_entity_id("U"),
        token_version=token_version,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


def authority(login_info: LoginInfo, *, active: bool = True, token_version: int | None = None) -> UserInfo:
    return UserInfo.build(
        user_id=login_info.user_id,
        user_is_active=active,
        user_is_protected=False,
        token_version=(
            login_info.token_version if token_version is None else token_version
        ),
        roles=(),
    )


@pytest.fixture
def authorization_session(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    monkeypatch.setattr(dependencies, "SessionFactory",
                        Mock(return_value=session))
    return session


@pytest.fixture(autouse=True)
def isolate_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        隔离本文件不关心的 Redis 计数，专门验证依赖日志和身份状态处理。

    :param monkeypatch: 把限流计数替换为不访问 Redis 的异步测试替身。
    :return: 无返回值；生产路由接线和真实限流行为由限流专项测试覆盖。
    """
    monkeypatch.setattr(
        dependencies,
        "rate_limit_user",
        AsyncMock(),
    )


def build_token_info() -> AccessTokenInfo:
    return AccessTokenInfo(
        user_id=new_entity_id("U"),
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


async def test_login_info_only_path_does_not_mark_authenticated_current_user(monkeypatch: pytest.MonkeyPatch) -> None:
    current_request = request()
    current_token_info = build_token_info()
    monkeypatch.setattr(
        dependencies, "decode_access_token", Mock(return_value=current_token_info)
    )
    monkeypatch.setattr(dependencies, "get_redis",
                        Mock(return_value=AsyncMock()))
    monkeypatch.setattr(login_session_repository, "check_login_session",
                        AsyncMock(return_value=3))
    current_user_limit = AsyncMock()
    monkeypatch.setattr(dependencies, "rate_limit_user", current_user_limit)

    result = await dependencies.check_token(
        current_request,
        HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="signed-token"),
        get_settings(),
    )

    assert result.user_id == current_token_info.user_id
    assert not hasattr(current_request.state, "user_id")
    current_user_limit.assert_not_awaited()


@pytest.mark.parametrize(
    ("active", "authority_token_version"),
    [(False, 3), (True, 4)],
)
async def test_rejected_postgresql_identity_does_not_mark_current_user(authorization_session: AsyncMock,
                                                                       monkeypatch: pytest.MonkeyPatch, active: bool,
                                                                       authority_token_version: int) -> None:
    current_request = request()
    current_login_info = login_info()
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(
            return_value=User(
                user_id=current_login_info.user_id,
                is_active=active,
                token_version=authority_token_version,
            )
        ),
    )
    revoke = AsyncMock()
    current_user_limit = AsyncMock()
    monkeypatch.setattr(
        dependencies,
        "_clear_invalid_login",
        revoke,
    )
    monkeypatch.setattr(dependencies, "rate_limit_user", current_user_limit)

    with pytest.raises(AppError) as caught:
        await dependencies.get_current_user(
            current_request,
            current_login_info,
            get_settings(),
        )

    assert caught.value.status_code == 401
    assert not hasattr(current_request.state, "user_id")
    revoke.assert_awaited_once()
    current_user_limit.assert_awaited_once()


async def test_database_failure_logs_once_without_marking_current_user(authorization_session: AsyncMock,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    current_request = request()
    current_login_info = login_info()
    error = OperationalError(
        "SELECT secret FROM users",
        {},
        RuntimeError("database-password"),
        connection_invalidated=True,
    )
    monkeypatch.setattr(user_repository,
                        "check_current_user", AsyncMock(side_effect=error))
    log = Mock(return_value=True)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "OperationalError",
    }
    monkeypatch.setattr(dependencies, "safe_log", log)
    monkeypatch.setattr(
        dependencies,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )

    with pytest.raises(AppError) as caught:
        await dependencies.get_current_user(
            current_request,
            current_login_info,
            get_settings(),
        )

    assert caught.value.status_code == 503
    assert not hasattr(current_request.state, "user_id")
    log.assert_called_once_with(
        dependencies.logger,
        logging.ERROR,
        "dependency.database.unavailable",
        extra={
            "dependency": "postgresql",
            "dependency_operation": "load_current_user",
            "error_category": "connection",
            **exception_metadata,
        },
    )


async def test_successful_authorization_context_marks_current_user(authorization_session: AsyncMock,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    current_request = request()
    current_login_info = login_info()
    events: list[str] = []

    async def load_current_authority(*_args: object, **_kwargs: object) -> UserInfo:
        events.append("database")
        return authority(current_login_info)

    monkeypatch.setattr(
        user_repository,
        "check_current_user",
        load_current_authority,
    )

    async def current_user_limit(*_args: object, **_kwargs: object) -> None:
        events.append("current_user_limit")

    monkeypatch.setattr(dependencies, "rate_limit_user", current_user_limit)

    context = await dependencies.get_current_user(
        current_request,
        current_login_info,
        get_settings(),
    )

    assert context.login_info == current_login_info
    assert current_request.state.user_id == str(current_login_info.user_id)
    assert events == ["current_user_limit", "database"]


async def test_audit_log_failure_does_not_replace_permission_denial(
    monkeypatch: pytest.MonkeyPatch,
    override_management: Callable[[AuthorizationContext], None],
) -> None:
    current_login_info = login_info()
    context = AuthorizationContext(
        login_info=current_login_info,
        user_info=authority(current_login_info),
    )
    override_management(context)
    current_request = Request(
        {"type": "http", "method": "POST", "path": "/test", "headers": []}
    )
    build_denied_response = Mock(
        side_effect=RuntimeError("audit-database-password"))
    log = Mock(return_value=False)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "RuntimeError",
    }
    monkeypatch.setattr(AuditService,
                        "_response_snapshot", build_denied_response)
    monkeypatch.setattr(audit_module, "safe_log", log)
    monkeypatch.setattr(
        audit_module,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )
    require_read = permission_dependency.require_permission(
        PermissionKey.ROLES_READ, management=True)

    with pytest.raises(AppError) as caught:
        await require_read(request=current_request, login_info=current_login_info, settings=get_settings())

    assert caught.value.status_code == 403
    log.assert_called_once_with(
        audit_module.logger,
        logging.ERROR,
        "audit.write.failed",
        extra={
            "audit_action": "api.protected_write",
            **exception_metadata,
        },
    )


@pytest.mark.parametrize(
    ("error", "category"),
    [
        pytest.param(RedisConnectionError(
            "redis://user:password@example.test/0"), "connection", id="connection"),
        pytest.param(RedisTimeoutError(
            "redis://user:password@example.test/0"), "timeout", id="timeout"),
        pytest.param(RedisResponseError(
            "redis://user:password@example.test/0"), "unknown", id="other"),
    ],
)
@pytest.mark.parametrize(
    ("operation", "dependency_operation"),
    [
        ("issue", "register_active_jti"),
        ("require", "read_active_jti"),
        ("revoke", "revoke_active_jti"),
        ("list", "list_active_sessions"),
    ],
)
async def test_redis_failure_logs_once_before_503_conversion(monkeypatch: pytest.MonkeyPatch, operation: str,
                                                             dependency_operation: str, error: RedisError,
                                                             category: str) -> None:
    """
        四种会话 Redis 操作发生断连、超时或其他故障时只记录一次安全日志，再返回统一 503。

    :param monkeypatch: 临时替换日志入口与安全异常元信息生成函数。
    :param operation: 本次模拟故障的会话操作。
    :param dependency_operation: 该操作在结构化日志中的固定名称。
    :param error: 含敏感模拟连接串的 Redis 异常，不得进入日志字段。
    :param category: 当前异常应记录的稳定故障类别。
    :return: 无返回值；断言故障结果与安全日志内容。
    """
    redis = AsyncMock()
    redis.eval.side_effect = error
    log = Mock(return_value=True)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": type(error).__name__,
    }
    monkeypatch.setattr(session_repository_module, "safe_log", log)
    monkeypatch.setattr(
        session_repository_module,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )
    settings = get_settings()
    current_token_info = build_token_info()

    calls: dict[str, Callable[[], Awaitable[object]]] = {
        "issue": lambda: auth_service.issue_access_token(
            cast(Redis, redis),
            user_id=current_token_info.user_id,
            user_token_version=3,
            settings=settings,
        ),
        "require": lambda: session_repository_module.login_session_repository.check_login_session(
            cast(Redis, redis), token_info=current_token_info
        ),
        "revoke": lambda: session_repository_module.login_session_repository.delete_login_session(
            cast(Redis, redis),
            token_info=current_token_info,
            user_token_version=3,
        ),
        "list": lambda: session_repository_module.login_session_repository.list_active_sessions(
            cast(Redis, redis),
            user_id=current_token_info.user_id,
            token_version=3,
        ),
    }

    with pytest.raises(AppError) as caught:
        await calls[operation]()

    assert caught.value.status_code == 503
    log.assert_called_once_with(
        session_repository_module.logger,
        logging.ERROR,
        "dependency.redis.unavailable",
        extra={
            "dependency": "redis",
            "dependency_operation": dependency_operation,
            "error_category": category,
            **exception_metadata,
        },
    )
