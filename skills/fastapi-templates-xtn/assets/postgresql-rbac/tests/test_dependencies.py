#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证请求认证与权限依赖的身份、额度、异常及数据库会话顺序。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        补充文件职责并验证验证码不消耗通用业务额度
# 2026/10/04    XTN       V1.001        断言验证码依赖直接选择拒绝额度而非转发
# 2026/10/04    XTN       V1.002        验证验证码场景只读取一次并传入额度预查
# 2026/10/04    XTN       V1.003        验证码依赖改为调用统一场景扣次入口
# 2026/10/09    XTN       V1.004        用户限流和验证码用途读取使用直观名称
# 2026/10/09    XTN       V1.005        对齐验证码无效用途限流的直观业务名称
# 2026/10/10    XTN       V1.006        验证单次用户计数先于数据库且失效账号仍撤销会话
# 2026/10/10    XTN       V1.007        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.008        认证会话检查和失效 JTI 清理不再传入配置
# 2026/10/15    XTN       V1.009        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V1.010        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.011        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/20    XTN       V1.012        请求头解析结果采用 token_header，保留 FastAPI 原有字段
# 2026/10/20    XTN       V1.013        同步登录会话检查与删除入口，保留原有行为断言
# 2026/10/22    XTN       V1.014        对齐 Token 和当前用户入口，直接验证权限回调
# 2026/10/22    XTN       V1.015        验证接口权限不自动选择管理额度，保留认证及拒绝顺序
# 2026/10/24    XTN       V1.016        验证码场景名称明确具体用户操作
# 2026/10/26    XTN       V1.017        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from httpx import ASGITransport, AsyncClient, Response
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

import app.dependencies.auth as auth_dependency
import app.dependencies.rate_limit as rate_limit_dependency
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.codes import BusinessCode
from app.core.config import get_settings
from app.core.exceptions import AppError, unauthenticated_401, unavailable_503
from app.core.ids import new_entity_id
from app.core.rate_limit.limiter import RateLimitExceeded, RateLimitResult
from app.core.security.jwt_tokens import AccessTokenInfo
from app.dependencies.auth import (
    check_token,
    get_captcha_user,
    get_current_user,
)
from app.dependencies.permission import require_permission
from app.main import app
from app.models.postgres.user import User
from app.repositories.postgres.user_repository import user_repository
from app.services.auth_service import auth_service


@pytest.fixture
def authorization_session(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """
        隔离数据库和唯一用户计数入口，让身份边界测试无需真实服务。

    :param monkeypatch: 替换授权会话工厂和单次用户限流依赖。
    :return: 可以断言连接及查询时机的模拟会话。
    """
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    monkeypatch.setattr(
        "app.dependencies.auth.SessionFactory", Mock(return_value=session)
    )
    # 非限流单元测试替换唯一的用户扣次入口；专门的限流测试自行模拟拒绝。
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        AsyncMock(),
    )
    return session


def assert_error_response(response: Response, expected_code: BusinessCode) -> None:
    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(expected_code)
    assert body["data"] is None
    request_id = uuid.UUID(body["request_id"])
    assert request_id.version == 4
    assert response.headers["X-Request-ID"] == body["request_id"]


def authorization_context(*permission_groups: set[str]) -> AuthorizationContext:
    user_id = new_entity_id("U")
    roles = tuple(
        RoleGrant(
            role_id=new_entity_id("R"),
            key=f"role_{index}",
            level=index + 1,
            permissions=frozenset(permissions),
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        )
        for index, permissions in enumerate(permission_groups)
    )
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=roles,
    )
    return AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )


async def test_require_permission_accepts_grant_from_second_role(
    override_management: Callable[[AuthorizationContext], None],
) -> None:
    context = authorization_context(
        {PermissionKey.PROJECTS_READ.value},
        {PermissionKey.ROLES_READ.value},
    )
    dependency = require_permission(PermissionKey.ROLES_READ, management=True)
    override_management(context)

    request = Request({"type": "http", "method": "GET", "headers": []})
    assert await dependency(request=request, login_info=context.login_info, settings=get_settings()) is context


@pytest.mark.parametrize("management", [False, True], ids=["business", "management"])
async def test_require_permission_denies_missing_grant(
    management: bool,
    override_management: Callable[[AuthorizationContext], None],
) -> None:
    dependency = require_permission(PermissionKey.ROLES_READ, management=management)
    denied = authorization_context({PermissionKey.PROJECTS_UPDATE.value})
    override_management(denied)
    request = Request({"type": "http", "method": "GET", "headers": []})

    with pytest.raises(AppError) as caught:
        await dependency(request=request, login_info=denied.login_info, settings=get_settings())
    assert caught.value.status_code == 403
    assert caught.value.business_code == BusinessCode.ACCESS_FORBIDDEN


@pytest.mark.parametrize(
    ("method", "management", "expected_limit"),
    [
        pytest.param("GET", False, 611, id="business-read"),
        pytest.param("POST", False, 123, id="business-write"),
        pytest.param("GET", True, 307, id="management-read"),
        pytest.param("POST", True, 67, id="management-write"),
    ],
)
async def test_permission_quota_is_selected_explicitly_and_counted_once_before_account(
    monkeypatch: pytest.MonkeyPatch, method: str, management: bool, expected_limit: int,
) -> None:
    context = authorization_context({PermissionKey.PROJECTS_READ.value})
    settings = get_settings().model_copy(update={
        "rate_limit_user_read": 611,
        "rate_limit_user_write": 123,
        "rate_limit_admin_read": 307,
        "rate_limit_admin_write": 67,
    })
    events: list[str] = []

    async def checked_token() -> LoginInfo:
        events.append("token")
        return context.login_info

    async def charge_quota(*_args: object, **_kwargs: object) -> None:
        events.append("quota")

    async def load_account(*_args: object, **_kwargs: object) -> AuthorizationContext:
        events.append("account")
        return context

    quota = AsyncMock(side_effect=charge_quota)
    account = AsyncMock(side_effect=load_account)
    monkeypatch.setattr(rate_limit_dependency, "_check_quota", quota)
    monkeypatch.setattr(auth_dependency, "_load_current_user", account)
    if management:
        permission_check = require_permission(PermissionKey.PROJECTS_READ, management=True)
    else:
        # 普通业务故意省略参数，验证权限依赖默认不会选管理额度。
        permission_check = require_permission(PermissionKey.PROJECTS_READ)

    async def business_route(context: AuthorizationContext = Depends(permission_check)) -> dict[str, str]:
        return {"user_id": str(context.login_info.user_id)}

    test_app = FastAPI()
    test_app.dependency_overrides[check_token] = checked_token
    test_app.dependency_overrides[get_settings] = lambda: settings
    test_app.add_api_route("/permission-demo", business_route, methods=[method], name="permission_demo")
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        response = await client.request(method, "/permission-demo")

    assert response.status_code == 200, response.text
    assert response.json() == {"user_id": str(context.login_info.user_id)}
    assert events == ["token", "quota", "account"]
    quota.assert_awaited_once()
    account.assert_awaited_once()
    assert quota.await_args is not None
    assert quota.await_args.kwargs["limit"] == expected_limit
    assert quota.await_args is not None
    assert quota.await_args.kwargs["window_seconds"] == 60
    assert quota.await_args is not None
    assert quota.await_args.kwargs["key_parts"] == [context.login_info.user_id]


@pytest.mark.parametrize("management", [False, True], ids=["business", "management"])
async def test_exhausted_permission_quota_never_loads_account(
    monkeypatch: pytest.MonkeyPatch, management: bool,
) -> None:
    context = authorization_context({PermissionKey.PROJECTS_READ.value})
    denied = RateLimitExceeded(
        policy_name="permission_demo",
        result=RateLimitResult(False, 1, 0, 750, 750),
    )
    quota = AsyncMock(side_effect=denied)
    account = AsyncMock(return_value=context)
    monkeypatch.setattr(rate_limit_dependency, "_check_quota", quota)
    monkeypatch.setattr(auth_dependency, "_load_current_user", account)
    dependency = require_permission(PermissionKey.PROJECTS_READ, management=management)
    request = Request({
        "type": "http", "method": "GET", "headers": [],
        "route": SimpleNamespace(name="permission_demo"),
    })

    with pytest.raises(RateLimitExceeded) as caught:
        await dependency(request=request, login_info=context.login_info, settings=get_settings())

    assert caught.value is denied
    quota.assert_awaited_once()
    account.assert_not_awaited()


async def test_post_permission_denial_attempts_an_audit(
    monkeypatch: pytest.MonkeyPatch, override_management: Callable[[AuthorizationContext], None],
) -> None:
    context = authorization_context({PermissionKey.PROJECTS_READ.value})
    dependency = require_permission(PermissionKey.ROLES_DELETE, management=True)
    override_management(context)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [],
            "path": "/api/v1/roles/example/delete",
            "route": type("Route", (), {"name": "delete_role"})(),
        }
    )
    write_audit = AsyncMock()
    monkeypatch.setattr(
        "app.dependencies.permission.AuditService.audit_denied",
        write_audit,
    )

    with pytest.raises(AppError) as caught:
        await dependency(request=request, login_info=context.login_info, settings=get_settings())

    assert caught.value.status_code == 403
    write_audit.assert_awaited_once_with(
        error=caught.value,
        action="api.delete_role",
        context=context,
        target_user_id=None,
        target_role_id=None,
    )


@pytest.mark.parametrize("authorization", [None, "Basic credentials", "Bearer invalid"])
async def test_http_authentication_failures_return_bearer_challenge(authorization: str | None) -> None:
    request_headers = {} if authorization is None else {"Authorization": authorization}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/me/user_info", headers=request_headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert_error_response(response, BusinessCode.INVALID_AUTHENTICATION)


def test_missing_authoritative_state_maps_to_service_unavailable() -> None:
    error = unavailable_503("rbac_state_missing")

    assert error.status_code == 503
    assert error.business_code == BusinessCode.SERVICE_UNAVAILABLE


async def test_disappearing_authenticated_user_remains_a_401(authorization_session: AsyncMock,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )

    async def missing_authority(*_args: object, **_kwargs: object) -> UserInfo:
        raise unauthenticated_401("user_no_longer_active")

    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        missing_authority,
    )
    revoke = AsyncMock()
    monkeypatch.setattr(
        "app.dependencies.auth._clear_invalid_login",
        revoke,
    )
    request = Request({"type": "http", "method": "GET", "headers": []})

    with pytest.raises(AppError) as caught:
        await get_current_user(request, login_info, get_settings())

    assert caught.value.status_code == 401
    assert caught.value.business_code == BusinessCode.INVALID_AUTHENTICATION
    revoke.assert_awaited_once_with(
        request=request,
        login_info=login_info,
    )


async def test_postgresql_authority_failure_maps_to_service_unavailable(authorization_session: AsyncMock,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    error = OperationalError(
        "SELECT authority",
        {},
        RuntimeError("database unavailable"),
        connection_invalidated=True,
    )
    monkeypatch.setattr(user_repository, "check_current_user",
                        AsyncMock(side_effect=error))

    with pytest.raises(AppError) as caught:
        await get_current_user(
            Request({"type": "http", "method": "GET", "headers": []}),
            login_info,
            get_settings(),
        )

    assert caught.value.status_code == 503
    assert caught.value.business_code == BusinessCode.SERVICE_UNAVAILABLE


async def test_authorization_programming_error_is_not_disguised_as_outage(authorization_session: AsyncMock,
                                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    context = authorization_context()
    error = ProgrammingError("invalid query", {}, RuntimeError("syntax error"))
    monkeypatch.setattr(user_repository, "check_current_user",
                        AsyncMock(side_effect=error))

    with pytest.raises(ProgrammingError) as caught:
        await get_current_user(
            Request({"type": "http", "method": "GET", "headers": []}),
            context.login_info,
            get_settings(),
        )

    assert caught.value is error
    authorization_session.__aexit__.assert_awaited_once()


async def test_authorization_charges_once_before_opening_postgresql(authorization_session: AsyncMock,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """
        用户业务先扣一次额度再打开数据库会话，避免超限请求占用数据库连接。

    :param authorization_session: 模拟的授权查询会话。
    :param monkeypatch: 替换权限读取与唯一的额度入口。
    :return: 无返回值；正常请求只扣一次并返回数据库中的当前权限。
    """
    context = authorization_context()
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        AsyncMock(return_value=context.user_info),
    )

    async def current_user_admission(*_args: object, **_kwargs: object) -> None:
        """
            在扣次时确认数据库会话尚未打开。

        :param _args: 用户扣次依赖的位置参数。
        :param _kwargs: 用户扣次依赖的额度档位。
        :return: 无返回值；此次扣次允许继续。
        """
        authorization_session.__aenter__.assert_not_awaited()

    current_user_limit = AsyncMock(side_effect=current_user_admission)
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        current_user_limit,
    )
    result = await get_current_user(
        Request({"type": "http", "method": "GET", "headers": []}),
        context.login_info,
        get_settings(),
    )

    assert result.user_info is context.user_info
    authorization_session.scalar.assert_not_awaited()
    current_user_limit.assert_awaited_once()


async def test_authenticated_captcha_does_not_charge_generic_current_user_quota(
    authorization_session: AsyncMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
        验证码先扣一次独立额度再确认账号；无效请求使用拒绝额度。

    :param authorization_session: 模拟的授权查询会话。
    :param monkeypatch: 替换授权读取及两种额度入口。
    :return: 无返回值；只读取一次场景，不扣普通写入额度。
    """
    context = authorization_context()
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        AsyncMock(return_value=context.user_info),
    )
    generic_charge = AsyncMock()
    read_scene = AsyncMock(return_value=None)

    async def reject_scene_charge(*_args: object, **_kwargs: object) -> None:
        """
            确认验证码独立计数发生在数据库连接之前。

        :param _args: 验证码依赖的位置参数。
        :param _kwargs: 本次已读取的验证码用途。
        :return: 无返回值；模拟独立额度允许继续。
        """
        authorization_session.__aenter__.assert_not_awaited()

    rejected_check = AsyncMock(side_effect=reject_scene_charge)
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user", generic_charge)
    monkeypatch.setattr("app.dependencies.auth.get_captcha_scene", read_scene)
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_private_captcha", rejected_check)

    result = await get_captcha_user(
        Request({"type": "http", "method": "POST", "headers": []}),
        context.login_info,
        get_settings(),
    )

    assert result.user_info is context.user_info
    generic_charge.assert_not_awaited()
    read_scene.assert_awaited_once()
    rejected_check.assert_awaited_once()
    assert rejected_check.await_args is not None
    assert rejected_check.await_args.args[1] == context.login_info
    assert rejected_check.await_args is not None
    assert rejected_check.await_args.kwargs["scene"] is None


async def test_inactive_identity_releases_connection_before_jti_cleanup(authorization_session: AsyncMock,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    context = authorization_context()
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        AsyncMock(side_effect=unauthenticated_401("user_no_longer_active")),
    )

    async def cleanup(**_kwargs: object) -> None:
        authorization_session.__aexit__.assert_awaited_once()

    monkeypatch.setattr(
        "app.dependencies.auth._clear_invalid_login",
        cleanup,
    )
    with pytest.raises(AppError) as caught:
        await get_current_user(
            Request({"type": "http", "method": "GET", "headers": []}),
            context.login_info,
            get_settings(),
        )

    assert caught.value.status_code == 401


async def test_bearer_size_limit_runs_before_redis_lookup() -> None:
    redis = AsyncMock()
    app.state.redis = redis
    request = Request({"type": "http", "headers": [], "app": app})
    token_header = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="x" * 4097,
    )
    try:
        with pytest.raises(AppError) as caught:
            await check_token(request, token_header, get_settings())
    finally:
        del app.state.redis

    assert caught.value.status_code == 401
    redis.eval.assert_not_awaited()


async def test_redis_outage_prevents_postgresql_authority_query(authorization_session: AsyncMock) -> None:
    redis = AsyncMock()
    redis.eval.return_value = 1
    settings = get_settings()
    token = await auth_service.issue_access_token(
        cast(Redis, redis),
        user_id=new_entity_id("U"),
        user_token_version=0,
        settings=settings,
    )
    redis.reset_mock()
    redis.eval.side_effect = RedisConnectionError("registry unavailable")
    session = authorization_session

    app.state.redis = redis
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/me/user_info",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        del app.state.redis

    assert response.status_code == 503
    assert_error_response(response, BusinessCode.SERVICE_UNAVAILABLE)
    redis.eval.assert_awaited_once()
    session.scalar.assert_not_awaited()
    cast(AsyncMock, vars(auth_dependency)["rate_limit_user"]).assert_not_awaited()


async def test_forged_token_is_rejected_before_redis_and_postgresql(authorization_session: AsyncMock) -> None:
    redis = AsyncMock()
    session = authorization_session

    app.state.redis = redis
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/me/user_info",
                headers={"Authorization": "Bearer not-a-signed-jwt"},
            )
    finally:
        del app.state.redis

    assert response.status_code == 401
    assert_error_response(response, BusinessCode.INVALID_AUTHENTICATION)
    redis.eval.assert_not_awaited()
    session.scalar.assert_not_awaited()
    cast(AsyncMock, vars(auth_dependency)["rate_limit_user"]).assert_not_awaited()


async def test_postgresql_snapshot_rejects_stale_redis_token_version(authorization_session: AsyncMock,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    """
        活跃 Redis 登录先计数，数据库发现旧登录版本后拒绝并撤销该登录。

    :param authorization_session: 返回当前数据库版本的模拟会话。
    :param monkeypatch: 隔离权限快照、单次计数和失效会话清理。
    :return: 无返回值；已计数一次且旧版本登录得到 401。
    """
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    user = User(
        user_id=login_info.user_id,
        is_active=True,
        token_version=5,
    )
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.get_user",
        AsyncMock(return_value=user),
    )
    revoke = AsyncMock()
    current_user_limit = AsyncMock()
    monkeypatch.setattr(
        "app.dependencies.auth._clear_invalid_login",
        revoke,
    )
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        current_user_limit,
    )
    request = Request({"type": "http", "method": "GET", "headers": []})

    with pytest.raises(AppError) as caught:
        await get_current_user(
            request,
            login_info,
            get_settings(),
        )

    assert caught.value.status_code == 401
    revoke.assert_awaited_once()
    current_user_limit.assert_awaited_once()


async def test_exhausted_current_user_window_is_rejected_before_postgresql(authorization_session: AsyncMock,
                                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    """
        唯一用户计数返回额度耗尽时，认证依赖在数据库连接前拒绝。

    :param authorization_session: 用于证明未连接、未查询的数据库会话。
    :param monkeypatch: 将单次计数入口替换为额度拒绝。
    :return: 无返回值；只调用一次额度入口且不查询 PostgreSQL。
    """
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    current_user_limit = AsyncMock(
        side_effect=RateLimitExceeded(
            policy_name="get_user_info",
            result=RateLimitResult(False, 600, 0, 750, 750),
        )
    )
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        current_user_limit,
    )
    request = Request({"type": "http", "method": "GET", "headers": []})

    with pytest.raises(RateLimitExceeded):
        await get_current_user(
            request,
            login_info,
            get_settings(),
        )

    current_user_limit.assert_awaited_once()
    authorization_session.__aenter__.assert_not_awaited()
    authorization_session.scalar.assert_not_awaited()


async def test_exhausted_private_captcha_scene_skips_postgresql(
    authorization_session: AsyncMock,
) -> None:
    """
        登录后验证码用途窗口超限时，仅执行一次计数并跳过数据库。

    :param authorization_session: 用于证明未访问数据库的模拟会话。
    :return: 无返回值；准确用途窗口返回额度拒绝。
    """
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    redis = AsyncMock()
    redis.eval.return_value = [11, 120_000]
    application = SimpleNamespace(
        state=SimpleNamespace(rate_limit_redis=redis))
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {
            "type": "http.request",
            "body": b'{"scene":"admin_reset_user_password"}',
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/json")],
            "app": application,
            "route": SimpleNamespace(name="create_authenticated_captcha"),
        },
        receive,
    )
    session = authorization_session
    settings = get_settings()

    with pytest.raises(RateLimitExceeded) as caught:
        await get_captcha_user(
            request,
            login_info,
            settings,
        )

    assert caught.value.policy_name == "captcha_create_admin_reset_user_password"
    redis.eval.assert_awaited_once()
    session.__aenter__.assert_not_awaited()
    session.scalar.assert_not_awaited()
    key = redis.eval.await_args.args[2]
    assert ":captcha_create_admin_reset_user_password:user_id:" in key


async def test_text_plain_rejection_limit_skips_postgresql(
    authorization_session: AsyncMock,
) -> None:
    """
        文本请求使用无效用途窗口，超限后不查询数据库或正常用途窗口。

    :param authorization_session: 用于证明未访问数据库的模拟会话。
    :return: 无返回值；拒绝窗口只计数一次并抛出额度拒绝。
    """
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    redis = AsyncMock()
    redis.eval.return_value = [11, 120_000]
    application = SimpleNamespace(
        state=SimpleNamespace(rate_limit_redis=redis))
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {
            "type": "http.request",
            "body": b'{"scene":"admin_reset_user_password"}',
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"text/plain")],
            "app": application,
            "route": SimpleNamespace(name="create_authenticated_captcha"),
        },
        receive,
    )
    session = authorization_session
    settings = get_settings()

    with pytest.raises(RateLimitExceeded) as caught:
        await get_captcha_user(
            request,
            login_info,
            settings,
        )

    assert caught.value.policy_name == "captcha_invalid_scene"
    redis.eval.assert_awaited_once()
    session.__aenter__.assert_not_awaited()
    session.scalar.assert_not_awaited()
    key = redis.eval.await_args.args[2]
    assert ":captcha_invalid_scene:user_id:" in key


async def test_database_rejected_jti_is_revoked_before_redis_rejects_its_next_use(
    authorization_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = get_settings()
    token_info = AccessTokenInfo(
        user_id=new_entity_id("U"),
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    require_jti = AsyncMock(
        side_effect=[3, unauthenticated_401("inactive_access_token")])
    revoke_jti = AsyncMock()
    load_authority = AsyncMock(side_effect=unauthenticated_401("user_no_longer_active"))
    current_user_limit = AsyncMock()
    monkeypatch.setattr(
        "app.dependencies.auth.decode_access_token",
        Mock(return_value=token_info),
    )
    monkeypatch.setattr(
        "app.dependencies.auth.login_session_repository.check_login_session", require_jti
    )
    monkeypatch.setattr("app.dependencies.auth.login_session_repository.delete_login_session", revoke_jti)
    monkeypatch.setattr(
        "app.dependencies.auth.get_redis", Mock(return_value=object())
    )
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        load_authority,
    )
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        current_user_limit,
    )
    token_header = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="signed-token",
    )
    first_request = Request({"type": "http", "method": "GET", "headers": []})
    login_info = await check_token(first_request, token_header, settings)
    session = authorization_session

    with pytest.raises(AppError) as first_denial:
        await get_current_user(
            first_request,
            login_info,
            settings,
        )

    with pytest.raises(AppError) as second_denial:
        await check_token(
            Request({"type": "http", "method": "GET", "headers": []}),
            token_header,
            settings,
        )

    assert first_denial.value.status_code == 401
    assert second_denial.value.status_code == 401
    load_authority.assert_awaited_once()
    session.scalar.assert_not_awaited()
    revoke_jti.assert_awaited_once()
    assert revoke_jti.await_args is not None
    assert revoke_jti.await_args.kwargs == {
        "token_info": token_info, "user_token_version": 3}
    assert all(call.kwargs == {"token_info": token_info}
               for call in require_jti.await_args_list)
    current_user_limit.assert_awaited_once()


async def test_inactive_jti_cleanup_failure_preserves_401_after_single_user_charge(
    authorization_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        数据库发现账号停用后已计数一次，撤销会话失败仍保留原始 401。

    :param authorization_session: 返回停用账号状态的模拟会话。
    :param monkeypatch: 隔离单次计数、撤销故障及安全日志。
    :return: 无返回值；撤销错误没有改变身份拒绝结果或重复计数。
    """
    login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=3,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    current_user_limit = AsyncMock()
    log = Mock()
    monkeypatch.setattr(
        "app.dependencies.auth.user_repository.check_current_user",
        AsyncMock(side_effect=unauthenticated_401("user_no_longer_active")),
    )
    monkeypatch.setattr(
        "app.dependencies.auth.get_redis",
        Mock(return_value=object()),
    )
    monkeypatch.setattr(
        "app.dependencies.auth.login_session_repository.delete_login_session",
        AsyncMock(side_effect=RuntimeError("controlled cleanup failure")),
    )
    monkeypatch.setattr(
        "app.dependencies.auth.rate_limit_user",
        current_user_limit,
    )
    monkeypatch.setattr("app.dependencies.auth.safe_log", log)
    monkeypatch.setattr(
        "app.dependencies.auth.safe_exception_metadata",
        Mock(
            return_value={"error_id": "cleanup-test",
                          "exception_type": "RuntimeError"}
        ),
    )

    with pytest.raises(AppError) as caught:
        await get_current_user(
            Request({"type": "http", "method": "GET", "headers": []}),
            login_info,
            get_settings(),
        )

    assert caught.value.status_code == 401
    current_user_limit.assert_awaited_once()
    log.assert_called_once()
