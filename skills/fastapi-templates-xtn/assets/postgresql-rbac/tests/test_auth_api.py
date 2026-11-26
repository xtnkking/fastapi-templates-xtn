#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查认证、本人和用户密码接口的请求与响应契约
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充文件记录并使测试密码符合可见 ASCII 规则
# 2026/09/30    XTN       V1.001        验证无临时密码接口且管理员重置直接生效
# 2026/09/30    XTN       V1.002        验证会话列表仅在有权限的用户管理入口提供
# 2026/10/02    XTN       V1.003        会话列表路由只委托用户服务组装统计结果
# 2026/10/04    XTN       V1.004        验证码测试覆盖依赖内正常与拒绝场景的实际扣次
# 2026/10/04    XTN       V1.005        验证场景传递及其他字段无效时的参数校验边界
# 2026/10/04    XTN       V1.006        对齐 Service 统一选择正常与拒绝场景额度
# 2026/10/08    XTN       V1.007        对齐注册接口限流方法 check_register
# 2026/10/08    XTN       V2.000        测试路由显式限流依赖的维度与执行顺序
# 2026/10/08    XTN       V2.001        区分实际限流维度与主体类型标记
# 2026/10/09    XTN       V2.002        管理员会话统计从用户模型导入
# 2026/10/09    XTN       V2.003        限流模拟只替换真实所属模块，不再修改认证模块的私有入口
# 2026/10/09    XTN       V2.004        现行注册测试名称与内部执行轨迹统一使用 register
# 2026/10/09    XTN       V2.005        会话与访问令牌响应模型统一使用 Response 后缀
# 2026/10/09    XTN       V2.006        对齐验证码无效用途限流的直观业务名称
# 2026/10/09    XTN       V2.007        验证码签发模拟对齐共享实例的公开创建方法
# 2026/10/10    XTN       V2.008        保留真实验证码认证链并验证数据库前单次计数
# 2026/10/10    XTN       V2.009        统一用户 ID 与当前用户命名
# 2026/10/10    XTN       V2.010        验证码模拟返回数据模型并核对路由独立包装响应
# 2026/10/12    XTN       V2.011        验证五种验证码依赖的场景、前置检查及单次计数
# 2026/10/12    XTN       V2.012        简化验证码依赖后验证独立参数校验及路由前置检查
# 2026/10/12    XTN       V2.013        验证码统一 user_id 并验证直接读取字段的请求错误边界
# 2026/10/13    XTN       V2.014        管理员会话查询断言不再传递配置
# 2026/10/15    XTN       V2.015        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/15    XTN       V2.016        管理员新增接口替身统一使用 admin_create_user
# 2026/10/16    XTN       V2.017        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/16    XTN       V2.018        登录路由模拟与调用检查统一使用 login 业务入口
# 2026/10/16    XTN       V2.019        登录路由只传入配置和 Redis，并包装完整登录结果
# 2026/10/19    XTN       V2.020        直接替换路由使用的共享 Service 实例，保留真实认证依赖覆盖
# 2026/10/20    XTN       V2.021        登录原样传递短旧密码及超过新密码上限的旧密码
# 2026/10/22    XTN       V2.022        对齐鉴权入口，验证本人和管理额度独立且只计一次
# 2026/10/22    XTN       V2.023        写入额度断言对齐本人和管理的简短配置名
# 2026/10/24    XTN       V2.024        验证码场景名称明确具体用户操作
# 2026/10/26    XTN       V2.025        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V2.026        验证普通用户基础权限及本人业务单次认证、限流和验证码顺序
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Callable
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.endpoints.auth as auth_api
import app.api.v1.endpoints.me as me_api
import app.api.v1.endpoints.users as users_api
import app.dependencies.auth as auth_dependencies
import app.dependencies.captcha as captcha_dependencies
import app.dependencies.permission as permission_dependencies
import app.dependencies.rate_limit as rate_limit_dependencies
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.codes import BusinessCode
from app.core.config import get_settings
from app.core.exception_handlers import register_exception_handlers
from app.core.exceptions import AppError
from app.core.i18n.messages import MessageKey
from app.core.ids import new_entity_id
from app.core.rate_limit.limiter import RateLimitExceeded, RateLimitResult
from app.dependencies.auth import check_token
from app.main import app
from app.repositories.postgres.user_repository import user_repository
from app.schemas.captcha import CaptchaResponse
from app.schemas.user import ActiveSessionsResponse
from app.services.auth_service import LoginResult
from app.services.captcha_service import captcha_service

VALID_PASSWORD = "correct-horse-battery-staple"
NEW_PASSWORD = "new-correct-horse-battery-staple"


def _context(*, password_reset: bool = False, users_read: bool = False,
             users_create: bool = False, account_read: bool = True,
             password_change: bool = True) -> AuthorizationContext:
    user_id = new_entity_id("U")
    permissions = frozenset(
        key.value for key, enabled in (
            (PermissionKey.ACCOUNT_READ, account_read),
            (PermissionKey.ACCOUNT_CHANGE_PASSWORD, password_change),
            (PermissionKey.USERS_PASSWORD_RESET, password_reset),
            (PermissionKey.USERS_READ, users_read),
            (PermissionKey.USERS_CREATE, users_create),
        ) if enabled
    )
    role = RoleGrant(
        role_id=new_entity_id("R"),
        key="test-current_user",
        level=500 if password_reset or users_read or users_create else 0,
        permissions=permissions,
        is_system=False,
        is_protected=False,
        is_super_admin=False,
    )
    return AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=4,
            token_id=uuid.uuid4(),
            issued_at=1,
            expires_at=2,
        ),
        user_info=UserInfo.build(
            user_id=user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=4,
            roles=(role,),
        ),
    )


def _assert_envelope(response_status: int, body: dict[str, object]) -> None:
    assert body.keys() == {"code", "message", "data", "request_id"}
    code = body["code"]
    assert isinstance(code, int) and not isinstance(code, bool)
    assert code // 100 == response_status
    request_id = uuid.UUID(str(body["request_id"]))
    assert request_id.version == 4


@pytest.fixture(autouse=True)
def fake_captcha(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    # 路由测试替换真实 Redis 边界；运行时代码没有跳过限流的开关。
    monkeypatch.setattr(
        rate_limit_dependencies,
        "get_rate_limit_redis",
        lambda _request: object(),
    )
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", AsyncMock())
    monkeypatch.setattr(captcha_dependencies, "get_redis",
                        lambda _request: object())
    verify = AsyncMock()
    monkeypatch.setattr(captcha_service, "verify_captcha", verify)
    return verify


@pytest.fixture
def captcha_authorization(monkeypatch: pytest.MonkeyPatch) -> tuple[AuthorizationContext, AsyncMock]:
    """
        只替换验证码认证中的数据库读取，保留实际单次限流和认证执行顺序。

    :param monkeypatch: 隔离 PostgreSQL 会话及当前账号权限读取。
    :return: 当前账号上下文和用于断言是否访问数据库的模拟会话。
    """
    context = _context(password_reset=True, users_create=True)
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    monkeypatch.setattr(auth_dependencies, "SessionFactory",
                        Mock(return_value=session))
    monkeypatch.setattr(
        user_repository,
        "check_current_user",
        AsyncMock(return_value=context.user_info),
    )
    return context, session


CAPTCHA = {"captcha_id": str(uuid.uuid4()), "captcha_answer": "AB234"}


def _authentication_app() -> FastAPI:
    isolated_app = FastAPI()
    register_exception_handlers(isolated_app)
    isolated_app.include_router(auth_api.router, prefix="/api/v1")
    return isolated_app


async def test_public_register_route_remains_available() -> None:
    isolated_app = _authentication_app()

    async with AsyncClient(
        transport=ASGITransport(app=isolated_app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/auth/register", json={})

    assert response.status_code == 400
    assert set(isolated_app.openapi()["paths"]
               ["/api/v1/auth/register"]) == {"post"}


async def test_captcha_is_required_before_public_register_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AsyncMock()
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/register",
                json={"user_name": "Alice", "password": VALID_PASSWORD},
            )
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 400
    assert result.json()["code"] == int(BusinessCode.BAD_REQUEST)
    service.register.assert_not_awaited()


@pytest.mark.parametrize(("scene", "path", "payload"), [
    ("login", "/auth/login",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("register", "/auth/register",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("user_change_password", "/me/password/change",
     {"current_password": VALID_PASSWORD, "new_password": NEW_PASSWORD}),
    ("admin_create_user", "/users/create",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("admin_reset_user_password", "/users/password/reset",
     {"user_id": new_entity_id("U"), "new_password": NEW_PASSWORD}),
])
@pytest.mark.parametrize("missing_captcha", [False, True])
async def test_captcha_dependency_stops_business_for_wrong_answer_or_missing_captcha(
    override_management: Callable[[AuthorizationContext], None],
    scene: str,
    path: str,
    payload: dict[str, str],
    missing_captcha: bool,
    fake_captcha: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        五种业务均由真实验证码依赖阻断错误答案；验证码字段缺失时不调用消费服务。

    :param scene: 该接口必须固定使用的验证码业务。
    :param path: 登录、注册、本人改密或管理员操作的实际接口。
    :param payload: 验证码字段以外的合法业务请求。
    :param missing_captcha: True 删除答案字段，证明验证码参数无效时不调用 Service。
    :param fake_captcha: 仅替换真正消费验证码的 Service 边界。
    :param monkeypatch: 替换各端点实际调用的共享业务实例，不改认证依赖。
    :return: 无返回值；两种失败均不得进入业务服务。
    """
    service = AsyncMock()
    context = _context(password_reset=True, users_create=True)

    override_management(context)
    monkeypatch.setattr(auth_api, "auth_service", service)
    monkeypatch.setattr(me_api, "auth_service", service)
    monkeypatch.setattr(users_api, "user_service", service)
    fake_captcha.side_effect = AppError(
        status_code=400, business_code=BusinessCode.CAPTCHA_INVALID,
        message_key=MessageKey.ERROR_CAPTCHA_INVALID, reason_code="captcha_invalid_or_expired",
    )
    body = {**payload, **CAPTCHA}
    if missing_captcha:
        del body["captcha_answer"]
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json=body)
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400, response.text
    assert response.json()["code"] == int(
        BusinessCode.BAD_REQUEST if missing_captcha else BusinessCode.CAPTCHA_INVALID
    )
    if missing_captcha:
        fake_captcha.assert_not_awaited()
    else:
        fake_captcha.assert_awaited_once()
        assert fake_captcha.await_args is not None
        assert fake_captcha.await_args.kwargs["scene"] == scene
        expected_user_id = None if path.startswith(
            "/auth/") else context.login_info.user_id
        assert fake_captcha.await_args is not None
        assert fake_captcha.await_args.kwargs["user_id"] == expected_user_id
    assert service.mock_calls == []


@pytest.mark.parametrize(("field", "invalid_value"), [
    ("captcha_id", "not-a-uuid"), ("captcha_id", "a" * 37), ("captcha_id", None),
    ("captcha_id", 123), ("captcha_id", True), ("captcha_id", []),
    ("captcha_answer", ""), ("captcha_answer", "  "), ("captcha_answer", "A" * 17),
    ("captcha_answer", None), ("captcha_answer",
                               123), ("captcha_answer", False), ("captcha_answer", {}),
])
async def test_invalid_captcha_fields_do_not_reach_consumption(
    field: str, invalid_value: object, fake_captcha: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        验证码 ID 格式或答案长度错误时，只返回参数错误，不调用一次性消费服务。

    :param field: 要破坏的验证码字段。
    :param invalid_value: 非 UUID、非字符串、空白答案或超过传输上限的字段。
    :param fake_captcha: 不应被调用的验证码消费边界。
    :param monkeypatch: 替换注册端点的业务实例，检查无效请求不会进入注册。
    :return: 无返回值；验证码参数错误不会消费 Redis 中的挑战。
    """
    service = AsyncMock()
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1/auth/register", json={
                "user_name": "Alice", "password": VALID_PASSWORD, **CAPTCHA, field: invalid_value,
            })
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400, response.text
    assert response.json()["code"] == int(BusinessCode.BAD_REQUEST)
    fake_captcha.assert_not_awaited()
    assert service.mock_calls == []


@pytest.mark.parametrize(("content_type", "content", "expected_status"), [
    ("text/plain", "{", 400),
    ("text/plain", "", 400),
    ("application/json", "[]", 400),
    ("application/json", "null", 400),
    ("application/json", "true", 400),
    ("application/json", "{", 422),
])
async def test_captcha_dependency_rejects_unreadable_or_non_object_body(
    content_type: str, content: str, expected_status: int, fake_captcha: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        非 JSON 对象不能提取验证码；即使请求伪装成纯文本，格式错误也返回安全的请求错误。
        application/json 的语法错误仍由 FastAPI 在执行依赖之前处理。

    :param content_type: 请求声明的格式，用于覆盖框架解析和依赖自己解析两条路径。
    :param content: 空内容、损坏的 JSON 或不是对象的 JSON。
    :param expected_status: 依赖拒绝为 400；框架预先拒绝 JSON 语法错误为 422。
    :param fake_captcha: 无效请求不得调用的验证码消费边界。
    :param monkeypatch: 隔离注册端点实际调用的共享业务实例。
    :return: 无返回值；无效请求不会进入验证码消费或注册业务。
    """
    service = AsyncMock()
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/register", content=content, headers={"Content-Type": content_type},
            )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == expected_status, response.text
    assert response.json()["code"] == int(
        BusinessCode.BAD_REQUEST if expected_status == 400 else BusinessCode.VALIDATION_FAILED
    )
    fake_captcha.assert_not_awaited()
    assert service.mock_calls == []


async def test_captcha_dependency_preserves_answer_and_parses_uuid(fake_captcha: AsyncMock,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """
        读取字段仅判断非空，不裁剪验证码答案或把数字强行转成字符串。

    :param fake_captcha: 记录传入答案和验证码 ID 的 Service 边界。
    :param monkeypatch: 仅替换注册端点的业务实例，保留真实验证码依赖。
    :return: 无返回值；答案按原文传递，ID 按 Service 契约转成 UUID，公开用途不绑定用户。
    """
    service = AsyncMock()
    service.register.return_value = new_entity_id("U")
    answer = " AB234 "
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1/auth/register", json={
                "user_name": "Alice", "password": VALID_PASSWORD, **CAPTCHA, "captcha_answer": answer,
            })
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 201, response.text
    fake_captcha.assert_awaited_once()
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["answer"] == answer
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["captcha_id"] == uuid.UUID(
        CAPTCHA["captcha_id"])
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["user_id"] is None


@pytest.mark.parametrize(("scene", "path", "payload"), [
    ("login", "/auth/login",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("register", "/auth/register",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("user_change_password", "/me/password/change",
     {"current_password": VALID_PASSWORD, "new_password": NEW_PASSWORD}),
    ("admin_create_user", "/users/create",
     {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("admin_reset_user_password", "/users/password/reset",
     {"user_id": new_entity_id("U"), "new_password": NEW_PASSWORD}),
])
async def test_other_business_field_validation_follows_captcha_consumption(
    override_management: Callable[[AuthorizationContext], None],
    scene: str,
    path: str,
    payload: dict[str, str],
    fake_captcha: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        验证码依赖只校验自己的两个字段；其他字段错误由路由模型拒绝，此时验证码已消费。

    :param scene: 路由固定的验证码用途。
    :param path: 五个验证码保护的业务接口之一。
    :param payload: 完整合法业务参数，在发送前增加禁止字段。
    :param fake_captcha: 模拟验证码通过并记录一次消费。
    :param monkeypatch: 替换各业务端点的共享实例，不改变请求参数校验。
    :return: 无返回值；返回 422，已消费验证码，但不执行业务服务。
    """
    context = _context(password_reset=True, users_create=True)
    service = AsyncMock()

    override_management(context)
    monkeypatch.setattr(auth_api, "auth_service", service)
    monkeypatch.setattr(me_api, "auth_service", service)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json={**payload, **CAPTCHA, "unexpected": "rejected"})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422, response.text
    fake_captcha.assert_awaited_once()
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["scene"] == scene
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["user_id"] == (
        None if path.startswith("/auth/") else context.login_info.user_id
    )
    assert service.mock_calls == []


@pytest.mark.parametrize("path", ["/auth/login", "/auth/register"])
async def test_public_submission_over_quota_does_not_consume_captcha(
    path: str, monkeypatch: pytest.MonkeyPatch, fake_captcha: AsyncMock,
) -> None:
    """
        登录和注册先检查 IP 限流，超额后不消费本次验证码或执行业务。

    :param path: 两个公开提交接口之一。
    :param monkeypatch: 将 Redis 额度边界替换为超限结果。
    :param fake_captcha: 验证码消费边界，拒绝请求不应调用它。
    :return: 无返回值；标准 429、一次计数且没有后续工作。
    """
    check = AsyncMock(side_effect=RateLimitExceeded(
        "login" if path.endswith("login") else "register", RateLimitResult(
            False, 10, 0, 3000, 3000),
    ))
    service = AsyncMock()
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json={
                "user_name": "Alice", "password": VALID_PASSWORD, **CAPTCHA,
            })
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 429, response.text
    check.assert_awaited_once()
    fake_captcha.assert_not_awaited()
    assert service.mock_calls == []


@pytest.mark.parametrize(("path", "payload"), [
    ("/users/create", {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("/users/password/reset",
     {"user_id": new_entity_id("U"), "new_password": NEW_PASSWORD}),
])
async def test_administrator_permission_is_checked_before_captcha_consumption(
    override_management: Callable[[AuthorizationContext], None],
    path: str,
    payload: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    fake_captcha: AsyncMock,
) -> None:
    """
        有登录身份但缺少具体管理权限时，不消费管理员新增或重置验证码。

    :param path: 要求明确管理权限的受保护接口。
    :param payload: 合法业务请求，不靠参数错误触发拒绝。
    :param monkeypatch: 隔离权限拒绝审计，不访问 PostgreSQL。
    :param fake_captcha: 不应执行的验证码消费边界。
    :return: 无返回值；权限拒绝必须先于验证码和业务执行。
    """
    service = AsyncMock()
    context = _context()
    monkeypatch.setattr(
        "app.dependencies.permission.AuditService.audit_denied", AsyncMock())
    override_management(context)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json={**payload, **CAPTCHA})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 403, response.text
    fake_captcha.assert_not_awaited()
    assert service.mock_calls == []


@pytest.mark.parametrize(("path", "payload"), [
    ("/me/password/change",
     {"current_password": VALID_PASSWORD, "new_password": NEW_PASSWORD}),
    ("/users/create", {"user_name": "Alice", "password": VALID_PASSWORD}),
    ("/users/password/reset",
     {"user_id": new_entity_id("U"), "new_password": NEW_PASSWORD}),
])
async def test_private_operations_require_authentication_before_captcha(
    path: str, payload: dict[str, str], fake_captcha: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        私有路由先执行自己的真实认证依赖，未登录时不消费任何用户的验证码。

    :param path: 本人改密、管理员新增或管理员重置接口。
    :param payload: 除登录身份外均合法的业务参数。
    :param fake_captcha: 不应执行的验证码消费边界。
    :param monkeypatch: 隔离本人和管理员端点的业务实例，保留真实认证拒绝。
    :return: 无返回值；401 在验证码及业务服务之前返回。
    """
    service = AsyncMock()
    monkeypatch.setattr(me_api, "auth_service", service)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json={**payload, **CAPTCHA})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 401, response.text
    fake_captcha.assert_not_awaited()
    assert service.mock_calls == []


@pytest.mark.parametrize(("scene", "path", "payload", "expected_status"), [
    ("user_change_password", "/me/password/change",
     {"current_password": VALID_PASSWORD, "new_password": NEW_PASSWORD}, 200),
    ("admin_create_user", "/users/create",
     {"user_name": "Alice", "password": VALID_PASSWORD}, 201),
    ("admin_reset_user_password", "/users/password/reset",
     {"user_id": new_entity_id("U"), "new_password": NEW_PASSWORD}, 200),
])
async def test_private_captcha_dependency_reuses_authentication_and_counts_once(
    scene: str, path: str, payload: dict[str, str], expected_status: int,
    monkeypatch: pytest.MonkeyPatch, fake_captcha: AsyncMock,
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        保留真实账号与权限依赖，证明路由先完成认证且只扣一次额度，验证码不再次认证。

    :param scene: 本次接口固定的私有验证码业务。
    :param path: 本人改密、管理员新增或重置的实际接口。
    :param payload: 该业务的完整合法请求参数。
    :param expected_status: 对应成功状态，新增为 201，其他为 200。
    :param monkeypatch: 隔离 Redis 计数和后续业务服务。
    :param fake_captcha: 用于检查已认证 user_id 的验证码 Service 边界。
    :param captcha_authorization: 真实认证流程使用的隔离账号读取边界。
    :return: 无返回值；一次用户计数、一次账号读取后验证正确场景和所属用户。
    """
    context, session = captcha_authorization

    async def count_before_account(*_args: object, **_kwargs: object) -> None:
        session.__aenter__.assert_not_awaited()

    quota_check = AsyncMock(side_effect=count_before_account)
    service = AsyncMock()
    service.change_password.return_value = None
    service.reset_user_password.return_value = None
    service.admin_create_user.return_value = new_entity_id("U")

    async def verify_after_authentication(**_kwargs: object) -> None:
        """
            在消费边界确认当前用户已经通过一次计数与一次账号查询。

        :param _kwargs: 固定场景、用户绑定与验证码内容，不输出任何秘密。
        :return: 无返回值；顺序或重复计数错误时断言失败。
        """
        quota_check.assert_awaited_once()
        cast(AsyncMock, user_repository.check_current_user).assert_awaited_once()
        session.scalar.assert_not_awaited()

    fake_captcha.side_effect = verify_after_authentication
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", quota_check)
    app.dependency_overrides[check_token] = lambda: context.login_info
    monkeypatch.setattr(me_api, "auth_service", service)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1" + path, json={**payload, **CAPTCHA})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == expected_status, response.text
    quota_check.assert_awaited_once()
    cast(AsyncMock, user_repository.check_current_user).assert_awaited_once()
    session.scalar.assert_not_awaited()
    fake_captcha.assert_awaited_once()
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["scene"] == scene
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["user_id"] == context.login_info.user_id
    assert quota_check.await_args is not None
    assert quota_check.await_args.kwargs["key_parts"] == [
        context.login_info.user_id]
    settings = get_settings()
    expected_limit = (
        settings.rate_limit_user_write if scene == "user_change_password"
        else settings.rate_limit_admin_write
    )
    assert quota_check.await_args is not None
    assert quota_check.await_args.kwargs["limit"] == expected_limit


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/auth/registration/detail"),
    ("POST", "/api/v1/auth/registration/update"),
])
async def test_registration_switch_routes_are_absent(method: str, path: str) -> None:
    """
        注册保持公开，但不暴露读取或修改注册开关的接口。

    :param method: 旧开关接口使用的 HTTP 方法。
    :param path: 旧开关接口路径。
    :return: 无返回值；旧路径均应返回不存在。
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        result = await client.request(method, path)
    assert result.status_code == 404


async def test_public_captcha_is_scene_bound_but_not_bound_to_issuing_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    captcha_id = uuid.uuid4()
    redis = object()
    service = AsyncMock()
    service.login.return_value = LoginResult(
        user_id=new_entity_id("U"),
        access_token="signed-access-token",
        expires_in=86_400,
    )
    issue = AsyncMock(return_value=CaptchaResponse(
        captcha_id=captcha_id,
        image_base64="data:image/png;base64,AA==",
    ))
    quota_check = AsyncMock()
    consume = AsyncMock()
    monkeypatch.setattr(auth_api, "get_redis", lambda _request: redis)
    monkeypatch.setattr(captcha_dependencies, "get_redis",
                        lambda _request: object())
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", quota_check)
    monkeypatch.setattr(captcha_service, "verify_captcha", consume)
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, client=("198.51.100.10", 40100)),
            base_url="http://test",
        ) as issuer:
            challenge = await issuer.post(
                "/api/v1/auth/captcha",
                json={"scene": "login"},
            )
        async with AsyncClient(
            transport=ASGITransport(app=app, client=("198.51.100.11", 40101)),
            base_url="http://test",
        ) as submitter:
            login = await submitter.post(
                "/api/v1/auth/login",
                json={
                    "user_name": "Alice",
                    "password": VALID_PASSWORD,
                    "captcha_id": str(captcha_id),
                    "captcha_answer": "AB234",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert challenge.status_code == 200, challenge.text
    assert challenge.json()["data"] == {
        "captcha_id": str(captcha_id),
        "image_base64": "data:image/png;base64,AA==",
        "expires_in": 300,
    }
    assert challenge.json()["request_id"] == challenge.headers["X-Request-ID"]
    assert challenge.headers["Cache-Control"] == "no-store"
    assert login.status_code == 200, login.text
    issue.assert_awaited_once()
    issue_call = issue.await_args
    assert issue_call is not None
    assert issue_call.kwargs["scene"] == "login"
    assert issue_call.kwargs["user_id"] is None
    assert quota_check.await_args_list[0].kwargs["scope"] == "captcha_create_login"
    assert quota_check.await_args_list[0].kwargs["subject_type"] == "ip"
    assert quota_check.await_args_list[0].kwargs["key_parts"] == [
        "198.51.100.10"]
    consume.assert_awaited_once()
    consume_call = consume.await_args
    assert consume_call is not None
    assert set(consume_call.kwargs) == {
        "redis", "settings", "captcha_id", "answer", "scene", "user_id"}
    assert {key: value for key, value in consume_call.kwargs.items() if key not in {"redis", "settings"}} == {
        "captcha_id": captcha_id,
        "answer": "AB234",
        "scene": "login",
        "user_id": None,
    }
    login_call = service.login.await_args
    assert login_call is not None
    assert login_call.kwargs == {
        "redis": redis,
        "settings": get_settings(),
        "user_name": "Alice",
        "password": VALID_PASSWORD,
    }
    assert not login_call.args


async def test_three_authenticated_captcha_scenes_are_separately_admitted(
    monkeypatch: pytest.MonkeyPatch,
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        三种登录后验证码分别使用用途和用户窗口，每个请求只扣一次。

    :param monkeypatch: 隔离 Redis 计数及验证码图片签发。
    :param captcha_authorization: 当前账号和模拟数据库会话。
    :return: 无返回值；三个独立用途均签发给当前用户。
    """
    context, session = captcha_authorization
    quota_check = AsyncMock()
    data = CaptchaResponse(captcha_id=uuid.uuid4(),
                           image_base64="data:image/png;base64,AA==")
    issue = AsyncMock(return_value=data)
    monkeypatch.setattr(me_api, "get_redis", lambda _request: object())
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _request: object())
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", quota_check)

    app.dependency_overrides[check_token] = lambda: context.login_info
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            for scene in ("admin_create_user", "admin_reset_user_password", "user_change_password"):
                response = await client.post(
                    "/api/v1/me/captcha", json={"scene": scene}
                )
                assert response.status_code == 200, response.text
                assert response.json()["data"] == data.model_dump(mode="json")
                assert response.json()[
                    "request_id"] == response.headers["X-Request-ID"]
                assert response.headers["Cache-Control"] == "no-store"
    finally:
        app.dependency_overrides.clear()
    assert [call.kwargs["scope"] for call in quota_check.await_args_list] == [
        "captcha_create_admin_create_user",
        "captcha_create_admin_reset_user_password",
        "captcha_create_user_change_password",
    ]
    assert cast(AsyncMock, user_repository.check_current_user).await_count == 3
    session.scalar.assert_not_awaited()
    assert all(call.kwargs["subject_type"] == "user_id"
               and call.kwargs["key_parts"] == [str(context.login_info.user_id)]
               for call in quota_check.await_args_list)
    assert all(
        call.kwargs["user_id"] == context.login_info.user_id
        for call in issue.await_args_list
    )


async def test_wrong_captcha_endpoint_is_metered_without_creating_an_image(
    monkeypatch: pytest.MonkeyPatch,
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        正常用途送到错误入口时各扣一次拒绝额度，不创建验证码图片。

    :param monkeypatch: 隔离计数和验证码签发服务。
    :param captcha_authorization: 登录后申请者及其模拟数据库会话。
    :return: 无返回值；公开入口按 IP、登录后入口按用户计数。
    """
    context, _session = captcha_authorization
    check = AsyncMock()
    issue = AsyncMock()
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    app.dependency_overrides[check_token] = lambda: context.login_info
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            public = await client.post(
                "/api/v1/auth/captcha", json={"scene": "admin_reset_user_password"}
            )
            private = await client.post("/api/v1/me/captcha", json={"scene": "login"})
    finally:
        app.dependency_overrides.clear()
    assert public.status_code == 400
    assert private.status_code == 400
    assert check.await_count == 2
    assert check.await_args_list[0].kwargs["scope"] == "captcha_invalid_scene"
    assert check.await_args_list[0].kwargs["subject_type"] == "ip"
    assert check.await_args_list[0].kwargs["key_parts"] == ["127.0.0.1"]
    assert check.await_args_list[1].kwargs["scope"] == "captcha_invalid_scene"
    assert check.await_args_list[1].kwargs["subject_type"] == "user_id"
    assert check.await_args_list[1].kwargs["key_parts"] == [
        str(context.login_info.user_id)]
    issue.assert_not_awaited()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"scene": "unknown"},
    ],
)
async def test_invalid_private_captcha_body_is_metered_and_then_checks_authority(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, str],
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        缺失或未知用途先扣一次拒绝额度，再确认账号并返回参数错误。

    :param monkeypatch: 隔离 Redis 计数和验证码签发。
    :param payload: 缺失或未知验证码用途的请求体。
    :param captcha_authorization: 当前账号和模拟数据库会话。
    :return: 无返回值；一次计数后查库，未签发图片。
    """
    context, session = captcha_authorization
    issue = AsyncMock()

    async def admit_quota(*_args: object, **_kwargs: object) -> None:
        """
            在允许本次拒绝额度时确认数据库会话尚未打开。

        :param _args: 限流检查的位置参数。
        :param _kwargs: 当前用户的拒绝额度窗口。
        :return: 无返回值；允许后续账号查询。
        """
        session.__aenter__.assert_not_awaited()

    check = AsyncMock(side_effect=admit_quota)
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    app.dependency_overrides[check_token] = lambda: context.login_info
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/me/captcha", json=payload)
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert response.json()["code"] == int(BusinessCode.VALIDATION_FAILED)
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    check.assert_awaited_once()
    assert check.await_args is not None
    assert check.await_args.kwargs["scope"] == "captcha_invalid_scene"
    assert check.await_args is not None
    assert check.await_args.kwargs["subject_type"] == "user_id"
    assert check.await_args is not None
    assert check.await_args.kwargs["key_parts"] == [
        str(context.login_info.user_id)]
    cast(AsyncMock, user_repository.check_current_user).assert_awaited_once()
    session.scalar.assert_not_awaited()
    issue.assert_not_awaited()


async def test_extra_captcha_field_uses_scene_quota_before_validation(
    monkeypatch: pytest.MonkeyPatch,
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        额外字段不参与选限流窗口；按已知场景扣次后由路由返回参数错误。

    :param monkeypatch: 隔离身份读取、限流和验证码签发服务。
    :param captcha_authorization: 当前账号和模拟数据库会话。
    :return: 无返回值；未签发图片且没有消耗错误场景额度。
    """
    context, _session = captcha_authorization
    scene_check = AsyncMock()
    issue = AsyncMock()
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", scene_check)
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    app.dependency_overrides[check_token] = lambda: context.login_info
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/me/captcha",
                json={"scene": "admin_reset_user_password",
                      "unexpected_field": "ignored-by-limiter"},
            )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    scene_check.assert_awaited_once()
    assert scene_check.await_args is not None
    assert scene_check.await_args.kwargs["scope"] == "captcha_create_admin_reset_user_password"
    assert scene_check.await_args is not None
    assert scene_check.await_args.kwargs["subject_type"] == "user_id"
    assert scene_check.await_args is not None
    assert scene_check.await_args.kwargs["key_parts"] == [
        str(context.login_info.user_id)]
    issue.assert_not_awaited()


async def test_invalid_private_captcha_body_rejects_quota_before_postgresql(
    monkeypatch: pytest.MonkeyPatch,
    captcha_authorization: tuple[AuthorizationContext, AsyncMock],
) -> None:
    """
        无效用途额度耗尽时立即拒绝，不打开账号数据库会话。

    :param monkeypatch: 将唯一限流检查替换为额度拒绝。
    :param captcha_authorization: 当前账号和用于证明未查库的模拟会话。
    :return: 无返回值；只计数一次并返回真实 429 与剩余窗口。
    """
    context, session = captcha_authorization
    denied = RateLimitExceeded(
        "captcha_invalid_scene", RateLimitResult(False, 10, 0, 2100, 2100)
    )

    check = AsyncMock(side_effect=denied)
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    app.dependency_overrides[check_token] = lambda: context.login_info
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/me/captcha", json={"scene": "nope"})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 429
    assert response.json()["code"] == int(BusinessCode.RATE_LIMITED)
    assert response.headers["Retry-After"] == "3"
    check.assert_awaited_once()
    session.__aenter__.assert_not_awaited()
    session.scalar.assert_not_awaited()


async def test_invalid_public_captcha_body_is_metered_by_trusted_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    check = AsyncMock()
    issue = AsyncMock()
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/auth/captcha", json={})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert check.await_args is not None
    assert check.await_args.kwargs["scope"] == "captcha_invalid_scene"
    assert check.await_args is not None
    assert check.await_args.kwargs["subject_type"] == "ip"
    assert check.await_args is not None
    assert check.await_args.kwargs["key_parts"] == ["127.0.0.1"]
    issue.assert_not_awaited()


async def test_wrong_captcha_endpoint_over_quota_returns_429(monkeypatch: pytest.MonkeyPatch) -> None:
    denied = RateLimitExceeded(
        "captcha_invalid_scene", RateLimitResult(False, 10, 0, 2100, 2100)
    )
    check = AsyncMock(side_effect=denied)
    issue = AsyncMock()
    monkeypatch.setattr(rate_limit_dependencies,
                        "get_rate_limit_redis", lambda _: object())
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", check)
    monkeypatch.setattr(captcha_service, "create_captcha", issue)
    app.dependency_overrides[get_settings] = get_settings
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/captcha", json={"scene": "admin_reset_user_password"}
            )
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 429
    assert result.json()["code"] == int(BusinessCode.RATE_LIMITED)
    assert result.headers["Retry-After"] == "3"
    assert result.headers["Cache-Control"] == "no-store"
    assert result.json()["request_id"] == result.headers["X-Request-ID"]
    check.assert_awaited_once()
    issue.assert_not_awaited()


async def test_register_normalizes_username_and_returns_only_user_id(monkeypatch: pytest.MonkeyPatch) -> None:
    user_id = new_entity_id("U")
    service = AsyncMock()
    service.register.return_value = user_id
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={"user_name": "  Alice  ",
                      "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 201
    assert body["code"] == int(BusinessCode.CREATED)
    assert body["data"] == {"user_id": str(user_id)}
    assert response.headers["Cache-Control"] == "no-store"
    _assert_envelope(response.status_code, body)
    assert service.register.await_args.kwargs["user_name"] == "Alice"
    assert service.register.await_args.kwargs["password"] == VALID_PASSWORD


async def test_register_http_flow_admits_before_captcha_and_write(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    user_id = new_entity_id("U")
    service = AsyncMock()

    async def admit_register(*_args: object, **_kwargs: object) -> None:
        events.append("rate_limit")

    async def verify_captcha(*_args: object, **_kwargs: object) -> None:
        events.append("captcha")

    async def register(**_kwargs: object) -> str:
        events.append("register")
        return user_id

    service.register.side_effect = register
    monkeypatch.setattr(rate_limit_dependencies,
                        "_check_quota", admit_register)
    monkeypatch.setattr(
        captcha_service,
        "verify_captcha",
        verify_captcha,
    )
    monkeypatch.setattr(
        rate_limit_dependencies, "get_rate_limit_redis", lambda _request: object()
    )
    app.dependency_overrides[get_settings] = get_settings
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={"user_name": "Alice",
                      "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201, response.text
    assert events == ["rate_limit", "captcha", "register"]


@pytest.mark.parametrize("password", [VALID_PASSWORD, "old", "Ab1!" + "x" * 29])
async def test_login_route_returns_the_complete_service_result(password: str, monkeypatch: pytest.MonkeyPatch) -> None:
    login_result = LoginResult(
        user_id=new_entity_id("U"),
        access_token="signed-access-token",
        expires_in=3_600,
    )
    service = AsyncMock()
    service.login.return_value = login_result
    redis = object()
    monkeypatch.setattr(auth_api, "get_redis", lambda _request: redis)
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={"user_name": "Alice", "password": password, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 200
    assert body["data"] == {
        "access_token": "signed-access-token",
        "token_type": "bearer",
        "expires_in": 3_600,
    }
    assert response.headers["Cache-Control"] == "no-store"
    service.login.assert_awaited_once_with(redis=redis, settings=get_settings(),
                                           user_name="Alice", password=password)


async def test_login_http_flow_admits_before_captcha_and_complete_login(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    login_result = LoginResult(
        user_id=new_entity_id("U"),
        access_token="signed-access-token",
        expires_in=86_400,
    )
    service = AsyncMock()

    async def admit_login(*_args: object, **_kwargs: object) -> None:
        events.append("rate_limit")

    async def verify_captcha(*_args: object, **_kwargs: object) -> None:
        events.append("captcha")

    async def login(*_args: object, **_kwargs: object) -> LoginResult:
        events.append("login")
        return login_result

    service.login.side_effect = login
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", admit_login)
    monkeypatch.setattr(
        captcha_service,
        "verify_captcha",
        verify_captcha,
    )
    monkeypatch.setattr(auth_api, "get_redis", lambda _request: object())
    monkeypatch.setattr(
        rate_limit_dependencies, "get_rate_limit_redis", lambda _request: object()
    )
    app.dependency_overrides[get_settings] = get_settings
    monkeypatch.setattr(auth_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={"user_name": "Alice",
                      "password": VALID_PASSWORD, **CAPTCHA},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    assert events == ["rate_limit", "captcha", "login"]


async def test_managed_user_sessions_require_visibility_and_are_not_cacheable(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(users_read=True)
    target_id = new_entity_id("U")
    redis = object()
    service = AsyncMock()
    service.list_user_sessions.return_value = ActiveSessionsResponse(
        active_count=2,
        login_times=("2023-11-14T22:13:20+00:00", "2023-11-14T22:23:20+00:00"),
    )

    monkeypatch.setattr(users_api, "get_redis", lambda _request: redis)
    override_management(context)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/api/v1/users/sessions/list", params={"user_id": str(target_id)})
            self_response = await client.get("/api/v1/me/sessions/list")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["data"]["active_count"] == 2
    assert self_response.status_code == 404
    service.list_user_sessions.assert_awaited_once_with(
        current_user=context.user_info,
        user_id=target_id,
        redis=redis,
    )


@pytest.mark.parametrize(("method", "path", "has_required_permission", "expected_status"), [
    ("GET", "/me/user_info", True, 200),
    ("GET", "/me/user_info", False, 403),
    ("POST", "/me/password/change", False, 403),
    ("GET", "/users/list", True, 403),
])
async def test_basic_account_permissions_control_own_routes_without_granting_management(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
    fake_captcha: AsyncMock,
    method: str,
    path: str,
    has_required_permission: bool,
    expected_status: int,
) -> None:
    context = _context(
        account_read=has_required_permission if path == "/me/user_info" else True,
        password_change=has_required_permission if path == "/me/password/change" else True,
    )
    assert context.user_info.role_level == 0
    override_management(context)
    quota = AsyncMock()
    account = AsyncMock(return_value=context)
    audit = AsyncMock()
    service = AsyncMock()
    monkeypatch.setattr(permission_dependencies, "rate_limit_user", quota)
    monkeypatch.setattr(auth_dependencies, "_load_current_user", account)
    monkeypatch.setattr(permission_dependencies, "AuditService", Mock(return_value=audit))
    monkeypatch.setattr(me_api, "auth_service", service)
    payload = {"current_password": VALID_PASSWORD, "new_password": NEW_PASSWORD, **CAPTCHA}
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.request(method, "/api/v1" + path, json=payload if method == "POST" else None)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == expected_status, response.text
    quota.assert_awaited_once()
    assert quota.await_args is not None
    assert quota.await_args.kwargs["management"] is path.startswith("/users/")
    account.assert_awaited_once()
    fake_captcha.assert_not_awaited()
    service.change_password.assert_not_awaited()
    if expected_status == 200:
        assert response.json()["data"] == {
            "user_id": context.login_info.user_id,
            "role_level": 0,
            "permissions": sorted(context.permissions),
        }
    else:
        assert response.json()["code"] == int(BusinessCode.ACCESS_FORBIDDEN)
    if method == "POST":
        audit.audit_denied.assert_awaited_once()
    else:
        audit.audit_denied.assert_not_awaited()


async def test_self_change_reauthenticates_and_returns_relogin_message(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
    fake_captcha: AsyncMock,
) -> None:
    context = _context()
    service = AsyncMock()
    service.change_password.return_value = None

    override_management(context)
    quota = AsyncMock()
    account = AsyncMock(return_value=context)
    monkeypatch.setattr(permission_dependencies, "rate_limit_user", quota)
    monkeypatch.setattr(auth_dependencies, "_load_current_user", account)
    monkeypatch.setattr(me_api, "auth_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/me/password/change",
                json={
                    "current_password": VALID_PASSWORD,
                    "new_password": NEW_PASSWORD,
                    **CAPTCHA,
                },
            )
    finally:
        app.dependency_overrides.clear()

    body = response.json()
    assert response.status_code == 200
    assert context.user_info.role_level == 0
    quota.assert_awaited_once()
    assert quota.await_args is not None
    assert quota.await_args.kwargs["management"] is False
    account.assert_awaited_once()
    fake_captcha.assert_awaited_once()
    assert fake_captcha.await_args is not None
    assert fake_captcha.await_args.kwargs["user_id"] == context.login_info.user_id
    assert body["data"] is None
    assert "重新登录" in body["message"]
    assert service.change_password.await_args.kwargs["context"] is context
    assert (
        service.change_password.await_args.kwargs["current_password"] == VALID_PASSWORD
    )


async def test_admin_reset_sets_a_directly_usable_password(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(password_reset=True)
    target_id = new_entity_id("U")
    service = AsyncMock()
    service.reset_user_password.return_value = None

    override_management(context)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                '/api/v1/users/password/reset',
                json={"user_id": str(target_id),
                      "new_password": NEW_PASSWORD, **CAPTCHA},
                headers={"Accept-Language": "en"},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["data"] is None
    assert response.json()["message"] == "Password reset successful"
    assert response.headers["Content-Language"] == "en"
    assert NEW_PASSWORD not in response.text
    assert service.reset_user_password.await_args.kwargs == {
        "context": context,
        "target_user_id": target_id,
        "new_password": NEW_PASSWORD,
    }


async def test_admin_reset_request_rejects_unsupported_mode(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(password_reset=True)
    service = AsyncMock()

    override_management(context)
    monkeypatch.setattr(users_api, "user_service", service)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                '/api/v1/users/password/reset',
                json={"user_id": new_entity_id("U"),
                      "new_password": NEW_PASSWORD,
                      "reset_mode": "temporary",
                      **CAPTCHA,
                      },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    assert NEW_PASSWORD not in response.text
    service.reset_user_password.assert_not_awaited()


async def test_password_requests_reject_unknown_fields_without_echoing_secrets() -> (None):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "alice",
                "password": VALID_PASSWORD,
                "role": "super_admin",
                **CAPTCHA,
            },
        )

    body = response.json()
    assert response.status_code == 422
    assert body["code"] == int(BusinessCode.VALIDATION_FAILED)
    assert VALID_PASSWORD not in response.text


def test_password_routes_are_post_only_and_do_not_expose_the_mechanism() -> None:
    schema = app.openapi()
    assert "/api/v1/auth/password/reset/complete" not in schema["paths"]
    assert "TemporaryPasswordChangeRequest" not in schema["components"]["schemas"]
    assert "password_change_required" not in schema["components"][
        "schemas"]["AccessTokenResponse"]["properties"]
    paths = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/me/password/change",
        "/api/v1/users/password/reset",
        "/api/v1/auth/captcha",
        "/api/v1/me/captcha",
        "/api/v1/users/create",
    }
    for path in paths:
        assert "post" in schema["paths"][path]
        operation = schema["paths"][path]["post"]
        assert "rbac" not in str(operation).casefold()
        assert any(status.startswith("2") for status in operation["responses"])

    reset_schema = schema["components"]["schemas"]["UserPasswordResetRequest"]
    expected_fields = {"user_id", "captcha_id",
                       "captcha_answer", "new_password"}
    assert set(reset_schema["properties"]) == expected_fields
    assert set(reset_schema["required"]) == expected_fields
    create_schema = schema["components"]["schemas"]["UserCreateRequest"]
    assert "password" in create_schema["required"]
    assert "temporary_password" not in create_schema["properties"]
