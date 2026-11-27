#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    对全部受保护接口验证 Token 门禁和权限门禁，使用真实 JWT 验签、登录仓储与权限依赖。
#    Redis 只用内存回包，不执行 Lua；数据库账号读取、限流、审计和业务写入使用隔离替身。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/11/26    XTN       V1.000        新建
# 2026/11/28    XTN       V1.001        权限目录业务读取真实启动收集的接口关系，测试后恢复应用状态
# --------------------------------------------------------------------------------------------------

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from httpx import ASGITransport, AsyncClient, Response

from app.api.v1.endpoints import auth as auth_api
from app.api.v1.endpoints import me as me_api
from app.api.v1.endpoints import permissions as permission_api
from app.api.v1.endpoints import roles as role_api
from app.api.v1.endpoints import users as user_api
from app.api.v1.route_validation import validate_v1_api_routes
from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.roles import USER_PERMISSION_KEYS
from app.core.captcha import CaptchaScene
from app.core.config import get_settings
from app.core.exceptions import invalid_request_400
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import AccessTokenInfo, encode_access_token
from app.dependencies import auth as auth_dependencies
from app.dependencies import permission as permission_dependencies
from app.dependencies import rate_limit as rate_limit_dependencies
from app.main import app
from app.repositories.postgres.user_repository import user_repository
from app.schemas.captcha import CaptchaResponse

TARGET_USER_ID = new_entity_id("U")
TARGET_ROLE_ID = new_entity_id("R")
TARGET_PERMISSION_ID = new_entity_id("P")
CAPTCHA = {"captcha_id": str(uuid.uuid4()), "captcha_answer": "AB234"}
PASSWORD_CHANGE = {"current_password": "Older-Pass8!", "new_password": "Newer-Pass9!", **CAPTCHA}
ROLE_VERSION = {"role_id": TARGET_ROLE_ID, "expected_version": 1}


@dataclass(frozen=True)
class RouteRequest:
    """为一个实际接口提供完整请求，避免无效参数掩盖权限检查。"""

    method: str
    path: str
    data: dict[str, Any] = field(default_factory=dict)
    permission: PermissionKey | None = None


PUBLIC_ROUTES = frozenset({
    ("POST", "/api/v1/auth/captcha"),
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/login"),
})
# 明确列出每个接口的合法请求；新增接口而未补充测试时，下面的路由清单断言会失败。
PROTECTED_ROUTES = (
    RouteRequest("POST", "/api/v1/auth/logout"),
    RouteRequest("GET", "/api/v1/me/user_info", permission=PermissionKey.ACCOUNT_READ),
    RouteRequest("POST", "/api/v1/me/password/change", PASSWORD_CHANGE, PermissionKey.ACCOUNT_CHANGE_PASSWORD),
    RouteRequest("POST", "/api/v1/me/captcha", {"scene": CaptchaScene.USER_CHANGE_PASSWORD.value}),
    RouteRequest("GET", "/api/v1/users/list", permission=PermissionKey.USERS_READ),
    RouteRequest("GET", "/api/v1/users/detail", {"user_id": TARGET_USER_ID}, PermissionKey.USERS_READ),
    RouteRequest("POST", "/api/v1/users/create", {
        "user_name": "member_42", "password": "Valid-Pass9!", **CAPTCHA,
    }, PermissionKey.USERS_CREATE),
    RouteRequest("POST", "/api/v1/users/enable", {"user_id": TARGET_USER_ID}, PermissionKey.USERS_STATUS_UPDATE),
    RouteRequest("POST", "/api/v1/users/disable", {"user_id": TARGET_USER_ID}, PermissionKey.USERS_STATUS_UPDATE),
    RouteRequest("POST", "/api/v1/users/password/reset", {
        "user_id": TARGET_USER_ID, "new_password": "Valid-Pass9!", **CAPTCHA,
    }, PermissionKey.USERS_PASSWORD_RESET),
    RouteRequest("POST", "/api/v1/users/roles/bind", {
        "user_id": TARGET_USER_ID, "role_ids": [TARGET_ROLE_ID],
    }, PermissionKey.ROLES_BIND),
    RouteRequest("POST", "/api/v1/users/roles/unbind", {
        "user_id": TARGET_USER_ID, "role_ids": [TARGET_ROLE_ID],
    }, PermissionKey.ROLES_UNBIND),
    RouteRequest("GET", "/api/v1/users/sessions/list", {"user_id": TARGET_USER_ID}, PermissionKey.USERS_READ),
    RouteRequest("POST", "/api/v1/users/sessions/logout-all", {
        "user_id": TARGET_USER_ID,
    }, PermissionKey.USERS_SESSIONS_REVOKE),
    RouteRequest("GET", "/api/v1/roles/list", permission=PermissionKey.ROLES_READ),
    RouteRequest("GET", "/api/v1/roles/detail", {"role_id": TARGET_ROLE_ID}, PermissionKey.ROLES_READ),
    RouteRequest("POST", "/api/v1/roles/create", {
        "key": "reviewer", "name": "Reviewer", "level": 20,
    }, PermissionKey.ROLES_CREATE),
    RouteRequest("POST", "/api/v1/roles/update", {**ROLE_VERSION, "name": "Renamed"}, PermissionKey.ROLES_UPDATE),
    RouteRequest("POST", "/api/v1/roles/enable", ROLE_VERSION, PermissionKey.ROLES_STATUS_UPDATE),
    RouteRequest("POST", "/api/v1/roles/disable", ROLE_VERSION, PermissionKey.ROLES_STATUS_UPDATE),
    RouteRequest("POST", "/api/v1/roles/delete", ROLE_VERSION, PermissionKey.ROLES_DELETE),
    RouteRequest("POST", "/api/v1/roles/permissions/bind", {
        **ROLE_VERSION, "permission_ids": [TARGET_PERMISSION_ID],
    }, PermissionKey.ROLES_PERMISSIONS_BIND),
    RouteRequest("POST", "/api/v1/roles/permissions/unbind", {
        **ROLE_VERSION, "permission_ids": [TARGET_PERMISSION_ID],
    }, PermissionKey.ROLES_PERMISSIONS_UNBIND),
    RouteRequest("GET", "/api/v1/permissions/list", permission=PermissionKey.PERMISSIONS_READ),
    RouteRequest("GET", "/api/v1/permissions/detail", {
        "permission_id": TARGET_PERMISSION_ID,
    }, PermissionKey.PERMISSIONS_READ),
)
MANAGEMENT_ROUTES = tuple(route for route in PROTECTED_ROUTES if not route.path.startswith((
    "/api/v1/auth/", "/api/v1/me/",
)))
ROUTE_IDS = tuple(f"{route.method} {route.path}" for route in PROTECTED_ROUTES)
MANAGEMENT_IDS = tuple(f"{route.method} {route.path}" for route in MANAGEMENT_ROUTES)
PERMISSION_ROUTES = tuple(route for route in PROTECTED_ROUTES if route.permission is not None)
PERMISSION_IDS = tuple(f"{route.method} {route.path}" for route in PERMISSION_ROUTES)
BUSINESS_ENTRIES = {
    "/api/v1/users/list": ("user_service", "list_users"),
    "/api/v1/users/detail": ("user_service", "get_user_detail"),
    "/api/v1/users/create": ("user_service", "admin_create_user"),
    "/api/v1/users/enable": ("user_service", "update_user_status"),
    "/api/v1/users/disable": ("user_service", "update_user_status"),
    "/api/v1/users/password/reset": ("user_service", "reset_user_password"),
    "/api/v1/users/roles/bind": ("user_service", "change_user_roles"),
    "/api/v1/users/roles/unbind": ("user_service", "change_user_roles"),
    "/api/v1/users/sessions/list": ("user_service", "list_user_sessions"),
    "/api/v1/users/sessions/logout-all": ("user_service", "revoke_user_sessions"),
    "/api/v1/roles/list": ("role_service", "list_roles"),
    "/api/v1/roles/detail": ("role_service", "get_role_detail"),
    "/api/v1/roles/create": ("role_service", "create_role"),
    "/api/v1/roles/update": ("role_service", "update_role"),
    "/api/v1/roles/enable": ("role_service", "set_role_active"),
    "/api/v1/roles/disable": ("role_service", "set_role_active"),
    "/api/v1/roles/delete": ("role_service", "delete_role"),
    "/api/v1/roles/permissions/bind": ("role_service", "change_role_permissions"),
    "/api/v1/roles/permissions/unbind": ("role_service", "change_role_permissions"),
    "/api/v1/permissions/list": ("permission_service", "list_permissions"),
    "/api/v1/permissions/detail": ("permission_service", "get_permission_detail"),
    "/api/v1/me/password/change": ("auth_service", "change_password"),
}


class MemorySessions:
    """仅模拟 Redis.eval 的回包及撤销结果，保留真实登录仓储对记录的校验。"""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[object, ...]] = []

    async def eval(self, script: str, number_of_keys: int, *arguments: object) -> object:
        """按用户和 JTI 返回内存记录；这里不运行或验证 Lua。"""
        self.calls.append(arguments)
        assert script and number_of_keys == 2
        assert len(arguments) in (3, 4), "unexpected session operation reached the Redis substitute"
        session_key, sequence_key, token_id = arguments[:3]
        assert isinstance(session_key, str) and isinstance(sequence_key, str) and isinstance(token_id, str)
        assert sequence_key == session_key.replace("login:sessions:", "login:sequence:")
        key = (session_key, token_id)
        if len(arguments) == 3:
            return self.records.get(key)
        if self.records.get(key) != arguments[3]:
            return 0
        del self.records[key]
        return 1

    def remember(self, token_info: AccessTokenInfo, *, stored_user_id: str | None = None) -> None:
        """写入固定格式的测试记录，可故意存入另一个用户以检查身份匹配。"""
        self.records[(f"login:sessions:{token_info.user_id}", token_info.token_id.hex)] = json.dumps(
            {"user_id": stored_user_id or token_info.user_id, "iat": token_info.issued_at,
             "exp": token_info.expires_at, "token_version": 0, "typ": "access"},
            sort_keys=True, separators=(",", ":"),
        )


@dataclass
class HttpWorld:
    """保存真实 Token 与可断言调用次数的外部资源替身。"""

    user_id: str
    token: str
    token_info: AccessTokenInfo
    sessions: MemorySessions
    account: AsyncMock
    session_factory: Mock
    quota: AsyncMock
    private_quota: AsyncMock
    audit: AsyncMock
    auth_service: AsyncMock
    user_service: AsyncMock
    role_service: AsyncMock
    permission_service: AsyncMock
    captcha_service: AsyncMock

    def user_info(self, permissions: frozenset[str] = USER_PERMISSION_KEYS) -> UserInfo:
        """构造最低级普通用户，允许用空集合检查本人接口的精确权限。"""
        return UserInfo.build(
            user_id=self.user_id, user_is_active=True, user_is_protected=False,
            roles=(RoleGrant(
                role_id=new_entity_id("R"), key="user", level=0, permissions=permissions,
                is_system=True, is_protected=False, is_super_admin=False,
            ),),
        )

    def assert_no_business_work(self) -> None:
        """拒绝请求后确认没有调用业务、验证码生成或验证码校验。"""
        for service in (self.auth_service, self.user_service, self.role_service,
                        self.permission_service, self.captcha_service):
            assert service.mock_calls == []


@pytest.fixture
def http_world(monkeypatch: pytest.MonkeyPatch) -> Iterator[HttpWorld]:
    """隔离外部资源；不替换 Token、账号装配或权限依赖。"""
    assert not app.dependency_overrides, "an earlier test left a dependency override behind"
    # 启动校验只读路由和依赖，不连接外部服务；当前测试结束时恢复原有目录。
    monkeypatch.setattr(app.state, "permission_api_routes", {}, raising=False)
    validate_v1_api_routes(app)
    user_id = new_entity_id("U")
    token, token_info = encode_access_token(user_id=user_id, token_id=uuid.uuid4(), settings=get_settings())
    sessions = MemorySessions()
    sessions.remember(token_info)
    account = AsyncMock()
    session = AsyncMock()
    session.__aenter__.return_value = session
    session_factory = Mock(return_value=session)
    world = HttpWorld(user_id, token, token_info, sessions, account, session_factory,
                      AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock(),
                      AsyncMock(), AsyncMock(), AsyncMock())
    account.return_value = world.user_info()
    # 保留 _load_current_user，只有查库的最后一层使用预置账号权限。
    monkeypatch.setattr(auth_dependencies, "SessionFactory", session_factory)
    monkeypatch.setattr("app.db.postgres_db.SessionFactory", session_factory)
    monkeypatch.setattr(user_repository, "check_current_user", account)
    monkeypatch.setattr(app.state, "redis", sessions, raising=False)
    monkeypatch.setattr(auth_dependencies, "rate_limit_user", world.quota)
    monkeypatch.setattr(permission_dependencies, "rate_limit_user", world.quota)
    monkeypatch.setattr(auth_dependencies, "rate_limit_private_captcha", world.private_quota)
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", AsyncMock())
    monkeypatch.setattr(permission_dependencies, "AuditService", Mock(return_value=world.audit))
    monkeypatch.setattr(auth_api, "auth_service", world.auth_service)
    monkeypatch.setattr(me_api, "auth_service", world.auth_service)
    monkeypatch.setattr(user_api, "user_service", world.user_service)
    monkeypatch.setattr(role_api, "role_service", world.role_service)
    monkeypatch.setattr(permission_api, "permission_service", world.permission_service)
    monkeypatch.setattr(me_api, "captcha_service", world.captcha_service)
    monkeypatch.setattr(auth_api, "captcha_service", world.captcha_service)
    monkeypatch.setattr("app.dependencies.captcha.captcha_service", world.captcha_service)
    yield world
    assert not app.dependency_overrides


async def send_request(route: RouteRequest, token: str | None) -> Response:
    """发送合法的 JSON 或查询参数，让鉴权结果不被无效请求体干扰。"""
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    parameters: dict[str, Any] = {"params": route.data} if route.method == "GET" else {"json": route.data}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(
            route.method, route.path, headers=headers, **parameters,
        )


def assert_denied(response: Response, *, status: int, code: int) -> None:
    """拒绝必须使用统一错误响应，不能仅靠底层错误碰巧返回相同 HTTP 状态。"""
    assert response.status_code == status, response.text
    assert response.json()["code"] == code
    if status == 422:
        assert set(response.json()["data"]) == {"errors"}
        assert response.json()["data"]["errors"]
    else:
        assert response.json()["data"] is None
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    if status == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


def test_all_registered_business_routes_are_accounted_for() -> None:
    """任何新接口都必须明确加入匿名或鉴权矩阵，不能默默漏测。"""
    actual = {(method, context.path) for context in iter_route_contexts(app.router.routes)
              if isinstance(context.route, APIRoute) and isinstance(context.path, str)
              and context.path.startswith("/api/v1/") for method in (context.route.methods or ())}
    protected = {(route.method, route.path) for route in PROTECTED_ROUTES}
    assert actual == PUBLIC_ROUTES | protected
    assert len(actual) == 28 and len(protected) == 25 and len(MANAGEMENT_ROUTES) == 21
    assert PUBLIC_ROUTES.isdisjoint(protected)


@pytest.mark.parametrize("route", PROTECTED_ROUTES, ids=ROUTE_IDS)
@pytest.mark.parametrize("token_state", ["missing", "forged", "expired", "revoked", "other_user_record"])
async def test_every_protected_route_rejects_invalid_login_before_business(
    http_world: HttpWorld, route: RouteRequest, token_state: str,
) -> None:
    """全部受保护接口都要真正经过 JWT 与 Redis 门禁，失败不能触碰业务。"""
    token: str | None = http_world.token
    if token_state == "missing":
        token = None
    elif token_state in {"forged", "expired"}:
        now = int(datetime.now(UTC).timestamp())
        token = jwt.encode({
            "user_id": http_world.user_id, "jti": str(http_world.token_info.token_id),
            "iat": now - 3600 if token_state == "expired" else now,
            "exp": now - 300 if token_state == "expired" else now + 3600, "token_type": "access",
        }, "X" * 32 if token_state == "forged" else get_settings().jwt_secret.get_secret_value(), algorithm="HS256")
    elif token_state == "revoked":
        http_world.sessions.records.clear()
    else:
        http_world.sessions.remember(http_world.token_info, stored_user_id=TARGET_USER_ID)
    response = await send_request(route, token)
    assert_denied(response, status=401, code=40110)
    http_world.assert_no_business_work()
    http_world.account.assert_not_awaited()
    http_world.session_factory.assert_not_called()
    http_world.quota.assert_not_awaited()
    http_world.private_quota.assert_not_awaited()
    assert http_world.audit.mock_calls == []
    assert len(http_world.sessions.calls) == (1 if token_state in {"revoked", "other_user_record"} else 0)


@pytest.mark.parametrize("route", MANAGEMENT_ROUTES, ids=MANAGEMENT_IDS)
async def test_every_management_route_rejects_a_valid_basic_user(http_world: HttpWorld, route: RouteRequest) -> None:
    """真实 Token 和 Redis 记录通过后，普通 user 仍不能进入任何管理接口。"""
    response = await send_request(route, http_world.token)
    assert_denied(response, status=403, code=40301)
    http_world.assert_no_business_work()
    http_world.account.assert_awaited_once()
    assert http_world.account.await_args is not None
    assert http_world.account.await_args.kwargs["user_id"] == http_world.user_id
    assert http_world.account.await_args.kwargs["token_version"] == 0
    http_world.quota.assert_awaited_once()
    http_world.private_quota.assert_not_awaited()
    assert len(http_world.sessions.calls) == 1
    if route.method == "POST":
        http_world.audit.audit_denied.assert_awaited_once()
    else:
        http_world.audit.audit_denied.assert_not_awaited()


@pytest.mark.parametrize("route", tuple(route for route in PROTECTED_ROUTES if route.permission in {
    PermissionKey.ACCOUNT_READ, PermissionKey.ACCOUNT_CHANGE_PASSWORD,
}), ids=("own_info", "own_password"))
async def test_own_routes_require_their_exact_basic_permission(http_world: HttpWorld, route: RouteRequest) -> None:
    """登录成功不等于拥有本人业务权限，缺少精确权限必须在验证码和业务之前拒绝。"""
    other_permission = (PermissionKey.ACCOUNT_CHANGE_PASSWORD if route.permission == PermissionKey.ACCOUNT_READ
                        else PermissionKey.ACCOUNT_READ)
    http_world.account.return_value = http_world.user_info(frozenset({other_permission.value}))
    response = await send_request(route, http_world.token)
    assert_denied(response, status=403, code=40301)
    http_world.assert_no_business_work()
    http_world.account.assert_awaited_once()


@pytest.mark.parametrize("route", PERMISSION_ROUTES, ids=PERMISSION_IDS)
@pytest.mark.parametrize("has_exact_permission", [True, False], ids=("only_required", "all_except_required"))
async def test_each_route_checks_its_own_exact_permission(
    http_world: HttpWorld, route: RouteRequest, has_exact_permission: bool,
) -> None:
    """逐接口验证精确权限：只持该项能过门禁，拥有其他所有权限仍不能代替该项。"""
    assert route.permission is not None
    permissions = (frozenset({route.permission.value}) if has_exact_permission else
                   frozenset(item.value for item in PermissionKey if item != route.permission))
    http_world.account.return_value = http_world.user_info(permissions)
    entry = None
    if route.path in BUSINESS_ENTRIES:
        service_name, method_name = BUSINESS_ENTRIES[route.path]
        entry = getattr(getattr(http_world, service_name), method_name)
        # 进入业务的第一行就返回受控错误，不执行任何实际管理或密码写入。
        entry.side_effect = invalid_request_400("controlled_business_entry")
    response = await send_request(route, http_world.token)
    if has_exact_permission:
        if entry is None:
            assert route.path == "/api/v1/me/user_info"
            assert response.status_code == 200, response.text
        else:
            assert_denied(response, status=400, code=40001)
            entry.assert_awaited_once()
        http_world.audit.audit_denied.assert_not_awaited()
    else:
        assert_denied(response, status=403, code=40301)
        if entry is not None:
            entry.assert_not_awaited()
        http_world.assert_no_business_work()
    assert len(http_world.sessions.calls) == 1
    http_world.account.assert_awaited_once()


async def test_basic_user_can_read_only_their_own_identity(http_world: HttpWorld) -> None:
    """正向验证普通 user 可查看本人；额外 query 用户 ID 不会改变可信身份。"""
    route = RouteRequest("GET", "/api/v1/me/user_info", {"user_id": TARGET_USER_ID, "role_level": 1000})
    response = await send_request(route, http_world.token)
    assert response.status_code == 200, response.text
    assert response.json()["data"] == {
        "user_id": http_world.user_id, "role_level": 0, "permissions": sorted(USER_PERMISSION_KEYS),
    }
    http_world.assert_no_business_work()


async def test_basic_user_password_change_uses_authenticated_identity(http_world: HttpWorld) -> None:
    """正向改密只使用可信登录身份和固定本人场景，query 不能把目标换成其他用户。"""
    route = RouteRequest("POST", f"/api/v1/me/password/change?user_id={TARGET_USER_ID}", PASSWORD_CHANGE)
    response = await send_request(route, http_world.token)
    assert response.status_code == 200, response.text
    http_world.captcha_service.verify_captcha.assert_awaited_once()
    checked = http_world.captcha_service.verify_captcha.await_args
    assert checked is not None and checked.kwargs["user_id"] == http_world.user_id
    assert checked.kwargs["scene"] == CaptchaScene.USER_CHANGE_PASSWORD
    http_world.auth_service.change_password.assert_awaited_once()
    changed = http_world.auth_service.change_password.await_args
    assert changed is not None and changed.kwargs["context"].login_info.user_id == http_world.user_id
    assert "target_user_id" not in changed.kwargs


@pytest.mark.parametrize("injected", [
    {"user_id": TARGET_USER_ID}, {"scene": CaptchaScene.ADMIN_RESET_USER_PASSWORD.value}, {"is_super_admin": True},
], ids=("target_user", "admin_scene", "super_admin_flag"))
async def test_password_change_cannot_accept_client_authority_fields(
    http_world: HttpWorld, injected: dict[str, Any],
) -> None:
    """客户端不能给本人改密请求追加目标、用途或管理员身份来改变业务。"""
    route = RouteRequest("POST", "/api/v1/me/password/change", {**PASSWORD_CHANGE, **injected})
    response = await send_request(route, http_world.token)
    assert_denied(response, status=422, code=42201)
    http_world.auth_service.change_password.assert_not_awaited()
    # 验证码依赖可能早于业务模型报错，但只认服务端固定的本人用途和已登录用户。
    checked = http_world.captcha_service.verify_captcha.await_args
    assert checked is not None and checked.kwargs["user_id"] == http_world.user_id
    assert checked.kwargs["scene"] == CaptchaScene.USER_CHANGE_PASSWORD


@pytest.mark.parametrize("scene", [CaptchaScene.USER_CHANGE_PASSWORD, CaptchaScene.ADMIN_CREATE_USER,
                                   CaptchaScene.ADMIN_RESET_USER_PASSWORD])
async def test_private_captcha_issuance_never_changes_the_current_user(
    http_world: HttpWorld, scene: CaptchaScene,
) -> None:
    """各私有验证码都绑定 Token 用户；领取管理用途图片不会授予管理权限。"""
    http_world.captcha_service.create_captcha.return_value = CaptchaResponse(
        captcha_id=uuid.uuid4(), image_base64="test-image",
    )
    route = RouteRequest("POST", "/api/v1/me/captcha", {"scene": scene.value})
    response = await send_request(route, http_world.token)
    assert response.status_code == 200, response.text
    issued = http_world.captcha_service.create_captcha.await_args
    assert issued is not None and issued.kwargs["user_id"] == http_world.user_id
    assert issued.kwargs["scene"] == scene
    http_world.private_quota.assert_awaited_once()
    http_world.quota.assert_not_awaited()
    assert http_world.account.return_value.permissions == USER_PERMISSION_KEYS


async def test_current_token_logout_succeeds_without_account_or_permission_lookup(http_world: HttpWorld) -> None:
    """正向退出只撤销当前 Token，不需要普通用户的基础权限，也不查询数据库。"""
    response = await send_request(RouteRequest("POST", "/api/v1/auth/logout"), http_world.token)
    assert response.status_code == 200, response.text
    assert response.json()["data"] is None
    assert http_world.sessions.records == {}
    assert len(http_world.sessions.calls) == 2
    http_world.account.assert_not_awaited()
    http_world.quota.assert_not_awaited()
    http_world.assert_no_business_work()


@pytest.mark.parametrize("path", ["/api/v1/auth/register", "/api/v1/users/create"],
                         ids=("registration", "admin_create"))
@pytest.mark.parametrize("injected", [
    {"role_ids": [TARGET_ROLE_ID]}, {"permissions": [PermissionKey.ROLES_DELETE.value]},
    {"is_protected": True}, {"is_system": True}, {"user_id": TARGET_USER_ID},
], ids=("roles", "permissions", "protected", "system", "user_id"))
async def test_account_creation_rejects_client_supplied_authority(
    http_world: HttpWorld, path: str, injected: dict[str, Any],
) -> None:
    """注册与管理员新增都不能靠多传字段指定角色、权限或系统身份。"""
    http_world.account.return_value = http_world.user_info(frozenset({PermissionKey.USERS_CREATE.value}))
    route = RouteRequest("POST", path, {"user_name": "member_42", "password": "Valid-Pass9!", **CAPTCHA, **injected})
    response = await send_request(route, http_world.token if path.startswith("/api/v1/users/") else None)
    assert_denied(response, status=422, code=42201)
    http_world.auth_service.register.assert_not_awaited()
    http_world.user_service.admin_create_user.assert_not_awaited()
    http_world.captcha_service.verify_captcha.assert_awaited_once()
    checked = http_world.captcha_service.verify_captcha.await_args
    assert checked is not None
    assert checked.kwargs["scene"] == (CaptchaScene.REGISTER if path == "/api/v1/auth/register"
                                       else CaptchaScene.ADMIN_CREATE_USER)
    assert checked.kwargs["user_id"] == (None if path == "/api/v1/auth/register" else http_world.user_id)
