#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    第一版接口参数位置与业务归类回归测试
#    使用隔离的依赖验证查询参数、JSON 目标 ID 和权限边界，不连接数据库或 Redis
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        增加统一路由和参数安全契约验证
# 2026/09/26    XTN       V1.001        对齐认证路由函数与公开操作 ID
# 2026/09/27    XTN       V1.002        校验访问权限、操作 ID 与显式限流声明
# 2026/09/29    XTN       V2.000        改用路由函数名和管理认证依赖，移除操作 ID 与限流标签断言
# 2026/09/29    XTN       V2.001        使用 API 装配层的启动路由校验入口
# 2026/09/29    XTN       V2.002        使用独立 v1 路由校验模块
# 2026/09/30    XTN       V2.003        移除临时密码路由契约
# 2026/09/30    XTN       V2.004        会话列表改为管理查询并明确全部退出路径
# 2026/10/09    XTN       V2.005        查询 ID 增加错误前缀和尾部换行拒绝检查
# 2026/10/10    XTN       V2.006        统一用户 ID 与当前用户命名
# 2026/10/12    XTN       V2.007        验证码依赖直接模拟共享服务校验边界
# 2026/10/12    XTN       V2.008        管理认证替身保留验证码读取的可信用户 ID
# 2026/10/15    XTN       V2.009        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V2.010        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/19    XTN       V2.011        参数测试直接替换路由模块的共享业务服务实例
# 2026/10/22    XTN       V2.012        对齐直接权限检查后的参数和验证码测试隔离
# 2026/10/24    XTN       V2.013        角色绑定及解绑接口权限采用 bind 和 unbind
# 2026/10/26    XTN       V2.014        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/11/26    XTN       V2.015        本人接口文档检查纳入基础权限及其说明格式
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Callable, Iterator
from typing import Annotated, Any
from unittest.mock import AsyncMock

import pytest
from fastapi import Body, Depends, FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from httpx import ASGITransport, AsyncClient

import app.api.v1.endpoints.roles as role_api_module
import app.api.v1.endpoints.users as user_api_module
from app.api.v1.route_validation import validate_v1_api_routes
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.ids import new_entity_id
from app.db.postgres_db import get_postgres_session
from app.dependencies import captcha
from app.dependencies.auth import get_current_user
from app.main import app
from app.schemas.user import UserResponse
from app.services.captcha_service import captcha_service

# 每项列出目标字段以外仍必填的业务参数，保证失败确实来自目标 ID，而非其他缺失字段。
TARGET_WRITES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("/roles/update", "role_id", {"expected_version": 0, "name": "Updated"}),
    ("/roles/disable", "role_id", {"expected_version": 0}),
    ("/roles/enable", "role_id", {"expected_version": 0}),
    ("/roles/delete", "role_id", {"expected_version": 0}),
    ("/roles/permissions/bind", "role_id",
     {"expected_version": 0, "permission_ids": [new_entity_id("P")]}),
    ("/roles/permissions/unbind", "role_id",
     {"expected_version": 0, "permission_ids": [new_entity_id("P")]}),
    ("/users/disable", "user_id", {}),
    ("/users/enable", "user_id", {}),
    ("/users/roles/bind", "user_id", {"role_ids": [new_entity_id("R")]}),
    ("/users/roles/unbind", "user_id", {"role_ids": [new_entity_id("R")]}),
    ("/users/password/reset", "user_id", {
        "new_password": "correct-horse-battery", "captcha_id": str(uuid.uuid4()), "captcha_answer": "AB234",
    }),
    ("/users/sessions/logout-all", "user_id", {}),
)
DETAIL_READS = (("roles/detail", "role_id"), ("users/detail", "user_id"),
                ("users/sessions/list", "user_id"), ("permissions/detail", "permission_id"))
# 路由名称由各模块的直接处理函数名生成，业务归并不能丢失已有入口。
EXPECTED_ROUTE_NAMES_BY_MODULE = {
    "auth": {"register", "login",
             "create_public_captcha", "logout"},
    "me": {"get_user_info", "change_my_password", "create_authenticated_captcha"},
    "users": {"list_users", "get_user_detail", "bind_user_roles", "unbind_user_roles", "disable_user",
              "enable_user", "list_user_sessions", "revoke_user_sessions", "create_user", "reset_user_password"},
    "roles": {"list_roles", "get_role_detail", "create_role", "update_role", "disable_role", "enable_role",
              "delete_role", "bind_role_permissions", "unbind_role_permissions"},
    "permissions": {"list_permissions", "get_permission_detail"},
}
# 每个公开路由对应 docstring 必须写出的准确权限；None 表示无需额外业务权限。
EXPECTED_PERMISSION_BY_ROUTE_NAME: dict[str, str | None] = {
    "register": None,
    "login": None,
    "create_public_captcha": None,
    "logout": None,
    "get_user_info": "account:read",
    "change_my_password": "account:change_password",
    "create_authenticated_captcha": None,
    "list_permissions": "permissions:read",
    "get_permission_detail": "permissions:read",
    "list_users": "users:read",
    "get_user_detail": "users:read",
    "list_user_sessions": "users:read",
    "bind_user_roles": "roles:bind",
    "unbind_user_roles": "roles:unbind",
    "disable_user": "users:status:update",
    "enable_user": "users:status:update",
    "revoke_user_sessions": "users:sessions:revoke",
    "create_user": "users:create",
    "reset_user_password": "users:password:reset",
    "list_roles": "roles:read",
    "get_role_detail": "roles:read",
    "create_role": "roles:create",
    "update_role": "roles:update",
    "disable_role": "roles:status:update",
    "enable_role": "roles:status:update",
    "delete_role": "roles:delete",
    "bind_role_permissions": "roles:permissions:bind",
    "unbind_role_permissions": "roles:permissions:unbind",
}


def management_context() -> AuthorizationContext:
    """
        构造拥有管理能力的隔离身份，让无效请求进入参数校验而不访问真实身份服务。

    :return: 包含全部明确权限键的测试操作者上下文。
    """
    user_id = new_entity_id("U")
    role = RoleGrant(role_id=new_entity_id("R"), key="contract_manager", level=500,
                     permissions=frozenset(item.value for item in PermissionKey), is_system=False,
                     is_protected=False, is_super_admin=False)
    user_info = UserInfo.build(user_id=user_id, user_is_active=True, user_is_protected=False,
                               token_version=0, roles=(role,))
    return AuthorizationContext(
        login_info=LoginInfo(user_id=user_id, token_version=0,
                             token_id=uuid.uuid4(), issued_at=0, expires_at=1),
        user_info=user_info,
    )


@pytest.fixture
def isolated_management(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[AsyncMock]:
    """
        替换身份、业务服务和数据库依赖，记录参数错误时是否错误地调用了业务服务。

    :param monkeypatch: 测试结束时恢复业务服务、验证码验证与拒绝审计替身的夹具。
    :yield: 供所有管理服务共用的调用记录对象，退出时清理全部依赖替换。
    """
    service = AsyncMock()
    context = management_context()
    monkeypatch.setattr(captcha, "get_redis", lambda _request: object())
    monkeypatch.setattr(captcha_service, "verify_captcha", AsyncMock())
    monkeypatch.setattr(
        "app.dependencies.permission.AuditService.audit_denied", AsyncMock())

    override_management(context)
    app.dependency_overrides[get_postgres_session] = lambda: object()
    monkeypatch.setattr(role_api_module, "role_service", service)
    monkeypatch.setattr(user_api_module, "user_service", service)
    try:
        yield service
    finally:
        app.dependency_overrides.clear()


def test_public_route_metadata_has_no_path_parameters_and_get_names_are_explicit() -> None:
    """
        检查完整 OpenAPI，防止新增接口重新引入路径 ID、非 GET/POST 方法或模糊查询名称。

    :return: 无返回值；所有业务接口均满足统一方法和参数位置约定。
    """
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/api/v1/"):
            continue
        assert "{" not in path
        assert set(operations) <= {"get", "post"}
        for method, operation in operations.items():
            assert all(parameter["in"] != "path" for parameter in operation.get(
                "parameters", []))
            if method == "get":
                assert path == "/api/v1/me/user_info" or path.endswith(("/list", "/detail"))
                assert "requestBody" not in operation

    schemas = app.openapi()["components"]["schemas"]
    for suffix, field, _body in TARGET_WRITES:
        operation = app.openapi()["paths"]["/api/v1" + suffix]["post"]
        body_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        schema = schemas[body_ref.rsplit("/", 1)[-1]]
        assert field in schema["required"]
        prefix = "R" if field == "role_id" else "U"
        assert schema["properties"][field]["pattern"] == rf"^{prefix}[A-Z0-9]{{14}}$"
        assert schema["additionalProperties"] is False
        assert not any(
            parameter["name"] == field for parameter in operation.get("parameters", []))


def test_all_business_routes_live_in_five_business_modules_without_duplicates() -> None:
    """
        检查合并后的真实路由，确保认证、本人账户、用户、角色、权限五个业务组未丢失接口。

    :return: 无返回值；模块归属、路由函数名和方法路径组合均完整且唯一。
    """
    routes = [context.route for context in iter_route_contexts(app.router.routes)
              if context.path and context.path.startswith("/api/v1/") and isinstance(context.route, APIRoute)]
    assert {route.endpoint.__module__.rsplit(".", 1)[-1] for route in routes} == {
        "auth", "me", "users", "roles", "permissions",
    }
    route_names = [route.name for route in routes]
    assert len(route_names) == len(set(route_names))
    assert all(route.name == route.endpoint.__name__ for route in routes)
    assert all(route.operation_id is None for route in routes)
    combinations = [(context.path, method) for context in iter_route_contexts(app.router.routes)
                    if context.path and context.path.startswith("/api/v1/") and isinstance(context.route, APIRoute)
                    for method in context.route.methods or set()]
    assert len(combinations) == len(set(combinations))
    for module, expected_names in EXPECTED_ROUTE_NAMES_BY_MODULE.items():
        assert {route.name for route in routes
                if route.endpoint.__module__.rsplit(".", 1)[-1] == module} == expected_names


def test_business_route_descriptions_separate_access_and_exact_permission() -> None:
    """
        检查接口文档把访问条件和精确权限分行展示，避免初学者把登录状态误当成业务权限。

    :return: 无返回值；28 个业务接口的文档标题和权限键均与公开操作登记一致。
    """
    routes = [context.route for context in iter_route_contexts(app.router.routes)
              if context.path and context.path.startswith("/api/v1/") and isinstance(context.route, APIRoute)]
    assert {route.name for route in routes} == set(
        EXPECTED_PERMISSION_BY_ROUTE_NAME)
    for route in routes:
        route_name = route.name
        # FastAPI 会把函数 docstring 写入 OpenAPI description，因此直接校验最终路由描述。
        description_lines = [line.strip()
                             for line in route.description.splitlines()]
        access_lines = [
            line for line in description_lines if line.startswith("访问条件：")]
        permission_lines = [
            line for line in description_lines if line.startswith("所需权限：")]
        assert len(access_lines) == 1, route_name
        assert len(permission_lines) == 1, route_name
        assert "所需权限：" not in access_lines[0]

        expected_permission = EXPECTED_PERMISSION_BY_ROUTE_NAME[route_name]
        if expected_permission is None:
            assert permission_lines[0] == "所需权限：无管理权限要求。", route_name
        else:
            assert permission_lines[0].startswith((
                f"所需权限：{expected_permission}（",
                f"所需权限：{expected_permission}，",
            )), route_name


@pytest.mark.parametrize(("path", "method", "source", "message"), [
    ("/api/v1/orders/{order_id}", "GET", "query",
     "must not contain path parameters"),
    ("/api/v1/orders/detail", "GET", "body",
     "use query parameters instead of a request body"),
    ("/api/v1/orders/delete", "POST", "query",
     "in a JSON request body, not query parameters"),
    ("/api/v1/orders/delete", "POST", "dependency",
     "in a JSON request body, not query parameters"),
])
def test_startup_rejects_wrong_route_or_parameter_placement(path: str, method: str, source: str, message: str) -> None:
    """
        新业务接入时在启动检查中发现路由或参数位置错误，包含藏在依赖里的查询 ID。

    :param path: 故意违反统一约定的测试业务路径。
    :param method: 查询或写入请求方法。
    :param source: 目标参数位于查询、请求体或依赖的查询参数中。
    :param message: 启动检查应返回的可操作错误说明。
    :return: 无返回值；错误接线在连接外部资源之前被拒绝。
    """
    def query_target(order_id: uuid.UUID) -> None:
        """
            定义从查询参数或路径中读取目标的测试业务入口。

        :param order_id: 模拟接线错误的订单目标 ID。
        :return: 无返回值；测试只读取依赖声明，不执行入口。
        """

    def body_target(payload: Annotated[dict[str, str], Body()]) -> None:
        """
            定义从请求体读取数据的测试入口，用来检查 GET 请求禁止 body。

        :param payload: 模拟错误用于 GET 请求的 JSON 数据。
        :return: 无返回值；测试只检查入口声明。
        """

    def dependency_target(_target: None = Depends(query_target)) -> None:
        """
            把目标字段藏入子依赖，验证检查覆盖整个依赖树。

        :param _target: 读取查询目标的子依赖，不实际执行。
        :return: 无返回值；测试只检查入口声明。
        """

    handlers: dict[str, Callable[..., None]] = {
        "query": query_target, "body": body_target, "dependency": dependency_target,
    }
    handler = handlers[source]
    application = FastAPI()
    application.add_api_route(
        path,
        handler,
        methods=[method],
        dependencies=[Depends(get_current_user)],
    )
    with pytest.raises(ValueError, match=message):
        validate_v1_api_routes(application)


@pytest.mark.parametrize(("suffix", "field", "body"), TARGET_WRITES)
@pytest.mark.parametrize("invalid_id", [None, "not-a-uuid"])
async def test_post_target_must_be_valid_json_field(suffix: str, field: str, body: dict[str, Any],
                                                    invalid_id: str | None, isolated_management: AsyncMock) -> None:
    """
        即使查询参数提供合法 ID，JSON 缺少目标或目标格式错误也必须拒绝且不得执行业务。

    :param suffix: 被验证管理操作的固定路径。
    :param field: 此操作必填的 JSON 目标字段名。
    :param body: 其余必填业务字段的合法数据。
    :param invalid_id: 缺少目标时为 None，否则为不合法的 UUID 文本。
    :param isolated_management: 隔离业务服务及调用记录。
    :return: 无返回值；接口返回标准 422 且未进入业务服务。
    """
    payload = dict(body)
    if invalid_id is not None:
        payload[field] = invalid_id
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1" + suffix, params={field: str(uuid.uuid4())}, json=payload)
    assert response.status_code == 422, response.text
    assert response.json()["code"] == 42201
    assert isolated_management.mock_calls == []


@pytest.mark.parametrize(("resource", "field"), DETAIL_READS)
@pytest.mark.parametrize("query", [{}, {"target": "not-a-uuid"},
                                   {"target": "X" + "A" * 14}, {"target": "U" + "A" * 14 + "\n"}])
async def test_get_target_requires_query_parameter(resource: str, field: str, query: dict[str, str],
                                                   isolated_management: AsyncMock) -> None:
    """
        详情与会话查询只从查询参数读取目标，JSON 不能替代缺失或无效的查询参数。

    :param resource: 带有目标 ID 的用户、角色、权限或会话查询路径。
    :param field: 该详情操作要求的查询参数名。
    :param query: 缺少目标或格式错误的查询参数样本。
    :param isolated_management: 不应被无效查询调用的业务服务替身。
    :return: 无返回值；接口返回标准 422，业务查询未执行。
    """
    params = {field: query["target"]} if query else {}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request("GET", f"/api/v1/{resource}", params=params,
                                        json={field: str(uuid.uuid4())})
    assert response.status_code == 422, response.text
    assert response.json()["code"] == 42201
    assert isolated_management.mock_calls == []


async def test_post_uses_json_target_when_query_names_conflict(isolated_management: AsyncMock) -> None:
    """
        通过实际禁用用户接口验证同名查询参数不能替换 JSON 中的目标用户。

    :param isolated_management: 返回固定用户快照并记录实际目标的业务服务替身。
    :return: 无返回值；服务收到 JSON 目标，而非额外查询参数中的另一个用户。
    """
    target_id = new_entity_id("U")
    isolated_management.update_user_status.return_value = UserResponse(
        user_id=target_id, user_name="normal_user", is_active=False, bound_role_ids=(), effective_role_ids=(),
        role_level=0, effective_permissions=(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/users/disable", params={"user_id": new_entity_id("U")},
                                     json={"user_id": str(target_id)})
    assert response.status_code == 200, response.text
    assert isolated_management.update_user_status.await_args.kwargs[
        "target_user_id"] == target_id


async def test_moving_id_to_body_does_not_bypass_permission_gate(
    override_management: Callable[[AuthorizationContext], None],
    isolated_management: AsyncMock,
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    """
        使用普通用户身份提交合法 JSON，证明参数位置改变没有放松管理权限校验。

    :param isolated_management: 记录业务操作是否被拒绝请求错误调用的替身。
    :param unprivileged_authorization_context: 已登录但没有管理能力的真实权限快照。
    :return: 无返回值；各管理写入均为 403，服务没有执行任何操作。
    """
    override_management(unprivileged_authorization_context)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for suffix, field, body in TARGET_WRITES:
            prefix = "R" if field == "role_id" else "U"
            response = await client.post("/api/v1" + suffix, json={field: new_entity_id(prefix), **body})
            assert response.status_code == 403, (suffix, response.text)
            assert response.json()["code"] == 40301
    assert isolated_management.mock_calls == []


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/api/v1/roles"), ("GET", "/api/v1/users"), ("GET", "/api/v1/permissions"),
    ("GET", f"/api/v1/roles/{uuid.uuid4()}"), ("POST",
                                               f"/api/v1/users/{uuid.uuid4()}/disable"),
    ("POST", f"/api/v1/roles/{uuid.uuid4()}/permissions/bind"),
])
async def test_legacy_path_aliases_are_not_registered(method: str, path: str) -> None:
    """
        请求旧路径应明确返回不存在，防止新旧两套路由长期混用。

    :param method: 旧接口使用的请求方法。
    :param path: 已移除的集合根路径或包含目标 ID 的路径。
    :return: 无返回值；旧路径返回统一 404 响应。
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path)
    assert response.status_code == 404
    assert response.json()["code"] == 40401
