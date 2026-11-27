#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    公开接口路由、响应格式及异常响应的离线契约测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        异常响应测试引用独立异常处理模块
# 2026/09/26    XTN       V1.001        对齐注册状态查询的简洁操作 ID
# 2026/09/29    XTN       V2.000        禁用公开 OpenAPI 入口并保留离线成功响应 schema 校验
# 2026/09/29    XTN       V2.001        断言默认健康入口为 404，成功响应使用临时测试路由
# 2026/09/30    XTN       V2.002        移除临时密码业务码断言
# 2026/09/30    XTN       V2.003        同步管理员会话查询与全部退出路由契约
# 2026/10/02    XTN       V2.004        登录失败通过通用业务异常处理器保持 401 契约
# 2026/10/02    XTN       V2.005        非错误 HTTP 状态的异常统一归为内部错误
# 2026/10/09    XTN       V2.006        对齐用户限流新名称，按真实依赖链验证当前登录退出
# 2026/10/09    XTN       V2.007        当前登录退出测试在统一限流模块替换计数边界
# 2026/10/09    XTN       V2.008        公开响应模型及泛型 Schema 引用统一使用 Response 后缀
# 2026/10/10    XTN       V2.009        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V2.010        当前登录退出只委托登录声明和版本，不传配置
# 2026/10/15    XTN       V2.011        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V2.012        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V2.013        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/19    XTN       V2.014        路由直接使用共享业务服务，测试替换对应模块实例
# 2026/10/20    XTN       V2.015        同步登录会话检查与删除入口，保留原有行为断言
# 2026/10/22    XTN       V2.016        权限测试保留真实检查，移除管理准备层替换
# 2026/10/24    XTN       V2.017        验证用户列表四项筛选透传、默认范围及格式错误
# 2026/10/24    XTN       V2.018        同步用户展示信息读取函数名称
# 2026/10/24    XTN       V2.019        用户列表契约替换统一使用 list_users 入口
# 2026/10/24    XTN       V2.020        用户角色写入测试使用绑定及解绑权限新名称
# 2026/10/24    XTN       V2.021        用户角色操作响应及 OpenAPI 使用 UserRoleResponse 名称
# 2026/10/24    XTN       V2.022        角色删除响应替身使用 delete_role 入口
# 2026/10/24    XTN       V2.023        管理用户资料查询替身使用 get_users_info 入口
# 2026/10/26    XTN       V2.024        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V2.025        验证角色列表六项筛选转发、默认值和输入边界
# 2026/11/26    XTN       V2.026        空角色列表对齐仓储约定并直接替换登录记录仓储
# 2026/11/27    XTN       V2.027        登录失败的双语提示给出操作指引并保持统一错误结构
# 2026/11/27    XTN       V2.028        登录失败求助文案改为联系平台
# 2026/11/27    XTN       V2.029        登录失败提示不再假设用户忘记密码
# --------------------------------------------------------------------------------------------------

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from httpx import ASGITransport, AsyncClient, Response
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

import app.api.v1.endpoints.auth as session_api_module
import app.api.v1.endpoints.roles as role_api_module
import app.api.v1.endpoints.users as user_api_module
import app.dependencies.auth as auth_dependencies
import app.dependencies.rate_limit as rate_limit_dependencies
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.codes import BusinessCode
from app.core.exception_handlers import (
    handle_access_error,
    handle_database_unavailable,
    handle_http_error,
    handle_rate_limit_exceeded,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.core.exceptions import (
    AppError,
    InvalidLoginCredentialsError,
    conflict_409,
    forbidden_403,
    invalid_request_400,
    not_found_404,
    stale_resource_version_409,
    unauthenticated_401,
    unavailable_503,
)
from app.core.ids import new_entity_id
from app.core.rate_limit.limiter import RateLimitExceeded, RateLimitResult
from app.core.response import ApiResponse, PageResponse
from app.db.postgres_db import get_postgres_session
from app.main import app
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import user_repository
from app.repositories.redis.login_session_repository import login_session_repository
from app.schemas.role import RoleMutationResponse, RoleResponse
from app.schemas.user import UserResponse, UserRoleResponse

REQUIRED_ROUTES = {
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/users/sessions/list"),
    ("POST", "/api/v1/users/sessions/logout-all"),
    ("GET", '/api/v1/permissions/list'),
    ("GET", "/api/v1/permissions/detail"),
    ("GET", '/api/v1/roles/list'),
    ("GET", "/api/v1/roles/detail"),
    ("POST", '/api/v1/roles/create'),
    ("POST", "/api/v1/roles/update"),
    ("POST", "/api/v1/roles/disable"),
    ("POST", "/api/v1/roles/enable"),
    ("POST", "/api/v1/roles/delete"),
    ("POST", "/api/v1/roles/permissions/bind"),
    ("POST", "/api/v1/roles/permissions/unbind"),
    ("POST", "/api/v1/users/roles/bind"),
    ("POST", "/api/v1/users/roles/unbind"),
}
ROLE_MUTATION_PATHS = {
    "/api/v1/roles/update",
    "/api/v1/roles/disable",
    "/api/v1/roles/enable",
    "/api/v1/roles/delete",
    "/api/v1/roles/permissions/bind",
    "/api/v1/roles/permissions/unbind",
}


def _public_operations() -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (method.upper(), path, operation)
        for path, path_item in app.openapi()["paths"].items()
        if path.startswith("/api/v1")
        for method, operation in path_item.items()
        if method
        in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    ]


def assert_standard_response(response: Response, *, status_code: int, business_code: BusinessCode) -> dict[str, Any]:
    assert response.status_code == status_code
    body: dict[str, Any] = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert type(body["code"]) is int
    assert body["code"] == int(business_code)
    assert body["code"] // 100 == status_code
    request_id = uuid.UUID(body["request_id"])
    assert request_id.version == 4
    assert response.headers["X-Request-ID"] == body["request_id"]
    return body


def test_public_contract_contains_required_routes_and_only_get_or_post() -> None:
    actual = {(method, path)
              for method, path, _operation in _public_operations()}

    assert REQUIRED_ROUTES <= actual
    assert {method for method, _path in actual} <= {"GET", "POST"}


async def test_user_list_filters_normalize_validate_and_reach_the_repository(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="user-reader",
                level=1,
                permissions=frozenset({PermissionKey.USERS_READ.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )
    target_user_id = new_entity_id("U")
    received_filters: list[dict[str, Any]] = []

    async def current_session() -> object:
        return object()

    async def list_users_page(*_args: Any, **kwargs: Any) -> tuple[tuple[Any, ...], int]:
        received_filters.append(kwargs)
        return (), 0

    async def load_access_views(*_args: Any, **_kwargs: Any) -> dict[Any, Any]:
        return {}

    monkeypatch.setattr(
        user_repository,
        "list_users",
        list_users_page,
    )
    monkeypatch.setattr(
        user_repository,
        "get_users_info",
        load_access_views,
    )
    override_management(context)
    app.dependency_overrides[get_postgres_session] = current_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            normalized = await client.get(
                '/api/v1/users/list',
                params={
                    "user_id": target_user_id,
                    "user_name": "  Alice_1  ",
                    "is_active": "false",
                    "is_deleted": "true",
                    "page": 2,
                    "page_size": 7,
                },
            )
            defaults = await client.get('/api/v1/users/list')
            invalid_responses = [
                await client.get('/api/v1/users/list', params=parameters)
                for parameters in (
                    {"user_name": "  Alice-1  "},
                    {"user_id": "not-a-user-id"},
                    {"is_active": "disabled"},
                    {"is_deleted": "all"},
                )
            ]
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        normalized,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert normalized.json()["data"] == {
        "items": [],
        "page": 2,
        "page_size": 7,
        "total": 0,
    }
    assert_standard_response(
        defaults,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert defaults.json()["data"] == {"items": [], "page": 1, "page_size": 20, "total": 0}
    assert received_filters == [
        {
            "current_user": context.user_info,
            "page": 2,
            "page_size": 7,
            "user_id": target_user_id,
            "user_name": "Alice_1",
            "is_active": False,
            "is_deleted": True,
        },
        {
            "current_user": context.user_info,
            "page": 1,
            "page_size": 20,
            "user_id": None,
            "user_name": None,
            "is_active": None,
            "is_deleted": False,
        },
    ]
    for invalid in invalid_responses:
        assert_standard_response(
            invalid,
            status_code=422,
            business_code=BusinessCode.VALIDATION_FAILED,
        )


async def test_role_list_filters_validate_and_reach_the_repository(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        使用真实路由和服务验证角色列表六项筛选、默认状态、长度与格式边界。

    :return: 无返回值；有效筛选原样传给仓储，无效请求返回统一 422 且不查询角色。
    """
    user_id = new_entity_id("U")
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id, token_version=0, token_id=uuid.uuid4(), issued_at=0, expires_at=1,
        ),
        user_info=UserInfo.build(
            user_id=user_id, user_is_active=True, user_is_protected=False,
            roles=(RoleGrant(
                role_id=new_entity_id("R"), key="role-reader", level=500,
                permissions=frozenset({PermissionKey.ROLES_READ.value}),
                is_system=False, is_protected=False, is_super_admin=False,
            ),),
        ),
    )
    target_role_id = new_entity_id("R")
    session = object()

    async def current_session() -> object:
        return session

    list_roles = AsyncMock(return_value=((), 0))
    load_permissions = AsyncMock()
    monkeypatch.setattr(role_repository, "list_roles", list_roles)
    monkeypatch.setattr(role_repository, "get_role_permissions", load_permissions)
    override_management(context)
    app.dependency_overrides[get_postgres_session] = current_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            selected = await client.get('/api/v1/roles/list', params={
                "role_id": target_role_id, "key": " Exact key ", "name": " 100%_ ",
                "is_active": "false", "is_system": "false", "is_deleted": "true",
                "page": 2, "page_size": 7,
            })
            defaults = await client.get('/api/v1/roles/list')
            boundaries = await client.get('/api/v1/roles/list', params={
                "key": "k" * 80, "name": "名" * 160, "is_active": "true", "is_system": "true",
            })
            invalid_responses = [
                await client.get('/api/v1/roles/list', params=parameters)
                for parameters in (
                    {"role_id": "not-a-role-id"}, {"role_id": user_id},
                    {"key": ""}, {"key": "k" * 81}, {"name": ""}, {"name": "名" * 161},
                    {"is_active": "disabled"}, {"is_system": "custom"}, {"is_deleted": "all"},
                    {"page": 0}, {"page_size": 0}, {"page_size": 201},
                )
            ]
    finally:
        app.dependency_overrides.clear()

    for response in (selected, defaults, boundaries):
        assert_standard_response(response, status_code=200, business_code=BusinessCode.OK)
    assert selected.json()["data"] == {"items": [], "page": 2, "page_size": 7, "total": 0}
    assert defaults.json()["data"] == {"items": [], "page": 1, "page_size": 20, "total": 0}
    assert [call.args for call in list_roles.await_args_list] == [(session,)] * 3
    assert [call.kwargs for call in list_roles.await_args_list] == [
        {"current_user": context.user_info, "page": 2, "page_size": 7, "role_id": target_role_id,
         "key": " Exact key ", "name": " 100%_ ", "is_active": False, "is_system": False, "is_deleted": True},
        {"current_user": context.user_info, "page": 1, "page_size": 20, "role_id": None,
         "key": None, "name": None, "is_active": None, "is_system": None, "is_deleted": False},
        {"current_user": context.user_info, "page": 1, "page_size": 20, "role_id": None,
         "key": "k" * 80, "name": "名" * 160, "is_active": True, "is_system": True, "is_deleted": False},
    ]
    # 空列表会传给权限仓储；空集合由仓储直接返回，不执行权限 SQL。
    assert [call.args for call in load_permissions.await_args_list] == [(session,)] * 3
    assert [call.kwargs for call in load_permissions.await_args_list] == [{"roles": ()}] * 3
    for invalid in invalid_responses:
        assert_standard_response(invalid, status_code=422, business_code=BusinessCode.VALIDATION_FAILED)


async def test_admin_session_revocation_uses_authoritative_context(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    target_id = new_entity_id("U")
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=3,
            token_id=uuid.uuid4(),
            issued_at=1,
            expires_at=2,
        ),
        user_info=UserInfo.build(
            user_id=user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=3,
            roles=(
                RoleGrant(
                    role_id=new_entity_id("R"),
                    key="session_manager",
                    level=100,
                    permissions=frozenset(
                        {PermissionKey.USERS_SESSIONS_REVOKE.value}),
                    is_system=False,
                    is_protected=False,
                    is_super_admin=False,
                ),
            ),
        ),
    )
    revoke_all = AsyncMock()

    class RevocationService:
        revoke_user_sessions = revoke_all

    override_management(context)
    monkeypatch.setattr(user_api_module, "user_service", RevocationService())
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post('/api/v1/users/sessions/logout-all', json={"user_id": str(target_id)})
    finally:
        app.dependency_overrides.clear()

    body = assert_standard_response(
        response,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert body["data"] is None
    assert revoke_all.await_count == 1
    awaited_call = revoke_all.await_args
    assert awaited_call is not None
    assert awaited_call.kwargs["context"] is context
    assert awaited_call.kwargs["target_user_id"] == target_id


def test_public_contract_does_not_name_the_authorization_implementation() -> None:
    assert "rbac" not in app.title.casefold()

    for _method, path, operation in _public_operations():
        public_metadata = " ".join(
            [
                path,
                operation.get("operationId", ""),
                *(str(tag) for tag in operation.get("tags", [])),
            ]
        )
        assert "rbac" not in public_metadata.casefold()

    public_errors = [
        unauthenticated_401("test"),
        not_found_404("test"),
        forbidden_403("test"),
        conflict_409("test"),
        unavailable_503("test"),
        invalid_request_400("test"),
        stale_resource_version_409("test"),
    ]
    assert all(
        "rbac" not in error.message_key.value.casefold() for error in public_errors
    )

    semantic_error = invalid_request_400("test")
    assert semantic_error.status_code == 400
    assert semantic_error.business_code == BusinessCode.BAD_REQUEST


def test_removed_capabilities_are_not_seeded_or_exposed() -> None:
    assert "super_admin:transfer" not in {
        permission.value for permission in PermissionKey
    }
    assert "roles:delegation:update" not in {
        permission.value for permission in PermissionKey
    }
    paths = app.openapi()["paths"]
    assert "/api/v1/system/super-admin/transfer" not in paths
    assert not any("delegable-permissions" in path for path in paths)


def test_public_response_schemas_include_management_state() -> None:
    schemas = app.openapi()["components"]["schemas"]
    assert "authorization_epoch" not in schemas["UserAccessResponse"]["properties"]

    response_schema = schemas["ApiResponse_PageResponse_RoleResponse__"]
    assert response_schema["additionalProperties"] is False
    assert set(response_schema["properties"]) == {
        "code",
        "message",
        "data",
        "request_id",
    }
    page_schema = schemas["PageResponse_RoleResponse_"]
    assert page_schema["additionalProperties"] is False
    assert set(page_schema["properties"]) == {
        "items",
        "page",
        "page_size",
        "total",
    }
    assert "id" in schemas["PermissionResponse"]["properties"]
    assert {
        "description",
        "deleted_at",
    } <= schemas["RoleResponse"]["properties"].keys()
    assert "is_super_admin" not in schemas["RoleResponse"]["properties"]
    assert set(schemas["RoleMutationResponse"]["properties"]) == {"role"}
    assert set(schemas["UserRoleResponse"]["properties"]) == {"user"}
    assert "OperationResponse" not in schemas
    assert "PasswordMutationResponse" not in schemas
    assert "permissions" not in schemas["RoleCreateRequest"]["properties"]
    assert "expected_version" in schemas["RoleUpdateRequest"]["required"]
    assert "expected_version" in schemas["RoleVersionRequest"]["required"]
    assert "expected_version" in schemas["RolePermissionIdsRequest"]["required"]
    role_update_schema = schemas["RoleUpdateRequest"]
    assert role_update_schema["anyOf"] == [
        {"required": ["name"]},
        {"required": ["description"]},
    ]
    assert role_update_schema["properties"]["name"]["type"] == "string"
    assert role_update_schema["properties"]["description"]["type"] == "string"

    role_list_responses = app.openapi(
    )["paths"]["/api/v1/roles/list"]["get"]["responses"]
    assert role_list_responses["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ApiResponse_PageResponse_RoleResponse__"
    }
    assert "/api/v1/system/super-admin/transfer" not in app.openapi()["paths"]
    assert "/api/v1/auth/logout-all" not in app.openapi()["paths"]
    assert "/api/v1/me/sessions/list" not in app.openapi()["paths"]
    assert "/api/v1/users/sessions/revoke" not in app.openapi()["paths"]
    assert not any(
        "delegable-permissions" in path for path in app.openapi()["paths"])


def test_openapi_schema_remains_available_for_offline_contract_checks() -> None:
    schema = app.openapi()

    assert schema["openapi"]
    assert "/api/v1/roles/list" in schema["paths"]
    assert "ApiResponse_PageResponse_RoleResponse__" in schema["components"]["schemas"]


@pytest.mark.parametrize(
    "path",
    ["/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"],
)
async def test_public_openapi_and_documentation_routes_are_disabled(path: str) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(path)

    assert_standard_response(
        response,
        status_code=404,
        business_code=BusinessCode.NOT_FOUND,
    )


@pytest.mark.parametrize("path", ["/health/live", "/health/ready"])
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_default_health_routes_are_not_registered(path: str, method: str) -> None:
    """
        验证默认应用完全移除健康入口，读取和提交均返回统一不存在响应。

    :param path: 已从默认应用移除的健康入口路径。
    :param method: 用于检查是否仍有路由残留的 HTTP 方法。
    :return: 无返回值；两个健康路径必须返回统一 404 响应。
    """
    assert path not in app.openapi()["paths"]
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.request(method, path)

    assert_standard_response(
        response,
        status_code=404,
        business_code=BusinessCode.NOT_FOUND,
    )


async def test_current_token_logout_revokes_without_quota_or_database_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        通过真实退出路由确认有效登录可以直接退出，不限流也不查询 PostgreSQL。

    :param monkeypatch: 替换身份和撤销边界，禁止限流或数据库访问。
    :return: 无返回值；只撤销当前登录，未进入限流或数据库。
    """
    events: list[str] = []
    current_login_info = LoginInfo(
        user_id=new_entity_id("U"),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )

    async def revoke(*_args: object, **_kwargs: object) -> None:
        """
            记录当前登录撤销发生的时机。

        :param _args: 撤销入口的位置参数。
        :param _kwargs: 当前 Token 及会话版本参数。
        :return: 无返回值；本次撤销已记入执行顺序。
        """
        assert set(_kwargs) == {"token_info", "user_token_version"}
        events.append("revoke_jti")

    # 只替换已验证身份和删除边界；实际路由不得再执行任何限流。
    monkeypatch.setitem(app.dependency_overrides, auth_dependencies.check_token,
                        lambda: current_login_info)
    quota_check = AsyncMock(side_effect=AssertionError("logout must not check quotas"))
    monkeypatch.setattr(rate_limit_dependencies, "_check_quota", quota_check)
    database_factory = AsyncMock(side_effect=AssertionError(
        "logout must not query PostgreSQL"))
    monkeypatch.setattr(auth_dependencies, "SessionFactory", database_factory)
    monkeypatch.setattr(login_session_repository, "delete_login_session", revoke)
    monkeypatch.setattr(session_api_module, "get_redis",
                        lambda _request: object())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/auth/logout")

    assert_standard_response(response, status_code=200,
                             business_code=BusinessCode.OK)
    assert response.json()["data"] is None
    assert events == ["revoke_jti"]
    quota_check.assert_not_awaited()
    database_factory.assert_not_called()


def test_response_models_reject_coercion_and_extra_fields() -> None:
    request_id = str(uuid.uuid4())
    valid = {
        "code": 20000,
        "message": "ok",
        "data": None,
        "request_id": request_id,
    }

    assert ApiResponse[dict[str, object]].model_validate(valid).code == 20000
    with pytest.raises(ValidationError):
        ApiResponse[dict[str, object]].model_validate(
            {**valid, "code": "20000"})
    with pytest.raises(ValidationError):
        ApiResponse[dict[str, object]].model_validate(
            {**valid, "code": 200000})
    with pytest.raises(ValidationError):
        ApiResponse[dict[str, object]].model_validate({**valid, "extra": True})
    with pytest.raises(ValidationError):
        PageResponse[int].model_validate(
            {"items": [], "page": 1, "page_size": 20, "total": 0, "extra": True}
        )


def test_role_mutations_document_expected_version_in_the_body() -> None:
    paths = app.openapi()["paths"]

    for path in ROLE_MUTATION_PATHS:
        operation = paths[path]["post"]
        assert not any(
            parameter["name"].casefold() == "if-match"
            for parameter in operation.get("parameters", [])
        )
        assert operation["requestBody"]["required"] is True


def test_numeric_business_codes_match_their_http_prefix() -> None:
    values = [int(code) for code in BusinessCode]

    assert len(values) == len(set(values))
    assert all(10000 <= value <= 59999 for value in values)
    assert int(BusinessCode.ROLE_VERSION_STALE) == 40931
    assert int(BusinessCode.INVALID_AUTHENTICATION) == 40110
    assert int(BusinessCode.USER_ROLE_SELECTION_INVALID) == 40020
    assert int(BusinessCode.USER_CREATE_CONFLICT) == 40920
    assert int(BusinessCode.PERMISSION_SELECTION_INVALID) == 40040
    assert int(BusinessCode.CAPTCHA_INVALID) == 40050
    assert int(BusinessCode.ROLE_KEY_CONFLICT) % 100 == 30


def test_business_error_helpers_use_the_requested_business_group() -> None:
    """
        通用错误保留通用码，明确的用户、角色和权限错误使用对应业务号段。

    :return: 无返回值；业务码的 HTTP 前缀和后两位分组必须保持稳定。
    """
    cases = (
        (invalid_request_400("generic"), BusinessCode.BAD_REQUEST),
        (invalid_request_400("permission", business_code=BusinessCode.PERMISSION_SELECTION_INVALID),
         BusinessCode.PERMISSION_SELECTION_INVALID),
        (conflict_409("user", business_code=BusinessCode.USER_CREATE_CONFLICT),
         BusinessCode.USER_CREATE_CONFLICT),
        (conflict_409("role", business_code=BusinessCode.ROLE_KEY_CONFLICT),
         BusinessCode.ROLE_KEY_CONFLICT),
        (stale_resource_version_409("role_version"),
         BusinessCode.ROLE_VERSION_STALE),
    )
    for error, expected in cases:
        assert error.business_code == expected
        assert int(error.business_code) // 100 == error.status_code


async def test_success_uses_server_request_id_in_body_and_header(success_app: FastAPI) -> None:
    """
        验证成功响应的正文和响应头共享服务端生成的请求 ID。

    :param success_app: 临时注册成功路由并保留真实中间件的应用。
    :return: 无返回值；统一成功响应不得使用调用方指定的请求 ID。
    """
    transport = ASGITransport(app=success_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/controlled-test/success",
            headers={"X-Request-ID": "caller-controlled"},
        )

    body = assert_standard_response(
        response,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert body["request_id"] != "caller-controlled"
    assert body["data"] == {"status": "ok"}


async def test_framework_404_and_405_use_the_standard_envelope() -> None:
    """
        验证未知路径和现有业务路由的错误方法均使用统一错误响应。

    :return: 无返回值；框架 404 和 405 必须保留对应业务码及请求 ID。
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.get("/not-present")
        wrong_method = await client.post("/api/v1/me/user_info")

    assert_standard_response(
        missing,
        status_code=404,
        business_code=BusinessCode.NOT_FOUND,
    )
    assert_standard_response(
        wrong_method,
        status_code=405,
        business_code=BusinessCode.METHOD_NOT_ALLOWED,
    )


async def test_uncommon_framework_error_preserves_its_real_http_status() -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/controlled-test",
            "headers": [],
        }
    )

    response = await handle_http_error(
        request,
        StarletteHTTPException(status_code=418),
    )

    assert response.status_code == 418
    body = json.loads(bytes(response.body))
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == 41801
    assert body["code"] // 100 == response.status_code
    assert response.headers["X-Request-ID"] == body["request_id"]


@pytest.mark.parametrize("status_code", [200, 700])
async def test_non_error_framework_status_uses_internal_error(status_code: int) -> None:
    """
        异常携带非 4xx/5xx 状态时返回统一 500，不伪装成成功响应。

    :param status_code: 注入异常的非法或非错误 HTTP 状态。
    :return: 无返回值；断言响应状态、业务码和请求 ID。
    """
    request = Request(
        {"type": "http", "method": "GET", "path": "/controlled-test", "headers": []}
    )

    response = await handle_http_error(
        request,
        StarletteHTTPException(status_code=status_code),
    )

    assert response.status_code == 500
    body = json.loads(bytes(response.body))
    assert body["code"] == int(BusinessCode.INTERNAL_ERROR)
    assert response.headers["X-Request-ID"] == body["request_id"]


@pytest.mark.parametrize(
    ("status_code", "business_code"),
    [
        (401, BusinessCode.INVALID_AUTHENTICATION),
        (500, BusinessCode.INTERNAL_ERROR),
    ],
)
async def test_framework_error_uses_registered_contract(status_code: int, business_code: BusinessCode) -> None:
    request = Request(
        {"type": "http", "method": "GET", "path": "/controlled-test", "headers": []}
    )

    response = await handle_http_error(
        request,
        StarletteHTTPException(status_code=status_code),
    )

    assert response.status_code == status_code
    body = json.loads(bytes(response.body))
    assert body["code"] == int(business_code)
    assert body["code"] // 100 == status_code
    if status_code == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_database_operational_error_is_dependency_unavailable() -> None:
    request = Request(
        {"type": "http", "method": "GET", "path": "/controlled-test", "headers": []}
    )
    error = OperationalError(
        "controlled statement", {}, RuntimeError("offline"), connection_invalidated=True
    )

    response = await handle_database_unavailable(request, error)

    assert response.status_code == 503
    body = json.loads(bytes(response.body))
    assert body["code"] == int(BusinessCode.SERVICE_UNAVAILABLE)
    assert "controlled statement" not in str(body)
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert response.headers["Cache-Control"] == "no-store"


async def test_semantic_rate_limit_exposes_deciding_result_not_bucket_identity() -> (None):
    request = Request(
        {"type": "http", "method": "POST", "path": "/api/v1/login", "headers": []}
    )
    error = RateLimitExceeded(
        policy_name="login_pair",
        result=RateLimitResult(
            allowed=False,
            limit=5,
            remaining=0,
            retry_after_ms=1_001,
            reset_after_ms=900_000,
        ),
    )

    response = await handle_rate_limit_exceeded(request, error)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "2"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["RateLimit-Limit"] == "5"
    assert response.headers["RateLimit-Remaining"] == "0"
    assert response.headers["RateLimit-Reset"] == "900"
    assert "login_pair" not in str(response.headers).casefold()


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (
            handle_request_validation_error,
            RequestValidationError([]),
        ),
        (handle_http_error, StarletteHTTPException(status_code=400)),
        (handle_unexpected_error, RuntimeError("controlled failure")),
    ],
)
async def test_global_error_handlers_prevent_sensitive_response_caching(handler: Any, error: BaseException) -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [],
        }
    )

    response = await handler(request, error)

    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("locale,expected_message", [
    (None, "登录失败，请核对登录信息后重试；如仍无法登录，请联系平台。"),
    ("zh-CN", "登录失败，请核对登录信息后重试；如仍无法登录，请联系平台。"),
    ("en", "Unable to sign in. Check your login details and try again. "
     "If you still cannot sign in, contact platform support."),
])
async def test_invalid_login_credentials_use_one_non_leaking_contract(locale: str | None,
                                                                      expected_message: str) -> None:
    """
        验证登录失败走通用业务异常处理器，且不泄露账号存在与否。

    :return: 无返回值；检查中英文指引、统一结构及必要响应头，不公开内部原因。
    """
    error = InvalidLoginCredentialsError()
    assert isinstance(error, AppError)
    assert app.exception_handlers[AppError] is handle_access_error
    headers = [] if locale is None else [(b"accept-language", locale.encode("ascii"))]
    request = Request(
        {"type": "http", "method": "POST", "path": "/api/v1/auth/login", "headers": headers}
    )

    response = await handle_access_error(
        request,
        error,
    )

    assert response.status_code == 401
    body = json.loads(bytes(response.body))
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(BusinessCode.INVALID_AUTHENTICATION)
    assert body["message"] == expected_message
    assert body["data"] is None
    assert "invalid_login_credentials" not in body["message"]
    assert response.headers["Content-Language"] == (locale or "zh-CN")
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"] == body["request_id"]


@pytest.mark.parametrize("expected_version", ["1", 1.0, True])
async def test_role_mutation_rejects_coerced_expected_version(
    override_management: Callable[[AuthorizationContext], None],
    expected_version: object,
) -> None:
    user_id = new_entity_id("U")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="status-manager",
                level=100,
                permissions=frozenset(
                    {PermissionKey.ROLES_STATUS_UPDATE.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )

    override_management(context)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                '/api/v1/roles/disable',
                json={"role_id": new_entity_id(
                    "R"), "expected_version": expected_version},
            )
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        response,
        status_code=422,
        business_code=BusinessCode.VALIDATION_FAILED,
    )


async def test_validation_and_unexpected_errors_use_the_standard_envelope(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="reader",
                level=1,
                permissions=frozenset({PermissionKey.ROLES_READ.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )

    override_management(context)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            invalid = await client.get('/api/v1/roles/detail?role_id=not-a-uuid')
    finally:
        app.dependency_overrides.clear()

    validation_body = assert_standard_response(
        invalid,
        status_code=422,
        business_code=BusinessCode.VALIDATION_FAILED,
    )
    assert validation_body["data"]["errors"]

    override_management(context)
    monkeypatch.setattr(
        auth_dependencies, "_load_current_user", AsyncMock(side_effect=RuntimeError("controlled-test-failure")),
    )
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            failed = await client.get("/api/v1/me/user_info")
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        failed,
        status_code=500,
        business_code=BusinessCode.INTERNAL_ERROR,
    )


async def test_role_delete_uses_the_committed_service_snapshot(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    role_id = new_entity_id("R")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="test-admin",
                level=100,
                permissions=frozenset({PermissionKey.ROLES_DELETE.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )
    result = RoleMutationResponse(
        role=RoleResponse(
            id=role_id,
            key="deleted-role",
            name="Deleted role",
            description="",
            level=10,
            is_active=False,
            is_system=False,
            is_protected=False,
            permissions=("projects:read",),
            version=8,
            deleted_at=datetime.now(UTC),
        ),
    )

    class SnapshotService:
        async def delete_role(self, **_kwargs: object) -> RoleMutationResponse:
            return result

    override_management(context)
    monkeypatch.setattr(role_api_module, "role_service", SnapshotService())
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                '/api/v1/roles/delete',
                json={"role_id": str(role_id), "expected_version": 7},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "etag" not in response.headers
    assert set(response.json()["data"]) == {"role"}
    assert response.json()["data"]["role"]["permissions"] == ["projects:read"]
    assert response.json()["data"]["role"]["deleted_at"] is not None


async def test_user_write_routes_use_service_transaction_snapshots(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    target_user_id = new_entity_id("U")
    role_id = new_entity_id("R")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="user-manager",
                level=100,
                permissions=frozenset(
                    {
                        PermissionKey.ROLES_BIND.value,
                        PermissionKey.ROLES_UNBIND.value,
                        PermissionKey.USERS_STATUS_UPDATE.value,
                    }
                ),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )
    active_user = UserResponse(
        user_id=target_user_id,
        user_name="managed_user",
        is_active=True,
        bound_role_ids=(role_id,),
        effective_role_ids=(role_id,),
        role_level=10,
        effective_permissions=(PermissionKey.PROJECTS_READ.value,),
    )
    role_response = UserRoleResponse(user=active_user)
    disabled_user = active_user.model_copy(
        update={"is_active": False}
    )
    enabled_user = active_user.model_copy()

    class SnapshotService:
        def __init__(self) -> None:
            self.change_user_roles = AsyncMock(
                side_effect=(role_response, role_response)
            )
            self.update_user_status = AsyncMock(
                side_effect=(disabled_user, enabled_user)
            )

    service = SnapshotService()

    post_transaction_reload = AsyncMock(
        side_effect=AssertionError(
            "user write route reloaded state after service return"
        )
    )
    monkeypatch.setattr(
        user_repository,
        "get_users_info",
        post_transaction_reload,
    )
    override_management(context)
    monkeypatch.setattr(user_api_module, "user_service", service)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            bound = await client.post(
                '/api/v1/users/roles/bind',
                json={"user_id": str(target_user_id),
                      "role_ids": [str(role_id)]},
            )
            unbound = await client.post(
                '/api/v1/users/roles/unbind',
                json={"user_id": str(target_user_id),
                      "role_ids": [str(role_id)]},
            )
            disabled = await client.post('/api/v1/users/disable', json={"user_id": str(target_user_id)})
            enabled = await client.post('/api/v1/users/enable', json={"user_id": str(target_user_id)})
    finally:
        app.dependency_overrides.clear()

    assert [
        response.status_code for response in (bound, unbound, disabled, enabled)
    ] == [
        200,
        200,
        200,
        200,
    ]
    assert bound.json()["data"] == json.loads(role_response.model_dump_json())
    assert unbound.json()["data"] == json.loads(
        role_response.model_dump_json())
    assert disabled.json()["data"] == json.loads(
        disabled_user.model_dump_json())
    assert enabled.json()["data"] == json.loads(enabled_user.model_dump_json())
    post_transaction_reload.assert_not_awaited()

    role_calls = service.change_user_roles.await_args_list
    assert [item.kwargs["operation"]
            for item in role_calls] == ["bind", "unbind"]
    assert all(item.kwargs["context"] is context for item in role_calls)
    assert all(item.kwargs["target_user_id"] ==
               target_user_id for item in role_calls)
    assert all(item.kwargs["role_ids"] == [role_id] for item in role_calls)

    status_calls = service.update_user_status.await_args_list
    assert [item.kwargs["is_active"] for item in status_calls] == [False, True]
    assert all(item.kwargs["context"] is context for item in status_calls)
    assert all(item.kwargs["target_user_id"] ==
               target_user_id for item in status_calls)


async def test_unprivileged_user_cannot_call_required_management_routes(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = new_entity_id("U")
    user_info = UserInfo.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        roles=(),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )

    write_audit = AsyncMock()
    monkeypatch.setattr(
        "app.dependencies.permission.AuditService.audit_denied",
        write_audit,
    )

    role_id = new_entity_id("R")
    permission_id = new_entity_id("P")
    target_user_id = new_entity_id("U")
    requests: list[tuple[str, str, dict[str, Any]]] = [
        ("GET", '/api/v1/permissions/list', {}),
        ("GET",
         f'/api/v1/permissions/detail?permission_id={permission_id}', {}),
        ("GET", '/api/v1/roles/list', {}),
        ("GET", f'/api/v1/roles/detail?role_id={role_id}', {}),
        (
            "POST",
            '/api/v1/roles/create',
            {
                "json": {
                    "key": "manager",
                    "name": "Manager",
                    "level": 100,
                }
            },
        ),
        (
            "POST",
            '/api/v1/roles/update',
            {"json": {"role_id": str(
                role_id), "name": "Renamed", "expected_version": 1}},
        ),
        (
            "POST",
            '/api/v1/roles/disable',
            {"json": {"role_id": str(role_id), "expected_version": 1}},
        ),
        (
            "POST",
            '/api/v1/roles/enable',
            {"json": {"role_id": str(role_id), "expected_version": 1}},
        ),
        (
            "POST",
            '/api/v1/roles/delete',
            {"json": {"role_id": str(role_id), "expected_version": 1}},
        ),
        (
            "POST",
            '/api/v1/roles/permissions/bind',
            {
                "json": {"role_id": str(role_id),
                         "permission_ids": [str(permission_id)],
                         "expected_version": 1,
                         },
            },
        ),
        (
            "POST",
            '/api/v1/roles/permissions/unbind',
            {
                "json": {"role_id": str(role_id),
                         "permission_ids": [str(permission_id)],
                         "expected_version": 1,
                         },
            },
        ),
        (
            "POST",
            '/api/v1/users/roles/bind',
            {"json": {"user_id": str(target_user_id),
                      "role_ids": [str(role_id)]}},
        ),
        (
            "POST",
            '/api/v1/users/roles/unbind',
            {"json": {"user_id": str(target_user_id),
                      "role_ids": [str(role_id)]}},
        ),
        ("GET", '/api/v1/users/sessions/list',
         {"params": {"user_id": str(target_user_id)}}),
        ("POST", '/api/v1/users/sessions/logout-all',
         {"json": {"user_id": str(target_user_id)}}),
    ]

    override_management(context)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for method, path, kwargs in requests:
                response = await client.request(method, path, **kwargs)
                assert response.status_code == 403, (
                    method, path, response.text)
                body = response.json()
                assert set(body) == {"code", "message", "data", "request_id"}
                assert body["code"] == 40301
                assert body["data"] is None
                assert response.headers["X-Request-ID"] == body["request_id"]
    finally:
        app.dependency_overrides.clear()
