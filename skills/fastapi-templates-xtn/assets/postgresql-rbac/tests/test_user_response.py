#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证用户响应区分已分配角色与生效权限，并在接口文档中解释停用角色。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件说明并同步中文字段描述断言，保留响应边界校验
# 2026/10/09    XTN       V1.001        用户角色变更响应模型统一使用 Response 后缀
# 2026/10/10    XTN       V1.002        对齐统一用户标识与当前用户命名
# 2026/10/15    XTN       V1.003        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/15    XTN       V1.004        验证已绑定角色使用新字段，仍与生效角色区分
# 2026/10/20    XTN       V1.005        验证角色 level 汇总为用户 role_level，并检查真实接口字段
# 2026/10/22    XTN       V1.006        本人权限响应使用 get_current_user 测试入口
# 2026/10/24    XTN       V1.007        用户角色操作响应统一使用直观的 UserRoleResponse 名称
# 2026/10/26    XTN       V1.008        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/11/26    XTN       V1.009        本人响应测试保留真实基础权限检查
# --------------------------------------------------------------------------------------------------

from collections.abc import Callable
from dataclasses import fields, replace

from httpx import ASGITransport, AsyncClient

from app.core.access.authorization import AuthorizationContext, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.ids import new_entity_id
from app.main import app
from app.models.postgres.user import User
from app.schemas.user import UserAccessResponse, UserResponse, UserRoleResponse


def test_user_response_separates_assigned_and_effective_authority() -> None:
    """
        确认停用角色可以保留在已分配列表，但不会进入生效角色和权限集合。

    :return: 无返回值；响应字段及 OpenAPI 对两种角色集合的区分符合业务约定。
    """
    base_role_id = new_entity_id("R")
    disabled_role_id = new_entity_id("R")
    response = UserResponse(
        user_id=new_entity_id("U"),
        user_name="alice",
        is_active=True,
        bound_role_ids=(base_role_id, disabled_role_id),
        effective_role_ids=(base_role_id,),
        role_level=0,
        effective_permissions=(),
    )

    assert response.bound_role_ids == (base_role_id, disabled_role_id)
    assert response.user_name == "alice"
    assert response.effective_role_ids == (base_role_id,)
    assert response.role_level == 0

    properties = UserResponse.model_json_schema()["properties"]
    assert {
        "user_id",
        "bound_role_ids",
        "user_name",
        "effective_role_ids",
        "role_level",
        "effective_permissions",
    } <= properties.keys()
    assert {
        "id",
        "role_ids",
        "assigned_role_ids",
        "management_tier",
        "effective_management_tier",
        "permissions",
        "delegable_permissions",
        "authz_version",
    }.isdisjoint(properties)
    assert "已停用角色" in properties["bound_role_ids"]["description"]
    assert "仍启用" in properties["effective_role_ids"]["description"]

    openapi_properties = app.openapi()["components"]["schemas"]["UserResponse"][
        "properties"
    ]
    assert set(openapi_properties) == set(properties)

    role_response = UserRoleResponse(user=response)
    assert set(role_response.model_dump()) == {"user"}
    assert "authz_version" not in response.model_dump()
    assert "authz_version" not in UserAccessResponse.model_fields
    assert "authz_version" not in User.__table__.columns
    assert "authz_version" not in {
        field.name for field in fields(UserInfo)}
    assert "token_version" in User.__table__.columns
    assert role_response.user is response
    assert isinstance(role_response.user.bound_role_ids, tuple)


async def test_my_access_returns_highest_role_level(
    unprivileged_authorization_context: AuthorizationContext,
    override_management: Callable[[AuthorizationContext], None],
) -> None:
    """验证多个角色的 level 汇总为最高 role_level，真实响应不再暴露旧字段。"""
    roles = tuple(
        RoleGrant(
            role_id=new_entity_id("R"),
            key=f"reader_{level}",
            level=level,
            permissions=frozenset({PermissionKey.ACCOUNT_READ.value, "projects:read"}),
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        )
        for level in (10, 30)
    )
    context = replace(
        unprivileged_authorization_context,
        user_info=UserInfo.build(
            user_id=unprivileged_authorization_context.login_info.user_id,
            user_is_active=True,
            user_is_protected=False,
            roles=roles,
        ),
    )

    # 隔离 Token、限流和数据库边界，仍执行接口真实的 account:read 检查。
    override_management(context)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/me/user_info")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert {role.level for role in context.user_info.roles} == {10, 30}
    assert context.user_info.role_level == 30
    assert response.json()["data"] == {
        "user_id": context.login_info.user_id,
        "role_level": 30,
        "permissions": ["account:read", "projects:read"],
    }
