#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证权限目录的业务分组、中英文说明和实际列表、详情响应。
#    数据访问与身份使用测试替身，不连接 PostgreSQL 或 Redis。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        验证权限说明语言协商、自定义文本回退及并发请求隔离
# 2026/10/15    XTN       V1.001        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/22    XTN       V1.002        目录接口测试直接运行权限检查并隔离外部依赖
# 2026/10/26    XTN       V1.003        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# --------------------------------------------------------------------------------------------------

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from typing import cast
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import AuthorizationContext, RoleGrant, UserInfo
from app.core.access.permissions import PERMISSION_CATALOG, PermissionKey, get_permission_description
from app.core.i18n.messages import CATALOGS, MessageKey
from app.core.ids import new_entity_id
from app.db.postgres_db import get_postgres_session
from app.main import app
from app.models.postgres.permission import Permission
from app.repositories.postgres.permission_repository import permission_repository


@pytest.fixture
async def permissions_client(
    override_management: Callable[[AuthorizationContext], None],
    monkeypatch: pytest.MonkeyPatch,
    unprivileged_authorization_context: AuthorizationContext,
) -> AsyncIterator[tuple[AsyncClient, Permission]]:
    """
        为权限接口提供已获 permissions:read 的身份与离线目录记录。
        保留真实路由、语言协商、响应模型和权限检查，只替换外部数据访问。

    :param monkeypatch: 在测试结束后自动恢复依赖与仓储方法。
    :param unprivileged_authorization_context: 当前测试独享的基础身份。
    :return: HTTP 测试客户端及仓储复用的权限模型，供检查原始数据未被修改。
    """
    original = unprivileged_authorization_context
    context = replace(
        original,
        user_info=UserInfo.build(
            user_id=original.login_info.user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=original.login_info.token_version,
            roles=(RoleGrant(
                role_id=new_entity_id("R"),
                key="permission_reader",
                level=10,
                permissions=frozenset({PermissionKey.PERMISSIONS_READ.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),),
        ),
    )
    # 模拟数据库已有的英文说明；内置权限仍须依据当前请求语言返回。
    permission = Permission(id=new_entity_id("P"), key=PermissionKey.PERMISSIONS_READ.value,
                            description="Legacy English description")
    monkeypatch.setattr(permission_repository,
                        "count_live_permissions", AsyncMock(return_value=1))
    monkeypatch.setattr(permission_repository, "list_live_permissions", AsyncMock(
        return_value=(permission,)))
    monkeypatch.setattr(permission_repository, "get_live_permission", AsyncMock(
        return_value=permission))

    async def current_session() -> AsyncSession:
        """
            提供不会连接数据库的会话占位对象，真实查询已由仓储替身接管。

        :return: 仅供类型契约与依赖传递使用的会话替身。
        """
        return cast(AsyncSession, object())

    override_management(context)
    monkeypatch.setitem(app.dependency_overrides,
                        get_postgres_session, current_session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client, permission


def test_builtin_permission_catalog_has_two_languages() -> None:
    """
        检查每个内置权限都有固定消息键和完整的中英文说明。

    :return: 无返回值；目录缺项、漏译或将消息键当成说明都会导致断言失败。
    """
    assert set(PERMISSION_CATALOG) == set(PermissionKey)
    for key, message_key in PERMISSION_CATALOG.items():
        assert isinstance(message_key, MessageKey)
        for locale in ("zh-CN", "en"):
            description = get_permission_description(key.value, locale=locale)
            assert description == CATALOGS[locale][message_key.value]
            assert description and description != message_key.value
        assert get_permission_description(
            key.value) != get_permission_description(key.value, locale="en")


@pytest.mark.parametrize("locale", ["zh-CN", "en", "unsupported"])
def test_custom_permission_preserves_its_authored_description(locale: str) -> None:
    """
        检查未知业务权限沿用数据库说明，不能虚构自动翻译结果。

    :param locale: 调用方选用的语言，未知权限在任何语言下都保留原文。
    :return: 无返回值；自定义描述和空描述均保持原值。
    """
    assert get_permission_description(
        "invoices:approve", stored_description="业务自定义说明", locale=locale
    ) == "业务自定义说明"
    assert get_permission_description("invoices:approve", locale=locale) == ""


@pytest.mark.parametrize("operation", ["list", "detail"])
@pytest.mark.parametrize("accept_language,locale", [
    (None, "zh-CN"),
    ("zh-CN", "zh-CN"),
    ("en", "en"),
    ("en-US", "en"),
    ("fr", "zh-CN"),
])
async def test_permission_api_localizes_description(permissions_client: tuple[AsyncClient, Permission],
                                                    operation: str,
                                                    accept_language: str | None,
                                                    locale: str
                                                    ) -> None:
    """
        通过真实列表和详情路由验证权限说明使用请求语言，且固定权限标识不变。

    :param permissions_client: 已完成外部依赖隔离的客户端和目录模型。
    :param operation: 权限列表或详情业务路径。
    :param accept_language: 客户端语言头，缺失与不支持时回退中文。
    :param locale: 语言协商后应使用的目录语言。
    :return: 无返回值；响应正文、语言头、固定字段及数据库原文必须正确。
    """
    client, permission = permissions_client
    response = await client.get(
        f"/api/v1/permissions/{operation}",
        params={"permission_id": str(
            permission.id)} if operation == "detail" else {},
        headers={"Accept-Language": accept_language} if accept_language else {},
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert response.headers["Content-Language"] == locale
    item = body["data"]["items"][0] if operation == "list" else body["data"]
    assert item == {
        "id": str(permission.id),
        "key": PermissionKey.PERMISSIONS_READ.value,
        "description": get_permission_description(permission.key, locale=locale),
    }
    assert permission.description == "Legacy English description"


async def test_concurrent_languages_do_not_modify_shared_permission(
    permissions_client: tuple[AsyncClient, Permission],
) -> None:
    """
        让中英文请求并发读取同一个模型，检查翻译仅作用于各自响应。

    :param permissions_client: 共享目录模型的离线客户端。
    :return: 无返回值；响应语言不得互相污染，原始说明不得被覆盖。
    """
    client, permission = permissions_client
    responses = await asyncio.gather(
        client.get("/api/v1/permissions/list",
                   headers={"Accept-Language": "zh-CN"}),
        client.get("/api/v1/permissions/detail", params={"permission_id": str(permission.id)},
                   headers={"Accept-Language": "en"}),
    )
    assert all(response.status_code == 200 for response in responses)
    assert responses[0].json()[
        "data"]["items"][0]["description"] == get_permission_description(permission.key)
    assert responses[1].json()["data"]["description"] == get_permission_description(
        permission.key, locale="en")
    assert permission.description == "Legacy English description"
