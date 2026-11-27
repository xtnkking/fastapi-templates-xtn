#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在 SQLite 内存中执行实际角色权限关联查询，检查解绑、软删除和不同用户的权限隔离。
#    CTE 只提供 SELECT 数据，不创建表；不能代替 PostgreSQL 行锁和并发集成测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/11/26    XTN       V1.000        新建
# --------------------------------------------------------------------------------------------------

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import Select
from sqlalchemy.dialects import sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import RoleGrant, UserInfo
from app.models.postgres.role import Role
from app.models.postgres.user import User
from app.repositories.postgres.user_repository import user_repository

_AUTHORITY_DATA = """
    WITH role_data(id, key, level, is_active, is_protected, deleted_at) AS (VALUES
        ('R-shared', 'shared', 100, 1, 0, NULL),
        ('R-high', 'high', 700, ?, 1, NULL),
        ('R-deleted', 'deleted', 800, 1, 1, '2026-11-01'),
        ('R-unbound', 'unbound', 800, 1, 1, NULL),
        ('R-empty', 'empty', 20, 1, 0, NULL),
        ('R-second', 'second', 150, 1, 0, NULL),
        ('R-dead-permission', 'dead_permission', 30, 1, 0, NULL),
        ('R-dead-grant', 'dead_grant', 40, 1, 0, NULL)
    ), roles AS (
        SELECT *, key AS name, '' AS description, 0 AS is_system, 0 AS is_super_admin,
            0 AS version, '2026-11-01' AS created_at, NULL AS deleted_by_user_id FROM role_data
    ), user_roles(user_id, role_id, deleted_at) AS (VALUES
        ('U-first', 'R-shared', NULL), ('U-first', 'R-high', NULL),
        ('U-first', 'R-deleted', NULL), ('U-first', 'R-unbound', '2026-11-01'),
        ('U-first', 'R-empty', NULL), ('U-first', 'R-dead-permission', NULL),
        ('U-first', 'R-dead-grant', NULL),
        ('U-second', 'R-shared', NULL), ('U-second', 'R-second', NULL),
        ('U-not-requested', 'R-high', NULL)
    ), permissions(id, key, deleted_at) AS (VALUES
        ('P-read', 'projects:read', NULL), ('P-high', 'roles:delete', NULL),
        ('P-second', 'projects:update', NULL), ('P-dead', 'users:password:reset', '2026-11-01')
    ), role_permissions(role_id, permission_id, deleted_at) AS (VALUES
        ('R-shared', 'P-read', NULL), ('R-high', 'P-high', NULL),
        ('R-deleted', 'P-high', NULL), ('R-unbound', 'P-high', NULL),
        ('R-second', 'P-second', NULL), ('R-dead-permission', 'P-dead', NULL),
        ('R-dead-grant', 'P-high', '2026-11-01')
    )
"""


@pytest.fixture
def authority_database() -> Iterator[sqlite3.Connection]:
    """只为本次 SELECT 创建内存连接，测试结束即关闭，不访问业务库。"""
    with closing(sqlite3.connect(":memory:")) as database:
        database.row_factory = sqlite3.Row
        yield database


def query_session(database: sqlite3.Connection, *, high_role_active: bool,
                  data_sql: str = _AUTHORITY_DATA) -> tuple[AsyncSession, AsyncMock]:
    """把仓储真正拼出的 SELECT 放入内存数据库执行，再组装 ORM 返回值。"""
    async def execute(query: Select[Any]) -> SimpleNamespace:
        sql = str(query.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
        query_rows = database.execute(data_sql + sql, (int(high_role_active),)).fetchall()
        roles_by_id: dict[str, Role] = {}
        permissions = []
        for row in query_rows:
            if row["id"] not in roles_by_id:
                roles_by_id[row["id"]] = Role(
                    id=row["id"], key=row["key"], name=row["name"], level=row["level"],
                    is_active=bool(row["is_active"]), is_protected=bool(row["is_protected"]),
                    is_system=bool(row["is_system"]), is_super_admin=bool(row["is_super_admin"]),
                )
            permissions.append((row["user_id"], roles_by_id[row["id"]], row["permission_key"]))
        return SimpleNamespace(all=lambda: permissions)

    execute_query = AsyncMock(side_effect=execute)
    return cast(AsyncSession, SimpleNamespace(execute=execute_query)), execute_query


def account(user_id: str) -> User:
    """准备已查出的账号字段；权限仍由真实查询和仓储组装，不手填结果。"""
    return User(
        user_id=user_id, user_name=user_id.replace("-", "_"), is_active=True,
        is_protected=False, token_version=0,
    )


@pytest.mark.parametrize("high_role_active", [False, True], ids=["disabled-high-role", "active-high-role"])
@pytest.mark.parametrize("include_second_user", [False, True], ids=["one-user", "multiple-users"])
async def test_authority_query_does_not_restore_removed_or_other_user_permissions(
    authority_database: sqlite3.Connection, high_role_active: bool, include_second_user: bool,
) -> None:
    """真实关联查询排除软删除和解绑授权，批量查询不把其他用户的权限串到当前用户。"""
    session, execute = query_session(authority_database, high_role_active=high_role_active)
    first, second, empty = account("U-first"), account("U-second"), account("U-empty")
    users = (first, second, empty) if include_second_user else (first, empty)

    permissions = await user_repository.get_user_permissions(session, users=users)

    execute.assert_awaited_once()
    assert set(permissions) == {user.user_id for user in users}
    first_permissions = permissions[first.user_id]
    assert first_permissions.user_info.permissions == frozenset(
        {"projects:read", "roles:delete"} if high_role_active else {"projects:read"},
    )
    assert first_permissions.user_info.role_level == (700 if high_role_active else 100)
    assert first_permissions.user_info.is_protected is high_role_active
    complete = first_permissions.user_info_with_disabled_roles
    assert complete.permissions == frozenset({"projects:read", "roles:delete"})
    assert complete.role_level == 700
    assert complete.is_protected
    assert {role.role_id for role in complete.roles} == {
        "R-shared", "R-high", "R-empty", "R-dead-permission", "R-dead-grant",
    }
    assert permissions[empty.user_id].user_info.permissions == frozenset()
    assert permissions[empty.user_id].user_info_with_disabled_roles.roles == ()
    if include_second_user:
        assert permissions[second.user_id].user_info.permissions == frozenset({"projects:read", "projects:update"})


@pytest.mark.parametrize("high_role_active", [False, True])
async def test_display_projection_cannot_replace_complete_authority(
    authority_database: sqlite3.Connection, high_role_active: bool,
) -> None:
    """管理页面隐藏高角色时，完整权限入口仍保留它，不能拿页面结果绕过管理保护。"""
    session, execute = query_session(authority_database, high_role_active=high_role_active)
    user = account("U-first")
    viewer = UserInfo.build(
        user_id="U-viewer", user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id="R-manager", key="manager", level=500, permissions=frozenset({"users:read"}),
            is_system=False, is_protected=False, is_super_admin=False,
        ),),
    )

    display = await user_repository.get_users_info(session, users=(user,), current_user=viewer)
    complete = await user_repository.get_user_permissions(session, users=(user,))

    assert execute.await_count == 2
    assert display[user.user_id].user_info.permissions == frozenset({"projects:read"})
    assert display[user.user_id].user_info.role_level == 100
    assert "R-high" not in display[user.user_id].bound_role_ids
    assert complete[user.user_id].user_info_with_disabled_roles.role_level == 700
    assert complete[user.user_id].user_info_with_disabled_roles.is_protected


@pytest.mark.parametrize(("level", "protected", "super_admin_flag", "visible"), [
    (700, False, False, False),
    (100, True, False, False),
    (100, False, True, False),
    (100, False, False, True),
], ids=["higher-only", "protected-only", "super-admin-only", "ordinary-lower-role"])
async def test_display_query_checks_each_hidden_role_boundary_independently(
    authority_database: sqlite3.Connection, level: int, protected: bool, super_admin_flag: bool, visible: bool,
) -> None:
    """等级、受保护和超级管理员标记分别触发隐藏；没有这些限制的下级角色仍应显示。"""
    data_sql = _AUTHORITY_DATA.replace(
        "('R-high', 'high', 700, ?, 1, NULL)",
        f"('R-high', 'high', {level}, ?, {int(protected)}, NULL)",
    ).replace(
        "0 AS is_super_admin",
        f"CASE WHEN id = 'R-high' THEN {int(super_admin_flag)} ELSE 0 END AS is_super_admin",
    )
    session, execute = query_session(authority_database, high_role_active=True, data_sql=data_sql)
    user = account("U-first")
    viewer = UserInfo.build(
        user_id="U-viewer", user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id="R-manager", key="manager", level=500, permissions=frozenset({"users:read"}),
            is_system=False, is_protected=False, is_super_admin=False,
        ),),
    )

    display = await user_repository.get_users_info(session, users=(user,), current_user=viewer)

    execute.assert_awaited_once()
    assert ("R-high" in display[user.user_id].bound_role_ids) is visible
    assert ("roles:delete" in display[user.user_id].user_info.permissions) is visible
