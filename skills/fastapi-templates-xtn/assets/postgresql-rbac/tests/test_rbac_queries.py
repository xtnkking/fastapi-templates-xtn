#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证角色权限批量查询、可见范围、软删除及权限业务分页，不连接真实数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        验证权限业务分层并补充查询测试说明
# 2026/09/30    XTN       V1.001        验证管理员会话查询沿用用户可见范围
# 2026/10/02    XTN       V1.002        超级管理员持有人查询测试改用维护命令专属仓储
# 2026/10/02    XTN       V1.003        验证单角色权限查询复用已加载角色，不重复访问角色表
# 2026/10/02    XTN       V1.004        验证用户在线统计先释放数据库会话再查询 Redis
# 2026/10/02    XTN       V1.005        验证操作者快照复用已刷新的用户行
# 2026/10/10    XTN       V1.006        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.007        会话列表调用只传用户与版本，不再传入配置
# 2026/10/15    XTN       V1.008        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V1.009        验证默认角色按编码一次查询、排除软删除、加锁并刷新已有对象
# 2026/10/16    XTN       V1.010        验证移除权限版本后仍按固定全局记录获取协调行锁
# 2026/10/22    XTN       V1.011        离线执行用户可见查询，覆盖多角色、保护状态和分页总数
# 2026/10/23    XTN       V1.012        覆盖共享角色权限隔离、停用保护及无权限角色
# 2026/10/24    XTN       V1.013        覆盖用户列表组合筛选及已删除用户的空权限展示
# 2026/10/24    XTN       V1.014        同步用户展示信息与可见查询构造函数名称
# 2026/10/24    XTN       V1.015        用户列表、详情和查询构造调用采用简短业务名称
# 2026/10/24    XTN       V1.016        角色权限共用集合查询入口并使用直观解绑名称
# 2026/10/24    XTN       V1.017        用户角色查询和解绑调用使用 get_role_ids 及 unbind_roles
# 2026/10/24    XTN       V1.018        管理用户资料查询使用 get_users_info 入口
# 2026/10/26    XTN       V1.019        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V1.020        权限结果字段明确区分有效用户信息与包含停用角色的信息
# 2026/10/26    XTN       V1.021        离线执行角色组合筛选并验证删除记录不读取权限
# 2026/10/26    XTN       V1.022        空角色集合交由权限仓储直接返回，验证不执行数据库查询
# 2026/10/26    XTN       V1.023        精简角色单值查询接线，保留绑定行锁和无序权限汇总验证
# 2026/11/26    XTN       V1.024        测试使用字符串业务 ID，并明确查询与筛选替身类型
# 2026/11/27    XTN       V1.025        管理员查询夹具按普通自定义角色标记，不再使用系统身份
# 2026/11/28    XTN       V1.026        权限目录查询带上展示字段和已收集的关联接口，不改变 SQL 范围
# --------------------------------------------------------------------------------------------------

"""权限查询与软解绑的隔离范围验证。"""

import sqlite3
import uuid
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, TypedDict, cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import Select, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ClauseElement
from sqlalchemy.sql.selectable import Subquery

from app.commands.operator_password_repository import operator_password_repository
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PERMISSION_CATALOG, PERMISSION_GROUP_NAMES, PermissionGroup, PermissionKey
from app.core.exceptions import AppError
from app.core.i18n.messages import translate_for_locale
from app.core.ids import new_entity_id
from app.db.redis_db import RedisClient
from app.models.postgres.permission import Permission
from app.models.postgres.rbac_state import RbacState
from app.models.postgres.role import Role
from app.models.postgres.user import User
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import UserPermissions, user_repository
from app.repositories.postgres.user_role_repository import user_role_repository
from app.services.permission_service import permission_service
from app.services.role_service import RoleService
from app.services.user_service import UserService


class _Rows:
    """
        提供关联查询结果的最小测试替身，不模拟数据库查询逻辑。
    """

    def __init__(self, *rows: object) -> None:
        """
            保存本次查询应返回的记录。

        :param rows: 按查询顺序排列的关联记录。
        :return: 无返回值，初始化只读测试记录。
        """
        self._rows = rows

    def all(self) -> tuple[object, ...]:
        """
            返回预设的全部关联记录。

        :return: 初始化时提供的查询记录元组。
        """
        return self._rows


def _session_returning(*rows: object) -> tuple[AsyncSession, AsyncMock]:
    """
        构造只支持 execute 的会话替身，供批量查询测试统计数据库往返。

    :param rows: 单次 execute 应返回的关联记录。
    :return: 会话替身及用于检查调用次数的异步方法。
    """
    execute = AsyncMock(return_value=_Rows(*rows))
    session = cast(AsyncSession, SimpleNamespace(execute=execute))
    return session, execute


@pytest.mark.parametrize("found", [False, True])
async def test_authorization_writes_still_lock_the_single_global_record(found: bool) -> None:
    """
        删除权限版本不会删除并发协调：授权写入仍锁住同一条 global 记录。

    :param found: True 返回固定锁记录；False 表示数据库尚未初始化该记录。
    :return: 无返回值；查询必须带行锁，缺失时仍阻止授权写入。
    """
    expected = RbacState(scope="global") if found else None
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=expected)

    if found:
        assert await rbac_state_repository.lock_rbac_state(cast(AsyncSession, session)) is expected
    else:
        with pytest.raises(AppError) as caught:
            await rbac_state_repository.lock_rbac_state(cast(AsyncSession, session))
        assert caught.value.status_code == 503
        assert caught.value.reason_code == "rbac_state_missing"

    session.scalar.assert_awaited_once()
    compiled = session.scalar.await_args.args[0].compile()
    assert "rbac_state.scope = :scope_1" in str(compiled)
    assert compiled.params["scope_1"] == "global"
    assert "FOR UPDATE" in str(compiled)


@pytest.mark.parametrize(
    ("user_id", "user_name", "is_active", "is_deleted", "expected", "absent"),
    [
        ("U123", None, None, False, ("users.user_id =", "users.deleted_at IS NULL"), ("users.user_name =",)),
        (None, "alice", None, False, ("users.user_name =", "users.deleted_at IS NULL"), ("users.user_id =",)),
        ("U123", "alice", True, False, ("users.user_id =", "users.user_name =", "users.is_active IS true"), ()),
        ("U123", None, False, False, ("users.is_active IS false", "users.deleted_at IS NULL"), ()),
        ("U123", None, None, True, ("users.deleted_at IS NOT NULL",), ("users.deleted_at IS NULL",)),
        ("U123", None, None, None, (), ("users.deleted_at IS NULL", "users.deleted_at IS NOT NULL")),
    ],
)
async def test_get_user_filters_are_combined_without_locks(
    user_id: str | None,
    user_name: str | None,
    is_active: bool | None,
    is_deleted: bool | None,
    expected: tuple[str, ...],
    absent: tuple[str, ...],
) -> None:
    user = User(user_id="U123", user_name="alice")
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=user)

    result = await user_repository.get_user(
        cast(AsyncSession, session), user_id=user_id, user_name=user_name,
        is_active=is_active, is_deleted=is_deleted,
    )

    assert result is user
    session.scalar.assert_awaited_once()
    statement = session.scalar.await_args.args[0]
    compiled = statement.compile()
    sql = str(compiled)
    assert all(fragment in sql for fragment in expected)
    assert all(fragment not in sql for fragment in absent)
    assert "FOR UPDATE" not in sql
    assert statement.get_execution_options()["populate_existing"] is True
    if user_id is not None:
        assert user_id in compiled.params.values()
    if user_name is not None:
        assert user_name in compiled.params.values()


async def test_get_user_defaults_to_live_accounts_and_preserves_not_found() -> None:
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=None)

    assert await user_repository.get_user(cast(AsyncSession, session), user_id="U123") is None

    sql = str(session.scalar.await_args.args[0].compile())
    assert "users.deleted_at IS NULL" in sql
    assert "users.is_active IS" not in sql


async def test_get_user_requires_an_identifier_before_database_access() -> None:
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock()

    with pytest.raises(ValueError, match="user_id or user_name"):
        await user_repository.get_user(cast(AsyncSession, session), is_active=True)

    session.scalar.assert_not_awaited()


@pytest.mark.parametrize("state", ["missing", "disabled", "revoked"])
async def test_current_user_rejects_invalid_accounts_before_loading_roles(
    monkeypatch: pytest.MonkeyPatch, state: str,
) -> None:
    user = None if state == "missing" else User(
        user_id="U123", is_active=state != "disabled", token_version=4 if state == "revoked" else 3,
    )
    get_user = AsyncMock(return_value=user)
    load_roles = AsyncMock()
    monkeypatch.setattr(user_repository, "get_user", get_user)
    monkeypatch.setattr(user_repository, "get_user_permissions", load_roles)
    session = cast(AsyncSession, object())

    with pytest.raises(AppError) as caught:
        await user_repository.check_current_user(session, user_id="U123", token_version=3)

    assert caught.value.status_code == 401
    assert caught.value.reason_code == "user_no_longer_active"
    get_user.assert_awaited_once_with(session, user_id="U123")
    load_roles.assert_not_awaited()


@pytest.mark.parametrize("found", [False, True])
async def test_role_key_lock_uses_one_fresh_live_role_query(found: bool) -> None:
    """
        默认角色用一次查询完成按编码定位和加锁，缺失时直接返回 None。

    :param found: True 模拟找到角色，False 模拟角色不存在或已被软删除过滤掉。
    :return: 无返回值；查询包含软删除过滤、行锁和已有对象刷新，未发起第二次查询。
    """
    expected = Role(id=new_entity_id("R"), key="user") if found else None
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=expected)

    result = await role_repository.lock_role_by_key(cast(AsyncSession, session), key="user")

    assert result is expected
    session.scalar.assert_awaited_once()
    session.execute.assert_not_called()
    session.scalars.assert_not_called()
    statement = session.scalar.await_args.args[0]
    compiled = statement.compile()
    sql = str(compiled)
    assert "roles.key = :key_1" in sql
    assert compiled.params["key_1"] == "user"
    assert "roles.deleted_at IS NULL" in sql
    assert "FOR UPDATE" in sql
    assert statement.get_execution_options()["populate_existing"] is True


async def test_permission_binding_lock_keeps_live_rows_and_locks_only_bindings() -> None:
    """
        权限绑定锁仍按固定顺序处理未删除关系，只锁绑定行，不锁权限目录。

    :return: 无返回值；SQL 保留目标角色、两处软删除过滤和稳定的绑定加锁顺序。
    """
    role_id = new_entity_id("R")
    execute = AsyncMock()
    session = cast(AsyncSession, SimpleNamespace(execute=execute))

    await role_repository.lock_permission_bindings(session, role_id=role_id)

    execute.assert_awaited_once()
    assert execute.await_args is not None
    query = cast(ClauseElement, execute.await_args.args[0])
    compiled = query.compile(dialect=cast(Callable[[], Dialect], postgresql.dialect)())
    sql = str(compiled)
    assert "JOIN permissions ON permissions.id = role_permissions.permission_id" in sql
    assert "permissions.deleted_at IS NULL" in sql
    assert "role_permissions.deleted_at IS NULL" in sql
    assert "role_permissions.role_id =" in sql
    assert role_id in compiled.params.values()
    assert "ORDER BY permissions.key" in sql
    assert "FOR UPDATE OF role_permissions" in sql


async def test_batch_authority_loader_uses_one_select_for_multiple_users() -> None:
    """
        验证多个用户的完整权限以一次查询批量读取，并保留状态与版本。

    :return: 无返回值，断言批量结果完整且没有逐用户追加查询。
    """
    first_user = User(
        user_id=new_entity_id("U"),
        user_name="first",
        is_active=True,
        is_protected=False,
        token_version=3,
    )
    second_user = User(
        user_id=new_entity_id("U"),
        user_name="second",
        is_active=False,
        is_protected=True,
        token_version=7,
    )
    no_role_user = User(
        user_id=new_entity_id("U"), user_name="no_role", is_active=True,
        is_protected=False, token_version=1,
    )
    first_role = Role(
        id=new_entity_id("R"), key="reader", level=10, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    second_role = Role(
        id=new_entity_id("R"), key="disabled-manager", level=90, is_active=False,
        is_system=False, is_protected=True, is_super_admin=False,
    )
    session, execute = _session_returning(
        (first_user.user_id, first_role, "projects:read"),
        (first_user.user_id, first_role, "projects:read"),
        (first_user.user_id, first_role, "projects:update"),
        (second_user.user_id, second_role, "projects:update"),
    )

    snapshots = await user_repository.get_user_permissions(
        session,
        users=(first_user, second_user, no_role_user),
    )

    execute.assert_awaited_once()
    assert snapshots[first_user.user_id].user_info.permissions == frozenset({"projects:read", "projects:update"})
    assert len(snapshots[first_user.user_id].user_info.roles) == 1
    assert snapshots[first_user.user_id].user_info.token_version == 3
    assert snapshots[second_user.user_id].user_info.token_version == 7
    assert snapshots[second_user.user_id].user_info.permissions == frozenset()
    assert snapshots[second_user.user_id].user_info_with_disabled_roles.permissions == frozenset({"projects:update"})
    assert not snapshots[second_user.user_id].user_info.user_is_active
    assert snapshots[second_user.user_id].user_info_with_disabled_roles.is_protected
    assert snapshots[no_role_user.user_id].user_info.roles == ()
    assert snapshots[no_role_user.user_id].user_info_with_disabled_roles.roles == ()
    assert execute.await_args is not None
    query = execute.await_args.args[0]
    assert query.get_execution_options()["populate_existing"] is True
    sql = str(query.compile())
    assert "user_roles.deleted_at IS NULL" in sql
    assert "roles.deleted_at IS NULL" in sql
    assert "role_permissions.deleted_at IS NULL" in sql
    assert "permissions.deleted_at IS NULL" in sql


async def test_user_permissions_returns_a_mapping_for_one_loaded_user() -> None:
    user = User(
        user_id=new_entity_id("U"), user_name="single", is_active=True,
        is_protected=False, token_version=3,
    )
    role = Role(
        id=new_entity_id("R"), key="reader", level=100, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    session, execute = _session_returning((user.user_id, role, "projects:read"))

    permissions = await user_repository.get_user_permissions(session, users=(user,))

    execute.assert_awaited_once()
    assert set(permissions) == {user.user_id}
    assert permissions[user.user_id].user_info.permissions == frozenset({"projects:read"})
    assert permissions[user.user_id].user_info_with_disabled_roles == permissions[user.user_id].user_info


@pytest.mark.parametrize("shared_active", [False, True])
async def test_user_permissions_keep_shared_roles_and_user_permissions_separate(shared_active: bool) -> None:
    first_user = User(
        user_id=new_entity_id("U"), user_name="first", is_active=True,
        is_protected=False, token_version=1,
    )
    second_user = User(
        user_id=new_entity_id("U"), user_name="second", is_active=True,
        is_protected=False, token_version=2,
    )
    shared_role = Role(
        id=new_entity_id("R"), key="shared", level=900, is_active=shared_active,
        is_system=False, is_protected=True, is_super_admin=False,
    )
    first_role = Role(
        id=new_entity_id("R"), key="first-only", level=100, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    second_role = Role(
        id=new_entity_id("R"), key="second-only", level=200, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    no_permission_role = Role(
        id=new_entity_id("R"), key="no-permissions", level=400, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    session, execute = _session_returning(
        (first_user.user_id, shared_role, "projects:read"),
        (first_user.user_id, shared_role, "projects:list"),
        (first_user.user_id, first_role, "first:update"),
        (first_user.user_id, no_permission_role, None),
        (second_user.user_id, shared_role, "projects:read"),
        (second_user.user_id, shared_role, "projects:list"),
        (second_user.user_id, second_role, "second:update"),
    )

    permissions = await user_repository.get_user_permissions(session, users=(first_user, second_user))

    execute.assert_awaited_once()
    shared_permissions = {"projects:read", "projects:list"}
    first_permissions = permissions[first_user.user_id]
    second_permissions = permissions[second_user.user_id]
    assert first_permissions.user_info.permissions == frozenset(
        {"first:update"} | (shared_permissions if shared_active else set()),
    )
    assert second_permissions.user_info.permissions == frozenset(
        {"second:update"} | (shared_permissions if shared_active else set()),
    )
    assert first_permissions.user_info_with_disabled_roles.permissions == frozenset(
        {"first:update"} | shared_permissions)
    assert second_permissions.user_info_with_disabled_roles.permissions == frozenset(
        {"second:update"} | shared_permissions)
    assert {role.role_id for role in first_permissions.user_info_with_disabled_roles.roles} == {
        shared_role.id, first_role.id, no_permission_role.id,
    }
    assert {role.role_id for role in second_permissions.user_info_with_disabled_roles.roles} == {
        shared_role.id, second_role.id}
    assert first_permissions.user_info_with_disabled_roles.is_protected
    assert second_permissions.user_info_with_disabled_roles.is_protected
    assert first_permissions.user_info.is_protected is shared_active
    assert second_permissions.user_info.is_protected is shared_active
    assert first_permissions.user_info.role_level == (900 if shared_active else 400)
    assert second_permissions.user_info.role_level == (900 if shared_active else 200)
    empty_role = next(role for role in first_permissions.user_info.roles if role.role_id == no_permission_role.id)
    assert empty_role.level == 400
    assert empty_role.permissions == frozenset()


async def test_user_permissions_reject_deleted_input_before_database_access() -> None:
    live_user = User(
        user_id=new_entity_id("U"), user_name="live", is_active=True,
        is_protected=False, token_version=1,
    )
    deleted_user = User(
        user_id=new_entity_id("U"), user_name="deleted", is_active=True,
        is_protected=False, token_version=1, deleted_at=datetime.now(UTC),
    )
    session, execute = _session_returning()
    with pytest.raises(AppError) as caught:
        await user_repository.get_user_permissions(session, users=(live_user, deleted_user))

    assert caught.value.status_code == 404
    assert caught.value.reason_code == "user_not_found"
    execute.assert_not_awaited()


@pytest.mark.parametrize("include_live", [False, True])
async def test_visible_details_show_deleted_users_without_loading_their_roles(include_live: bool) -> None:
    live_user = User(
        user_id=new_entity_id("U"), user_name="live", is_active=True,
        is_protected=False, token_version=1,
    )
    deleted_user = User(
        user_id=new_entity_id("U"), user_name="deleted", is_active=False,
        is_protected=False, token_version=4, deleted_at=datetime.now(UTC),
    )
    live_role = Role(
        id=new_entity_id("R"), key="reader", level=100, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id=new_entity_id("R"), key="manager", level=500,
            permissions=frozenset(), is_system=False, is_protected=False, is_super_admin=False,
        ),),
    )
    session, execute = _session_returning((live_user.user_id, live_role, "projects:read"))
    users = (live_user, deleted_user) if include_live else (deleted_user,)

    details = await user_repository.get_users_info(session, current_user=current_user, users=users)

    deleted_detail = details[deleted_user.user_id]
    assert deleted_detail.user_name == "deleted"
    assert deleted_detail.bound_role_ids == ()
    assert deleted_detail.user_info.user_id == deleted_user.user_id
    assert deleted_detail.user_info.user_is_active is False
    assert deleted_detail.user_info.role_level == 0
    assert deleted_detail.user_info.permissions == frozenset()
    if include_live:
        execute.assert_awaited_once()
        live_detail = details[live_user.user_id]
        assert live_detail.bound_role_ids == (live_role.id,)
        assert live_detail.user_info.permissions == frozenset({"projects:read"})
        assert execute.await_args is not None
        compiled = execute.await_args.args[0].compile()
        assert any(live_user.user_id in value for value in compiled.params.values() if isinstance(value, list))
        assert all(deleted_user.user_id not in value for value in compiled.params.values() if isinstance(value, list))
    else:
        execute.assert_not_awaited()


@pytest.mark.parametrize("visible", [False, True])
async def test_user_permissions_empty_input_does_not_query_database(visible: bool) -> None:
    session, execute = _session_returning()
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False, roles=(),
    )

    if visible:
        assert await user_repository.get_users_info(
            session, current_user=current_user, users=(),
        ) == {}
    else:
        assert await user_repository.get_user_permissions(session, users=()) == {}

    execute.assert_not_awaited()


@pytest.mark.parametrize("super_admin", [False, True])
async def test_visible_details_keep_disabled_bindings_out_of_effective_permissions(super_admin: bool) -> None:
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id=new_entity_id("R"), key="super_admin" if super_admin else "manager",
            level=1000 if super_admin else 500, permissions=frozenset(),
            is_system=super_admin, is_protected=super_admin, is_super_admin=super_admin,
        ),),
    )
    user = User(
        user_id=new_entity_id("U"), user_name="managed", is_active=True,
        is_protected=False, token_version=3,
    )
    active_role = Role(
        id=new_entity_id("R"), key="reader", level=100, is_active=True,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    disabled_role = Role(
        id=new_entity_id("R"), key="disabled-writer", level=200, is_active=False,
        is_system=False, is_protected=False, is_super_admin=False,
    )
    session, execute = _session_returning(
        (user.user_id, active_role, "projects:read"),
        (user.user_id, disabled_role, "projects:update"),
    )

    details = await user_repository.get_users_info(session, current_user=current_user, users=(user,))

    execute.assert_awaited_once()
    detail = details[user.user_id]
    assert detail.user_name == user.user_name
    assert set(detail.bound_role_ids) == {active_role.id, disabled_role.id}
    assert detail.user_info.permissions == frozenset({"projects:read"})
    assert detail.user_info.role_level == 100
    assert execute.await_args is not None
    sql = str(execute.await_args.args[0].compile())
    assert ("roles.level <" in sql) is not super_admin
    assert ("roles.is_protected IS false" in sql) is not super_admin
    assert ("roles.is_super_admin IS false" in sql) is not super_admin


async def test_current_user_reuses_the_fresh_user_for_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        操作者状态已从数据库刷新后，构造完整权限时不再次查询同一用户行。

    :param monkeypatch: 替换用户读取和角色权限查询，验证各层实际调用次数。
    :return: 无返回值；复用用户行并返回该用户完整权限快照。
    """
    user = User(
        user_id=new_entity_id("U"),
        user_name="user_id",
        is_active=True,
        token_version=3,
    )
    user_info = UserInfo.build(
        user_id=user.user_id,
        user_is_active=True,
        user_is_protected=False,
        token_version=3,
        roles=(),
    )
    session = cast(AsyncSession, object())
    get_user = AsyncMock(return_value=user)
    load_snapshots = AsyncMock(return_value={
        user.user_id: UserPermissions(
            user_info=user_info,
            user_info_with_disabled_roles=user_info,
        ),
    })
    monkeypatch.setattr(user_repository, "get_user", get_user)
    monkeypatch.setattr(user_repository, "get_user_permissions", load_snapshots)

    actual = await user_repository.check_current_user(
        session,
        user_id=user.user_id,
        token_version=3,
    )

    assert actual is user_info
    get_user.assert_awaited_once_with(session, user_id=user.user_id)
    load_snapshots.assert_awaited_once_with(session, users=(user,))


async def test_user_change_reads_target_permissions_once_after_rechecking_locked_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id, target_user_id = new_entity_id("U"), new_entity_id("U")
    operator = User(user_id=user_id, is_active=True, token_version=3)
    target = User(user_id=target_user_id, is_active=True, token_version=1)
    required = PermissionKey.USERS_STATUS_UPDATE
    manager_role = RoleGrant(
        role_id=new_entity_id("R"), key="manager", level=500,
        permissions=frozenset({required.value}), is_system=False,
        is_protected=False, is_super_admin=False,
    )
    before_lock = UserInfo.build(
        user_id=user_id, user_is_active=True, user_is_protected=False, token_version=3,
        roles=(manager_role,),
    )
    after_lock = UserInfo.build(
        user_id=user_id, user_is_active=True, user_is_protected=False, token_version=3,
        roles=(manager_role,),
    )
    active_target = UserInfo.build(
        user_id=target_user_id, user_is_active=True, user_is_protected=False, token_version=1, roles=(),
    )
    retained_target = UserInfo.build(
        user_id=target_user_id, user_is_active=True, user_is_protected=False, token_version=1,
        roles=(RoleGrant(
            role_id=new_entity_id("R"), key="disabled-higher-role", level=600,
            permissions=frozenset(), is_system=False, is_protected=True, is_super_admin=False,
        ),),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(user_id=user_id, token_version=3, token_id=uuid.uuid4(), issued_at=1, expires_at=2),
        user_info=before_lock,
    )
    session = cast(AsyncSession, object())
    service = UserService(cast(async_sessionmaker[AsyncSession], Mock()))
    events: list[str] = []

    async def check_current(*_args: object, **_kwargs: object) -> UserInfo:
        events.append("check_current")
        return before_lock if events.count("check_current") == 1 else after_lock

    async def lock_roles(*_args: object, **_kwargs: object) -> dict[str, Role]:
        events.append("lock_roles")
        return {}

    async def read_target(*_args: object, **_kwargs: object) -> dict[str, UserPermissions]:
        events.append("read_target")
        return {
            target_user_id: UserPermissions(
                user_info=active_target,
                user_info_with_disabled_roles=retained_target,
            ),
        }

    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock())
    monkeypatch.setattr(user_repository, "lock_users", AsyncMock(
        return_value={user_id: operator, target_user_id: target}))
    monkeypatch.setattr(user_repository, "check_current_user", AsyncMock(side_effect=check_current))
    monkeypatch.setattr(user_role_repository, "get_role_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr(role_repository, "lock_roles", AsyncMock(side_effect=lock_roles))
    read_permissions = AsyncMock(side_effect=read_target)
    monkeypatch.setattr(user_repository, "get_user_permissions", read_permissions)

    locked = await service._lock_current_and_target_user(
        session, context=context, target_user_id=target_user_id, required_permission=required,
    )

    assert events == ["check_current", "lock_roles", "check_current", "read_target"]
    read_permissions.assert_awaited_once_with(session, users=(target,))
    assert locked.current_user is after_lock
    assert locked.target_before is retained_target
    assert locked.target_row is target


async def test_batch_role_grant_loader_uses_one_select_for_multiple_roles() -> None:
    """
        验证角色权限一次批量查询完成，无序及重复记录仍按角色正确汇总。

    :return: 无返回值，断言每个角色得到自己的权限集合。
    """
    roles = (
        Role(
            id=new_entity_id("R"),
            key="reader",
            name="Reader",
            level=10,
            is_active=True,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        ),
        Role(
            id=new_entity_id("R"),
            key="writer",
            name="Writer",
            level=20,
            is_active=True,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        ),
    )
    session, execute = _session_returning(
        SimpleNamespace(
            role_id=roles[1].id,
            permission_key="projects:update",
        ),
        SimpleNamespace(
            role_id=roles[0].id,
            permission_key="projects:read",
        ),
        SimpleNamespace(
            role_id=roles[0].id,
            permission_key="projects:read",
        ),
    )

    grants = await role_repository.get_role_permissions(session, roles=roles)

    execute.assert_awaited_once()
    assert grants[roles[0].id].permissions == frozenset({"projects:read"})
    assert grants[roles[1].id].permissions == frozenset({"projects:update"})


async def test_single_role_grant_uses_loaded_inactive_role() -> None:
    """
        验证仓储只为已加载角色查询权限，不重复读取角色或自行拒绝停用角色。

    :return: 无返回值；断言权限快照包含原角色属性且仅执行一次查询。
    """
    role = Role(
        id=new_entity_id("R"),
        key="disabled-reader",
        name="Disabled reader",
        level=10,
        is_active=False,
        is_system=False,
        is_protected=False,
        is_super_admin=False,
    )
    session, execute = _session_returning(
        SimpleNamespace(role_id=role.id, permission_key="projects:read"),
    )

    role_permissions = await role_repository.get_role_permissions(session, roles=(role,))
    grant = role_permissions[role.id]

    execute.assert_awaited_once()
    assert grant.role_id == role.id
    assert grant.key == role.key
    assert grant.permissions == frozenset({"projects:read"})


async def test_super_admin_holder_loader_returns_the_complete_live_set() -> None:
    """
        验证超级管理员持有人查询返回完整集合，不只读取第一条记录。

    :return: 无返回值，断言全部存续绑定参与后续判断。
    """
    first_id = new_entity_id("U")
    second_id = new_entity_id("U")
    scalars = AsyncMock(return_value=SimpleNamespace(all=lambda: [first_id, second_id]))
    session = cast(AsyncSession, SimpleNamespace(scalars=scalars))

    holder_ids = await operator_password_repository.load_live_super_admin_holder_ids(session)

    assert holder_ids == frozenset({first_id, second_id})
    scalars.assert_awaited_once()


@pytest.mark.parametrize(
    ("level", "role_key", "super_admin_flag", "expected_users"),
    [
        (0, "user", False, ()),
        (1, "custom", False, (
            "U-deleted-role", "U-disabled-role", "U-no-role", "U-unbound-role", "U-zero-role",
        )),
        (500, "admin", False, (
            "U-deleted-role", "U-disabled-role", "U-disabled-user", "U-lower", "U-no-role",
            "U-unbound-role", "U-zero-role",
        )),
        (1000, "super_admin", True, (
            "U-current", "U-deleted-role", "U-disabled-role", "U-disabled-user", "U-higher",
            "U-lower", "U-mixed", "U-no-role", "U-peer", "U-protected", "U-protected-role",
            "U-unbound-role", "U-zero-role",
        )),
        (500, "super_admin", False, (
            "U-deleted-role", "U-disabled-role", "U-disabled-user", "U-lower", "U-no-role",
            "U-unbound-role", "U-zero-role",
        )),
        (500, "custom", True, (
            "U-deleted-role", "U-disabled-role", "U-disabled-user", "U-lower", "U-no-role",
            "U-unbound-role", "U-zero-role",
        )),
        (1000, "custom", False, (
            "U-deleted-role", "U-disabled-role", "U-disabled-user", "U-higher", "U-lower",
            "U-mixed", "U-no-role", "U-peer", "U-unbound-role", "U-zero-role",
        )),
    ],
    ids=("zero-level", "lowest-level", "admin", "super-admin", "name-only", "flag-only", "high-custom"),
)
@pytest.mark.parametrize("is_deleted", [False, True])
def test_visible_user_queries_keep_the_same_scope_for_list_count_page_and_detail(
    level: int,
    role_key: str,
    super_admin_flag: bool,
    expected_users: tuple[str, ...],
    is_deleted: bool,
) -> None:
    """
        用只读内存数据执行真实查询，检查多角色和隐藏目标不会从分页、总数或详情漏出。

    :param level: 操作者最高角色等级，覆盖 0 级、最低正等级和高等级。
    :param role_key: 操作者角色编码，单有超级管理员名称不能绕过范围限制。
    :param super_admin_flag: 操作者角色标记，单有标记也不能视作超级管理员。
    :param expected_users: 业务规则允许查看的用户 ID，已按 ID 排序。
    :param is_deleted: False 查询未删除用户，True 只查询已删除用户；两者都保留等级与保护限制。
    :return: 无返回值；列表、总数、分页和详情必须应用同一可见范围。
    """
    current_user = UserInfo.build(
        user_id="U-current",
        user_is_active=True,
        user_is_protected=False,
        roles=(RoleGrant(
            role_id="R-current", key=role_key, level=level, permissions=frozenset(),
            is_system=False, is_protected=False, is_super_admin=super_admin_flag,
        ),),
    )
    # CTE 仅提供本次 SELECT 的常量数据，不创建表、执行迁移或连接 PostgreSQL。
    fixture_sql = """
        WITH users(user_id, is_active, is_protected, deleted_at) AS (VALUES
            ('U-current', 1, 0, NULL), ('U-lower', 1, 0, NULL), ('U-peer', 1, 0, NULL),
            ('U-higher', 1, 0, NULL), ('U-protected', 1, 1, NULL), ('U-protected-role', 1, 0, NULL),
            ('U-mixed', 1, 0, NULL), ('U-disabled-role', 1, 0, NULL), ('U-deleted-role', 1, 0, NULL),
            ('U-unbound-role', 1, 0, NULL), ('U-no-role', 1, 0, NULL), ('U-zero-role', 1, 0, NULL),
            ('U-disabled-user', 0, 0, NULL), ('U-deleted', 1, 0, '2026-10-01'),
            ('U-deleted-lower', 0, 0, '2026-10-01'), ('U-deleted-peer', 0, 0, '2026-10-01'),
            ('U-deleted-higher', 0, 0, '2026-10-01'), ('U-deleted-protected', 0, 1, '2026-10-01')
        ), roles(id, level, is_active, is_protected, deleted_at) AS (VALUES
            ('R-zero', 0, 1, 0, NULL), ('R-low', 100, 1, 0, NULL),
            ('R-peer', 500, 1, 0, NULL), ('R-high', 600, 1, 0, NULL),
            ('R-protected', 100, 1, 1, NULL), ('R-disabled', 600, 0, 1, NULL),
            ('R-deleted', 600, 1, 1, '2026-10-01')
        ), user_roles(user_id, role_id, deleted_at) AS (VALUES
            ('U-current', 'R-low', NULL), ('U-lower', 'R-low', NULL),
            ('U-peer', 'R-peer', NULL), ('U-higher', 'R-high', NULL),
            ('U-protected-role', 'R-protected', NULL), ('U-mixed', 'R-low', NULL),
            ('U-mixed', 'R-high', NULL), ('U-disabled-role', 'R-disabled', NULL),
            ('U-deleted-role', 'R-deleted', NULL), ('U-unbound-role', 'R-high', '2026-10-01'),
            ('U-zero-role', 'R-zero', NULL), ('U-disabled-user', 'R-low', NULL),
            ('U-deleted-lower', 'R-low', NULL), ('U-deleted-peer', 'R-peer', NULL),
            ('U-deleted-higher', 'R-high', NULL)
        )
    """
    if is_deleted:
        deleted_targets = {
            "U-lower": "U-deleted-lower",
            "U-peer": "U-deleted-peer",
            "U-higher": "U-deleted-higher",
            "U-protected": "U-deleted-protected",
            "U-no-role": "U-deleted",
        }
        expected_users = tuple(sorted(
            deleted_targets[user_id] for user_id in expected_users if user_id in deleted_targets
        ))
    user_query = user_repository._build_user_query(
        current_user=current_user, is_deleted=is_deleted,
    ).with_only_columns(User.user_id)
    queries: tuple[Select[Any], ...] = (
        user_query.order_by(User.user_id),
        select(func.count()).select_from(user_query.subquery()),
        user_query.order_by(User.user_id).offset(1).limit(2),
        user_query.where(User.user_id == "U-mixed"),
    )
    expected_results = (
        [(user_id,) for user_id in expected_users],
        [(len(expected_users),)],
        [(user_id,) for user_id in expected_users[1:3]],
        [("U-mixed",)] if "U-mixed" in expected_users else [],
    )
    with closing(sqlite3.connect(":memory:")) as database:
        for query, expected in zip(queries, expected_results, strict=True):
            sql = str(query.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
            assert database.execute(fixture_sql + sql).fetchall() == expected


@pytest.mark.parametrize(
    ("user_id", "user_name", "is_active", "is_deleted"),
    [
        (None, None, None, False),
        (None, "Case_Sensitive", None, False),
        ("U-filter", "Case_Sensitive", True, False),
        ("U-filter", None, False, False),
        ("U-filter", "Case_Sensitive", False, True),
        ("U-filter", "Different_User", True, True),
    ],
)
async def test_user_filters_apply_to_the_same_count_and_page_scope(
    user_id: str | None,
    user_name: str | None,
    is_active: bool | None,
    is_deleted: bool,
) -> None:
    """
        验证各筛选以 AND 组合，同时用于列表和总数，保留用户名大小写。

    :return: 无返回值，断言两个 SQL 使用相同查询范围。
    """
    scalar = AsyncMock(return_value=0)
    scalars = AsyncMock(return_value=SimpleNamespace(all=lambda: []))
    session = cast(
        AsyncSession,
        SimpleNamespace(scalar=scalar, scalars=scalars),
    )
    current_user = UserInfo.build(
        user_id=new_entity_id("U"),
        user_is_active=True,
        user_is_protected=False,
        roles=(
            RoleGrant(
                role_id=new_entity_id("R"),
                key="super_admin",
                level=1000,
                permissions=frozenset(),
                is_system=True,
                is_protected=True,
                is_super_admin=True,
            ),
        ),
    )

    users, total = await user_repository.list_users(
        session,
        current_user=current_user,
        page=1,
        page_size=20,
        user_id=user_id,
        user_name=user_name,
        is_active=is_active,
        is_deleted=is_deleted,
    )

    assert users == ()
    assert total == 0
    scalar_call = scalar.await_args
    scalars_call = scalars.await_args
    assert scalar_call is not None
    assert scalars_call is not None
    count_statement = cast(Select[Any], scalar_call.args[0])
    page_statement = cast(Select[Any], scalars_call.args[0])
    for statement in (count_statement, page_statement):
        compiled = statement.compile()
        sql = str(compiled)
        assert ("users.user_id =" in sql) is (user_id is not None)
        assert ("users.user_name =" in sql) is (user_name is not None)
        assert ("users.is_active IS true" in sql) is (is_active is True)
        assert ("users.is_active IS false" in sql) is (is_active is False)
        assert ("users.deleted_at IS NOT NULL" in sql) is is_deleted
        assert ("users.deleted_at IS NULL" in sql) is not is_deleted
        if user_id is not None:
            assert user_id in compiled.params.values()
        if user_name is not None:
            assert user_name in compiled.params.values()
        assert " OR " not in sql
    count_from = count_statement.get_final_froms()[0]
    assert isinstance(count_from, Subquery)
    count_scope = count_from.element
    assert isinstance(count_scope, Select)
    assert count_scope.whereclause is not None
    assert page_statement.whereclause is not None
    assert count_scope.whereclause.compare(page_statement.whereclause)


# CTE 只给 SELECT 提供内存常量；完整角色列让原始总数和分页 SQL 都能直接执行。
_ROLE_FILTER_FIXTURE_SQL = r"""
    WITH role_fixture(id, key, name, level, is_active, is_system, is_protected, is_super_admin, deleted_at) AS (VALUES
        ('R-reader', 'a-reader', 'Reader 100%_done', 10, 1, 0, 0, 0, NULL),
        ('R-disabled', 'b-disabled', 'Disabled 100%_done', 20, 0, 0, 0, 0, NULL),
        ('R-percent', 'c-percent', 'Reader 100X_done', 30, 1, 0, 0, 0, NULL),
        ('R-underscore', 'd-underscore', 'Reader 100%Xdone', 40, 1, 0, 0, 0, NULL),
        ('R-escape', 'e-escape', 'Reader path/done', 40, 1, 0, 0, 0, NULL),
        ('R-system', 'user', 'User', 0, 1, 1, 0, 0, NULL),
        ('R-peer', 'admin', 'Administrator', 500, 1, 0, 0, 0, NULL),
        ('R-higher', 'higher', 'Higher', 600, 1, 0, 0, 0, NULL),
        ('R-protected', 'protected', 'Protected', 400, 1, 1, 1, 0, NULL),
        ('R-super', 'super_admin', 'Super administrator', 1000, 1, 1, 1, 1, NULL),
        ('R-deleted', 'old-reader', 'Reader 100%_done', 10, 0, 0, 0, 0, '2026-10-01'),
        ('R-deleted-peer', 'old-peer', 'Deleted peer', 500, 0, 0, 0, 0, '2026-10-01'),
        ('R-deleted-protected', 'old-protected', 'Deleted protected', 400, 0, 1, 1, 0, '2026-10-01'),
        ('R-deleted-super', 'old-super', 'Deleted super', 1000, 0, 1, 1, 1, '2026-10-01')
    ), roles AS (
        SELECT *, '' AS description, 0 AS version, '2026-10-01' AS created_at,
            NULL AS deleted_by_user_id FROM role_fixture
    )
"""


class _RoleFilters(TypedDict, total=False):
    """角色列表测试可传的筛选字段及对应类型。"""

    role_id: str | None
    key: str | None
    name: str | None
    is_active: bool | None
    is_system: bool | None
    is_deleted: bool


@pytest.mark.parametrize("super_admin", [False, True], ids=("admin", "super-admin"))
@pytest.mark.parametrize(
    ("filters", "expected_ids"),
    [
        ({"role_id": "R-reader"}, ("R-reader",)),
        ({"key": "a-reader"}, ("R-reader",)),
        ({"key": "A-reader"}, ()),
        ({"key": "reader"}, ()),
        ({"name": "100%_"}, ("R-reader", "R-disabled")),
        ({"name": "path/"}, ("R-escape",)),
        ({"is_active": False}, ("R-disabled",)),
        ({"is_system": True, "key": "user"}, ("R-system",)),
        ({"is_system": False, "name": "100%_", "is_active": True}, ("R-reader",)),
        ({"role_id": "R-reader", "key": "b-disabled"}, ()),
        ({"role_id": "R-reader", "key": "a-reader", "name": "100%_",
          "is_active": True, "is_system": False, "is_deleted": False}, ("R-reader",)),
        ({"is_deleted": True, "name": "100%_", "is_active": False, "is_system": False}, ("R-deleted",)),
        ({"is_deleted": True, "is_active": True}, ()),
        ({"role_id": "R-deleted"}, ()),
    ],
)
async def test_role_filters_execute_with_the_same_count_and_page_scope(
    super_admin: bool,
    filters: _RoleFilters,
    expected_ids: tuple[str, ...],
) -> None:
    """
        执行仓储实际生成的总数与分页 SQL，验证精确、文字包含和状态筛选以 AND 组合。

    :param super_admin: True 使用超级管理员，False 使用只能向下查看的普通管理员。
    :param filters: 本次传给角色列表的筛选组合，未传项沿用业务默认值。
    :param expected_ids: 当前用户在筛选下能看到的完整角色 ID，按角色编码排序。
    :return: 无返回值；同范围总数、稳定分页和转义后的名称匹配必须正确。
    """
    current_user = UserInfo.build(
        user_id="U-current", user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id="R-current", key="super_admin" if super_admin else "admin",
            level=1000 if super_admin else 500, permissions=frozenset(),
            is_system=super_admin, is_protected=super_admin, is_super_admin=super_admin,
        ),),
    )
    scalar = AsyncMock(return_value=len(expected_ids))
    expected_roles = tuple(Role(id=role_id) for role_id in expected_ids[1:2])
    scalars = AsyncMock(return_value=SimpleNamespace(all=lambda: expected_roles))
    session = cast(AsyncSession, SimpleNamespace(scalar=scalar, scalars=scalars))

    roles, total = await role_repository.list_roles(
        session, current_user=current_user, page=2, page_size=1, **filters,
    )

    assert roles == expected_roles
    assert tuple(role.id for role in roles) == expected_ids[1:2]
    assert total == len(expected_ids)
    assert scalar.await_args is not None
    count_query = scalar.await_args.args[0]
    assert scalars.await_args is not None
    page_query = scalars.await_args.args[0]
    count_scope = count_query.get_final_froms()[0].element
    assert count_scope.whereclause.compare(page_query.whereclause)
    assert "ORDER BY roles.key, roles.id" in str(page_query.compile())
    with closing(sqlite3.connect(":memory:")) as database:
        for query, expected in (
            (count_query, [(len(expected_ids),)]),
            (page_query.with_only_columns(Role.id), [(role_id,) for role_id in expected_ids[1:2]]),
            (page_query.with_only_columns(Role.id).offset(0).limit(200), [(role_id,) for role_id in expected_ids]),
        ):
            sql = str(query.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
            assert database.execute(_ROLE_FILTER_FIXTURE_SQL + sql).fetchall() == expected


@pytest.mark.parametrize(
    ("level", "key", "super_admin_flag", "live_ids", "deleted_ids"),
    [
        (0, "user", False, (), ()),
        (500, "admin", False,
         ("R-reader", "R-disabled", "R-percent", "R-underscore", "R-escape", "R-system"), ("R-deleted",)),
        (1000, "super_admin", True,
         ("R-reader", "R-peer", "R-disabled", "R-percent", "R-underscore", "R-escape", "R-higher",
          "R-protected", "R-super", "R-system"),
         ("R-deleted-peer", "R-deleted-protected", "R-deleted", "R-deleted-super")),
        (500, "super_admin", False,
         ("R-reader", "R-disabled", "R-percent", "R-underscore", "R-escape", "R-system"), ("R-deleted",)),
        (500, "custom", True,
         ("R-reader", "R-disabled", "R-percent", "R-underscore", "R-escape", "R-system"), ("R-deleted",)),
    ],
    ids=("zero-level", "admin", "super-admin", "name-only", "flag-only"),
)
@pytest.mark.parametrize("is_deleted", [False, True])
async def test_role_list_visibility_and_detail_keep_their_deletion_scopes(
    level: int,
    key: str,
    super_admin_flag: bool,
    live_ids: tuple[str, ...],
    deleted_ids: tuple[str, ...],
    is_deleted: bool,
) -> None:
    """
        删除状态筛选仍保留等级和保护限制；详情始终只查询未删除角色。

    :return: 无返回值；超级管理员须同时满足编码和标记才能查看全部所选状态角色。
    """
    current_user = UserInfo.build(
        user_id="U-current", user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id="R-current", key=key, level=level, permissions=frozenset(),
            is_system=False, is_protected=False, is_super_admin=super_admin_flag,
        ),),
    )
    expected_ids = deleted_ids if is_deleted else live_ids
    role_query = role_repository._build_role_query(
        current_user=current_user, is_deleted=is_deleted,
    ).with_only_columns(Role.id)
    scalar = AsyncMock(return_value=None)
    session = cast(AsyncSession, SimpleNamespace(scalar=scalar))
    assert await role_repository.get_role_detail(
        session, current_user=current_user, role_id="R-deleted",
    ) is None
    assert scalar.await_args is not None
    detail_query = scalar.await_args.args[0].with_only_columns(Role.id)
    with closing(sqlite3.connect(":memory:")) as database:
        for query, expected in (
            (role_query.order_by(Role.key, Role.id), [(role_id,) for role_id in expected_ids]),
            (select(func.count()).select_from(role_query.subquery()), [(len(expected_ids),)]),
            (role_query.order_by(Role.key, Role.id).offset(1).limit(2),
             [(role_id,) for role_id in expected_ids[1:3]]),
            (detail_query, []),
        ):
            sql = str(query.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
            assert database.execute(_ROLE_FILTER_FIXTURE_SQL + sql).fetchall() == expected


@pytest.mark.parametrize("state", ["empty", "deleted", "disabled", "mixed"])
async def test_role_list_loads_permissions_only_for_live_roles(
    state: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        已删除角色返回空权限且不读取旧绑定；未删除的停用角色仍批量加载权限。

    :return: 无返回值；权限仓储只收到未删除角色，空页和全删除页传空集合。
    """
    deleted = Role(
        id=new_entity_id("R"), key="old", name="Deleted", description="", level=10,
        is_active=False, is_system=False, is_protected=False, is_super_admin=False,
        version=0, deleted_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    disabled = Role(
        id=new_entity_id("R"), key="disabled", name="Disabled", description="", level=10,
        is_active=False, is_system=False, is_protected=False, is_super_admin=False,
        version=0, deleted_at=None,
    )
    roles = {"empty": (), "deleted": (deleted,), "disabled": (disabled,), "mixed": (deleted, disabled)}[state]
    live_roles = tuple(role for role in roles if role.deleted_at is None)
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False, roles=(),
    )
    session = cast(AsyncSession, object())
    list_roles = AsyncMock(return_value=(roles, len(roles)))
    load_permissions = AsyncMock(return_value={disabled.id: SimpleNamespace(permissions=frozenset({"roles:read"}))})
    monkeypatch.setattr(role_repository, "list_roles", list_roles)
    monkeypatch.setattr(role_repository, "get_role_permissions", load_permissions)
    service = RoleService(cast(async_sessionmaker[AsyncSession], Mock()))

    page = await service.list_roles(
        session, current_user=current_user, page=1, page_size=20, is_deleted=state == "deleted",
    )

    assert page.total == len(roles)
    assert [item.id for item in page.items] == [role.id for role in roles]
    for item in page.items:
        assert item.permissions == (() if item.deleted_at else ("roles:read",))
    load_permissions.assert_awaited_once_with(session, roles=live_roles)


async def test_permission_count_and_page_exclude_soft_deleted_entries() -> None:
    """
        验证权限业务返回正确分页元信息，列表和计数都排除软删除记录。

    :return: 无返回值，断言稳定排序、页码偏移和总数没有因分层调整而改变。
    """
    scalar = AsyncMock(return_value=3)
    scalars = AsyncMock(return_value=SimpleNamespace(all=lambda: []))
    session = cast(AsyncSession, SimpleNamespace(scalar=scalar, scalars=scalars))

    page = await permission_service.list_permissions(session, page=2, page_size=20, permission_api_routes={})

    assert page.items == []
    assert (page.page, page.page_size, page.total) == (2, 20, 3)
    for call in (scalar.await_args, scalars.await_args):
        assert call is not None
        statement = cast(ClauseElement, call.args[0])
        assert "permissions.deleted_at IS NULL" in str(statement.compile())
    assert scalars.await_args is not None
    page_statement = cast(ClauseElement, scalars.await_args.args[0])
    assert "ORDER BY permissions.key, permissions.id" in str(page_statement.compile())
    assert page_statement.compile().params["param_1"] == 20
    assert page_statement.compile().params["param_2"] == 20


@pytest.mark.parametrize("found", [True, False])
async def test_permission_detail_returns_public_fields_or_original_not_found(found: bool) -> None:
    """
        验证权限详情的公开字段和资源缺失错误仍由同一业务入口稳定返回。

    :param found: True 返回存续权限，False 模拟不存在或已删除权限。
    :return: 无返回值，断言公开结果与原 HTTP 404 业务语义保持一致。
    """
    permission_id = new_entity_id("P")
    permission = Permission(id=permission_id, key="projects:read", description="读取项目") if found else None
    execute = AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: permission))
    session = cast(AsyncSession, SimpleNamespace(execute=execute))

    if found:
        detail = await permission_service.get_permission_detail(
            session, permission_id=permission_id, permission_api_routes={})
        spec = PERMISSION_CATALOG[PermissionKey.PROJECTS_READ]
        assert detail.model_dump() == {
            "id": permission_id, "key": "projects:read",
            "name": translate_for_locale("zh-CN", spec.name),
            "group_key": "projects",
            "group_name": translate_for_locale("zh-CN", PERMISSION_GROUP_NAMES[PermissionGroup.PROJECTS]),
            "description": "读取项目", "api_routes": (),
        }
    else:
        with pytest.raises(AppError) as caught:
            await permission_service.get_permission_detail(
                session, permission_id=permission_id, permission_api_routes={})
        assert caught.value.status_code == 404
        assert caught.value.reason_code == "permission_not_found"

    assert execute.await_args is not None
    statement = cast(ClauseElement, execute.await_args.args[0])
    assert "permissions.deleted_at IS NULL" in str(statement.compile())


@pytest.mark.parametrize("restrict_to_user", [False, True])
async def test_role_unbinding_preserves_target_scope_and_transaction_ownership(restrict_to_user: bool) -> None:
    """
        验证解绑用户角色只更新指定范围，并由调用方负责事务提交。

    :param restrict_to_user: 是否仅解绑指定用户，否则解绑目标角色的全部用户关系。
    :return: 无返回值，断言软删除字段、目标范围和提交职责不变。
    """
    execute = AsyncMock()
    commit = AsyncMock()
    session = cast(AsyncSession, SimpleNamespace(execute=execute, commit=commit))
    role_id, target_user_id, user_id = new_entity_id("R"), new_entity_id("U"), new_entity_id("U")
    deleted_at = datetime.now(UTC)

    await user_role_repository.unbind_roles(
        session,
        role_ids=frozenset({role_id}),
        user_id=target_user_id if restrict_to_user else None,
        deleted_at=deleted_at,
        deleted_by_user_id=user_id,
    )

    execute.assert_awaited_once()
    commit.assert_not_awaited()
    assert execute.await_args is not None
    statement = cast(ClauseElement, execute.await_args.args[0])
    compiled = statement.compile()
    assert "user_roles.deleted_at IS NULL" in str(compiled)
    assert "user_roles.role_id IN" in str(compiled)
    assert ("user_roles.user_id =" in str(compiled)) is restrict_to_user
    assert compiled.params["deleted_at"] == deleted_at
    assert compiled.params["deleted_by_user_id"] == user_id
    assert [role_id] in compiled.params.values()


@pytest.mark.parametrize("restrict_permissions", [False, True])
async def test_permission_unbinding_preserves_role_and_optional_permission_scope(restrict_permissions: bool) -> None:
    """
        验证角色权限解绑保留角色边界及可选权限范围。

    :param restrict_permissions: 是否只解绑指定权限，否则解绑目标角色的全部权限关系。
    :return: 无返回值，断言仅执行软删除且不自行提交业务事务。
    """
    execute = AsyncMock()
    commit = AsyncMock()
    session = cast(AsyncSession, SimpleNamespace(execute=execute, commit=commit))
    role_id, permission_id, user_id = new_entity_id("R"), new_entity_id("P"), new_entity_id("U")

    await role_repository.unbind_permissions(
        session,
        role_id=role_id,
        permission_ids=frozenset({permission_id}) if restrict_permissions else None,
        deleted_at=datetime.now(UTC),
        deleted_by_user_id=user_id,
    )

    execute.assert_awaited_once()
    commit.assert_not_awaited()
    assert execute.await_args is not None
    statement = cast(ClauseElement, execute.await_args.args[0])
    compiled = statement.compile()
    assert "role_permissions.deleted_at IS NULL" in str(compiled)
    assert "role_permissions.role_id =" in str(compiled)
    assert (
        "role_permissions.permission_id IN" in str(compiled)
    ) is restrict_permissions
    assert role_id in compiled.params.values()


async def test_empty_binding_targets_do_not_run_database_queries() -> None:
    """
        验证空用户或空角色集合不被解释成全表查询及全量解绑。

    :return: 无返回值，断言空目标没有触发数据库访问。
    """
    execute = AsyncMock()
    scalars = AsyncMock()
    session = cast(AsyncSession, SimpleNamespace(execute=execute, scalars=scalars))
    user_id, role_id = new_entity_id("U"), new_entity_id("R")
    deleted_at = datetime.now(UTC)

    assert await role_repository.get_role_permissions(session, roles=()) == {}
    assert (
        await user_role_repository.get_role_ids(session, user_ids=set())
        == set()
    )
    assert (
        await user_role_repository.get_role_ids(
            session, user_ids={user_id}, role_ids=frozenset()
        )
        == set()
    )
    await user_role_repository.unbind_roles(
        session,
        role_ids=frozenset(),
        deleted_at=deleted_at,
        deleted_by_user_id=user_id,
    )
    await role_repository.unbind_permissions(
        session,
        role_id=role_id,
        permission_ids=frozenset(),
        deleted_at=deleted_at,
        deleted_by_user_id=user_id,
    )

    execute.assert_not_awaited()
    scalars.assert_not_awaited()


async def test_session_list_conceals_hidden_user_and_releases_database_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        验证会话统计只读取可见用户，关闭数据库会话后才访问 Redis。

    :param monkeypatch: 临时替换用户可见性仓储，不连接真实数据库。
    :return: 可见目标得到登录统计，隐藏目标不会触发 Redis 会话查询。
    """
    target = User(user_id=new_entity_id("U"), user_name="managed_user", token_version=7)
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False,
        token_version=1, roles=(),
    )
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    session_factory = Mock(return_value=session)
    service = UserService(cast(async_sessionmaker[AsyncSession], session_factory))
    load_user_detail = AsyncMock(side_effect=[target, None])
    monkeypatch.setattr(user_repository, "get_user_detail", load_user_detail)
    redis = cast(RedisClient, object())

    async def read_sessions(*_args: object, **_kwargs: object) -> tuple[int, int]:
        """
            模拟 Redis 会话读取，并断言数据库会话在此之前已经退出。

        :param _args: 实际 Redis 客户端，由断言以外的调用边界提供。
        :param _kwargs: 用户 ID 和 Token 版本。
        :return: 两次有效登录的 Unix 秒数。
        """
        assert session.__aexit__.await_count == 1
        return (1_700_000_000, 1_700_000_600)

    list_sessions = AsyncMock(side_effect=read_sessions)
    monkeypatch.setattr("app.services.user_service.login_session_repository.list_active_sessions", list_sessions)

    data = await service.list_user_sessions(
        current_user=current_user, user_id=target.user_id, redis=redis,
    )
    with pytest.raises(AppError) as error:
        await service.list_user_sessions(
            current_user=current_user, user_id=new_entity_id("U"), redis=redis,
        )

    assert data.active_count == 2
    assert data.login_times == (
        "2023-11-14T22:13:20+00:00",
        "2023-11-14T22:23:20+00:00",
    )
    assert error.value.status_code == 404
    assert error.value.reason_code == "user_not_found"
    assert load_user_detail.await_count == 2
    assert load_user_detail.await_args_list[0].kwargs["current_user"] is current_user
    list_sessions.assert_awaited_once_with(redis, user_id=target.user_id, token_version=7)
    assert session.__aexit__.await_count == 2
