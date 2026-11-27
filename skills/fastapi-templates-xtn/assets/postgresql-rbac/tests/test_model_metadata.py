#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查模型约束和统一元数据入口，不连接数据库或执行 DDL。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        记录模型元数据边界并检查固定系统角色键约束
# 2026/10/15    XTN       V1.001        离线验证两种绑定关系使用直观的绑定操作人和绑定时间字段
# 2026/10/16    XTN       V1.002        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/11/27    XTN       V1.003        系统角色仅限超级管理员和普通用户，admin 不再有固定模型形状
# --------------------------------------------------------------------------------------------------

"""验证统一模型入口在全新进程中加载完整元数据，无外部连接或 DDL 副作用。"""

import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import CheckConstraint, DateTime, Table

from app.models.postgres.rbac_state import RbacState
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import UserRole


def test_global_state_only_identifies_the_coordination_lock() -> None:
    """
        全局记录只标明锁定对象，不保存权限版本或公开注册开关。

    :return: 无返回值；额外加入没有实际用途的状态字段时断言失败。
    """
    assert set(RbacState.__table__.columns.keys()) == {"scope"}


def test_only_fixed_role_keys_can_be_marked_system() -> None:
    """
        模型约束只允许两个固定角色带系统标志，不把普通自定义角色变成不可删除角色。

    :return: 无返回值；缺少固定系统角色键约束时断言失败。
    """
    table = Role.__table__
    assert isinstance(table, Table)
    constraint = next(
        item for item in table.constraints
        if isinstance(item, CheckConstraint) and item.name == "ck_roles_system_role_key_fixed"
    )
    assert str(constraint.sqltext) == "NOT is_system OR key IN ('super_admin', 'user')"
    assert "ck_roles_admin_role_shape" not in {item.name for item in table.constraints}


@pytest.mark.parametrize("key,is_system,allowed", [
    ("super_admin", True, True),
    ("user", True, True),
    ("admin", True, False),
    ("admin", False, True),
    ("custom_manager", True, False),
    ("custom_manager", False, True),
])
def test_system_key_constraint_does_not_promote_custom_admin(key: str, is_system: bool, allowed: bool) -> None:
    """只执行当前模型的简单布尔表达式，不建表；不将 SQLite 结果作为 PostgreSQL 集成证明。"""
    table = Role.__table__
    assert isinstance(table, Table)
    constraint = next(
        item for item in table.constraints
        if isinstance(item, CheckConstraint) and item.name == "ck_roles_system_role_key_fixed"
    )
    with sqlite3.connect(":memory:") as database:
        value = database.execute(
            f"SELECT ({constraint.sqltext}) FROM (SELECT ? AS key, ? AS is_system)", (key, is_system),
        ).fetchone()[0]

    assert bool(value) is allowed


def test_relationship_binding_fields_share_clear_names_and_preserve_constraints() -> None:
    """
        两种关系都使用绑定操作人和绑定时间，改名不改变空值、外键和时间默认值。

    :return: 无返回值；旧字段残留、约束变化或新字段无法赋值时断言失败。
    """
    bound_at = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
    user_id = "U123456789ABCDE"
    for model in (UserRole, RolePermission):
        columns = model.__table__.columns
        assert {"bound_by_user_id", "bound_at"} <= set(columns.keys())
        assert not {"assigned_by_user_id", "assigned_at"} & set(columns.keys())
        assert columns.bound_by_user_id.nullable
        foreign_key = next(iter(columns.bound_by_user_id.foreign_keys))
        assert foreign_key.target_fullname == "users.user_id"
        assert foreign_key.ondelete == "RESTRICT"
        assert not columns.bound_at.nullable
        assert isinstance(columns.bound_at.type, DateTime)
        assert columns.bound_at.type.timezone
        assert str(columns.bound_at.server_default.arg) == "now()"
        binding = model(bound_by_user_id=user_id, bound_at=bound_at)
        assert binding.bound_by_user_id == user_id
        assert binding.bound_at == bound_at


def test_model_entrypoint_is_complete_without_database_connections_or_ddl() -> None:
    """
        在独立进程禁用网络连接、引擎创建和 DDL 后导入模型，避免已加载模型掩盖漏登记。

    :return: 无返回值；统一 Base 包含全部九张模型表且未加载应用数据库配置。
    """
    script = '''
import json
import sys
import sqlalchemy
import sqlalchemy.ext.asyncio

def reject_side_effect(*args, **kwargs):
    """
        阻止模型导入时创建引擎或执行数据库结构操作。

    :param args: 被阻止调用的位置参数。
    :param kwargs: 被阻止调用的关键字参数。
    :return: 不正常返回，立即终止具有副作用的导入。
    """
    raise AssertionError("model import must not create an engine or execute DDL")

def reject_connection(event, args):
    """
        拦截进程中的网络连接事件，模型登记不得访问外部服务。

    :param event: Python 审计事件名。
    :param args: 审计事件附带的数据，不输出其内容。
    :return: 非连接事件正常返回，网络连接立即失败。
    """
    if event == "socket.connect":
        raise AssertionError("model import must not connect to external services")

sys.addaudithook(reject_connection)
sqlalchemy.create_engine = reject_side_effect
sqlalchemy.ext.asyncio.create_async_engine = reject_side_effect
sqlalchemy.MetaData.create_all = reject_side_effect
sqlalchemy.MetaData.drop_all = reject_side_effect
from app.models.postgres import Base
assert not any(name.startswith("app.db.") for name in sys.modules)
assert "app.core.config" not in sys.modules
print(json.dumps(sorted(Base.metadata.tables)))
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, check=True, timeout=30)
    assert set(json.loads(result.stdout)) == {
        "users", "roles", "permissions", "role_permissions", "user_roles", "rbac_state", "operation_audit_events",
    }
