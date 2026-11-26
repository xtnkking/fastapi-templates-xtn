#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查数据库约束名提取，以及用户、默认角色关系、审计和角色 ID 碰撞的有限保存点重试。
#    使用隔离会话与仓储替身，不连接数据库，不生成或执行迁移。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/10    XTN       V1.001        统一用户 ID 与当前用户命名
# 2026/10/15    XTN       V1.002        验证用户创建归并后的约束重试、默认绑定及审计
# 2026/10/15    XTN       V1.003        验证首次用户插入包含初始密码哈希和数据库时间
# 2026/10/16    XTN       V1.004        用户 ID 改为服务内生成后保留有限碰撞重试覆盖
# 2026/10/16    XTN       V1.005        直接服务调用使用入口请求上下文关联审计
# 2026/10/16    XTN       V1.006        验证默认角色缺失或不可用时不建立绑定和成功审计
# 2026/10/16    XTN       V1.007        验证共享创建转换用户名冲突及单次加锁查询默认角色
# 2026/10/16    XTN       V1.008        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/24    XTN       V1.009        角色创建测试替身使用 get_role_ids 查询绑定角色
# 2026/10/24    XTN       V1.010        角色创建输入统一使用 body 参数
# 2026/10/24    XTN       V1.011        角色创建测试对齐 user_role_transaction 入口
# --------------------------------------------------------------------------------------------------

from dataclasses import replace
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SystemRoleKey
from app.core.codes import BusinessCode
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.db.postgres_db import get_constraint_name
from app.models.postgres.role import Role
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import user_repository
from app.repositories.postgres.user_role_repository import user_role_repository
from app.schemas.role import RoleCreateRequest
from app.services import role_service, user_service

pytestmark = pytest.mark.usefixtures("audit_request_context")


def _integrity_error(constraint: object, cause_constraint: object = None) -> IntegrityError:
    """
        模拟驱动直接异常和 SQLAlchemy 包装原因上的约束元数据。
        错误消息故意包含用户名约束名称，防止实现通过解析文案误判约束。

    :param constraint: 原异常的约束名，可用非字符串模拟缺失或异常元数据。
    :param cause_constraint: 包装前原因上的约束名；None 表示原因未提供可用名称。
    :return: 携带指定元数据、尚未执行任何数据库命令的完整性异常。
    """
    original = RuntimeError("duplicate key for uq_users_user_name")
    original.constraint_name = constraint  # type: ignore[attr-defined]
    original.__cause__ = RuntimeError("wrapped database error")
    original.__cause__.constraint_name = cause_constraint  # type: ignore[attr-defined]
    return IntegrityError("INSERT", {}, original)


@pytest.mark.parametrize("constraint,cause_constraint,expected", [
    ("uq_users_user_name", None, "uq_users_user_name"),
    (None, "uq_users_user_name", "uq_users_user_name"),
    (123, "pk_users", "pk_users"),
    ("pk_users", "uq_users_user_name", "pk_users"),
    ("", "uq_users_user_name", ""),
    (None, None, None),
    (123, 456, None),
    ("uq_users_user_name_extra", None, "uq_users_user_name_extra"),
])
def test_constraint_metadata_priority(constraint: object,
                                      cause_constraint: object,
                                      expected: str | None
                                      ) -> None:
    """
        核对直接异常与包装原因的约束名提取顺序，不解析错误消息。

    :param constraint: 原异常直接提供的约束元数据。
    :param cause_constraint: 原异常原因提供的约束元数据。
    :param expected: 应提取的约束名称；没有字符串时应为 None。
    :return: 无返回值；元数据提取优先级符合合同。
    """
    error = _integrity_error(constraint, cause_constraint)
    assert get_constraint_name(error) == expected


def test_constraint_absence_does_not_parse_error_message() -> None:
    """
        原异常及原因完全没有约束属性时，不因文案提到用户名约束就误报用户名占用。

    :return: 无返回值；缺失元数据返回 None。
    """
    error = IntegrityError("INSERT", {}, RuntimeError("uq_users_user_name"))
    assert get_constraint_name(error) is None


@pytest.fixture
def user_create_session(monkeypatch: pytest.MonkeyPatch) -> tuple[Mock, SimpleNamespace]:
    """
        准备用户创建所需的独立保存点和已初始化默认角色，不执行外层提交。

    :param monkeypatch: 临时替换状态、用户名和角色仓储查询，测试后自动恢复。
    :return: 可配置 flush 失败的隔离会话，以及全局协调锁的状态对象。
    """
    session = Mock(spec=AsyncSession)
    session.in_transaction.return_value = True
    session.begin_nested.return_value = AsyncMock()
    session.flush = AsyncMock()
    state = SimpleNamespace(scope="global")
    default_role = Role(id=new_entity_id("R"), key=SystemRoleKey.USER.value,
                        is_system=True, is_protected=False, is_super_admin=False,
                        is_active=True, level=0, deleted_at=None)
    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state",
                        AsyncMock(return_value=state))
    monkeypatch.setattr(user_repository, "user_name_exists", AsyncMock(return_value=False))
    monkeypatch.setattr(role_repository, "lock_role_by_key",
                        AsyncMock(return_value=default_role))
    return session, state


@pytest.mark.parametrize("stage,constraint,failures,succeeds", [
    ("user", "pk_users", 2, True),
    ("user", "pk_users", 3, False),
    ("user", "uq_users_user_name", 1, False),
    ("user", "uq_users_user_name_extra", 1, False),
    ("user", None, 1, False),
    ("assignment", "pk_user_roles", 2, True),
    ("assignment", "pk_user_roles", 3, False),
    ("assignment", "pk_operation_audit_events", 1, False),
    ("assignment", "uq_user_roles_live_pair", 1, False),
])
async def test_user_creation_retries_only_generated_id_collisions(user_create_session: tuple[Mock, SimpleNamespace],
                                                                  stage: str,
                                                                  constraint: str | None,
                                                                  failures: int,
                                                                  succeeds: bool
                                                                  ) -> None:
    """
        只对各自主键碰撞重试，最多三次；用户名占用转业务错误，其他约束保持原异常。
        用户 ID 由服务内部生成，保存点失败后才换 ID。

    :param user_create_session: 不连接数据库的会话及全局协调锁记录。
    :param stage: user 在用户插入阶段失败，assignment 在默认关系插入阶段失败。
    :param constraint: 模拟数据库提供的真实约束名。
    :param failures: 指定阶段连续发生的碰撞次数。
    :param succeeds: 是否应在第三次以内写入成功。
    :return: 无返回值；重试次数、保存点退出、错误身份和事务边界符合原行为。
    """
    session, _state = user_create_session
    error = _integrity_error(None, constraint)
    preceding_flushes = 1 if stage == "assignment" else 0
    session.flush.side_effect = [None] * preceding_flushes + [error] * failures + [None, None]
    service = user_service.UserService(cast(async_sessionmaker[AsyncSession], Mock()))

    if succeeds:
        user = await service.create_user(cast(AsyncSession, session),
                                         user_name="learner_42",
                                         password_hash="$argon2id$prepared-test-hash")
        assert user is next(call.args[0] for call in reversed(session.add.call_args_list)
                            if isinstance(call.args[0], User))
    else:
        expected_error = AppError if stage == "user" and constraint == "uq_users_user_name" else IntegrityError
        with pytest.raises(expected_error) as caught:
            await service.create_user(cast(AsyncSession, session),
                                      user_name="learner_42",
                                      password_hash="$argon2id$prepared-test-hash")
        if isinstance(caught.value, AppError):
            assert caught.value.status_code == 409
            assert caught.value.business_code == BusinessCode.USER_CREATE_CONFLICT
            assert caught.value.__cause__ is error
        else:
            assert caught.value is error

    # 每次 INSERT 都在保存点内；拒绝重试时不能回滚或提交调用方的整个事务。
    attempts = failures + 1 if succeeds else (3 if failures == 3 else 1)
    expected_user_attempts = attempts if stage == "user" else 1
    expected_assignment_attempts = (1 if succeeds else 0) if stage == "user" else attempts
    assert session.add.call_count == expected_user_attempts + expected_assignment_attempts
    session.add_all.assert_not_called()
    assert session.begin_nested.call_count == expected_user_attempts + expected_assignment_attempts
    assert session.flush.await_count == session.begin_nested.call_count
    savepoint_exits = session.begin_nested.return_value.__aexit__.await_args_list
    assert sum(call.args[1] is error for call in savepoint_exits) == min(failures, attempts)
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()

    user_ids = [call.args[0].user_id for call in session.add.call_args_list if isinstance(call.args[0], User)]
    assert len(set(user_ids)) == expected_user_attempts
    # 关系插入失败时重建关系 ID；共享创建不再额外记录一条重复账号审计。
    assignments = [call.args[0].id for call in session.add.call_args_list if isinstance(call.args[0], UserRole)]
    assert len(set(assignments)) == expected_assignment_attempts


@pytest.mark.parametrize("admin_binding", [False, True])
async def test_shared_creation_keeps_binding_without_duplicate_audit(user_create_session: tuple[Mock, SimpleNamespace],
                                                                     monkeypatch: pytest.MonkeyPatch,
                                                                     admin_binding: bool,
                                                                     ) -> None:
    """
        注册和管理员新增共用同一创建规则，默认角色与绑定操作人保持一致；审计由外层记录。

    :param user_create_session: 已开启事务的隔离会话及全局协调锁记录，不连接数据库。
    :param monkeypatch: 替换管理员行锁查询，避免访问真实 PostgreSQL。
    :param admin_binding: True 表示管理员新增；False 表示用户自行注册。
    :return: 无返回值；默认绑定完整，共享创建不插入重复审计，外层事务仍由调用方管理。
    """
    session, _state = user_create_session
    bound_by_user_id = new_entity_id("U") if admin_binding else None
    lock_users = AsyncMock(return_value={bound_by_user_id: object()} if bound_by_user_id else {})
    monkeypatch.setattr(user_repository, "lock_users", lock_users)
    session_factory = Mock()
    service = user_service.UserService(cast(async_sessionmaker[AsyncSession], session_factory))
    password_hash = "$argon2id$prepared-test-hash"

    def check_initial_user_insert(user: object) -> None:
        """首次发送用户写入时已经带密码，不依赖后续 UPDATE 补上。"""
        if isinstance(user, User):
            assert user.password_hash == password_hash
            assert str(user.password_changed_at) == "statement_timestamp()"

    session.add.side_effect = check_initial_user_insert

    user = await service.create_user(cast(AsyncSession, session), user_name="  learner_42  ",
                                     password_hash=password_hash,
                                     bound_by_user_id=bound_by_user_id)

    assert user.user_name == "learner_42"
    assert user.user_id.startswith("U")
    assert user.is_active is True
    assert user.is_protected is False
    assert user.token_version == 0
    assert session.add.call_count == 2
    assert session.add.call_args_list[0].args[0] is user
    binding = session.add.call_args_list[1].args[0]
    assert isinstance(binding, UserRole)
    session.add_all.assert_not_called()
    assert binding.user_id == user.user_id
    assert binding.role_id == cast(AsyncMock, role_repository.lock_role_by_key).return_value.id
    cast(AsyncMock, role_repository.lock_role_by_key).assert_awaited_once_with(session, key=SystemRoleKey.USER.value)
    assert binding.bound_by_user_id == bound_by_user_id
    cast(AsyncMock, rbac_state_repository.lock_rbac_state).assert_awaited_once_with(session)
    if bound_by_user_id:
        lock_users.assert_awaited_once_with(session, {bound_by_user_id})
    else:
        lock_users.assert_not_awaited()
    assert session.flush.await_count == 2
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()
    session_factory.assert_not_called()


@pytest.mark.parametrize("role_state,expected_error", [
    ("missing", AppError),
    ("inactive", RuntimeError),
    ("not_system", RuntimeError),
])
async def test_user_creation_rejects_unavailable_default_role(user_create_session: tuple[Mock, SimpleNamespace],
                                                              role_state: str,
                                                              expected_error: type[Exception]
                                                              ) -> None:
    """
        默认角色必须能查到且是启用中的系统角色，否则不建立绑定或记录成功。

    :param user_create_session: 隔离会话和全局协调锁记录，不连接真实数据库。
    :param role_state: 模拟加锁查询找不到角色、角色停用或非系统角色。
    :param expected_error: 缺失时返回业务错误，角色配置不可用时抛出配置异常。
    :return: 无返回值；失败不记录绑定或成功审计，外层事务仍由调用方回滚。
    """
    session, _state = user_create_session
    if role_state == "missing":
        cast(AsyncMock, role_repository.lock_role_by_key).return_value = None
    else:
        role = cast(AsyncMock, role_repository.lock_role_by_key).return_value
        role.is_active = role_state != "inactive"
        role.is_system = role_state != "not_system"

    service = user_service.UserService(cast(async_sessionmaker[AsyncSession], Mock()))
    with pytest.raises(expected_error):
        await service.create_user(cast(AsyncSession, session), user_name="learner_42",
                                  password_hash="$argon2id$prepared-test-hash")

    session.add_all.assert_not_called()
    cast(AsyncMock, rbac_state_repository.lock_rbac_state).assert_awaited_once_with(session)
    session.commit.assert_not_awaited()


@pytest.mark.parametrize("constraint,failures,succeeds", [
    ("pk_roles", 2, True),
    ("pk_roles", 3, False),
    ("uq_roles_key", 1, False),
])
async def test_role_creation_preserves_retry_boundary(monkeypatch: pytest.MonkeyPatch,
                                                      unprivileged_authorization_context: AuthorizationContext,
                                                      constraint: str,
                                                      failures: int,
                                                      succeeds: bool
                                                      ) -> None:
    """
        对合法的角色创建身份模拟插入失败，只在角色主键碰撞时有限重试并更新审计目标。
        实际权限判断保留；仓储返回固定隔离数据，保存点不访问真实数据库。

    :param monkeypatch: 临时替换事务入口和数据库查询，测试后自动恢复。
    :param unprivileged_authorization_context: 隔离身份模板，复制后仅授予创建角色所需能力。
    :param constraint: 插入失败时驱动报告的约束名。
    :param failures: 连续失败次数，三次失败必须终止。
    :param succeeds: 是否应成功创建角色并更新审计目标 ID。
    :return: 无返回值；重试、错误身份、角色响应及审计目标符合原合同。
    """
    context = replace(unprivileged_authorization_context,
                      user_info=replace(unprivileged_authorization_context.user_info,
                                        role_level=500,
                                        permissions=frozenset({PermissionKey.ROLES_CREATE.value})))
    user_id = context.login_info.user_id
    current_user_row = User(user_id=user_id, user_name="manager_42", is_active=True,
                            deleted_at=None, token_version=context.login_info.token_version)
    session = Mock(spec=AsyncSession)
    session.begin_nested.return_value = AsyncMock()
    error = _integrity_error(None, constraint)
    session.flush = AsyncMock(side_effect=[error] * failures + [None])
    transaction = AsyncMock()
    transaction.__aenter__.return_value = session
    monkeypatch.setattr(role_service, "user_role_transaction", Mock(return_value=transaction))
    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock())
    monkeypatch.setattr(user_repository, "lock_users", AsyncMock(return_value={user_id: current_user_row}))
    monkeypatch.setattr(user_role_repository,
                        "get_role_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr(role_repository, "lock_roles", AsyncMock(return_value={}))
    monkeypatch.setattr(user_repository, "check_current_user",
                        AsyncMock(return_value=context.user_info))
    monkeypatch.setattr(role_repository, "get_role_id_by_key", AsyncMock(return_value=None))

    def fill_role_default(role: object) -> None:
        """
            补充真实 flush 会生成的版本默认值，供成功分支继续构建响应。

        :param role: 本次保存点尝试插入的角色。
        :return: 无返回值；角色版本设为初始值，不模拟真实约束或提交。
        """
        if isinstance(role, Role):
            role.version = 0

    session.add.side_effect = fill_role_default
    service = role_service.RoleService(cast(async_sessionmaker[AsyncSession], Mock()))
    body = RoleCreateRequest(key="editors", name="编辑", level=1)
    if succeeds:
        result = await service.create_role(context=context, body=body)
        audit = session.add.call_args.args[0]
        assert result.role.id == session.add.call_args_list[-2].args[0].id
        assert audit.target_role_id == result.role.id
        assert audit.reason_code == "role_created"
    else:
        with pytest.raises(IntegrityError) as caught:
            await service.create_role(context=context, body=body)
        assert caught.value is error

    attempts = failures + 1 if succeeds else (3 if failures == 3 else 1)
    assert session.add.call_count == attempts + int(succeeds)
    assert session.begin_nested.call_count == attempts
    assert session.flush.await_count == attempts
    assert len({call.args[0].id for call in session.add.call_args_list
                if isinstance(call.args[0], Role)}) == attempts
    savepoint_exits = session.begin_nested.return_value.__aexit__.await_args_list
    assert sum(call.args[1] is error for call in savepoint_exits) == min(failures, attempts)
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()
