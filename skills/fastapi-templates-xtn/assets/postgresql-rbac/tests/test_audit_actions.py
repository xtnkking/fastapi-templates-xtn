#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    检查内置审计动作的原有字符串，以及服务在进入事务前选择的启停、绑定和解绑动作。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/24    XTN       V1.001        事务调用省略无关目标并保留实际审计动作和目标断言
# 2026/10/24    XTN       V1.002        审计动作测试对齐 user_role_transaction 入口
# --------------------------------------------------------------------------------------------------

from typing import cast
from unittest.mock import Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.audit import AccountAuditAction, RbacAuditAction, validate_audit_action
from app.core.ids import new_entity_id
from app.services import role_service, user_service


class _TransactionIntercepted(Exception):
    """
        仅供测试截停事务入口，避免执行会话创建、数据库查询或权限变更。
    """


@pytest.mark.parametrize("is_active,expected_action", [
    (True, "role.enable"),
    (False, "role.disable"),
])
async def test_role_status_selects_original_audit_action(monkeypatch: pytest.MonkeyPatch,
                                                         unprivileged_authorization_context: AuthorizationContext,
                                                         is_active: bool,
                                                         expected_action: str
                                                         ) -> None:
    """
        检查角色启停分支传入事务的原动作字符串，不执行事务内的权限检查或状态修改。

    :param monkeypatch: 临时替换角色服务使用的事务入口，测试后自动恢复。
    :param unprivileged_authorization_context: 没有角色授权的隔离测试身份。
    :param is_active: True 测试启用分支，False 测试禁用分支。
    :param expected_action: 该分支必须继续保存的原审计动作字符串。
    :return: 无返回值；动作及目标正确，且会话工厂没有被调用。
    """
    session_factory = Mock()
    service = role_service.RoleService(cast(async_sessionmaker[AsyncSession], session_factory))
    transaction = Mock(side_effect=_TransactionIntercepted)
    monkeypatch.setattr(role_service, "user_role_transaction", transaction)
    role_id = new_entity_id("R")

    # 在事务入口截停，只核对动作选择；不把无权限身份当成合法管理请求。
    with pytest.raises(_TransactionIntercepted):
        await service.set_role_active(context=unprivileged_authorization_context,
                                      role_id=role_id,
                                      is_active=is_active,
                                      expected_version=0)

    transaction.assert_called_once_with(session_factory,
                                        context=unprivileged_authorization_context,
                                        action=expected_action,
                                        target_role_id=role_id)
    session_factory.assert_not_called()


@pytest.mark.parametrize("operation,expected_action", [
    ("bind", "role.permissions.bind"),
    ("unbind", "role.permissions.unbind"),
])
async def test_role_permission_change_selects_original_audit_action(
    monkeypatch: pytest.MonkeyPatch,
    unprivileged_authorization_context: AuthorizationContext,
    operation: str,
    expected_action: str,
) -> None:
    """
        检查角色权限绑定和解绑各自选择原动作，不进入共享角色锁定或实际关系写入。

    :param monkeypatch: 临时替换角色服务使用的事务入口，测试后自动恢复。
    :param unprivileged_authorization_context: 没有角色授权的隔离测试身份。
    :param operation: bind 表示绑定权限，unbind 表示解绑权限。
    :param expected_action: 对应分支原有的审计动作字符串。
    :return: 无返回值；事务参数正确，且没有创建数据库会话。
    """
    session_factory = Mock()
    service = role_service.RoleService(cast(async_sessionmaker[AsyncSession], session_factory))
    transaction = Mock(side_effect=_TransactionIntercepted)
    monkeypatch.setattr(role_service, "user_role_transaction", transaction)
    role_id = new_entity_id("R")

    # 提供非空且格式正确的权限 ID，确保检查到真实动作分支而不是提前参数拒绝。
    with pytest.raises(_TransactionIntercepted):
        await service.change_role_permissions(context=unprivileged_authorization_context,
                                              role_id=role_id,
                                              permission_ids=(new_entity_id("P"),),
                                              operation=operation,
                                              expected_version=0)

    transaction.assert_called_once_with(session_factory,
                                        context=unprivileged_authorization_context,
                                        action=expected_action,
                                        target_role_id=role_id)
    session_factory.assert_not_called()


@pytest.mark.parametrize("operation,expected_action", [
    ("bind", "user.roles.bind"),
    ("unbind", "user.roles.unbind"),
])
async def test_user_role_change_selects_original_audit_action(monkeypatch: pytest.MonkeyPatch,
                                                              unprivileged_authorization_context: AuthorizationContext,
                                                              operation: str,
                                                              expected_action: str
                                                              ) -> None:
    """
        检查用户角色绑定和解绑使用不同原动作，不执行身份重查、锁定或实际授权。

    :param monkeypatch: 临时替换用户服务使用的事务入口，测试后自动恢复。
    :param unprivileged_authorization_context: 没有角色授权的隔离测试身份。
    :param operation: bind 表示分配角色，unbind 表示收回角色。
    :param expected_action: 对应分支原有的审计动作字符串。
    :return: 无返回值；动作和目标用户正确，且会话工厂没有被调用。
    """
    session_factory = Mock()
    service = user_service.UserService(cast(async_sessionmaker[AsyncSession], session_factory))
    transaction = Mock(side_effect=_TransactionIntercepted)
    monkeypatch.setattr(user_service, "user_role_transaction", transaction)
    user_id = new_entity_id("U")

    with pytest.raises(_TransactionIntercepted):
        await service.change_user_roles(context=unprivileged_authorization_context,
                                        target_user_id=user_id,
                                        role_ids=(new_entity_id("R"),),
                                        operation=operation)

    transaction.assert_called_once_with(session_factory,
                                        context=unprivileged_authorization_context,
                                        action=expected_action,
                                        target_user_id=user_id)
    session_factory.assert_not_called()


def test_rbac_action_catalog_preserves_stored_values() -> None:
    """
        保证十二种授权动作继续使用原记录值，并能通过现有审计动作格式校验。

    :return: 无返回值；目录没有丢失、重命名或重复动作。
    """
    expected = {
        "CREATE_USER": "user.create",
        "UPDATE_USER_STATUS": "user.status.update",
        "LOGOUT_USER_SESSIONS": "user.sessions.revoke",
        "BIND_USER_ROLES": "user.roles.bind",
        "UNBIND_USER_ROLES": "user.roles.unbind",
        "CREATE_ROLE": "role.create",
        "UPDATE_ROLE": "role.update",
        "ENABLE_ROLE": "role.enable",
        "DISABLE_ROLE": "role.disable",
        "DELETE_ROLE": "role.delete",
        "BIND_ROLE_PERMISSIONS": "role.permissions.bind",
        "UNBIND_ROLE_PERMISSIONS": "role.permissions.unbind",
    }
    assert {name: action.value for name, action in RbacAuditAction.__members__.items()} == expected
    assert len(set(expected.values())) == len(RbacAuditAction)
    for action in RbacAuditAction:
        assert validate_audit_action(action.value) == action.value


def test_account_action_catalog_preserves_stored_values() -> None:
    """
        保证五种账号安全动作继续使用原记录值，与授权动作目录保持各自业务归属。

    :return: 无返回值；账号目录完整，且原格式校验仍接受这些动作。
    """
    expected = {
        "REGISTER_USER": "account_security.registration.completed",
        "ADMIN_CREATE_USER": "account_security.registration.admin_created",
        "CHANGE_PASSWORD": "account_security.password.changed",
        "ADMIN_RESET_PASSWORD": "account_security.password.admin_reset",
        "OPERATOR_RESET_PASSWORD": "account_security.password.operator_reset",
    }
    assert {name: action.value for name, action in AccountAuditAction.__members__.items()} == expected
    assert len(set(expected.values())) == len(AccountAuditAction)
    for action in AccountAuditAction:
        assert validate_audit_action(action.value) == action.value


@pytest.mark.parametrize("action", ["api.update_role", "api.protected_write", "order.refund.requested"])
def test_dynamic_and_product_actions_remain_valid(action: str) -> None:
    """
        内置枚举不封死动态接口拒绝事件或项目自己的业务审计动作。

    :param action: 已有动态拒绝动作或符合格式的项目自定义动作。
    :return: 无返回值；现有通用校验仍返回原动作字符串。
    """
    assert validate_audit_action(action) == action
