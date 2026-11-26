#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证用户角色操作和角色权限变更，不连接数据库或 Redis。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/24    XTN       V1.000        补充角色权限变更的幂等、版本和事务内审计回归
# 2026/10/24    XTN       V1.001        权限变更测试对齐 user_role_transaction 入口
# 2026/10/26    XTN       V1.002        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.role_service as role_service_module
from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.audit import RbacAuditAction
from app.core.ids import new_entity_id
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.role import Role, RolePermission
from app.repositories.postgres.permission_repository import permission_repository
from app.repositories.postgres.role_repository import role_repository
from app.services.role_service import RoleService
from app.services.user_service import UserService


async def test_change_user_roles_rejects_unknown_operation_before_transaction(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    session_factory = Mock()
    service = UserService(cast(async_sessionmaker[AsyncSession], session_factory))

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_user_roles(
            context=unprivileged_authorization_context,
            target_user_id=new_entity_id("U"),
            role_ids=(new_entity_id("R"),),
            operation="biind",
        )

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    (
        "operation", "before", "requested", "after", "new_bindings", "removed_bindings", "expected_version",
    ),
    [
        (
            "bind", ("projects:read",), ("projects:read", "projects:update", "projects:update"),
            ("projects:read", "projects:update"), ("projects:update",), (), 8,
        ),
        (
            "bind", ("projects:read",), ("projects:read",),
            ("projects:read",), (), (), 7,
        ),
        (
            "unbind", ("projects:read", "projects:update"), ("projects:read",),
            ("projects:update",), (), ("projects:read",), 8,
        ),
        (
            "unbind", ("projects:read",), ("projects:update",),
            ("projects:read",), (), (), 7,
        ),
    ],
    ids=("bind-new", "bind-existing", "unbind-existing", "unbind-missing"),
)
async def test_role_permission_changes_keep_bindings_version_and_audit_consistent(
    monkeypatch: pytest.MonkeyPatch,
    audit_request_context: str,
    operation: str,
    before: tuple[str, ...],
    requested: tuple[str, ...],
    after: tuple[str, ...],
    new_bindings: tuple[str, ...],
    removed_bindings: tuple[str, ...],
    expected_version: int,
) -> None:
    current_user_id, bound_user_id = new_entity_id("U"), new_entity_id("U")
    role_id = new_entity_id("R")
    permission_ids = {key: new_entity_id("P") for key in ("projects:read", "projects:update")}
    role = Role(
        id=role_id, key="project-reader", name="项目查询", description="项目角色", level=100,
        is_active=True, is_system=False, is_protected=False, is_super_admin=False,
        version=7, deleted_at=None,
    )
    role_info = RoleGrant(
        role_id=role_id, key=role.key, level=role.level, permissions=frozenset(before),
        is_system=False, is_protected=False, is_super_admin=False,
    )
    current_user = UserInfo.build(
        user_id=current_user_id, user_is_active=True, user_is_protected=False,
        roles=(RoleGrant(
            role_id=new_entity_id("R"), key="project-manager", level=500,
            permissions=frozenset({
                PermissionKey.ROLES_PERMISSIONS_BIND.value,
                PermissionKey.ROLES_PERMISSIONS_UNBIND.value,
                PermissionKey.PROJECTS_READ.value,
                PermissionKey.PROJECTS_UPDATE.value,
            }),
            is_system=False, is_protected=False, is_super_admin=False,
        ),),
    )
    bound_user = UserInfo.build(
        user_id=bound_user_id, user_is_active=True, user_is_protected=False, roles=(role_info,),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(
            user_id=current_user_id, token_version=0, token_id=uuid.uuid4(), issued_at=1, expires_at=2,
        ),
        user_info=current_user,
    )
    session = Mock(spec=AsyncSession)
    service = RoleService(cast(async_sessionmaker[AsyncSession], Mock()))
    locked_role = role_service_module._LockedRole(
        current_user=current_user, role=role, role_info=role_info,
        bound_users=(bound_user,), bound_user_ids=frozenset({bound_user_id}),
    )
    monkeypatch.setattr(service, "_lock_role", AsyncMock(return_value=locked_role))
    monkeypatch.setattr(
        permission_repository,
        "load_permission_keys",
        AsyncMock(return_value={permission_ids[key]: key for key in requested}),
    )
    unbind = AsyncMock()
    monkeypatch.setattr(role_repository, "unbind_permissions", unbind)
    added_bindings: list[RolePermission] = []
    audits: list[OperationAuditEvent] = []
    transaction_open = False
    stages: list[str] = []

    def add_bindings(bindings: Iterable[RolePermission]) -> None:
        assert transaction_open
        added_bindings.extend(bindings)

    def add_audit(event: OperationAuditEvent) -> None:
        assert transaction_open
        audits.append(event)
        stages.append("audit")

    @asynccontextmanager
    async def transaction(*_args: object, **_kwargs: object) -> AsyncIterator[AsyncSession]:
        nonlocal transaction_open
        transaction_open = True
        stages.append("begin")
        try:
            yield cast(AsyncSession, session)
            # 事务结束前必须已经加入成功审计，不能等返回结果后再补写。
            assert len(audits) == 1
        finally:
            transaction_open = False
            stages.append("end")

    session.add_all.side_effect = add_bindings
    session.add.side_effect = add_audit
    monkeypatch.setattr(role_service_module, "user_role_transaction", transaction)

    result = await service.change_role_permissions(
        context=context, role_id=role_id,
        permission_ids=tuple(permission_ids[key] for key in requested),
        operation=operation, expected_version=7,
    )

    assert stages == ["begin", "audit", "end"]
    assert {binding.permission_id for binding in added_bindings} == {permission_ids[key] for key in new_bindings}
    assert len(added_bindings) == len(new_bindings)
    assert all(binding.role_id == role_id and binding.bound_by_user_id == current_user_id for binding in added_bindings)
    if removed_bindings:
        unbind.assert_awaited_once()
        assert unbind.await_args is not None
        assert unbind.await_args.args == (session,)
        assert unbind.await_args is not None
        assert unbind.await_args.kwargs["role_id"] == role_id
        assert unbind.await_args is not None
        assert unbind.await_args.kwargs["permission_ids"] == frozenset(permission_ids[key] for key in removed_bindings)
        assert unbind.await_args is not None
        assert unbind.await_args.kwargs["deleted_by_user_id"] == current_user_id
        assert unbind.await_args is not None
        assert unbind.await_args.kwargs["deleted_at"].tzinfo is not None
    else:
        unbind.assert_not_awaited()
    assert role.version == result.role.version == expected_version
    assert result.role.permissions == tuple(sorted(after))
    audit = audits[0]
    expected_action = (RbacAuditAction.BIND_ROLE_PERMISSIONS if operation == "bind"
                       else RbacAuditAction.UNBIND_ROLE_PERMISSIONS)
    assert audit.action == expected_action.value
    assert audit.user_id == current_user_id
    assert audit.target_role_id == role_id
    assert audit.request_id == audit_request_context
    assert audit.outcome == "succeeded"
    assert audit.before_state is not None
    assert audit.after_state is not None
    assert audit.response_data is not None
    assert audit.before_state["permissions"] == sorted(before)
    assert audit.before_state["version"] == 7
    assert audit.after_state["permissions"] == audit.response_data["data"]["role"]["permissions"] == list(
        result.role.permissions
    )
    assert audit.after_state["version"] == audit.response_data["data"]["role"]["version"] == expected_version
    session.commit.assert_not_awaited()


async def test_role_permission_change_rejects_unknown_operation(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    session_factory = Mock()
    service = RoleService(cast(async_sessionmaker[AsyncSession], session_factory))

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_role_permissions(
            context=unprivileged_authorization_context,
            role_id=new_entity_id("R"),
            permission_ids=(new_entity_id("P"),),
            operation="biind",
            expected_version=0,
        )

    session_factory.assert_not_called()
