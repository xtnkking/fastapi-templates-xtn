#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    直接调用真实用户和角色 Service，检查锁后身份变化、共享角色和批量目标的越权拒绝。
#    只用内存替代数据库读写和审计保存；不替换 Service、账号检查或授权策略。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/11/26    XTN       V1.000        新建
# 2026/11/27    XTN       V1.001        验证 admin 可作为无系统特权的自定义角色创建和管理
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext, LoginInfo, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SUPER_ADMIN_PERMISSION_KEYS
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.passwords import PasswordManager
from app.models.postgres.role import Role
from app.models.postgres.user import User
from app.repositories.postgres.permission_repository import permission_repository
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import UserDetails, UserPermissions, user_repository
from app.repositories.postgres.user_role_repository import user_role_repository
from app.schemas.role import RoleCreateRequest, RoleUpdateRequest
from app.services.audit_service import AuditService
from app.services.role_service import RoleService
from app.services.user_service import UserService

OPERATIONS = (
    "user-bind", "user-unbind", "user-enable", "user-disable", "user-reset", "user-logout", "user-create",
    "role-create", "role-update", "role-enable", "role-disable", "role-delete", "permission-bind", "permission-unbind",
)
ROLE_CHANGES = ("role-update", "role-enable", "role-disable", "role-delete", "permission-bind", "permission-unbind")


def grant(*, level: int, permissions: frozenset[str], role_id: str | None = None) -> RoleGrant:
    """创建明确等级及权限的普通角色，不使用系统角色特权绕过目标判断。"""
    return RoleGrant(
        role_id=role_id or new_entity_id("R"), key="custom_role", level=level, permissions=permissions,
        is_system=False, is_protected=False, is_super_admin=False,
    )


@dataclass
class ServiceWorld:
    """保存内存中的数据库读取结果和写入观察点，真实 Service 从这些资源继续执行。"""

    session: Mock
    user_service: UserService
    role_service: RoleService
    context: AuthorizationContext
    users: dict[str, User]
    infos: dict[str, UserInfo]
    roles: dict[str, Role]
    role_infos: dict[str, RoleGrant]
    target: User
    role: Role
    permission_id: str
    success_audit: Mock
    denied_audit: AsyncMock
    update_password: AsyncMock
    unbind_roles: AsyncMock
    unbind_permissions: AsyncMock
    role_lookup: AsyncMock
    password_hash: AsyncMock

    async def perform(self, operation: str, *, expected_version: int = 7) -> Any:
        """从公开 Service 方法进入，参数刻意有效，避免被格式错误提前拦住。"""
        if operation in ("user-bind", "user-unbind"):
            return await self.user_service.change_user_roles(
                context=self.context, target_user_id=self.target.user_id, role_ids=(self.role.id,),
                operation=operation.removeprefix("user-"),
            )
        if operation in ("user-enable", "user-disable"):
            return await self.user_service.update_user_status(
                context=self.context, target_user_id=self.target.user_id, is_active=operation == "user-enable",
            )
        if operation == "user-reset":
            return await self.user_service.reset_user_password(
                context=self.context, target_user_id=self.target.user_id, new_password="New-Password7!",
            )
        if operation == "user-logout":
            return await self.user_service.revoke_user_sessions(
                context=self.context, target_user_id=self.target.user_id,
            )
        if operation == "user-create":
            return await self.user_service.admin_create_user(
                context=self.context, user_name="new_member_42", password="New-Password7!",
            )
        if operation == "role-create":
            return await self.role_service.create_role(
                context=self.context, body=RoleCreateRequest(key="new_role", name="New role", level=100),
            )
        if operation == "role-update":
            return await self.role_service.update_role(
                context=self.context,
                body=RoleUpdateRequest(role_id=self.role.id, name="Renamed", expected_version=expected_version),
            )
        if operation in ("role-enable", "role-disable"):
            return await self.role_service.set_role_active(
                context=self.context, role_id=self.role.id, is_active=operation == "role-enable",
                expected_version=expected_version,
            )
        if operation == "role-delete":
            return await self.role_service.delete_role(
                context=self.context, role_id=self.role.id, expected_version=expected_version,
            )
        return await self.role_service.change_role_permissions(
            context=self.context, role_id=self.role.id, permission_ids=(self.permission_id,),
            operation=operation.removeprefix("permission-"), expected_version=expected_version,
        )

    def assert_no_write(self) -> None:
        """拒绝发生在任何数据库写入和成功审计之前，目标字段也不能被就地改变。"""
        self.session.add.assert_not_called()
        self.session.add_all.assert_not_called()
        self.session.flush.assert_not_awaited()
        self.update_password.assert_not_awaited()
        self.unbind_roles.assert_not_awaited()
        self.unbind_permissions.assert_not_awaited()
        self.success_audit.assert_not_called()
        assert (self.target.is_active, self.target.token_version) == (True, 3)
        assert (self.role.name, self.role.is_active, self.role.version, self.role.deleted_at) == (
            "Original", True, 7, None,
        )


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> ServiceWorld:
    """提供内存仓储资源；保留真实锁定流程、账号有效性检查和权限策略。"""
    session = Mock(spec=AsyncSession)

    @asynccontextmanager
    async def transaction() -> AsyncIterator[None]:
        yield None

    @asynccontextmanager
    async def session_context() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    session.begin.side_effect = transaction
    session.begin_nested.side_effect = transaction
    factory = cast(async_sessionmaker[AsyncSession], Mock(side_effect=session_context))
    current_id, target_id, role_id = new_entity_id("U"), new_entity_id("U"), new_entity_id("R")
    manager_role = grant(level=500, permissions=SUPER_ADMIN_PERMISSION_KEYS)
    target_role = grant(level=100, permissions=frozenset({PermissionKey.PROJECTS_READ.value}), role_id=role_id)
    current_info = UserInfo.build(
        user_id=current_id, user_is_active=True, user_is_protected=False, roles=(manager_role,),
    )
    target_info = UserInfo.build(
        user_id=target_id, user_is_active=True, user_is_protected=False, token_version=3, roles=(target_role,),
    )
    context = AuthorizationContext(
        login_info=LoginInfo(user_id=current_id, token_version=0, token_id=uuid.uuid4(), issued_at=1, expires_at=2),
        user_info=current_info,
    )
    users = {
        current_id: User(user_id=current_id, user_name="current_manager", is_active=True, token_version=0),
        target_id: User(user_id=target_id, user_name="target_member", is_active=True, token_version=3),
    }
    infos = {current_id: current_info, target_id: target_info}
    role = Role(
        id=role_id, key="project_reader", name="Original", description="Description", level=100,
        is_active=True, is_system=False, is_protected=False, is_super_admin=False, version=7, deleted_at=None,
    )
    roles = {role_id: role}
    role_infos = {role_id: target_role, manager_role.role_id: manager_role}

    async def lock_users(_session: AsyncSession, user_ids: set[str]) -> dict[str, User]:
        return {user_id: users[user_id] for user_id in user_ids if user_id in users}

    async def get_user(_session: AsyncSession, *, user_id: str, **_kwargs: object) -> User | None:
        return users.get(user_id)

    async def get_permissions(_session: AsyncSession, *, users: Sequence[User]) -> dict[str, UserPermissions]:
        return {user.user_id: UserPermissions(infos[user.user_id], infos[user.user_id]) for user in users}

    async def get_role_ids(_session: AsyncSession, *, user_ids: set[str],
                           role_ids: frozenset[str] | None = None) -> set[str]:
        found = {item.role_id for user_id in user_ids if user_id in infos for item in infos[user_id].roles}
        return found if role_ids is None else found & role_ids

    async def get_user_ids(_session: AsyncSession, *, role_id: str) -> set[str]:
        return {user_id for user_id, info in infos.items() if any(item.role_id == role_id for item in info.roles)}

    async def lock_roles(_session: AsyncSession, *, role_ids: set[str]) -> dict[str, Role]:
        return {role_id: roles[role_id] for role_id in role_ids if role_id in roles}

    async def get_role_permissions(_session: AsyncSession, *, roles: Sequence[Role]) -> dict[str, RoleGrant]:
        return {item.id: role_infos[item.id] for item in roles}

    async def get_users_info(_session: AsyncSession, *, users: Sequence[User],
                             current_user: UserInfo) -> dict[str, UserDetails]:
        return {
            user.user_id: UserDetails(
                user.user_name, tuple(item.role_id for item in infos[user.user_id].roles),
                replace(infos[user.user_id], user_is_active=user.is_active, token_version=user.token_version),
            ) for user in users
        }

    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock())
    monkeypatch.setattr(user_repository, "lock_users", AsyncMock(side_effect=lock_users))
    monkeypatch.setattr(user_repository, "get_user", AsyncMock(side_effect=get_user))
    monkeypatch.setattr(user_repository, "get_user_permissions", AsyncMock(side_effect=get_permissions))
    monkeypatch.setattr(user_repository, "get_users_info", AsyncMock(side_effect=get_users_info))
    monkeypatch.setattr(user_role_repository, "get_role_ids", AsyncMock(side_effect=get_role_ids))
    monkeypatch.setattr(user_role_repository, "get_user_ids", AsyncMock(side_effect=get_user_ids))
    monkeypatch.setattr(user_role_repository, "count_roles", AsyncMock(return_value=1))
    monkeypatch.setattr(role_repository, "lock_roles", AsyncMock(side_effect=lock_roles))
    monkeypatch.setattr(role_repository, "get_role_permissions", AsyncMock(side_effect=get_role_permissions))
    monkeypatch.setattr(role_repository, "lock_permission_bindings", AsyncMock())
    success_audit, denied_audit = Mock(), AsyncMock()
    monkeypatch.setattr(AuditService, "audit_success", success_audit)
    monkeypatch.setattr(AuditService, "audit_denied", denied_audit)
    update_password, unbind_roles, unbind_permissions = AsyncMock(), AsyncMock(), AsyncMock()
    monkeypatch.setattr(user_repository, "update_password", update_password)
    monkeypatch.setattr(user_role_repository, "unbind_roles", unbind_roles)
    monkeypatch.setattr(role_repository, "unbind_permissions", unbind_permissions)
    role_lookup = AsyncMock(return_value=None)
    monkeypatch.setattr(role_repository, "get_role_id_by_key", role_lookup)
    permission_id = new_entity_id("P")
    monkeypatch.setattr(permission_repository, "load_permission_keys", AsyncMock(
        return_value={permission_id: PermissionKey.PROJECTS_READ.value},
    ))
    password_manager = PasswordManager()
    password_hash = AsyncMock(return_value="$argon2id$not-used-by-these-tests")
    monkeypatch.setattr(password_manager, "hash_new_password", password_hash)
    return ServiceWorld(
        session, UserService(factory, password_manager), RoleService(factory), context, users, infos, roles, role_infos,
        users[target_id], role, permission_id, success_audit, denied_audit, update_password, unbind_roles,
        unbind_permissions, role_lookup, password_hash,
    )


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("changed_state", ("disabled", "token-version", "permission-revoked", "missing-account"))
async def test_old_context_cannot_authorize_after_locked_account_changes(
    world: ServiceWorld, operation: str, changed_state: str,
) -> None:
    """请求最初有全权限，锁后身份失效或权限被撤回；不存在目标和旧页面版本都不能掩盖拒绝。"""
    current_id = world.context.login_info.user_id
    assert world.context.permissions == SUPER_ADMIN_PERMISSION_KEYS
    if changed_state == "disabled":
        world.users[current_id].is_active = False
    elif changed_state == "token-version":
        world.users[current_id].token_version = 1
    elif changed_state == "permission-revoked":
        world.infos[current_id] = replace(world.infos[current_id], roles=(), permissions=frozenset(), role_level=0)
    else:
        world.users.pop(current_id)
    # 目标故意不存在、页面版本故意过期，必须仍先返回身份或权限错误。
    world.users.pop(world.target.user_id)
    world.roles.pop(world.role.id)
    with pytest.raises(AppError) as caught:
        await world.perform(operation, expected_version=0)
    assert caught.value.status_code == (403 if changed_state == "permission-revoked" else 401)
    if changed_state == "permission-revoked":
        assert caught.value.reason_code == "missing_operation_permission"
    world.assert_no_write()
    world.role_lookup.assert_not_awaited()
    if operation != "user-create":
        world.password_hash.assert_not_awaited()


@pytest.mark.parametrize("operation", ROLE_CHANGES)
@pytest.mark.parametrize(("boundary", "reason"), (
    ("self", "indirect_self_change_forbidden"),
    ("protected", "affected_subject_not_manageable"),
    ("peer", "affected_subject_not_strictly_lower"),
    ("higher", "affected_subject_not_strictly_lower"),
    ("outside-permissions", "permission_ceiling_exceeded"),
))
async def test_shared_role_checks_every_affected_user_before_version_or_writes(
    world: ServiceWorld, operation: str, boundary: str, reason: str,
) -> None:
    """共享角色本身可管理；混入任一不可管理持有者，整次修改必须拒绝且不先报告版本过期。"""
    # 原有低级持有者保留，再增加一名越界持有者，确保不是只检查第一名用户。
    affected_id = new_entity_id("U")
    affected_roles: tuple[RoleGrant, ...] = (world.role_infos[world.role.id],)
    if boundary == "self":
        current_id = world.context.login_info.user_id
        world.infos[current_id] = world.infos[current_id].with_role(world.role_infos[world.role.id])
    if boundary in ("peer", "higher"):
        affected_roles += (grant(level=500 if boundary == "peer" else 700, permissions=frozenset()),)
    if boundary == "outside-permissions":
        current_id = world.context.login_info.user_id
        current = world.infos[current_id]
        allowed = current.permissions - {PermissionKey.PROJECTS_UPDATE.value}
        world.infos[current_id] = UserInfo.build(
            user_id=current_id, user_is_active=True, user_is_protected=False,
            roles=(replace(current.roles[0], permissions=allowed),),
        )
        affected_roles += (grant(level=50, permissions=frozenset({PermissionKey.PROJECTS_UPDATE.value})),)
    world.users[affected_id] = User(user_id=affected_id, user_name="other_holder", is_active=True, token_version=0)
    world.infos[affected_id] = UserInfo.build(
        user_id=affected_id, user_is_active=True, user_is_protected=boundary == "protected", roles=affected_roles,
    )
    with pytest.raises(AppError) as caught:
        await world.perform(operation, expected_version=0)
    assert (caught.value.status_code, caught.value.reason_code) == (403, reason)
    world.assert_no_write()


@pytest.mark.parametrize("changed_state", ("disabled", "token-version", "permission-revoked", "missing-account"))
async def test_password_reset_rechecks_authority_after_password_work(
    world: ServiceWorld, changed_state: str,
) -> None:
    """首次有权重置也不够；计算密码期间被撤权或退出后，第二次事务必须拒绝保存。"""
    current_id = world.context.login_info.user_id

    def change_account_during_hash(*_args: object, **_kwargs: object) -> str:
        if changed_state == "disabled":
            world.users[current_id].is_active = False
        elif changed_state == "token-version":
            world.users[current_id].token_version += 1
        elif changed_state == "permission-revoked":
            current = world.infos[current_id]
            remaining = current.permissions - {PermissionKey.USERS_PASSWORD_RESET.value}
            world.infos[current_id] = UserInfo.build(
                user_id=current_id, user_is_active=True, user_is_protected=False,
                roles=(replace(current.roles[0], permissions=remaining),),
            )
        else:
            world.users.pop(current_id)
        return "$argon2id$test-hash"

    world.password_hash.side_effect = change_account_during_hash
    with pytest.raises(AppError) as caught:
        await world.perform("user-reset")
    assert caught.value.status_code == (403 if changed_state == "permission-revoked" else 401)
    world.password_hash.assert_awaited_once()
    world.denied_audit.assert_awaited_once()
    world.assert_no_write()


@pytest.mark.parametrize("operation", (
    "user-bind", "user-unbind", "user-enable", "user-disable", "user-reset", "user-logout",
))
@pytest.mark.parametrize(("boundary", "status"), (
    ("protected", 404), ("peer", 404), ("higher", 404), ("outside-permissions", 403),
))
async def test_user_writes_check_complete_target_authority(
    world: ServiceWorld, operation: str, boundary: str, status: int,
) -> None:
    """只有接口权限还不够，真实 Service 必须继续检查目标完整等级、保护和权限范围。"""
    target_info = world.infos[world.target.user_id]
    if boundary == "protected":
        world.infos[world.target.user_id] = replace(target_info, user_is_protected=True, is_protected=True)
    elif boundary in ("peer", "higher"):
        higher_role = grant(level=500 if boundary == "peer" else 700, permissions=frozenset())
        # 保留原低角色，额外高角色不能被忽略。
        world.infos[world.target.user_id] = target_info.with_role(higher_role)
    else:
        current_id = world.context.login_info.user_id
        current = world.infos[current_id]
        allowed = current.permissions - {PermissionKey.PROJECTS_UPDATE.value}
        world.infos[current_id] = UserInfo.build(
            user_id=current_id, user_is_active=True, user_is_protected=False,
            roles=(replace(current.roles[0], permissions=allowed),),
        )
        world.infos[world.target.user_id] = target_info.with_role(
            grant(level=50, permissions=frozenset({PermissionKey.PROJECTS_UPDATE.value})),
        )
    with pytest.raises(AppError) as caught:
        await world.perform(operation)
    assert caught.value.status_code == status
    if boundary == "outside-permissions":
        assert caught.value.reason_code == "permission_ceiling_exceeded"
    world.assert_no_write()
    world.password_hash.assert_not_awaited()


@pytest.mark.parametrize("operation", ("bind", "unbind"))
async def test_user_cannot_bind_or_unbind_a_low_role_with_unheld_permissions(
    world: ServiceWorld, operation: str,
) -> None:
    """角色等级低且看得见，也不能操作含有自己未持有权限的角色。"""
    current_id = world.context.login_info.user_id
    current = world.infos[current_id]
    world.infos[current_id] = UserInfo.build(
        user_id=current_id, user_is_active=True, user_is_protected=False,
        roles=(replace(current.roles[0], permissions=current.permissions - {PermissionKey.PROJECTS_READ.value}),),
    )
    with pytest.raises(AppError) as caught:
        await world.user_service.change_user_roles(
            context=world.context, target_user_id=world.target.user_id, role_ids=(world.role.id,), operation=operation,
        )
    assert (caught.value.status_code, caught.value.reason_code) == (403, "permission_ceiling_exceeded")
    world.assert_no_write()


@pytest.mark.parametrize("operation", ("bind", "unbind"))
@pytest.mark.parametrize("hidden_kind", ("missing", "peer", "higher", "protected"))
async def test_user_role_batch_never_applies_visible_subset(
    world: ServiceWorld, operation: str, hidden_kind: str,
) -> None:
    """一次提交含可见角色和不可见角色时，不能只处理其中可见的部分。"""
    hidden_id = new_entity_id("R")
    if hidden_kind != "missing":
        hidden_role = grant(level=700 if hidden_kind == "higher" else 500 if hidden_kind == "peer" else 50,
                            permissions=frozenset(), role_id=hidden_id)
        if hidden_kind == "protected":
            hidden_role = replace(hidden_role, is_protected=True)
        world.role_infos[hidden_id] = hidden_role
        world.roles[hidden_id] = Role(id=hidden_id, is_active=True, deleted_at=None)
    with pytest.raises(AppError) as caught:
        await world.user_service.change_user_roles(
            context=world.context, target_user_id=world.target.user_id,
            role_ids=(world.role.id, hidden_id), operation=operation,
        )
    assert (caught.value.status_code, caught.value.reason_code) == (404, "role_not_found")
    world.assert_no_write()


@pytest.mark.parametrize("operation", ("user-bind", "user-unbind", "user-disable", "user-logout", *ROLE_CHANGES))
async def test_valid_lower_targets_still_succeed(world: ServiceWorld, operation: str) -> None:
    """用相同资源和真实策略验证合法下级可以操作，避免拒绝测试因无条件报错而假通过。"""
    response = await world.perform(operation)
    world.success_audit.assert_called_once()
    world.denied_audit.assert_not_awaited()
    if operation == "user-disable":
        assert (world.target.is_active, world.target.token_version) == (False, 4)
    elif operation == "user-logout":
        assert world.target.token_version == 4
    elif operation == "role-update":
        assert (world.role.name, world.role.version) == ("Renamed", 8)
    elif operation == "role-disable":
        assert (world.role.is_active, world.role.version) == (False, 8)
    elif operation == "role-delete":
        assert world.role.deleted_at is not None
        assert world.role.version == 8
    if operation in ROLE_CHANGES:
        assert response.role.id == world.role.id


async def test_admin_key_can_create_an_ordinary_role_without_default_permissions(world: ServiceWorld) -> None:
    """admin 只是可用的自定义标识，500 只是本次输入，创建时不附送管理权限或系统身份。"""
    current_id = world.context.login_info.user_id
    current = world.infos[current_id]
    world.infos[current_id] = replace(current, roles=(replace(current.roles[0], level=800),), role_level=800)

    async def apply_insert_defaults() -> None:
        inserted = world.session.add.call_args.args[0]
        assert isinstance(inserted, Role)
        inserted.version = 0
        inserted.deleted_at = None

    world.session.flush.side_effect = apply_insert_defaults
    response = await world.role_service.create_role(
        context=world.context,
        body=RoleCreateRequest(key="admin", name="Custom administrator", level=500),
    )

    assert response.role.key == "admin"
    assert response.role.level == 500
    assert not response.role.is_system
    assert not response.role.is_protected
    assert response.role.permissions == ()
    inserted = world.session.add.call_args.args[0]
    assert isinstance(inserted, Role) and not inserted.is_super_admin
    world.role_lookup.assert_awaited_once_with(world.session, key="admin")
    world.session.add_all.assert_not_called()
    world.success_audit.assert_called_once()
    world.denied_audit.assert_not_awaited()


@pytest.mark.parametrize("operation", ["role-update", "role-disable", "role-delete"])
async def test_custom_admin_role_remains_editable_and_deletable(world: ServiceWorld, operation: str) -> None:
    """更高且有权限的用户可以管理名为 admin 的自定义角色，不再套用系统角色保护。"""
    world.role.key = "admin"
    world.role_infos[world.role.id] = replace(world.role_infos[world.role.id], key="admin")
    response = await world.perform(operation)

    assert response.role.key == "admin"
    assert not response.role.is_system
    assert not response.role.is_protected
    world.success_audit.assert_called_once()
    world.denied_audit.assert_not_awaited()
    if operation == "role-update":
        assert world.role.name == "Renamed"
    elif operation == "role-disable":
        assert not world.role.is_active
    else:
        assert world.role.deleted_at is not None
