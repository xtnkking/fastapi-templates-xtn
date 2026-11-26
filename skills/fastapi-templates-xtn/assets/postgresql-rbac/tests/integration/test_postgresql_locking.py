#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证 PostgreSQL 权限写入的锁顺序、并发撤权和目标集合刷新。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/15    XTN       V1.000        移除用户权限版本并补充实际维护说明
# 2026/10/16    XTN       V1.001        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/24    XTN       V1.002        角色加锁查询使用简短的 _lock_role 入口
# 2026/10/26    XTN       V1.003        权限结果字段明确区分有效用户信息与包含停用角色的信息
# --------------------------------------------------------------------------------------------------

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text, update

from app.core.access.authorization import AuthorizationContext, LoginInfo
from app.core.access.permissions import PermissionKey
from app.core.exceptions import AppError
from app.db.postgres_db import SessionFactory
from app.models.postgres.permission import Permission
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.role_service import RoleService
from app.services.user_service import UserService
from tests.integration.conftest import World
from tests.integration.query_capture import capture_selects

pytestmark = [pytest.mark.postgresql, pytest.mark.usefixtures("audit_request_context")]


async def context_for(world: World, user_name: str) -> AuthorizationContext:
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users[user_name].user_id)
        assert user is not None
        user_info = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    return AuthorizationContext(
        login_info=LoginInfo(
            user_id=world.users[user_name].user_id,
            token_version=world.users[user_name].token_version,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )


async def test_engine_uses_required_read_committed_isolation() -> None:
    async with SessionFactory() as session:
        isolation = await session.scalar(text("SHOW transaction_isolation"))

    assert isolation == "read committed"


async def test_user_lock_reloads_preloaded_identity_map(world: World) -> None:
    user_id = world.users["lower"].user_id
    async with SessionFactory() as first_session:
        stale = await first_session.get(User, user_id)
        assert stale is not None
        assert stale.is_active

        async with SessionFactory() as second_session:
            async with second_session.begin():
                await second_session.execute(
                    update(User).where(User.user_id == user_id).values(is_active=False)
                )

        locked = await user_repository.lock_users(first_session, {user_id})

        assert locked[user_id] is stale
        assert not locked[user_id].is_active


async def test_global_guard_serializes_authorization_changes() -> None:
    attempted = asyncio.Event()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await rbac_state_repository.lock_rbac_state(first_session)

            async def take_same_guard() -> None:
                async with SessionFactory() as second_session:
                    async with second_session.begin():
                        attempted.set()
                        await rbac_state_repository.lock_rbac_state(second_session)

            second_writer = asyncio.create_task(take_same_guard())
            await attempted.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(second_writer), timeout=0.1)

        await asyncio.wait_for(second_writer, timeout=2)


async def test_current_user_role_revocation_commits_before_waiting_mutation(world: World) -> None:
    context = await context_for(world, "manager")
    service = UserService(SessionFactory)
    manager_user_id = world.users["manager"].user_id
    manager_role_id = world.roles["manager"].id

    async with SessionFactory() as revocation_session:
        async with revocation_session.begin():
            await rbac_state_repository.lock_rbac_state(revocation_session)
            users = await user_repository.lock_users(
                revocation_session, {manager_user_id}
            )
            await role_repository.lock_roles(
                revocation_session, role_ids={manager_role_id}
            )
            assignment = await revocation_session.scalar(
                select(UserRole).where(
                    UserRole.user_id == manager_user_id,
                    UserRole.role_id == manager_role_id,
                    UserRole.deleted_at.is_(None),
                )
            )
            assert assignment is not None
            assignment.deleted_at = datetime.now(UTC)
            assignment.deleted_by_user_id = world.users["super_admin"].user_id
            assert manager_user_id in users

            waiting_mutation = asyncio.create_task(
                service.change_user_roles(
                    context=context,
                    target_user_id=world.users["blank"].user_id,
                    role_ids=(world.roles["viewer"].id,),
                    operation="bind",
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(waiting_mutation),
                    timeout=0.1,
                )

    with pytest.raises(AppError) as caught:
        await asyncio.wait_for(waiting_mutation, timeout=2)
    assert caught.value.status_code == 403

    async with SessionFactory() as session:
        forbidden_assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].user_id,
                UserRole.role_id == world.roles["viewer"].id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert forbidden_assignment is None


async def test_shared_role_change_observes_new_high_authority_holder(world: World) -> None:
    async with SessionFactory() as setup_session:
        async with setup_session.begin():
            shared_role = Role(
                key="race-shared-role",
                name="Race shared role",
                level=30,
            )
            setup_session.add(shared_role)
            await setup_session.flush()
            setup_session.add_all(
                [
                    RolePermission(
                        role_id=shared_role.id,
                        permission_id=world.permissions[
                            PermissionKey.PROJECTS_READ.value
                        ].id,
                    ),
                    UserRole(
                        user_id=world.users["lower"].user_id,
                        role_id=shared_role.id,
                        bound_by_user_id=world.users["manager"].user_id,
                    ),
                ]
            )

    context = await context_for(world, "manager")
    service = RoleService(SessionFactory)
    high_user_id = world.users["higher"].user_id

    async with SessionFactory() as writer_session:
        async with writer_session.begin():
            await rbac_state_repository.lock_rbac_state(writer_session)
            users = await user_repository.lock_users(writer_session, {high_user_id})
            await role_repository.lock_roles(writer_session, role_ids={shared_role.id})

            waiting_change = asyncio.create_task(
                service.change_role_permissions(
                    context=context,
                    role_id=shared_role.id,
                    permission_ids=(
                        world.permissions[PermissionKey.PROJECTS_UPDATE.value].id,
                    ),
                    operation="bind",
                    expected_version=0,
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(waiting_change),
                    timeout=0.1,
                )

            writer_session.add(
                UserRole(
                    user_id=high_user_id,
                    role_id=shared_role.id,
                    bound_by_user_id=None,
                )
            )
            assert high_user_id in users

    with pytest.raises(AppError) as caught:
        await asyncio.wait_for(waiting_change, timeout=2)
    assert caught.value.status_code == 403

    async with SessionFactory() as session:
        granted_keys = set(
            (
                await session.scalars(
                    select(Permission.key)
                    .select_from(RolePermission)
                    .join(Permission, Permission.id == RolePermission.permission_id)
                    .where(
                        RolePermission.role_id == shared_role.id,
                        RolePermission.deleted_at.is_(None),
                        Permission.deleted_at.is_(None),
                    )
                )
            ).all()
        )
    assert granted_keys == {PermissionKey.PROJECTS_READ.value}


async def test_shared_role_lock_select_count_does_not_grow_with_holders(world: World) -> None:
    shared_role = Role(
        key="query-count-shared-role",
        name="Query count shared role",
        level=25,
    )
    async with SessionFactory() as session:
        async with session.begin():
            session.add(shared_role)
            await session.flush()
            session.add(
                UserRole(
                    user_id=world.users["lower"].user_id,
                    role_id=shared_role.id,
                    bound_by_user_id=world.users["super_admin"].user_id,
                )
            )

    context = await context_for(world, "manager")
    service = RoleService(SessionFactory)

    async def lock_select_count() -> int:
        with capture_selects() as statements:
            async with SessionFactory() as session:
                async with session.begin():
                    await service._lock_role(
                        session,
                        context=context,
                        role_id=shared_role.id,
                        required_permission=PermissionKey.ROLES_UPDATE,
                    )
        return len(statements)

    one_holder_count = await lock_select_count()

    async with SessionFactory() as session:
        async with session.begin():
            session.add_all(
                UserRole(
                    user_id=world.users[name].user_id,
                    role_id=shared_role.id,
                    bound_by_user_id=world.users["super_admin"].user_id,
                )
                for name in ("junior", "blank", "disabled", "newcomer")
            )

    five_holder_count = await lock_select_count()

    assert one_holder_count > 0
    assert five_holder_count == one_holder_count
