#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证用户最多十个有效角色及失败操作不改变角色关系。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/15    XTN       V1.000        移除用户权限版本并补充实际维护说明
# 2026/10/16    XTN       V1.001        授权服务使用显式请求上下文关联审计
# 2026/10/16    XTN       V1.002        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/26    XTN       V1.003        权限结果字段明确区分有效用户信息与包含停用角色的信息
# --------------------------------------------------------------------------------------------------

import asyncio
import uuid
from datetime import UTC, datetime

import asyncpg  # type: ignore[import-untyped]
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core.access.authorization import AuthorizationContext, LoginInfo
from app.core.access.roles import MAX_ROLES_PER_USER, SystemRoleKey
from app.core.exceptions import AppError
from app.db.postgres_db import SessionFactory
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.role import Role
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.user_service import UserService
from tests.integration.conftest import World
from tests.integration.test_bootstrap import _run_handover

pytestmark = [pytest.mark.postgresql, pytest.mark.usefixtures("audit_request_context")]


async def _create_roles(*, count: int, prefix: str) -> list[str]:
    async with SessionFactory() as session:
        async with session.begin():
            roles = [
                Role(
                    key=f"{prefix}-{index}-{uuid.uuid4().hex[:8]}",
                    name=f"{prefix} {index}",
                    level=10,
                )
                for index in range(count)
            ]
            session.add_all(roles)
            await session.flush()
            return [role.id for role in roles]


async def _assign_roles_directly(*, user_id: str,
                                 role_ids: list[str],
                                 bound_by_user_id: str
                                 ) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            session.add_all(
                UserRole(
                    user_id=user_id,
                    role_id=role_id,
                    bound_by_user_id=bound_by_user_id,
                )
                for role_id in role_ids
            )


async def _super_admin_context(world: World) -> AuthorizationContext:
    super_admin = world.users["super_admin"]
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=super_admin.user_id)
        assert user is not None
        user_info = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    return AuthorizationContext(
        login_info=LoginInfo(
            user_id=super_admin.user_id,
            token_version=super_admin.token_version,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )


async def _live_role_count(user_id: str) -> int:
    async with SessionFactory() as session:
        count = await session.scalar(
            select(func.count(UserRole.id)).where(
                UserRole.user_id == user_id,
                UserRole.deleted_at.is_(None),
            )
        )
    return int(count or 0)


async def test_service_enforces_limit_and_keeps_bind_idempotent(world: World, audit_request_context: str) -> None:
    target_id = world.users["blank"].user_id
    role_ids = await _create_roles(count=MAX_ROLES_PER_USER, prefix="service-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[: MAX_ROLES_PER_USER - 1],
        bound_by_user_id=world.users["super_admin"].user_id,
    )
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    async with SessionFactory() as session:
        async with session.begin():
            disabled_role = await session.get(Role, role_ids[0], with_for_update=True)
            assert disabled_role is not None
            disabled_role.is_active = False

    context = await _super_admin_context(world)
    service = UserService(SessionFactory)
    unchanged = await service.change_user_roles(
        context=context,
        target_user_id=target_id,
        role_ids=(role_ids[0],),
        operation="bind",
    )
    assert role_ids[0] in unchanged.user.bound_role_ids
    assert set(unchanged.model_dump()) == {"user"}
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    async with SessionFactory() as session:
        user_before = await session.get(User, target_id)
        assert user_before is not None
        token_version_before = user_before.token_version

    with pytest.raises(AppError) as caught:
        await service.change_user_roles(
            context=context,
            target_user_id=target_id,
            role_ids=(role_ids[-1],),
            operation="bind",
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "user_role_limit_exceeded"
    async with SessionFactory() as session:
        user_after = await session.get(User, target_id)
        denied_audit = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.request_id == audit_request_context,
                OperationAuditEvent.outcome == "denied",
            )
        )
        assert user_after is not None
        assert user_after.token_version == token_version_before
        assert denied_audit is not None
        assert denied_audit.reason_code == "user_role_limit_exceeded"
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    removed = await service.change_user_roles(
        context=await _super_admin_context(world),
        target_user_id=target_id,
        role_ids=(role_ids[0],),
        operation="unbind",
    )
    rebound = await service.change_user_roles(
        context=await _super_admin_context(world),
        target_user_id=target_id,
        role_ids=(role_ids[-1],),
        operation="bind",
    )
    assert role_ids[0] not in removed.user.bound_role_ids
    assert role_ids[-1] in rebound.user.bound_role_ids
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER


async def test_database_counts_disabled_roles_and_ignores_tombstones(world: World) -> None:
    target_id = world.users["blank"].user_id
    role_ids = await _create_roles(count=MAX_ROLES_PER_USER, prefix="database-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[: MAX_ROLES_PER_USER - 1],
        bound_by_user_id=world.users["super_admin"].user_id,
    )
    async with SessionFactory() as session:
        async with session.begin():
            disabled_role = await session.get(Role, role_ids[0], with_for_update=True)
            assert disabled_role is not None
            disabled_role.is_active = False

    async with SessionFactory() as session:
        session.add(
            UserRole(
                user_id=target_id,
                role_id=role_ids[-1],
                bound_by_user_id=world.users["super_admin"].user_id,
            )
        )
        with pytest.raises(IntegrityError, match="at most 10 live role assignments"):
            await session.commit()

    async with SessionFactory() as session:
        async with session.begin():
            assignment = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == target_id,
                    UserRole.role_id == role_ids[0],
                    UserRole.deleted_at.is_(None),
                )
            )
            assert assignment is not None
            assignment.deleted_at = datetime.now(UTC)
            assignment.deleted_by_user_id = world.users["super_admin"].user_id
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=[role_ids[-1]],
        bound_by_user_id=world.users["super_admin"].user_id,
    )
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER


async def test_concurrent_bind_cannot_create_an_eleventh_live_role(world: World) -> None:
    target_id = world.users["blank"].user_id
    role_ids = await _create_roles(count=10, prefix="concurrent-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[:8],
        bound_by_user_id=world.users["super_admin"].user_id,
    )
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER - 1

    second_started = asyncio.Event()

    async def bind_second() -> None:
        async with SessionFactory() as second_session:
            async with second_session.begin():
                second_session.add(
                    UserRole(
                        user_id=target_id,
                        role_id=role_ids[-1],
                        bound_by_user_id=world.users["super_admin"].user_id,
                    )
                )
                second_started.set()
                await second_session.flush()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await rbac_state_repository.lock_rbac_state(first_session)
            first_session.add(
                UserRole(
                    user_id=target_id,
                    role_id=role_ids[-2],
                    bound_by_user_id=world.users["super_admin"].user_id,
                )
            )
            await first_session.flush()
            second_bind = asyncio.create_task(bind_second())
            await second_started.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(second_bind), timeout=0.1)

    with pytest.raises(IntegrityError, match="at most 10 live role assignments"):
        await asyncio.wait_for(second_bind, timeout=2)
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER


async def test_operator_handover_rejects_a_full_target_atomically(world: World) -> None:
    target_id = world.users["blank"].user_id
    role_ids = await _create_roles(
        count=MAX_ROLES_PER_USER - 1,
        prefix="transfer-limit",
    )
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids,
        bound_by_user_id=world.users["super_admin"].user_id,
    )

    async with SessionFactory() as session:
        current_user_before = await session.get(User, world.users["super_admin"].user_id)
        target_before = await session.get(User, target_id)
        assert current_user_before is not None and target_before is not None
        current_user_version_before = current_user_before.token_version
        target_version_before = target_before.token_version

    with pytest.raises(asyncpg.PostgresError, match="target already has 10 live roles"):
        await _run_handover(world.users["super_admin"].user_id, target_id)
    async with SessionFactory() as session:
        super_admin_role_id = await session.scalar(
            select(Role.id).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role_id is not None
        holders = set(
            (
                await session.scalars(
                    select(UserRole.user_id).where(
                        UserRole.role_id == super_admin_role_id,
                        UserRole.deleted_at.is_(None),
                    )
                )
            ).all()
        )
        current_user_after = await session.get(User, world.users["super_admin"].user_id)
        target_after = await session.get(User, target_id)
        denied_audit = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.action == "super_admin.transfer",
            )
        )
        assert current_user_after is not None and target_after is not None
    assert holders == {world.users["super_admin"].user_id}
    assert current_user_after.token_version == current_user_version_before
    assert target_after.token_version == target_version_before
    assert denied_audit is None
