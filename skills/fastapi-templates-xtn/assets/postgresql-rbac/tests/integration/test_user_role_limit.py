import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory
from app.rbac.domain import (
    MAX_ROLES_PER_USER,
    AuthorizationContext,
    Principal,
    SystemRoleKey,
)
from app.rbac.errors import RbacError
from app.rbac.models import RbacAuditEvent, RbacState, Role, User, UserRole
from app.rbac.queries import load_authority_snapshot, lock_rbac_state
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def _create_roles(*, count: int, prefix: str) -> list[uuid.UUID]:
    async with SessionFactory() as session:
        async with session.begin():
            roles = [
                Role(
                    key=f"{prefix}-{index}-{uuid.uuid4().hex[:8]}",
                    name=f"{prefix} {index}",
                    management_tier=10,
                )
                for index in range(count)
            ]
            session.add_all(roles)
            await session.flush()
            return [role.id for role in roles]


async def _assign_roles_directly(
    *,
    user_id: uuid.UUID,
    role_ids: list[uuid.UUID],
    actor_user_id: uuid.UUID,
) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            session.add_all(
                UserRole(
                    user_id=user_id,
                    role_id=role_id,
                    assigned_by_user_id=actor_user_id,
                )
                for role_id in role_ids
            )


async def _super_admin_context(world: World, request_id: str) -> AuthorizationContext:
    super_admin = world.users["super_admin"]
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(session, user_id=super_admin.id)
        state = await session.get(RbacState, "global")
        assert state is not None
    return AuthorizationContext(
        principal=Principal(
            user_id=super_admin.id,
            token_version=super_admin.token_version,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=state.epoch,
        authority=authority,
        request_id=request_id,
    )


async def _live_role_count(user_id: uuid.UUID) -> int:
    async with SessionFactory() as session:
        count = await session.scalar(
            select(func.count(UserRole.id)).where(
                UserRole.user_id == user_id,
                UserRole.deleted_at.is_(None),
            )
        )
    return int(count or 0)


async def test_service_enforces_limit_and_keeps_bind_idempotent(world: World) -> None:
    target_id = world.users["blank"].id
    role_ids = await _create_roles(count=MAX_ROLES_PER_USER, prefix="service-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[: MAX_ROLES_PER_USER - 1],
        actor_user_id=world.users["super_admin"].id,
    )
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    async with SessionFactory() as session:
        async with session.begin():
            disabled_role = await session.get(Role, role_ids[0], with_for_update=True)
            assert disabled_role is not None
            disabled_role.is_active = False

    context = await _super_admin_context(world, "role-limit-service")
    service = RbacService(SessionFactory)
    unchanged = await service.change_user_roles(
        context=context,
        target_user_id=target_id,
        role_ids=(role_ids[0],),
        operation="bind",
    )
    assert unchanged.changed is False
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    async with SessionFactory() as session:
        user_before = await session.get(User, target_id)
        state_before = await session.get(RbacState, "global")
        assert user_before is not None and state_before is not None
        authz_version_before = user_before.authz_version
        epoch_before = state_before.epoch

    with pytest.raises(RbacError) as caught:
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
        state_after = await session.get(RbacState, "global")
        denied_audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.request_id == "role-limit-service",
                RbacAuditEvent.decision == "denied",
            )
        )
        assert user_after is not None and state_after is not None
        assert user_after.authz_version == authz_version_before
        assert state_after.epoch == epoch_before
        assert denied_audit is not None
        assert denied_audit.reason_code == "user_role_limit_exceeded"
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER

    removed = await service.change_user_roles(
        context=await _super_admin_context(world, "role-limit-unbind"),
        target_user_id=target_id,
        role_ids=(role_ids[0],),
        operation="unbind",
    )
    rebound = await service.change_user_roles(
        context=await _super_admin_context(world, "role-limit-rebind"),
        target_user_id=target_id,
        role_ids=(role_ids[-1],),
        operation="bind",
    )
    assert removed.changed is True
    assert rebound.changed is True
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER


async def test_database_counts_disabled_roles_and_ignores_tombstones(
    world: World,
) -> None:
    target_id = world.users["blank"].id
    role_ids = await _create_roles(count=MAX_ROLES_PER_USER, prefix="database-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[: MAX_ROLES_PER_USER - 1],
        actor_user_id=world.users["super_admin"].id,
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
                assigned_by_user_id=world.users["super_admin"].id,
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
            assignment.deleted_by_user_id = world.users["super_admin"].id
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=[role_ids[-1]],
        actor_user_id=world.users["super_admin"].id,
    )
    assert await _live_role_count(target_id) == MAX_ROLES_PER_USER


async def test_concurrent_bind_cannot_create_an_eleventh_live_role(
    world: World,
) -> None:
    target_id = world.users["blank"].id
    role_ids = await _create_roles(count=10, prefix="concurrent-limit")
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids[:8],
        actor_user_id=world.users["super_admin"].id,
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
                        assigned_by_user_id=world.users["super_admin"].id,
                    )
                )
                second_started.set()
                await second_session.flush()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await lock_rbac_state(first_session)
            first_session.add(
                UserRole(
                    user_id=target_id,
                    role_id=role_ids[-2],
                    assigned_by_user_id=world.users["super_admin"].id,
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


async def test_super_admin_transfer_rejects_a_full_target_atomically(
    world: World,
) -> None:
    target_id = world.users["blank"].id
    role_ids = await _create_roles(
        count=MAX_ROLES_PER_USER - 1,
        prefix="transfer-limit",
    )
    await _assign_roles_directly(
        user_id=target_id,
        role_ids=role_ids,
        actor_user_id=world.users["super_admin"].id,
    )
    context = await _super_admin_context(world, "role-limit-transfer")

    async with SessionFactory() as session:
        actor_before = await session.get(User, world.users["super_admin"].id)
        target_before = await session.get(User, target_id)
        state_before = await session.get(RbacState, "global")
        assert actor_before is not None and target_before is not None
        assert state_before is not None
        actor_version_before = actor_before.authz_version
        target_version_before = target_before.authz_version
        epoch_before = state_before.epoch

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).transfer_super_admin(
            context=context,
            target_user_id=target_id,
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "user_role_limit_exceeded"
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
        actor_after = await session.get(User, world.users["super_admin"].id)
        target_after = await session.get(User, target_id)
        state_after = await session.get(RbacState, "global")
        denied_audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.request_id == "role-limit-transfer",
                RbacAuditEvent.decision == "denied",
            )
        )
        assert actor_after is not None and target_after is not None
        assert state_after is not None
    assert holders == {world.users["super_admin"].id}
    assert actor_after.authz_version == actor_version_before
    assert target_after.authz_version == target_version_before
    assert state_after.epoch == epoch_before
    assert denied_audit is not None
    assert denied_audit.reason_code == "user_role_limit_exceeded"
