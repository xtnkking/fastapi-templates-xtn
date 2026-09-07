import asyncio
import uuid

import pytest
from sqlalchemy import select, text, update

from app.database import SessionFactory
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError
from app.rbac.models import (
    AuthorizationState,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import (
    load_authority_snapshot,
    lock_authorization_state,
    lock_roles,
    lock_users,
)
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def context_for(
    world: World, user_name: str, request_id: str
) -> AuthorizationContext:
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(
            session,
            user_id=world.users[user_name].id,
        )
        state = await session.get(AuthorizationState, "global")
        assert state is not None
    return AuthorizationContext(
        principal=Principal(
            user_id=world.users[user_name].id,
            token_version=world.users[user_name].token_version,
            token_id=uuid.uuid4(),
        ),
        authorization_epoch=state.epoch,
        authority=authority,
        request_id=request_id,
    )


async def test_engine_uses_required_read_committed_isolation() -> None:
    async with SessionFactory() as session:
        isolation = await session.scalar(text("SHOW transaction_isolation"))

    assert isolation == "read committed"


async def test_user_lock_refreshes_preloaded_identity_map(world: World) -> None:
    user_id = world.users["lower"].id
    async with SessionFactory() as first_session:
        stale = await first_session.get(User, user_id)
        assert stale is not None
        assert stale.is_active

        async with SessionFactory() as second_session:
            async with second_session.begin():
                await second_session.execute(
                    update(User).where(User.id == user_id).values(is_active=False)
                )

        locked = await lock_users(first_session, {user_id})

        assert locked[user_id] is stale
        assert not locked[user_id].is_active


async def test_global_guard_serializes_authorization_changes() -> None:
    attempted = asyncio.Event()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await lock_authorization_state(first_session)

            async def take_same_guard() -> None:
                async with SessionFactory() as second_session:
                    async with second_session.begin():
                        attempted.set()
                        await lock_authorization_state(second_session)

            second_writer = asyncio.create_task(take_same_guard())
            await attempted.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(second_writer), timeout=0.1)

        await asyncio.wait_for(second_writer, timeout=2)


async def test_actor_role_revocation_commits_before_waiting_mutation(
    world: World,
) -> None:
    context = await context_for(world, "manager", "race-actor-revoked")
    service = RbacService(SessionFactory)
    manager_user_id = world.users["manager"].id
    manager_role_id = world.roles["manager"].id

    async with SessionFactory() as revocation_session:
        async with revocation_session.begin():
            state = await lock_authorization_state(revocation_session)
            users = await lock_users(revocation_session, {manager_user_id})
            await lock_roles(revocation_session, role_ids={manager_role_id})
            assignment = await revocation_session.get(
                UserRole,
                (manager_user_id, manager_role_id),
            )
            assert assignment is not None
            await revocation_session.delete(assignment)
            users[manager_user_id].authz_version += 1
            state.epoch += 1

            waiting_mutation = asyncio.create_task(
                service.assign_role(
                    context=context,
                    target_user_id=world.users["blank"].id,
                    role_id=world.roles["viewer"].id,
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(waiting_mutation),
                    timeout=0.1,
                )

    with pytest.raises(RbacError) as caught:
        await asyncio.wait_for(waiting_mutation, timeout=2)
    assert caught.value.status_code == 403

    async with SessionFactory() as session:
        forbidden_assignment = await session.get(
            UserRole,
            (world.users["blank"].id, world.roles["viewer"].id),
        )
    assert forbidden_assignment is None


async def test_shared_role_change_observes_new_high_authority_holder(
    world: World,
) -> None:
    async with SessionFactory() as setup_session:
        async with setup_session.begin():
            shared_role = Role(
                key="race-shared-role",
                name="Race shared role",
                management_tier=30,
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
                        can_delegate=False,
                    ),
                    UserRole(
                        user_id=world.users["lower"].id,
                        role_id=shared_role.id,
                        assigned_by_user_id=world.users["manager"].id,
                    ),
                ]
            )

    context = await context_for(world, "manager", "race-new-holder")
    service = RbacService(SessionFactory)
    high_user_id = world.users["higher"].id

    async with SessionFactory() as writer_session:
        async with writer_session.begin():
            state = await lock_authorization_state(writer_session)
            users = await lock_users(writer_session, {high_user_id})
            await lock_roles(writer_session, role_ids={shared_role.id})

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
                    assigned_by_user_id=None,
                )
            )
            users[high_user_id].authz_version += 1
            state.epoch += 1

    with pytest.raises(RbacError) as caught:
        await asyncio.wait_for(waiting_change, timeout=2)
    assert caught.value.status_code == 403

    async with SessionFactory() as session:
        granted_keys = set(
            (
                await session.scalars(
                    select(Permission.key)
                    .select_from(RolePermission)
                    .join(Permission, Permission.id == RolePermission.permission_id)
                    .where(RolePermission.role_id == shared_role.id)
                )
            ).all()
        )
    assert granted_keys == {PermissionKey.PROJECTS_READ.value}
