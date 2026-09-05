import asyncio
import uuid

import pytest
from sqlalchemy import select, text, update

from app.database import SessionFactory
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError
from app.rbac.models import (
    Membership,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    TenantAuthorizationState,
)
from app.rbac.queries import (
    load_authority_snapshot,
    lock_memberships,
    lock_roles,
    lock_tenant_authorization_state,
    lock_users,
)
from app.rbac.schemas import RolePermissionsReplaceRequest
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def context_for(
    world: World, user_name: str, request_id: str
) -> AuthorizationContext:
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(
            session,
            tenant_id=world.tenant.id,
            membership_id=world.memberships[user_name].id,
        )
        state = await session.get(TenantAuthorizationState, world.tenant.id)
        assert state is not None
    return AuthorizationContext(
        principal=Principal(
            user_id=world.users[user_name].id,
            token_tenant_id=world.tenant.id,
            token_version=world.users[user_name].token_version,
            token_id=str(uuid.uuid4()),
        ),
        tenant_id=world.tenant.id,
        tenant_authz_epoch=state.epoch,
        authority=authority,
        request_id=request_id,
    )


async def test_engine_uses_required_read_committed_isolation() -> None:
    async with SessionFactory() as session:
        isolation = await session.scalar(text("SHOW transaction_isolation"))

    assert isolation == "read committed"


async def test_membership_lock_refreshes_preloaded_identity_map(world: World) -> None:
    membership_id = world.memberships["manager"].id
    async with SessionFactory() as first_session:
        stale = await first_session.get(Membership, membership_id)
        assert stale is not None
        assert stale.status == "active"

        async with SessionFactory() as second_session:
            async with second_session.begin():
                await second_session.execute(
                    update(Membership)
                    .where(Membership.id == membership_id)
                    .values(status="suspended")
                )

        locked = await lock_memberships(
            first_session,
            tenant_id=world.tenant.id,
            membership_ids={membership_id},
        )

        assert locked[membership_id] is stale
        assert locked[membership_id].status == "suspended"


async def test_user_lock_blocks_a_second_rbac_writer(world: World) -> None:
    user_id = world.users["manager"].id
    attempted = asyncio.Event()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await lock_users(first_session, {user_id})

            async def take_same_lock() -> None:
                async with SessionFactory() as second_session:
                    async with second_session.begin():
                        attempted.set()
                        await lock_users(second_session, {user_id})

            second_writer = asyncio.create_task(take_same_lock())
            await attempted.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(second_writer), timeout=0.1)

        await asyncio.wait_for(second_writer, timeout=2)


async def test_tenant_guard_serializes_authorization_changes(world: World) -> None:
    tenant_id = world.tenant.id
    attempted = asyncio.Event()

    async with SessionFactory() as first_session:
        async with first_session.begin():
            await lock_tenant_authorization_state(first_session, tenant_id)

            async def take_same_guard() -> None:
                async with SessionFactory() as second_session:
                    async with second_session.begin():
                        attempted.set()
                        await lock_tenant_authorization_state(second_session, tenant_id)

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
    manager_membership_id = world.memberships["manager"].id
    manager_role_id = world.roles["manager"].id

    async with SessionFactory() as revocation_session:
        async with revocation_session.begin():
            await lock_users(revocation_session, {world.users["manager"].id})
            _tenant, state = await lock_tenant_authorization_state(
                revocation_session, world.tenant.id
            )
            memberships = await lock_memberships(
                revocation_session,
                tenant_id=world.tenant.id,
                membership_ids={manager_membership_id},
            )
            await lock_roles(
                revocation_session,
                tenant_id=world.tenant.id,
                role_ids={manager_role_id},
            )
            assignment = await revocation_session.scalar(
                select(MembershipRole).where(
                    MembershipRole.tenant_id == world.tenant.id,
                    MembershipRole.membership_id == manager_membership_id,
                    MembershipRole.role_id == manager_role_id,
                )
            )
            assert assignment is not None
            await revocation_session.delete(assignment)
            memberships[manager_membership_id].authz_version += 1
            state.epoch += 1

            waiting_mutation = asyncio.create_task(
                service.assign_role(
                    context=context,
                    target_membership_id=world.memberships["blank"].id,
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
        forbidden_assignment = await session.scalar(
            select(MembershipRole).where(
                MembershipRole.tenant_id == world.tenant.id,
                MembershipRole.membership_id == world.memberships["blank"].id,
                MembershipRole.role_id == world.roles["viewer"].id,
            )
        )
    assert forbidden_assignment is None


async def test_shared_role_change_retries_when_phantom_holder_commits(
    world: World,
) -> None:
    async with SessionFactory() as setup_session:
        async with setup_session.begin():
            shared_role = Role(
                tenant_id=world.tenant.id,
                key="race-shared-role",
                name="Race shared role",
                management_tier=30,
            )
            setup_session.add(shared_role)
            await setup_session.flush()
            setup_session.add_all(
                [
                    RolePermission(
                        tenant_id=world.tenant.id,
                        role_id=shared_role.id,
                        permission_id=world.permissions[
                            PermissionKey.PROJECTS_READ.value
                        ].id,
                        can_delegate=False,
                    ),
                    MembershipRole(
                        tenant_id=world.tenant.id,
                        membership_id=world.memberships["lower"].id,
                        role_id=shared_role.id,
                        assigned_by_membership_id=world.memberships["manager"].id,
                    ),
                ]
            )

    context = await context_for(world, "manager", "race-phantom-holder")
    service = RbacService(SessionFactory)
    high_membership_id = world.memberships["higher"].id

    async with SessionFactory() as writer_session:
        async with writer_session.begin():
            await lock_users(writer_session, {world.users["higher"].id})
            _tenant, state = await lock_tenant_authorization_state(
                writer_session, world.tenant.id
            )
            memberships = await lock_memberships(
                writer_session,
                tenant_id=world.tenant.id,
                membership_ids={high_membership_id},
            )
            await lock_roles(
                writer_session,
                tenant_id=world.tenant.id,
                role_ids={shared_role.id},
            )

            waiting_change = asyncio.create_task(
                service.replace_role_permissions(
                    context=context,
                    role_id=shared_role.id,
                    request=RolePermissionsReplaceRequest(
                        permissions=["projects:read", "projects:update"]
                    ),
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(waiting_change),
                    timeout=0.1,
                )

            writer_session.add(
                MembershipRole(
                    tenant_id=world.tenant.id,
                    membership_id=high_membership_id,
                    role_id=shared_role.id,
                    assigned_by_membership_id=None,
                )
            )
            memberships[high_membership_id].authz_version += 1
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
