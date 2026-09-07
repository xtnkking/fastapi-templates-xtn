import uuid

import pytest
from sqlalchemy import delete, select

from app.database import SessionFactory
from app.rbac.bootstrap import bootstrap_super_admin
from app.rbac.domain import (
    PERMISSION_CATALOG,
    SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    SYSTEM_ROLE_KEYS,
    SYSTEM_ROLE_SPECS,
    SystemRoleKey,
)
from app.rbac.models import (
    AuthorizationAuditEvent,
    AuthorizationState,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.provisioning import create_user_with_default_role

pytestmark = pytest.mark.postgresql


async def test_explicit_bootstrap_assigns_preseeded_super_admin_and_user() -> None:
    super_admin = await bootstrap_super_admin(
        super_admin_email="bootstrap-super-admin@example.test"
    )

    async with SessionFactory() as session:
        roles = {
            role.key: role
            for role in (
                await session.scalars(
                    select(Role).where(Role.key.in_(SYSTEM_ROLE_KEYS))
                )
            ).all()
        }
        assignments = (
            await session.execute(
                select(UserRole, Role.key)
                .join(Role, Role.id == UserRole.role_id)
                .where(UserRole.user_id == super_admin.id)
            )
        ).all()
        grants = (
            await session.execute(
                select(Permission.key, RolePermission.can_delegate)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(
                    RolePermission.role_id == roles[SystemRoleKey.SUPER_ADMIN.value].id
                )
            )
        ).all()
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.action == "super_admin.bootstrap"
            )
        )

    assert set(roles) == SYSTEM_ROLE_KEYS
    for key, spec in SYSTEM_ROLE_SPECS.items():
        role = roles[key.value]
        assert role.management_tier == spec.management_tier
        assert role.is_system
        assert role.is_protected == spec.is_protected
        assert role.is_owner == spec.is_owner
        assert role.is_active
        assert role.deleted_at is None
    assert {row.key for row in assignments} == {
        SystemRoleKey.SUPER_ADMIN.value,
        SystemRoleKey.USER.value,
    }
    assert {row.key for row in grants} == SUPER_ADMIN_PERMISSION_KEYS
    assert {row.key for row in grants if row.can_delegate} == (
        SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS
    )
    assert audit is not None
    assert audit.decision == "allowed"
    assert audit.reason_code == "explicit_super_admin_bootstrap"


async def test_permission_catalog_matches_runtime_contract() -> None:
    async with SessionFactory() as session:
        rows = (
            await session.execute(
                select(Permission.key, Permission.description).where(
                    Permission.key.in_([item.value for item in PERMISSION_CATALOG])
                )
            )
        ).all()

    assert {row.key: row.description for row in rows} == {
        key.value: description for key, description in PERMISSION_CATALOG.items()
    }


async def test_bootstrap_does_not_grant_unknown_global_permission() -> None:
    extra_permission = Permission(
        id=uuid.uuid4(),
        key="platform:break_glass",
        description="Emergency-only permission",
    )
    async with SessionFactory() as session:
        session.add(extra_permission)
        await session.commit()

    try:
        super_admin = await bootstrap_super_admin(
            super_admin_email="isolated-super-admin@example.test"
        )
        async with SessionFactory() as session:
            role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
            )
            assert role is not None
            unexpected_grant = await session.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == extra_permission.id,
                )
            )
            assignment = await session.get(UserRole, (super_admin.id, role.id))
        assert unexpected_grant is None
        assert assignment is not None
    finally:
        async with SessionFactory() as session:
            await session.execute(
                delete(Permission).where(Permission.id == extra_permission.id)
            )
            await session.commit()


async def test_bootstrap_rejects_disabled_existing_identity_and_rolls_back() -> None:
    async with SessionFactory() as session:
        async with session.begin():
            user_role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.USER.value)
            )
            assert user_role is not None
            disabled = User(
                email="disabled-super-admin@example.test",
                is_active=False,
            )
            session.add(disabled)
            await session.flush()
            session.add(
                UserRole(
                    user_id=disabled.id,
                    role_id=user_role.id,
                    assigned_by_user_id=None,
                )
            )

    with pytest.raises(RuntimeError, match="inactive or system-protected"):
        await bootstrap_super_admin(
            super_admin_email="disabled-super-admin@example.test"
        )

    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role is not None
        assignment = await session.scalar(
            select(UserRole).where(UserRole.role_id == super_admin_role.id)
        )
    assert assignment is None


async def test_bootstrap_refuses_a_second_super_admin() -> None:
    await bootstrap_super_admin(super_admin_email="first-super-admin@example.test")

    with pytest.raises(RuntimeError, match="different super_admin already exists"):
        await bootstrap_super_admin(super_admin_email="second-super-admin@example.test")

    async with SessionFactory() as session:
        second = await session.scalar(
            select(User).where(User.email == "second-super-admin@example.test")
        )
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role is not None
        holders = (
            await session.scalars(
                select(UserRole).where(UserRole.role_id == super_admin_role.id)
            )
        ).all()
    assert second is None
    assert len(holders) == 1


async def test_bootstrap_same_identity_is_idempotent() -> None:
    first = await bootstrap_super_admin(
        super_admin_email="idempotent-super-admin@example.test"
    )
    async with SessionFactory() as session:
        state_before = await session.get(AuthorizationState, "global")
        user_before = await session.get(User, first.id)
        assert state_before is not None and user_before is not None
        epoch_before = state_before.epoch
        version_before = user_before.authz_version

    second = await bootstrap_super_admin(
        super_admin_email="idempotent-super-admin@example.test"
    )

    async with SessionFactory() as session:
        state_after = await session.get(AuthorizationState, "global")
        user_after = await session.get(User, first.id)
        replay_audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.reason_code
                == "super_admin_already_bootstrapped"
            )
        )
    assert second.id == first.id
    assert state_after is not None and state_after.epoch == epoch_before
    assert user_after is not None and user_after.authz_version == version_before
    assert replay_audit is not None


async def test_bootstrap_rejects_empty_email() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        await bootstrap_super_admin(super_admin_email="  ")


async def test_provisioning_creates_user_and_default_role_atomically() -> None:
    user_id = uuid.uuid4()
    async with SessionFactory() as session:
        async with session.begin():
            state_before = await session.get(AuthorizationState, "global")
            assert state_before is not None
            epoch_before = state_before.epoch
            created = await create_user_with_default_role(
                session,
                email="provisioned-user@example.test",
                user_id=user_id,
                request_id="provision-default-user",
            )
            assert created.authz_version == 1

    async with SessionFactory() as session:
        user_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.USER.value)
        )
        assert user_role is not None
        assignment = await session.get(UserRole, (user_id, user_role.id))
        state_after = await session.get(AuthorizationState, "global")
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "provision-default-user"
            )
        )

    assert assignment is not None
    assert state_after is not None and state_after.epoch == epoch_before + 1
    assert audit is not None and audit.reason_code == "default_user_role_assigned"
