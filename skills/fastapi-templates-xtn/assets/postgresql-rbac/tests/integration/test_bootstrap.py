import uuid

import pytest
from sqlalchemy import delete, select

from app.database import SessionFactory
from app.rbac.bootstrap import bootstrap_tenant
from app.rbac.domain import (
    PERMISSION_CATALOG,
    TENANT_OWNER_DELEGABLE_PERMISSION_KEYS,
    TENANT_OWNER_PERMISSION_KEYS,
    PermissionKey,
)
from app.rbac.models import (
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    User,
)

pytestmark = pytest.mark.postgresql


async def test_explicit_bootstrap_creates_one_protected_owner() -> None:
    tenant, membership = await bootstrap_tenant(
        owner_email="bootstrap-owner@example.test",
        tenant_slug="bootstrapped",
        tenant_name="Bootstrapped",
    )

    async with SessionFactory() as session:
        owner_role = await session.scalar(
            select(Role).where(Role.tenant_id == tenant.id, Role.is_owner.is_(True))
        )
        assignment = await session.scalar(
            select(MembershipRole).where(
                MembershipRole.tenant_id == tenant.id,
                MembershipRole.membership_id == membership.id,
            )
        )
        ownership_permission = await session.scalar(
            select(Permission).where(
                Permission.key == PermissionKey.TENANT_OWNERSHIP_TRANSFER.value
            )
        )
        assert owner_role is not None
        assert ownership_permission is not None
        ownership_grant = await session.get(
            RolePermission,
            (tenant.id, owner_role.id, ownership_permission.id),
        )
        grants = (
            await session.execute(
                select(Permission.key, RolePermission.can_delegate)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id == owner_role.id)
            )
        ).all()

    assert owner_role.is_system
    assert owner_role.is_protected
    assert owner_role.management_tier == 1000
    assert assignment is not None
    assert ownership_grant is not None
    assert not ownership_grant.can_delegate
    assert {row.key for row in grants} == TENANT_OWNER_PERMISSION_KEYS
    assert {row.key for row in grants if row.can_delegate} == (
        TENANT_OWNER_DELEGABLE_PERMISSION_KEYS
    )


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
    platform_permission = Permission(
        id=uuid.uuid4(),
        key="platform:break_glass",
        description="Platform-only emergency permission",
    )
    async with SessionFactory() as session:
        session.add(platform_permission)
        await session.commit()

    try:
        tenant, _membership = await bootstrap_tenant(
            owner_email="isolated-owner@example.test",
            tenant_slug="isolated",
            tenant_name="Isolated",
        )
        async with SessionFactory() as session:
            owner_role = await session.scalar(
                select(Role).where(
                    Role.tenant_id == tenant.id,
                    Role.is_owner.is_(True),
                )
            )
            assert owner_role is not None
            unexpected_grant = await session.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == owner_role.id,
                    RolePermission.permission_id == platform_permission.id,
                )
            )
        assert unexpected_grant is None
    finally:
        async with SessionFactory() as session:
            await session.execute(
                delete(Permission).where(Permission.id == platform_permission.id)
            )
            await session.commit()


async def test_bootstrap_rejects_disabled_existing_owner_and_rolls_back() -> None:
    async with SessionFactory() as session:
        session.add(User(email="disabled-owner@example.test", is_active=False))
        await session.commit()

    with pytest.raises(RuntimeError, match="inactive or platform-protected"):
        await bootstrap_tenant(
            owner_email="disabled-owner@example.test",
            tenant_slug="must-not-exist",
            tenant_name="Must Not Exist",
        )

    async with SessionFactory() as session:
        tenant = await session.scalar(
            select(Tenant).where(Tenant.slug == "must-not-exist")
        )
    assert tenant is None
