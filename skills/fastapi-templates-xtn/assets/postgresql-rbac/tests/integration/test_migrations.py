import asyncio
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import select

from alembic import command
from app.database import SessionFactory
from app.rbac.domain import PermissionKey
from app.rbac.models import (
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantAuthorizationState,
)

pytestmark = pytest.mark.postgresql


def alembic_config() -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    return config


async def test_upgrade_from_0001_backfills_control_plane_and_versions() -> None:
    config = alembic_config()
    await asyncio.to_thread(command.downgrade, config, "0001_postgresql_rbac")
    try:
        async with SessionFactory() as session:
            async with session.begin():
                tenant = Tenant(slug="migration-source", name="Migration source")
                session.add(tenant)
                await session.flush()
                state = TenantAuthorizationState(tenant_id=tenant.id, epoch=7)
                owner_role = Role(
                    tenant_id=tenant.id,
                    key="owner",
                    name="Owner",
                    management_tier=1000,
                    is_active=True,
                    is_protected=True,
                    is_system=True,
                    is_owner=True,
                    version=2,
                )
                legacy_system_role = Role(
                    tenant_id=tenant.id,
                    key="legacy-system",
                    name="Legacy system",
                    management_tier=900,
                    is_active=True,
                    is_protected=False,
                    is_system=True,
                    is_owner=False,
                    version=4,
                )
                legacy_owner_tier_role = Role(
                    tenant_id=tenant.id,
                    key="legacy-owner-tier",
                    name="Legacy owner-tier role",
                    management_tier=1000,
                    is_active=True,
                    is_protected=False,
                    is_system=False,
                    is_owner=False,
                    version=5,
                )
                session.add_all(
                    [state, owner_role, legacy_system_role, legacy_owner_tier_role]
                )

        await asyncio.to_thread(command.upgrade, config, "head")

        async with SessionFactory() as session:
            migrated_owner = await session.get(Role, owner_role.id)
            migrated_system = await session.get(Role, legacy_system_role.id)
            migrated_owner_tier_role = await session.get(
                Role, legacy_owner_tier_role.id
            )
            migrated_state = await session.get(TenantAuthorizationState, tenant.id)
            owner_grants = (
                await session.execute(
                    select(Permission.key, RolePermission.can_delegate)
                    .select_from(RolePermission)
                    .join(Permission, Permission.id == RolePermission.permission_id)
                    .where(
                        RolePermission.tenant_id == tenant.id,
                        RolePermission.role_id == owner_role.id,
                        Permission.key.in_(
                            {
                                PermissionKey.ROLES_DELEGATION_UPDATE.value,
                                PermissionKey.MEMBERSHIPS_CREATE.value,
                                PermissionKey.MEMBERSHIPS_STATUS_UPDATE.value,
                            }
                        ),
                    )
                )
            ).all()

        assert migrated_owner is not None
        assert migrated_system is not None
        assert migrated_owner_tier_role is not None
        assert migrated_state is not None
        assert migrated_owner.version == 3
        assert migrated_system.version == 5
        assert migrated_system.is_protected
        assert migrated_owner_tier_role.management_tier == 999
        assert migrated_owner_tier_role.version == 6
        assert migrated_state.epoch == 8
        assert {row.key: row.can_delegate for row in owner_grants} == {
            PermissionKey.ROLES_DELEGATION_UPDATE.value: False,
            PermissionKey.MEMBERSHIPS_CREATE.value: True,
            PermissionKey.MEMBERSHIPS_STATUS_UPDATE.value: True,
        }
    finally:
        await asyncio.to_thread(command.upgrade, config, "head")
