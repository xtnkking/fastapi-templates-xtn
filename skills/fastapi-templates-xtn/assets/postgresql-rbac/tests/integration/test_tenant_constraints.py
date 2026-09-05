import pytest
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory
from app.rbac.domain import PermissionKey
from app.rbac.models import MembershipRole, Role, RolePermission
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def test_database_rejects_cross_tenant_membership_role(world: World) -> None:
    async with SessionFactory() as session:
        session.add(
            MembershipRole(
                tenant_id=world.tenant.id,
                membership_id=world.memberships["blank"].id,
                role_id=world.roles["outsider"].id,
                assigned_by_membership_id=world.memberships["manager"].id,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_cross_tenant_role_permission(
    world: World,
) -> None:
    async with SessionFactory() as session:
        session.add(
            RolePermission(
                tenant_id=world.tenant.id,
                role_id=world.roles["outsider"].id,
                permission_id=world.permissions[PermissionKey.PROJECTS_READ.value].id,
                can_delegate=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_requires_every_system_role_to_be_protected(
    world: World,
) -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                tenant_id=world.tenant.id,
                key="unsafe-system-role",
                name="Unsafe system role",
                management_tier=900,
                is_system=True,
                is_protected=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_reserves_management_tier_1000_for_owner(
    world: World,
) -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                tenant_id=world.tenant.id,
                key="owner-tier-impostor",
                name="Owner tier impostor",
                management_tier=1000,
                is_system=False,
                is_protected=False,
                is_owner=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
