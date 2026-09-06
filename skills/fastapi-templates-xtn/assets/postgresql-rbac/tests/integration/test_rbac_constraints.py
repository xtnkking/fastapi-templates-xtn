import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory, engine
from app.rbac.domain import PermissionKey
from app.rbac.models import Role, RolePermission, UserRole
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def test_database_rejects_unknown_role_in_user_assignment(world: World) -> None:
    async with SessionFactory() as session:
        session.add(
            UserRole(
                user_id=world.users["blank"].id,
                role_id=uuid.uuid4(),
                assigned_by_user_id=world.users["manager"].id,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_unknown_role_in_permission_grant(
    world: World,
) -> None:
    async with SessionFactory() as session:
        session.add(
            RolePermission(
                role_id=uuid.uuid4(),
                permission_id=world.permissions[PermissionKey.PROJECTS_READ.value].id,
                can_delegate=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_requires_every_system_role_to_be_protected() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                key="unsafe-system-role",
                name="Unsafe system role",
                management_tier=900,
                is_system=True,
                is_protected=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_reserves_management_tier_1000_for_owner() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
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


async def test_database_allows_only_one_owner_role(world: World) -> None:
    assert world.roles["owner"].is_owner
    async with SessionFactory() as session:
        session.add(
            Role(
                key="second-owner",
                name="Second Owner",
                management_tier=1000,
                is_system=True,
                is_protected=True,
                is_owner=True,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_schema_uses_only_expected_tables_and_uuid_entity_ids() -> None:
    expected_tables = {
        "alembic_version",
        "authorization_audit_events",
        "authorization_state",
        "permissions",
        "role_permissions",
        "roles",
        "user_roles",
        "users",
    }
    entity_id_columns = {
        ("authorization_audit_events", "id"),
        ("permissions", "id"),
        ("roles", "id"),
        ("users", "id"),
    }

    async with engine.connect() as connection:
        tables = set(
            (
                await connection.scalars(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                )
            ).all()
        )
        rows = (
            await connection.execute(
                text(
                    "SELECT table_name, column_name, data_type, column_default "
                    "FROM information_schema.columns WHERE table_schema = 'public'"
                )
            )
        ).all()

    assert tables == expected_tables
    columns = {(row.table_name, row.column_name): row for row in rows}
    for key in entity_id_columns:
        row = columns[key]
        assert row.data_type == "uuid"
        assert row.column_default is not None
        assert "gen_random_uuid()" in row.column_default

    for key in (
        ("role_permissions", "role_id"),
        ("role_permissions", "permission_id"),
        ("user_roles", "user_id"),
        ("user_roles", "role_id"),
        ("user_roles", "assigned_by_user_id"),
    ):
        assert columns[key].data_type == "uuid"
