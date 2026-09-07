import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory, engine
from app.rbac.domain import PermissionKey, SystemRoleKey
from app.rbac.models import Role, RolePermission, User, UserRole
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


async def test_database_requires_every_protected_role_to_be_system() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                key="unsafe-protected-role",
                name="Unsafe protected role",
                management_tier=900,
                is_system=False,
                is_protected=True,
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


async def test_database_reserves_legacy_owner_role_key() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                key="owner",
                name="Legacy key collision",
                management_tier=100,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_allows_only_one_owner_role(world: World) -> None:
    assert world.roles["super_admin"].is_owner
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


async def test_database_seeds_fixed_system_role_shapes() -> None:
    async with SessionFactory() as session:
        roles = {
            role.key: role
            for role in (
                await session.scalars(
                    select(Role).where(
                        Role.key.in_([item.value for item in SystemRoleKey])
                    )
                )
            ).all()
        }

    assert set(roles) == {item.value for item in SystemRoleKey}
    assert roles[SystemRoleKey.SUPER_ADMIN.value].management_tier == 1000
    assert roles[SystemRoleKey.SUPER_ADMIN.value].is_protected
    assert roles[SystemRoleKey.SUPER_ADMIN.value].is_owner
    assert roles[SystemRoleKey.ADMIN.value].management_tier == 500
    assert not roles[SystemRoleKey.ADMIN.value].is_protected
    assert roles[SystemRoleKey.USER.value].management_tier == 0
    assert not roles[SystemRoleKey.USER.value].is_protected
    assert all(role.is_system and role.is_active for role in roles.values())


async def test_database_rejects_system_role_definition_changes() -> None:
    async with SessionFactory() as session:
        role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.ADMIN.value)
        )
        assert role is not None
        role.name = "Renamed administrator"
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_physical_system_role_deletion() -> None:
    async with SessionFactory() as session:
        role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.ADMIN.value)
        )
        assert role is not None
        await session.execute(
            delete(RolePermission).where(RolePermission.role_id == role.id)
        )
        await session.delete(role)
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_system_role_permission_changes() -> None:
    async with SessionFactory() as session:
        role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.ADMIN.value)
        )
        assert role is not None
        grant = await session.scalar(
            select(RolePermission).where(RolePermission.role_id == role.id)
        )
        assert grant is not None
        await session.delete(grant)
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_requires_soft_deleted_roles_to_be_inactive() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                key="invalid-soft-delete",
                name="Invalid soft delete",
                management_tier=10,
                is_active=True,
                deleted_at=datetime.now(UTC),
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_requires_every_user_to_retain_user_role() -> None:
    async with SessionFactory() as session:
        session.add(User(email="missing-user-role@example.test"))
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_removing_mandatory_user_role(world: World) -> None:
    async with SessionFactory() as session:
        user_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.USER.value)
        )
        assert user_role is not None
        assignment = await session.get(
            UserRole,
            (world.users["blank"].id, user_role.id),
        )
        assert assignment is not None
        await session.delete(assignment)
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_a_second_super_admin_assignment(
    world: World,
) -> None:
    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role is not None
        session.add(
            UserRole(
                user_id=world.users["blank"].id,
                role_id=super_admin_role.id,
                assigned_by_user_id=world.users["super_admin"].id,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_allows_base_role_assignment_before_bootstrap() -> None:
    async with SessionFactory() as session:
        user_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.USER.value)
        )
        assert user_role is not None
        new_user = User(email="pre-bootstrap-user@example.test")
        session.add(new_user)
        await session.flush()
        session.add(
            UserRole(
                user_id=new_user.id,
                role_id=user_role.id,
                assigned_by_user_id=None,
            )
        )
        await session.commit()


async def test_database_rejects_removing_final_super_admin_assignment(
    world: World,
) -> None:
    async with SessionFactory() as session:
        assignment = await session.get(
            UserRole,
            (world.users["owner"].id, world.roles["super_admin"].id),
        )
        assert assignment is not None
        await session.delete(assignment)
        with pytest.raises(IntegrityError):
            await session.commit()

    async with SessionFactory() as session:
        persisted = await session.get(
            UserRole,
            (world.users["owner"].id, world.roles["super_admin"].id),
        )
    assert persisted is not None


async def test_database_allows_atomic_super_admin_transfer(world: World) -> None:
    async with SessionFactory() as session:
        old_assignment = await session.get(
            UserRole,
            (world.users["owner"].id, world.roles["super_admin"].id),
        )
        assert old_assignment is not None
        await session.delete(old_assignment)
        session.add(
            UserRole(
                user_id=world.users["blank"].id,
                role_id=world.roles["super_admin"].id,
                assigned_by_user_id=world.users["owner"].id,
            )
        )
        await session.commit()

    async with SessionFactory() as session:
        holders = set(
            (
                await session.scalars(
                    select(UserRole.user_id).where(
                        UserRole.role_id == world.roles["super_admin"].id
                    )
                )
            ).all()
        )
    assert holders == {world.users["blank"].id}


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
        ("roles", "deleted_by_user_id"),
    ):
        assert columns[key].data_type == "uuid"
