import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.database import SessionFactory, engine
from app.rbac.domain import PermissionKey, SystemRoleKey
from app.rbac.models import (
    RbacAuditEvent,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


@pytest.mark.parametrize(
    ("user_name", "expected_error"),
    [
        pytest.param(None, IntegrityError, id="missing-user-name"),
        pytest.param("   ", IntegrityError, id="blank-user-name"),
        pytest.param("a!b", IntegrityError, id="invalid-user-name"),
        pytest.param("aa", IntegrityError, id="short-user-name"),
        pytest.param("x" * 33, DBAPIError, id="long-user-name"),
    ],
)
async def test_database_requires_a_valid_user_name(
    user_name: str | None, expected_error: type[DBAPIError]
) -> None:
    async with SessionFactory() as session:
        session.add(User(user_name=user_name))
        with pytest.raises(expected_error) as caught:
            await session.commit()
        if user_name is not None and len(user_name) > 32:
            assert getattr(caught.value.orig, "sqlstate", None) == "22001"


async def test_database_reserves_user_name_after_soft_deletion(world: World) -> None:
    target = world.users["blank"]
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, target.id, with_for_update=True)
            assert user is not None
            user.is_active = False
            user.deleted_at = datetime.now(UTC)
            bindings = (
                await session.scalars(
                    select(UserRole).where(
                        UserRole.user_id == target.id,
                        UserRole.deleted_at.is_(None),
                    )
                )
            ).all()
            for binding in bindings:
                binding.deleted_at = user.deleted_at

    async with SessionFactory() as session:
        session.add(User(user_name=target.user_name))
        with pytest.raises(IntegrityError):
            await session.commit()


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
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_duplicate_live_user_assignment(world: World) -> None:
    async with SessionFactory() as session:
        session.add(
            UserRole(
                user_id=world.users["lower"].id,
                role_id=world.roles["viewer"].id,
                assigned_by_user_id=world.users["manager"].id,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_duplicate_live_permission_grant(world: World) -> None:
    async with SessionFactory() as session:
        session.add(
            RolePermission(
                role_id=world.roles["viewer"].id,
                permission_id=world.permissions[PermissionKey.PROJECTS_READ.value].id,
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


async def test_database_reserves_management_tier_1000_for_super_admin() -> None:
    async with SessionFactory() as session:
        session.add(
            Role(
                key="super-admin-tier-impostor",
                name="Super administrator tier impostor",
                management_tier=1000,
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_allows_owner_as_a_custom_role_key() -> None:
    async with SessionFactory() as session:
        role = Role(
            key="owner",
            name="Custom owner label",
            management_tier=100,
        )
        session.add(role)
        await session.commit()

    assert role.key == "owner"
    assert not role.is_system
    assert not role.is_super_admin


async def test_database_allows_only_one_super_admin_role(world: World) -> None:
    assert world.roles["super_admin"].is_super_admin
    async with SessionFactory() as session:
        session.add(
            Role(
                key="second-super-admin",
                name="Second super administrator",
                management_tier=1000,
                is_system=True,
                is_protected=True,
                is_super_admin=True,
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
    assert roles[SystemRoleKey.SUPER_ADMIN.value].is_super_admin
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
        with pytest.raises(IntegrityError):
            await session.execute(delete(Role).where(Role.id == role.id))
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
        session.add(User(user_name="missing_user_role"))
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_database_rejects_removing_mandatory_user_role(world: World) -> None:
    async with SessionFactory() as session:
        user_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.USER.value)
        )
        assert user_role is not None
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].id,
                UserRole.role_id == user_role.id,
                UserRole.deleted_at.is_(None),
            )
        )
        assert assignment is not None
        assignment.deleted_at = datetime.now(UTC)
        assignment.deleted_by_user_id = world.users["super_admin"].id
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
        new_user = User(user_name="pre_bootstrap_user")
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
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["super_admin"].id,
                UserRole.role_id == world.roles["super_admin"].id,
                UserRole.deleted_at.is_(None),
            )
        )
        assert assignment is not None
        assignment.deleted_at = datetime.now(UTC)
        assignment.deleted_by_user_id = world.users["super_admin"].id
        with pytest.raises(IntegrityError):
            await session.commit()

    async with SessionFactory() as session:
        persisted = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["super_admin"].id,
                UserRole.role_id == world.roles["super_admin"].id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert persisted is not None


async def test_database_allows_atomic_super_admin_transfer(world: World) -> None:
    async with SessionFactory() as session:
        old_assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["super_admin"].id,
                UserRole.role_id == world.roles["super_admin"].id,
                UserRole.deleted_at.is_(None),
            )
        )
        assert old_assignment is not None
        old_assignment.deleted_at = datetime.now(UTC)
        old_assignment.deleted_by_user_id = world.users["super_admin"].id
        session.add(
            UserRole(
                user_id=world.users["blank"].id,
                role_id=world.roles["super_admin"].id,
                assigned_by_user_id=world.users["super_admin"].id,
            )
        )
        await session.commit()

    async with SessionFactory() as session:
        holders = set(
            (
                await session.scalars(
                    select(UserRole.user_id).where(
                        UserRole.role_id == world.roles["super_admin"].id,
                        UserRole.deleted_at.is_(None),
                    )
                )
            ).all()
        )
        historical = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.role_id == world.roles["super_admin"].id
                )
            )
        ).all()
    assert holders == {world.users["blank"].id}
    assert len(historical) == 2
    assert sum(item.deleted_at is None for item in historical) == 1


async def test_rbac_audit_rows_are_append_only(world: World) -> None:
    event_id = uuid.uuid4()
    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                RbacAuditEvent(
                    id=event_id,
                    actor_user_id=world.users["super_admin"].id,
                    target_role_id=world.roles["manager"].id,
                    action="role.update",
                    decision="allowed",
                    reason_code="role_updated",
                    before_state={"version": 1},
                    after_state={"version": 2},
                    request_id=str(uuid.uuid4()),
                )
            )

    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE rbac_audit_events SET reason_code = 'rewritten' "
                        "WHERE id = :event_id"
                    ),
                    {"event_id": event_id},
                )

    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text("DELETE FROM rbac_audit_events WHERE id = :event_id"),
                    {"event_id": event_id},
                )

    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(text("TRUNCATE TABLE rbac_audit_events"))


async def test_rbac_state_row_cannot_be_removed() -> None:
    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text("DELETE FROM rbac_state WHERE scope = 'global'")
                )

    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(text("TRUNCATE TABLE rbac_state"))

    async with SessionFactory() as session:
        state = await session.get(RbacState, "global")
    assert state is not None


async def test_schema_uses_only_expected_tables_and_uuid_entity_ids() -> None:
    expected_tables = {
        "account_security_audit_events",
        "alembic_version",
        "business_audit_events",
        "rbac_audit_events",
        "rbac_state",
        "permissions",
        "role_permissions",
        "roles",
        "user_roles",
        "users",
    }
    entity_id_columns = {
        ("account_security_audit_events", "id"),
        ("rbac_audit_events", "id"),
        ("permissions", "id"),
        ("role_permissions", "id"),
        ("roles", "id"),
        ("user_roles", "id"),
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
    business_audit_id = columns[("business_audit_events", "id")]
    assert business_audit_id.data_type == "uuid"
    assert business_audit_id.column_default is None
    assert columns[("users", "password_hash")].data_type == "character varying"
    assert columns[("users", "password_changed_at")].data_type == (
        "timestamp with time zone"
    )
    assert columns[("users", "must_change_password")].data_type == "boolean"
    assert "false" in columns[("users", "must_change_password")].column_default
    assert columns[("rbac_state", "public_registration_enabled")].data_type == (
        "boolean"
    )
    assert (
        "true" in columns[("rbac_state", "public_registration_enabled")].column_default
    )
    assert ("users", "user_name") in columns
    assert ("users", "email") not in columns

    for key in (
        ("role_permissions", "role_id"),
        ("role_permissions", "permission_id"),
        ("role_permissions", "assigned_by_user_id"),
        ("role_permissions", "deleted_by_user_id"),
        ("user_roles", "user_id"),
        ("user_roles", "role_id"),
        ("user_roles", "assigned_by_user_id"),
        ("user_roles", "deleted_by_user_id"),
        ("permissions", "deleted_by_user_id"),
        ("roles", "deleted_by_user_id"),
        ("users", "deleted_by_user_id"),
        ("account_security_audit_events", "actor_user_id"),
        ("account_security_audit_events", "target_user_id"),
    ):
        assert columns[key].data_type == "uuid"
