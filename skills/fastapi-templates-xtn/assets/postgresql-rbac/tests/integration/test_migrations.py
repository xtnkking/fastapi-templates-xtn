import asyncio
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy import select

from alembic import command
from app.database import SessionFactory, engine
from app.rbac.domain import (
    PERMISSION_CATALOG,
    SUPER_ADMIN_PERMISSION_KEYS,
    SYSTEM_ROLE_SPECS,
    SystemRoleKey,
)
from app.rbac.models import (
    Permission,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


def alembic_config() -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    return config


async def recreate_database_at_revision(config: Config, revision: str) -> None:
    # Rebuild the schema so every upgrade test starts at the exact requested
    # revision without data left by a later migration.
    await engine.dispose()
    await asyncio.to_thread(command.downgrade, config, "base")
    await asyncio.to_thread(command.upgrade, config, revision)


async def test_clean_migration_seeds_catalog_state_and_system_roles() -> None:
    config = alembic_config()
    await engine.dispose()
    await asyncio.to_thread(command.downgrade, config, "base")
    try:
        await asyncio.to_thread(command.upgrade, config, "head")
        async with SessionFactory() as session:
            state = await session.get(RbacState, "global")
            permission_keys = set((await session.scalars(select(Permission.key))).all())
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
            revision = await session.scalar(
                sa.text("SELECT version_num FROM alembic_version")
            )
            role_limit_trigger_count = await session.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE tgname = 'ct_user_roles_max_ten_live'"
                )
            )

        assert state is not None
        assert state.epoch == 2
        assert state.public_registration_enabled is True
        assert revision == "0004_password_auth"
        assert role_limit_trigger_count == 1
        assert permission_keys == {item.value for item in PERMISSION_CATALOG}
        assert set(roles) == {item.value for item in SystemRoleKey}
        for key, spec in SYSTEM_ROLE_SPECS.items():
            role = roles[key.value]
            assert role.management_tier == spec.management_tier
            assert role.is_system
            assert role.is_protected == spec.is_protected
            assert role.is_super_admin == spec.is_super_admin
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_nonempty_database_downgrades_to_base(world: World) -> None:
    assert world.users["super_admin"].id
    config = alembic_config()
    await engine.dispose()
    try:
        await asyncio.to_thread(command.downgrade, config, "base")
        async with engine.connect() as connection:
            assert (
                await connection.scalar(
                    sa.text("SELECT to_regclass('public.user_roles')")
                )
                is None
            )
            assert (
                await connection.scalar(sa.text("SELECT to_regclass('public.users')"))
                is None
            )
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_upgrade_preserves_custom_owner_key_and_backfills_base_role() -> None:
    config = alembic_config()
    await recreate_database_at_revision(config, "0001_single_project_rbac")
    custom_super_admin_role_id = uuid.uuid4()
    custom_owner_holder_id = uuid.uuid4()
    ordinary_user_id = uuid.uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO users (id, user_name) VALUES "
                    "(:custom_owner_holder_id, 'custom_owner'), "
                    "(:ordinary_user_id, 'ordinary_user')"
                ),
                {
                    "custom_owner_holder_id": custom_owner_holder_id,
                    "ordinary_user_id": ordinary_user_id,
                },
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO roles (id, key, name, management_tier) "
                    "VALUES (:id, 'owner', 'Custom owner label', 10)"
                ),
                {"id": custom_super_admin_role_id},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO user_roles "
                    "(user_id, role_id, assigned_by_user_id) "
                    "VALUES (:user_id, :role_id, NULL)"
                ),
                {
                    "user_id": custom_owner_holder_id,
                    "role_id": custom_super_admin_role_id,
                },
            )

        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")

        async with SessionFactory() as session:
            super_admin_role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
            )
            custom_super_admin_role = await session.scalar(
                select(Role).where(Role.key == "owner")
            )
            user_role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.USER.value)
            )
            assert super_admin_role is not None
            assert custom_super_admin_role is not None
            assert user_role is not None
            assignments = (
                await session.execute(
                    select(UserRole.user_id, Role.key)
                    .join(Role, Role.id == UserRole.role_id)
                    .where(
                        UserRole.user_id.in_({custom_owner_holder_id, ordinary_user_id})
                    )
                )
            ).all()
            users = {
                user.id: user
                for user in (
                    await session.scalars(
                        select(User).where(
                            User.id.in_({custom_owner_holder_id, ordinary_user_id})
                        )
                    )
                ).all()
            }
            state = await session.get(RbacState, "global")

        assert super_admin_role.id == uuid.uuid5(
            uuid.NAMESPACE_URL,
            "fastapi-rbac-system-role:super_admin",
        )
        assert custom_super_admin_role.id == custom_super_admin_role_id
        assert not custom_super_admin_role.is_system
        assert not custom_super_admin_role.is_super_admin
        assert set(assignments) == {
            (custom_owner_holder_id, "owner"),
            (custom_owner_holder_id, SystemRoleKey.USER.value),
            (ordinary_user_id, SystemRoleKey.USER.value),
        }
        assert users[custom_owner_holder_id].authz_version == 1
        assert users[ordinary_user_id].authz_version == 1
        assert state is not None and state.epoch == 2
        assert state.public_registration_enabled is True
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_migration_seeds_exact_super_admin_grants() -> None:
    async with SessionFactory() as session:
        role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert role is not None
        grants = (
            await session.execute(
                select(Permission.key)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id == role.id)
            )
        ).all()

    assert {row.key for row in grants} == SUPER_ADMIN_PERMISSION_KEYS


@pytest.mark.parametrize("system_key", tuple(item.value for item in SystemRoleKey))
async def test_upgrade_refuses_system_role_key_collision(system_key: str) -> None:
    config = alembic_config()
    await recreate_database_at_revision(config, "0001_single_project_rbac")
    try:
        collision_id = uuid.uuid4()
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO roles "
                    "(id, key, name, management_tier) "
                    "VALUES (:id, :key, 'Custom collision', 100)"
                ),
                {"id": collision_id, "key": system_key},
            )

        await engine.dispose()
        with pytest.raises(RuntimeError, match="non-system shape"):
            await asyncio.to_thread(command.upgrade, config, "head")

        async with SessionFactory() as session:
            collision_is_system = await session.scalar(
                sa.text("SELECT is_system FROM roles WHERE id = :id"),
                {"id": collision_id},
            )
            assert collision_is_system is False
            await session.execute(
                sa.text("DELETE FROM roles WHERE id = :id"),
                {"id": collision_id},
            )
            await session.commit()
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")
