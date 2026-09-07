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
    SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    SYSTEM_ROLE_SPECS,
    SystemRoleKey,
)
from app.rbac.models import (
    AuthorizationState,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)

pytestmark = pytest.mark.postgresql

NEW_PERMISSIONS_FOR_TEST = (
    "permissions:read",
    "roles:update",
    "roles:status:update",
    "roles:delete",
    "roles:permissions:bind",
    "roles:permissions:unbind",
    "super_admin:transfer",
)


def alembic_config() -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    return config


async def recreate_database_at_revision(config: Config, revision: str) -> None:
    # Downgrading 0002 preserves its super_admin as a legacy owner. Rebuild the
    # schema so upgrade tests start from data that could genuinely exist at 0001.
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
            state = await session.get(AuthorizationState, "global")
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

        assert state is not None
        assert state.epoch == 1
        assert permission_keys == {item.value for item in PERMISSION_CATALOG}
        assert set(roles) == {item.value for item in SystemRoleKey}
        for key, spec in SYSTEM_ROLE_SPECS.items():
            role = roles[key.value]
            assert role.management_tier == spec.management_tier
            assert role.is_system
            assert role.is_protected == spec.is_protected
            assert role.is_owner == spec.is_owner
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_upgrade_renames_owner_and_backfills_mandatory_user_role() -> None:
    config = alembic_config()
    await recreate_database_at_revision(config, "0001_single_project_rbac")
    legacy_owner_id = uuid.uuid4()
    owner_user_id = uuid.uuid4()
    ordinary_user_id = uuid.uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO users (id, email) VALUES "
                    "(:owner_id, 'legacy-owner@example.test'), "
                    "(:user_id, 'legacy-user@example.test')"
                ),
                {"owner_id": owner_user_id, "user_id": ordinary_user_id},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO roles "
                    "(id, key, name, management_tier, is_active, is_protected, "
                    "is_system, is_owner) VALUES "
                    "(:id, 'owner', 'Owner', 1000, true, true, true, true)"
                ),
                {"id": legacy_owner_id},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO user_roles "
                    "(user_id, role_id, assigned_by_user_id) "
                    "VALUES (:user_id, :role_id, NULL)"
                ),
                {"user_id": owner_user_id, "role_id": legacy_owner_id},
            )

        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")

        async with SessionFactory() as session:
            super_admin_role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
            )
            user_role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.USER.value)
            )
            assert super_admin_role is not None and user_role is not None
            assignments = (
                await session.execute(
                    select(UserRole.user_id, Role.key)
                    .join(Role, Role.id == UserRole.role_id)
                    .where(UserRole.user_id.in_({owner_user_id, ordinary_user_id}))
                )
            ).all()
            users = {
                user.id: user
                for user in (
                    await session.scalars(
                        select(User).where(
                            User.id.in_({owner_user_id, ordinary_user_id})
                        )
                    )
                ).all()
            }
            state = await session.get(AuthorizationState, "global")

        assert super_admin_role.id == legacy_owner_id
        assert set(assignments) == {
            (owner_user_id, SystemRoleKey.SUPER_ADMIN.value),
            (owner_user_id, SystemRoleKey.USER.value),
            (ordinary_user_id, SystemRoleKey.USER.value),
        }
        assert users[owner_user_id].authz_version == 1
        assert users[ordinary_user_id].authz_version == 1
        assert state is not None and state.epoch == 1
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


@pytest.mark.parametrize("legacy_key", ["owner", "super_admin"])
async def test_upgrade_rejects_multiple_legacy_owner_holders_and_rolls_back(
    legacy_key: str,
) -> None:
    config = alembic_config()
    await recreate_database_at_revision(config, "0001_single_project_rbac")
    legacy_owner_id = uuid.uuid4()
    holder_ids = (uuid.uuid4(), uuid.uuid4())
    try:
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO users (id, email) VALUES "
                    "(:first_id, 'first-legacy-owner@example.test'), "
                    "(:second_id, 'second-legacy-owner@example.test')"
                ),
                {"first_id": holder_ids[0], "second_id": holder_ids[1]},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO roles "
                    "(id, key, name, management_tier, is_active, is_protected, "
                    "is_system, is_owner) VALUES "
                    "(:id, :key, 'Owner', 1000, true, true, true, true)"
                ),
                {"id": legacy_owner_id, "key": legacy_key},
            )
            await connection.execute(
                sa.text(
                    "INSERT INTO user_roles "
                    "(user_id, role_id, assigned_by_user_id) VALUES "
                    "(:first_id, :role_id, NULL), "
                    "(:second_id, :role_id, NULL)"
                ),
                {
                    "first_id": holder_ids[0],
                    "second_id": holder_ids[1],
                    "role_id": legacy_owner_id,
                },
            )

        await engine.dispose()
        with pytest.raises(
            RuntimeError,
            match="legacy Owner role has multiple holders",
        ):
            await asyncio.to_thread(command.upgrade, config, "head")

        async with engine.connect() as connection:
            revision = await connection.scalar(
                sa.text("SELECT version_num FROM alembic_version")
            )
            role_key = await connection.scalar(
                sa.text("SELECT key FROM roles WHERE id = :role_id"),
                {"role_id": legacy_owner_id},
            )
            persisted_holders = set(
                (
                    await connection.scalars(
                        sa.text(
                            "SELECT user_id FROM user_roles WHERE role_id = :role_id"
                        ),
                        {"role_id": legacy_owner_id},
                    )
                ).all()
            )
            v2_column_count = await connection.scalar(
                sa.text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'roles' "
                    "AND column_name IN "
                    "('description', 'deleted_at', 'deleted_by_user_id')"
                )
            )
            new_permission_count = await connection.scalar(
                sa.text("SELECT count(*) FROM permissions WHERE key = ANY(:keys)"),
                {"keys": list(NEW_PERMISSIONS_FOR_TEST)},
            )

        assert revision == "0001_single_project_rbac"
        assert role_key == legacy_key
        assert persisted_holders == set(holder_ids)
        assert v2_column_count == 0
        assert new_permission_count == 0
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.downgrade, config, "base")
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_migration_seeds_exact_super_admin_grants() -> None:
    async with SessionFactory() as session:
        role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert role is not None
        grants = (
            await session.execute(
                select(Permission.key, RolePermission.can_delegate)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id == role.id)
            )
        ).all()

    assert {row.key for row in grants} == SUPER_ADMIN_PERMISSION_KEYS
    assert {row.key for row in grants if row.can_delegate} == (
        SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS
    )


async def test_upgrade_refuses_reserved_admin_key_collision() -> None:
    config = alembic_config()
    await recreate_database_at_revision(config, "0001_single_project_rbac")
    try:
        collision_id = uuid.uuid4()
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO roles "
                    "(id, key, name, management_tier) "
                    "VALUES (:id, 'admin', 'Legacy custom admin', 100)"
                ),
                {"id": collision_id},
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
