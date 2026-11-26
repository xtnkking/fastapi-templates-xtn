#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    维护用历史迁移回归；核对角色、绑定与全局权限变更序号。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/15    XTN       V1.000        移除用户权限版本并补充实际维护说明
# 2026/10/16    XTN       V1.001        移除运行时权限版本预期，保留协调锁与历史迁移契约
# --------------------------------------------------------------------------------------------------

import asyncio
import io
import logging
import uuid

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy import select

from alembic import command
from app.core.access.permissions import PERMISSION_CATALOG
from app.core.access.roles import SUPER_ADMIN_PERMISSION_KEYS, SYSTEM_ROLE_SPECS, SystemRoleKey
from app.db.postgres_db import SessionFactory, engine
from app.models.postgres.permission import Permission
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole
from tests.integration.conftest import World
from tests.migration_helpers import alembic_config

pytestmark = pytest.mark.postgresql


async def test_embedded_migration_preserves_application_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    logger = logging.getLogger("app.migration_regression")
    dependency_logger = logging.getLogger("httpx")
    root_handlers = list(logging.getLogger().handlers)
    monkeypatch.setattr(logger, "handlers", [logging.StreamHandler(output)])
    monkeypatch.setattr(logger, "level", logging.INFO)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(dependency_logger, "disabled", True)

    await asyncio.to_thread(command.upgrade, alembic_config(), "head")
    logger.info("migration.completed")

    assert output.getvalue() == "migration.completed\n"
    assert not logger.disabled
    assert dependency_logger.disabled
    assert logging.getLogger().handlers == root_handlers


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
            state = (await session.execute(sa.text("SELECT scope, epoch FROM rbac_state WHERE scope = 'global'"))).one()
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
        assert revision == "0004_password_auth"
        assert role_limit_trigger_count == 1
        # 已发布的历史迁移仍包含旧注册配置权限；当前模板不再使用它。
        assert permission_keys == {item.value for item in PERMISSION_CATALOG} | {"registration:configure"}
        assert set(roles) == {item.value for item in SystemRoleKey}
        for key, spec in SYSTEM_ROLE_SPECS.items():
            role = roles[key.value]
            assert role.level == spec.level
            assert role.is_system
            assert role.is_protected == spec.is_protected
            assert role.is_super_admin == spec.is_super_admin
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")


async def test_nonempty_database_downgrades_to_base(world: World) -> None:
    assert world.users["super_admin"].user_id
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
                user.user_id: user
                for user in (
                    await session.scalars(
                        select(User).where(
                            User.user_id.in_({custom_owner_holder_id, ordinary_user_id})
                        )
                    )
                ).all()
            }
            state = (await session.execute(sa.text("SELECT scope, epoch FROM rbac_state WHERE scope = 'global'"))).one()

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
        assert set(users) == {custom_owner_holder_id, ordinary_user_id}
        assert state is not None and state.epoch == 2
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

    # 此测试复核旧迁移的原始授权，不把旧权限带回当前目录。
    assert {row.key for row in grants} == SUPER_ADMIN_PERMISSION_KEYS | {"registration:configure"}


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
