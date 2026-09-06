import asyncio
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import select

from alembic import command
from app.database import SessionFactory, engine
from app.rbac.domain import OWNER_PERMISSION_KEYS
from app.rbac.models import AuthorizationState, Permission

pytestmark = pytest.mark.postgresql


def alembic_config() -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    return config


async def test_clean_migration_seeds_permissions_and_global_state() -> None:
    config = alembic_config()
    await engine.dispose()
    await asyncio.to_thread(command.downgrade, config, "base")
    try:
        await asyncio.to_thread(command.upgrade, config, "head")
        async with SessionFactory() as session:
            state = await session.get(AuthorizationState, "global")
            permission_keys = set((await session.scalars(select(Permission.key))).all())

        assert state is not None
        assert state.epoch == 0
        assert permission_keys == OWNER_PERMISSION_KEYS
    finally:
        await engine.dispose()
        await asyncio.to_thread(command.upgrade, config, "head")
