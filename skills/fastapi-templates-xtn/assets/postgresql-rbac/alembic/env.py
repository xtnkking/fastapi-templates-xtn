import asyncio
from logging.config import fileConfig

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app import business_audit as business_audit_models  # noqa: F401
from app import password_models  # noqa: F401
from app.base import Base
from app.rbac import models as rbac_models  # noqa: F401


class MigrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str


config = context.config
if config.config_file_name is not None and config.attributes.get(
    "configure_logger", True
):
    fileConfig(config.config_file_name)

migration_settings = MigrationSettings()  # type: ignore[call-arg]
config.set_main_option(
    "sqlalchemy.url",
    migration_settings.database_url.replace("%", "%%"),
)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
