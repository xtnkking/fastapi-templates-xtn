#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    Alembic 迁移环境文件；统一加载全部 PostgreSQL 模型元数据并支持离线、异步在线迁移。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/26    XTN       V1.000        统一模型登记入口并补充迁移环境说明
# 2026/10/13    XTN       V1.001        补齐迁移环境函数的通俗步骤注释
# --------------------------------------------------------------------------------------------------

import asyncio
from logging.config import fileConfig

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.models.postgres import Base


class MigrationSettings(BaseSettings):
    """
        读取迁移命令需要的最小配置，不加载应用运行期的 Redis 或 JWT 配置。
    """

    # 只读取数据库连接地址；extra=ignore 允许复用应用 .env 中的其他配置。
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Alembic 在线迁移使用的 PostgreSQL 异步连接地址。
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
    """
        在不建立数据库连接时生成迁移 SQL，使用命名参数和当前完整模型元数据。

    :return: 无返回值，Alembic 把生成结果写到其配置的输出目标。
    """
    # 只用连接地址识别数据库方言，将迁移里的参数展开到输出 SQL，不打开数据库连接。
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    # 让 Alembic 按迁移顺序生成事务和变更语句，输出目标由迁移配置决定。
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """
        使用已经建立的同步桥接连接执行 Alembic 迁移步骤。

    :param connection: 由异步连接通过 run_sync 提供的 SQLAlchemy 同步连接。
    :return: 无返回值，迁移事务完成后由外层异步连接继续清理资源。
    """
    # 将外层提供的连接交给 Alembic；当前函数不再另建连接。
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    # 在 Alembic 管理的迁移事务中执行待应用的版本步骤。
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
        创建不复用连接池的异步迁移引擎，正常执行迁移后明确释放连接资源。

    :return: 无返回值，迁移正常完成后释放临时引擎连接池。
    """
    # 迁移是一次性工作，用不保留空闲连接的引擎读取数据库配置。
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    # 建立异步连接，再通过同步桥接执行 Alembic 所需的同步迁移回调。
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    # 正常迁移结束后关闭引擎资源，连接已由上面的上下文退出关闭。
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
