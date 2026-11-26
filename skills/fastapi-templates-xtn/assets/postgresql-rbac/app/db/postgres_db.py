#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    创建 PostgreSQL 引擎与请求会话，配置连接检查和数据库故障处理。
#    业务负责提交事务；连接故障不会自动重做业务操作。
#    提供数据库约束名，供业务判断冲突原因。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        用中文解释借还连接、故障重连和事务提交边界
# 2026/09/30    XTN       V1.002        分离连接池故障处理，使会话入口更容易阅读
# 2026/09/30    XTN       V1.003        改用内置连接检查，将必要故障处理收回单文件
# 2026/09/30    XTN       V1.004        明确 PostgreSQL 请求会话依赖及事务归属
# 2026/10/02    XTN       V1.005        从专名模块导入 PostgreSQL 故障分类
# 2026/10/02    XTN       V1.006        故障类型与分类收回数据库入口，删除独立错误文件
# 2026/10/08    XTN       V1.007        故障类别使用普通字符串，在分类处解释实际返回值
# 2026/10/09    XTN       V1.008        集中读取数据库约束名，供各业务判断冲突来源
# 2026/10/13    XTN       V1.009        通俗说明连接池、故障分类和请求会话的执行步骤
# 2026/10/19    XTN       V1.010        精简数据库注释，改用简短的大白话说明
# --------------------------------------------------------------------------------------------------


from collections.abc import AsyncIterator
from typing import Any, cast

from sqlalchemy import event
from sqlalchemy.engine import AdaptedConnection, ExceptionContext
from sqlalchemy.engine.interfaces import DBAPIConnection, Dialect
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import ConnectionPoolEntry

from app.core.config import Settings, get_settings


class DatabaseUnavailableError(RuntimeError):
    """
        表示数据库暂时无法使用，不包含连接地址和原始错误信息。
    """

    def __init__(self, category: str) -> None:
        """
            保存连接、连接池或超时类别，供统一 HTTP 错误处理使用。

        :param category: 故障类别，如连接失败或超时。
        :return: 无返回值；保存故障类别。
        """
        # 只保留类别，避免错误提示泄露数据库信息。
        super().__init__("database unavailable")
        self.category = category


def get_constraint_name(exc: IntegrityError) -> str | None:
    """
        读取报错的数据库约束名，供业务区分用户名占用、ID 重复等问题。
        这里只取名称，是否重试或报错由业务决定。

    :param exc: SQLAlchemy 包装的数据库完整性异常。
    :return: 首个字符串约束名；驱动未提供名称时返回 None。
    """
    # 名称可能在原异常或它的 __cause__ 中；不解析可能带敏感信息的错误正文。
    for candidate in (exc.orig, getattr(exc.orig, "__cause__", None)):
        constraint_name = getattr(candidate, "constraint_name", None)
        if isinstance(constraint_name, str):
            return constraint_name
    return None


def database_error_category(exc: BaseException) -> str | None:
    """
        判断是否为连接失败、连接池满或超时；SQL 写错和数据冲突不算临时故障。

    :param exc: SQLAlchemy 或数据库驱动抛出的异常。
    :return: 已识别的连接、连接池或超时类别；其他错误返回 None。
    """
    # 1. 先检查异常类型，区分连接故障、连接池满和超时。
    if isinstance(exc, DatabaseUnavailableError):
        return exc.category
    if isinstance(exc, PoolTimeoutError):
        return "pool_exhausted"
    # 约束冲突和 SQL 写错需要修复，不能当成临时断连。
    if isinstance(exc, (IntegrityError, ProgrammingError)):
        return None
    if isinstance(exc, DBAPIError):
        if exc.connection_invalidated:
            return "connection"
        driver_error = exc.orig
    else:
        # 建连失败也可能直接抛出驱动异常。
        driver_error = exc
    # 2. 读取 PostgreSQL 错误编号 SQLSTATE，没有编号就不猜测。
    sqlstate = getattr(driver_error, "sqlstate", None) or getattr(
        driver_error, "pgcode", None
    )
    if not isinstance(sqlstate, str):
        return None
    # 3. 按编号分类：connection 连接故障、pool_exhausted 连接满、timeout 超时。
    # 08 类及 57P01～03 表示连接故障或数据库暂不接收连接。
    if sqlstate.startswith("08") or sqlstate in {"57P01", "57P02", "57P03"}:
        return "connection"
    if sqlstate == "53300":  # 数据库允许的连接数已用满。
        return "pool_exhausted"
    if sqlstate in {"57014", "55P03"}:  # 查询取消或锁等待超时。
        return "timeout"
    return None


def connect_database(dialect: Dialect, _connection_record: ConnectionPoolEntry, args: list[Any],
                     parameters: dict[str, Any]) -> DBAPIConnection:
    """
        建立 PostgreSQL 连接，失败时把已知连接故障转成统一错误。

    :param dialect: 创建底层 asyncpg 连接的 SQLAlchemy 方言。
    :param _connection_record: 当前连接池记录；建连时无需读取。
    :param args: 传给驱动的连接位置参数。
    :param parameters: 传给驱动的连接参数，不写入日志。
    :return: 建立成功的数据库连接。
    :raises DatabaseUnavailableError: 建连时发生已识别的网络或数据库故障。
    """
    # 1. 按配置建立连接，不自动重做业务 SQL。
    try:
        return dialect.connect(*args, **parameters)
    except TimeoutError as exc:
        raise DatabaseUnavailableError("timeout") from exc
    except OSError as exc:
        raise DatabaseUnavailableError("connection") from exc
    except Exception as exc:
        # 2. 只转换已知的临时故障，其他错误原样抛出。
        category = database_error_category(exc)
        if category is None:
            raise
        raise DatabaseUnavailableError(category) from exc


def _handle_database_error(context: ExceptionContext) -> Exception | None:
    """
        命令超时后丢弃当前连接，避免下次继续使用。

    :param context: SQLAlchemy 提供的数据库异常上下文。
    :return: 驱动超时时返回安全的不可用异常；其他错误交由 SQLAlchemy 处理。
    """
    # 超时连接可能已不可靠，只丢弃这一条，不影响其他连接。
    if isinstance(context.original_exception, TimeoutError):
        context.is_disconnect = True  # type: ignore[misc]
        context.invalidate_pool_on_disconnect = False  # type: ignore[misc]
        return DatabaseUnavailableError("timeout")
    return None


def _close_database_connection(connection: DBAPIConnection, _record: ConnectionPoolEntry) -> None:
    """
        直接终止被连接池关闭的 asyncpg 连接，不等待失联网络响应。

    :param connection: SQLAlchemy 准备关闭的驱动连接。
    :param _record: 对应的连接池记录；关闭时无需读取。
    :return: 无返回值；物理连接已终止。
    """
    # 直接终止底层连接，避免关闭过程一直等待失联服务器；连接池后续可新建连接。
    cast(AdaptedConnection, connection).driver_connection.terminate()


def create_database_engine(settings: Settings) -> AsyncEngine:
    """
        创建 PostgreSQL 连接池，设置连接数量、检查和超时规则。
        断线后重连同一地址，不自动重做业务操作。

    :param settings: 数据库地址、连接池大小和超时配置。
    :return: 由应用退出时释放连接池的异步引擎。
    """
    # 1. 配置连接池；业务需要时才建立连接，不会自动建表。
    database_engine = create_async_engine(
        settings.database_url,
        echo=settings.sql_echo,
        hide_parameters=True,  # SQL 日志和异常不包含绑定值；连接串仍不得输出到日志。
        pool_pre_ping=True,  # 借出旧连接前由 SQLAlchemy 检查；失效时重新连接同一地址。
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        connect_args={
            "timeout": settings.database_connect_timeout_seconds,
            "command_timeout": settings.database_command_timeout_seconds,
            "server_settings": {
                "statement_timeout": str(settings.database_statement_timeout_ms),
                "lock_timeout": str(settings.database_lock_timeout_ms),
            },
        },
        isolation_level="READ COMMITTED",  # 并发敏感操作仍须使用明确的行锁与锁后重读。
    )
    # 2. 登记建连、故障和关闭处理函数，发生对应事件时才会执行。
    event.listen(database_engine.sync_engine, "do_connect", connect_database)
    event.listen(database_engine.sync_engine, "handle_error", _handle_database_error)
    event.listen(database_engine.sync_engine, "close", _close_database_connection)
    return database_engine


# 引擎在每个进程内共享连接池；业务请求不共享 Session 或事务。
engine = create_database_engine(get_settings())
# 查询通过下方依赖取得会话，业务写入由 Service 自己开启事务。
# 提交后保留已查字段，方便返回结果；需要最新状态时仍要重新查询。
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)


async def get_postgres_session() -> AsyncIterator[AsyncSession]:
    """
        为当前请求提供独立的数据库会话，用完自动关闭。
        不自动提交，业务自己决定何时提交；请求出错时撤回未提交的修改。

    :yield: 当前请求使用的 PostgreSQL 异步会话；退出时关闭。
    """
    # 1. 创建本次请求的会话，交给依赖使用。
    async with SessionFactory() as session:
        try:
            yield session
        except Exception:
            # 2. 出错先回滚，再抛出原错误；会话退出时自动关闭。
            await session.rollback()
            raise
