import asyncio
from collections.abc import AsyncIterator
from typing import Any, cast

from sqlalchemy import event
from sqlalchemy.engine import AdaptedConnection, ExceptionContext
from sqlalchemy.engine.interfaces import DBAPIConnection, Dialect
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import ConnectionPoolEntry, PoolProxiedConnection

from app.core.config import Settings, get_settings
from app.db.errors import DatabaseUnavailableError, database_error_category

_CHECKOUT_RETRIED = "application_checkout_retried"


def connect_database(
    dialect: Dialect,
    _connection_record: ConnectionPoolEntry,
    args: list[Any],
    parameters: dict[str, Any],
) -> DBAPIConnection:
    # asyncpg may raise an unwrapped socket/DNS/TLS error while opening a
    # connection. Normalize it here so unrelated business OSError/TimeoutError
    # exceptions retain their ordinary error semantics. Never retry a command.
    try:
        return dialect.connect(*args, **parameters)
    except TimeoutError as exc:
        raise DatabaseUnavailableError("timeout") from exc
    except OSError as exc:
        raise DatabaseUnavailableError("connection") from exc
    except Exception as exc:
        category = database_error_category(exc)
        if category is None:
            raise
        raise DatabaseUnavailableError(category) from exc


def _handle_database_error(context: ExceptionContext) -> Exception | None:
    if isinstance(context.original_exception, TimeoutError):
        # A driver deadline gives no guarantee that cancellation was delivered.
        # Retire this connection before any rollback; leave healthy peers alone.
        # SQLAlchemy documents these as mutable event fields; the interface
        # stubs' empty __slots__ do not describe its concrete event context.
        context.is_disconnect = True  # type: ignore[misc]
        context.invalidate_pool_on_disconnect = False  # type: ignore[misc]
        return DatabaseUnavailableError("timeout")
    return None


def _close_database_connection(
    connection: DBAPIConnection, _record: ConnectionPoolEntry
) -> None:
    # asyncpg graceful close can await a pending cancellation before starting its
    # own close timeout. Public terminate() aborts locally without a network wait.
    # Pool close runs only when retiring a physical connection, never on check-in.
    cast(AdaptedConnection, connection).driver_connection.terminate()


def _reset_checkout_retry(
    _connection: DBAPIConnection | None, record: ConnectionPoolEntry
) -> None:
    # Check-in also runs after checkout failure, including failed reconnection.
    if record.record_info is not None:
        record.record_info.pop(_CHECKOUT_RETRIED, None)


def create_database_engine(settings: Settings) -> AsyncEngine:
    database_engine = create_async_engine(
        settings.database_url,
        echo=settings.sql_echo,
        hide_parameters=True,
        # The checkout hook below owns a bounded, transaction-free health probe.
        pool_pre_ping=False,
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
        isolation_level="READ COMMITTED",
    )

    async def probe(driver: Any) -> None:
        try:
            async with asyncio.timeout(settings.database_command_timeout_seconds):
                await driver.execute("SELECT 1")
        except asyncio.CancelledError:
            driver.terminate()
            raise
        except TimeoutError as exc:
            driver.terminate()
            raise DatabaseUnavailableError("timeout") from exc
        except Exception as exc:
            category = database_error_category(exc)
            disconnected = (
                driver.is_closed()
                or isinstance(exc, OSError)
                or category == "connection"
            )
            driver.terminate()
            if disconnected:
                # SQLAlchemy may reconnect during checkout only. No user SQL
                # has run here, and no transaction or commit is replayed.
                raise DisconnectionError("database connection unavailable") from exc
            if category is not None:
                raise DatabaseUnavailableError(category) from exc
            raise

    def checkout(
        connection: DBAPIConnection,
        record: ConnectionPoolEntry,
        _proxy: PoolProxiedConnection,
    ) -> None:
        try:
            cast(AdaptedConnection, connection).run_async(probe)
        except DisconnectionError as exc:
            # Allow one replacement before business SQL. Catch the second
            # disconnect here, before the pool turns exhaustion into a generic
            # InvalidRequestError that could be confused with a programming bug.
            retry_state = record.record_info
            if retry_state is None or retry_state.get(_CHECKOUT_RETRIED):
                raise DatabaseUnavailableError("connection") from exc
            retry_state[_CHECKOUT_RETRIED] = True
            raise

    event.listen(database_engine.sync_engine, "do_connect", connect_database)
    event.listen(database_engine.sync_engine, "handle_error", _handle_database_error)
    event.listen(database_engine.sync_engine, "close", _close_database_connection)
    event.listen(database_engine.sync_engine, "checkout", checkout)
    event.listen(database_engine.sync_engine, "checkin", _reset_checkout_retry)
    return database_engine


engine = create_database_engine(get_settings())
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
