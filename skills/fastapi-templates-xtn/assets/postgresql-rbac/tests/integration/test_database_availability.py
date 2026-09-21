"""Database budgets and failure recovery on the guarded disposable database."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.config import get_settings
from app.db.errors import database_error_category
from app.db.postgres import engine

pytestmark = pytest.mark.postgresql


async def test_new_database_connections_receive_configured_timeouts() -> None:
    async with engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT name, setting::bigint FROM pg_settings "
                "WHERE name IN ('statement_timeout', 'lock_timeout')"
            )
        )
        actual = {row[0]: row[1] for row in rows}

    settings = get_settings()
    assert actual == {
        "statement_timeout": settings.database_statement_timeout_ms,
        "lock_timeout": settings.database_lock_timeout_ms,
    }


async def test_statement_timeout_rolls_back_and_connection_recovers() -> None:
    async with engine.connect() as connection:
        with pytest.raises(DBAPIError) as caught:
            async with connection.begin():
                await connection.execute(text("SET LOCAL statement_timeout = '20ms'"))
                await connection.execute(text("SELECT pg_sleep(0.2)"))

        assert database_error_category(caught.value) == "timeout"
        assert not connection.in_transaction()
        assert await connection.scalar(text("SELECT 1")) == 1


async def test_lock_timeout_rolls_back_without_replaying_command() -> None:
    # Transaction-scoped advisory locks avoid touching the application's data.
    # The integration safety fixture requires a fresh disposable database.
    lock_statement = text("SELECT pg_advisory_xact_lock(731928415)")
    async with engine.begin() as holder:
        await holder.execute(lock_statement)
        async with engine.connect() as waiter:
            with pytest.raises(DBAPIError) as caught:
                async with waiter.begin():
                    await waiter.execute(text("SET LOCAL lock_timeout = '20ms'"))
                    await waiter.execute(lock_statement)

            assert database_error_category(caught.value) == "timeout"
            assert not waiter.in_transaction()
            assert await waiter.scalar(text("SELECT 1")) == 1
