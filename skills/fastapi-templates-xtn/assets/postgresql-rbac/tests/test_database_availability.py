from asyncio import CancelledError
from collections.abc import Callable
from typing import NoReturn, cast
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.asyncio.connection import AbstractConnection, ConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, ProgrammingError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.pool import AsyncAdaptedQueuePool, ConnectionPoolEntry
from sqlalchemy.util import greenlet_spawn

from app.core.api_contract import BusinessCode
from app.core.config import get_settings
from app.db.errors import DatabaseUnavailableError, database_error_category
from app.db.postgres import connect_database, engine
from app.db.redis import create_rate_limit_redis_client, create_redis_client
from app.main import RequestObservabilityMiddleware, app


class _DriverError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("private database connection detail")
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (PoolTimeoutError("private database connection detail"), 503),
        (
            InterfaceError(None, None, _DriverError(""), connection_invalidated=True),
            503,
        ),
        *[
            (DBAPIError(None, None, _DriverError(code)), 503)
            for code in ("08006", "57P01", "57P02", "57P03", "53300", "57014", "55P03")
        ],
        (ProgrammingError(None, None, _DriverError("42601")), 500),
        (IntegrityError(None, None, _DriverError("23505")), 500),
        (DBAPIError(None, None, _DriverError("40001")), 500),
        (DBAPIError(None, None, _DriverError("XX000")), 500),
        (TimeoutError("private database connection detail"), 500),
        (OSError("private database connection detail"), 500),
    ],
)
async def test_database_availability_http_contract_is_precise_and_safe(
    error: Exception,
    expected_status: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    test_app = FastAPI()
    test_app.exception_handlers.update(app.exception_handlers)
    test_app.add_middleware(RequestObservabilityMiddleware)

    @test_app.get("/controlled-database-operation")
    async def operation() -> None:
        raise error

    async with AsyncClient(
        transport=ASGITransport(app=test_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/controlled-database-operation")

    assert response.status_code == expected_status
    expected_code = (
        BusinessCode.SERVICE_UNAVAILABLE
        if expected_status == 503
        else BusinessCode.INTERNAL_ERROR
    )
    assert response.json()["code"] == int(expected_code)
    assert response.headers["X-Request-ID"] == response.json()["request_id"]
    assert "private database connection detail" not in response.text
    dependency_events = [
        event
        for event in caplog.records
        if event.getMessage() == "dependency.database.unavailable"
    ]
    assert len(dependency_events) == (1 if expected_status == 503 else 0)
    for record in dependency_events:
        assert "private database connection detail" not in str(record.__dict__)


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionRefusedError("private"),
        TimeoutError(),
        _DriverError("08006"),
        _DriverError("57P03"),
    ],
)
async def test_engine_normalizes_connect_failure_without_network_or_retry(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    await engine.dispose()
    connection_calls: list[dict[str, object]] = []

    def fail_connect(*_args: object, **kwargs: object) -> NoReturn:
        connection_calls.append(kwargs)
        raise failure

    monkeypatch.setattr(engine.dialect.loaded_dbapi, "connect", fail_connect)
    try:
        with pytest.raises(DatabaseUnavailableError) as caught:
            async with engine.connect():
                pytest.fail("a failed connection must not yield a connection")
    finally:
        await engine.dispose()

    assert len(connection_calls) == 1
    settings = get_settings()
    assert connection_calls[0]["timeout"] == settings.database_connect_timeout_seconds
    assert (
        connection_calls[0]["command_timeout"]
        == settings.database_command_timeout_seconds
    )
    assert connection_calls[0]["server_settings"] == {
        "statement_timeout": str(settings.database_statement_timeout_ms),
        "lock_timeout": str(settings.database_lock_timeout_ms),
    }
    assert str(caught.value) == "database unavailable"
    assert database_error_category(caught.value) == (
        "timeout" if isinstance(failure, TimeoutError) else "connection"
    )


@pytest.mark.parametrize("error", [ValueError("configuration"), CancelledError()])
def test_connect_preserves_cancellation_and_program_errors(
    error: BaseException,
) -> None:
    dialect = MagicMock(spec=Dialect)
    dialect.connect.side_effect = error
    with pytest.raises(type(error)) as caught:
        connect_database(
            cast(Dialect, dialect), MagicMock(spec=ConnectionPoolEntry), [], {}
        )
    assert caught.value is error


async def test_postgresql_pool_exhaustion_has_a_bounded_wait() -> None:
    # Exercise SQLAlchemy's real async pool, with no database or network.
    creator = MagicMock(return_value=MagicMock())
    pool = AsyncAdaptedQueuePool(creator, pool_size=1, max_overflow=0, timeout=0.01)
    held = await greenlet_spawn(pool.connect)
    try:
        with pytest.raises(PoolTimeoutError) as caught:
            await greenlet_spawn(pool.connect)
        assert database_error_category(caught.value) == "pool_exhausted"
        creator.assert_called_once()
    finally:
        await greenlet_spawn(held.close)
        await greenlet_spawn(pool.dispose)

    configured_pool = cast(AsyncAdaptedQueuePool, engine.pool)
    assert configured_pool.size() == get_settings().database_pool_size
    assert configured_pool.timeout() == get_settings().database_pool_timeout_seconds


async def test_each_redis_client_has_its_own_bounded_connection_pool() -> None:
    settings = get_settings().model_copy(update={"redis_max_connections": 2})
    active = create_redis_client(settings)
    limiter = create_rate_limit_redis_client(settings)
    try:
        assert active.connection_pool is not limiter.connection_pool
        for client in (active, limiter):
            pool = client.connection_pool
            assert isinstance(pool, ConnectionPool)
            assert pool.max_connections == 2
            next_connection = cast(
                Callable[[], AbstractConnection], pool.get_available_connection
            )
            first = next_connection()
            second = next_connection()
            assert not pool.can_get_connection()
            with pytest.raises(RedisConnectionError, match="Too many connections"):
                next_connection()
            await pool.release(first)
            await pool.release(second)
    finally:
        await active.aclose()
        await limiter.aclose()
