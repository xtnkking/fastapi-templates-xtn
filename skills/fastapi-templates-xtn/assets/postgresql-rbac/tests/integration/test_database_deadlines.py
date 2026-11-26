#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在另行准备的隔离数据库上验证连接超时与连接池恢复。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        连接故障测试直接引用请求日志中间件
# 2026/09/30    XTN       V1.001        删除依赖自定义借连接重试次数的过时用例
# 2026/10/02    XTN       V1.002        对齐 PostgreSQL 故障分类模块名称
# 2026/10/02    XTN       V1.003        从统一数据库入口读取暂不可用异常
# --------------------------------------------------------------------------------------------------

"""Established-connection blackholes, not simulated SQLAlchemy exceptions."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter
from typing import cast

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from app.core.config import get_settings
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.db.postgres_db import DatabaseUnavailableError, create_database_engine, engine
from app.main import app
from tests.integration.database_proxy import DatabaseFaultProxy

pytestmark = pytest.mark.postgresql


@asynccontextmanager
async def proxied_engine(*, pool_size: int = 1) -> AsyncIterator[tuple[AsyncEngine, DatabaseFaultProxy]]:
    async with DatabaseFaultProxy() as proxy:
        settings = get_settings().model_copy(
            update={
                "database_url": proxy.url,
                "database_command_timeout_seconds": 0.2,
                "database_pool_size": pool_size,
                "database_max_overflow": 0,
            }
        )
        test_engine = create_database_engine(settings)
        try:
            yield test_engine, proxy
        finally:
            proxy.restore()
            await asyncio.wait_for(test_engine.dispose(), timeout=3)


@pytest.mark.parametrize("operation", ["query", "commit", "rollback", "checkout"])
async def test_blackholed_database_returns_safe_503_and_pool_recovers(operation: str) -> None:
    async with proxied_engine() as (test_engine, proxy):
        async with test_engine.connect() as warmup:
            old_pid = await warmup.scalar(text("SELECT pg_backend_pid()"))
        test_app = FastAPI()
        test_app.exception_handlers.update(app.exception_handlers)
        test_app.add_middleware(RequestLoggingMiddleware)

        @test_app.get("/private-timeout-probe")
        async def probe() -> None:
            if operation == "checkout":
                proxy.drop_both()
            async with test_engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
                proxy.drop_both()
                if operation == "commit":
                    await connection.commit()
                elif operation == "rollback":
                    await connection.rollback()
                else:
                    await connection.execute(text("SELECT 2"))

        async with AsyncClient(
            transport=ASGITransport(app=test_app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            started = perf_counter()
            response = await asyncio.wait_for(
                client.get("/private-timeout-probe"), timeout=3
            )
        assert perf_counter() - started < 2
        assert response.status_code == 503
        assert response.json()["code"] == 50301
        assert set(response.json()) == {"code", "message", "data", "request_id"}
        assert response.headers["X-Request-ID"] == response.json()["request_id"]
        assert response.json()["data"] is None
        assert "postgres" not in response.text.lower()
        assert "select" not in response.text.lower()
        assert cast(AsyncAdaptedQueuePool, test_engine.pool).checkedout() == 0
        proxy.restore()
        async with test_engine.connect() as recovered:
            assert await recovered.scalar(text("SELECT 1")) == 1
            assert await recovered.scalar(text("SELECT pg_backend_pid()")) != old_pid


async def test_lost_commit_reply_does_not_replay_committed_write() -> None:
    # Only this disposable test owns this table. A missing COMMIT reply must not
    # be treated as proof of rollback or as permission to repeat the INSERT.
    async with engine.begin() as setup:
        await setup.execute(text("CREATE TABLE deadline_write_probe (value integer)"))
    try:
        async with proxied_engine() as (test_engine, proxy):
            test_app = FastAPI()
            test_app.exception_handlers.update(app.exception_handlers)
            test_app.add_middleware(RequestLoggingMiddleware)
            calls = 0

            @test_app.post("/private-write-probe")
            async def write() -> None:
                nonlocal calls
                calls += 1
                async with test_engine.begin() as connection:
                    await connection.execute(
                        text("INSERT INTO deadline_write_probe VALUES (1)")
                    )
                    proxy.drop_server_to_client()

            async with AsyncClient(
                transport=ASGITransport(app=test_app, raise_app_exceptions=False),
                base_url="http://test",
            ) as client:
                response = await asyncio.wait_for(
                    client.post("/private-write-probe"), timeout=3
                )
            assert response.status_code == 503
            assert calls == 1
            proxy.restore()
            async with engine.connect() as observer:
                assert (
                    await observer.scalar(
                        text("SELECT count(*) FROM deadline_write_probe")
                    )
                    == 1
                )
    finally:
        async with engine.begin() as cleanup:
            await cleanup.execute(text("DROP TABLE deadline_write_probe"))


async def test_cancellation_discards_connection_without_server_reply() -> None:
    async with proxied_engine() as (test_engine, proxy):
        async with test_engine.connect() as connection:
            old_pid = await connection.scalar(text("SELECT pg_backend_pid()"))
            proxy.drop_both()
            observed = proxy.client_data_count
            task = asyncio.create_task(connection.execute(text("SELECT 1")))
            await proxy.wait_for_client_data(after=observed)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
        assert cast(AsyncAdaptedQueuePool, test_engine.pool).checkedout() == 0
        proxy.restore()
        async with test_engine.connect() as recovered:
            assert await recovered.scalar(text("SELECT pg_backend_pid()")) != old_pid


async def test_dispose_does_not_wait_for_blackholed_idle_connection() -> None:
    async with proxied_engine() as (test_engine, proxy):
        async with test_engine.connect() as connection:
            assert await connection.scalar(text("SELECT 1")) == 1
        proxy.drop_both()
        await asyncio.wait_for(test_engine.dispose(), timeout=2)
        proxy.restore()
        async with test_engine.connect() as recovered:
            assert await recovered.scalar(text("SELECT 1")) == 1


async def test_cancelled_checkout_releases_slot_and_preserves_cancellation() -> None:
    async with proxied_engine() as (test_engine, proxy):
        async with test_engine.connect() as warmup:
            old_pid = await warmup.scalar(text("SELECT pg_backend_pid()"))
        proxy.drop_both()
        observed = proxy.client_data_count

        async def checkout() -> None:
            async with test_engine.connect():
                pytest.fail("a blackholed checkout must not yield a connection")

        task = asyncio.create_task(checkout())
        await proxy.wait_for_client_data(after=observed)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert cast(AsyncAdaptedQueuePool, test_engine.pool).checkedout() == 0
        proxy.restore()
        async with test_engine.connect() as recovered:
            assert await recovered.scalar(text("SELECT pg_backend_pid()")) != old_pid


async def test_checkout_recovers_after_server_terminates_idle_connection() -> None:
    async with proxied_engine() as (test_engine, _proxy):
        async with test_engine.connect() as warmup:
            old_pid = await warmup.scalar(text("SELECT pg_backend_pid()"))
        async with engine.connect() as operator:
            assert await operator.scalar(
                text("SELECT pg_terminate_backend(:pid)"), {"pid": old_pid}
            )
        async with test_engine.connect() as recovered:
            assert await recovered.scalar(text("SELECT 1")) == 1
            assert await recovered.scalar(text("SELECT pg_backend_pid()")) != old_pid


async def test_command_timeout_preserves_other_healthy_pooled_connections() -> None:
    async with proxied_engine(pool_size=2) as (test_engine, proxy):
        async with test_engine.connect() as healthy:
            healthy_pid = await healthy.scalar(text("SELECT pg_backend_pid()"))
            async with test_engine.connect() as failing:
                failed_pid = await failing.scalar(text("SELECT pg_backend_pid()"))
                proxy.drop_both()
                with pytest.raises(DatabaseUnavailableError):
                    await asyncio.wait_for(failing.execute(text("SELECT 2")), timeout=3)
            proxy.restore()
            assert await healthy.scalar(text("SELECT pg_backend_pid()")) == healthy_pid
        async with test_engine.connect() as first, test_engine.connect() as second:
            pids = {
                await first.scalar(text("SELECT pg_backend_pid()")),
                await second.scalar(text("SELECT pg_backend_pid()")),
            }
        assert healthy_pid in pids
        assert failed_pid not in pids
