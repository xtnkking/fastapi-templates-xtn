"""Exercise readiness against guarded disposable PostgreSQL and Redis targets."""

import asyncio
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis
from redis.asyncio.client import Monitor
from sqlalchemy import event

from app.api_contract import BusinessCode
from app.database import engine
from app.settings import get_settings

pytestmark = pytest.mark.postgresql

_EXPECTED_REDIS_COMMANDS = frozenset({"PING", "EVAL", "PSETEX", "GET", "DEL"})


def _redis_database(url: str) -> int:
    return int(urlsplit(url).path.removeprefix("/"))


async def _observe_redis_readiness_probe(
    monitor: Monitor,
    *,
    database: int,
    key_namespace: str,
) -> frozenset[str]:
    observed: set[str] = set()
    key_prefix = f"readiness:v1:{key_namespace}:"
    try:
        async with asyncio.timeout(3):
            while observed != _EXPECTED_REDIS_COMMANDS:
                command_info = await monitor.next_command()
                if command_info["db"] != database:
                    continue
                command = command_info["command"]
                command_name = command.partition(" ")[0].upper()
                if command_name == "PING":
                    observed.add(command_name)
                elif command_name in _EXPECTED_REDIS_COMMANDS and key_prefix in command:
                    observed.add(command_name)
    except TimeoutError:
        pytest.fail(
            f"real {key_namespace} Redis readiness commands were not all observed",
            pytrace=False,
        )
    return frozenset(observed)


async def test_readiness_uses_real_postgresql_and_both_redis_targets(
    client: AsyncClient,
) -> None:
    settings = get_settings()
    statements: list[str] = []

    def record_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(" ".join(statement.split()))

    active_jti_observer = Redis.from_url(settings.redis_url, decode_responses=True)
    rate_limit_observer = Redis.from_url(
        settings.effective_rate_limit_redis_url,
        decode_responses=True,
    )
    event.listen(engine.sync_engine, "before_cursor_execute", record_statement)
    try:
        async with active_jti_observer.monitor() as active_jti_monitor:
            async with rate_limit_observer.monitor() as rate_limit_monitor:
                async with asyncio.TaskGroup() as task_group:
                    active_jti_commands = task_group.create_task(
                        _observe_redis_readiness_probe(
                            active_jti_monitor,
                            database=_redis_database(settings.redis_url),
                            key_namespace="active-jti",
                        )
                    )
                    rate_limit_commands = task_group.create_task(
                        _observe_redis_readiness_probe(
                            rate_limit_monitor,
                            database=_redis_database(
                                settings.effective_rate_limit_redis_url
                            ),
                            key_namespace="rate-limit",
                        )
                    )
                    response = await client.get("/health/ready")
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record_statement)
        await active_jti_observer.aclose()
        await rate_limit_observer.aclose()

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = cast(dict[str, object], response.json())
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(BusinessCode.OK)
    assert body["message"] == "服务已就绪"
    assert body["data"] == {"status": "ready"}
    request_id = body["request_id"]
    assert isinstance(request_id, str)
    assert UUID(request_id).version == 4
    assert response.headers["X-Request-ID"] == request_id

    assert any(
        "count(*) FROM alembic_version" in statement
        and "WHERE version_num =" in statement
        and "FROM rbac_state" in statement
        and "scope = 'global'" in statement
        for statement in statements
    )
    assert active_jti_commands.result() == _EXPECTED_REDIS_COMMANDS
    assert rate_limit_commands.result() == _EXPECTED_REDIS_COMMANDS

    response_text = response.text.casefold()
    for marker in (
        "postgresql",
        "redis",
        "alembic",
        "rbac_state",
        "0004_password_auth",
        "readiness:v1",
        "active-jti",
        "rate-limit",
    ):
        assert marker not in response_text

    for raw_url in (
        settings.database_url,
        settings.redis_url,
        settings.effective_rate_limit_redis_url,
    ):
        parsed = urlsplit(raw_url)
        for detail in (
            raw_url,
            parsed.username,
            parsed.password,
            parsed.hostname,
            parsed.path.removeprefix("/"),
        ):
            if (
                detail is not None
                and len(detail) >= 4
                and detail.casefold() in response_text
            ):
                pytest.fail(
                    "readiness response leaked a connection detail",
                    pytrace=False,
                )
