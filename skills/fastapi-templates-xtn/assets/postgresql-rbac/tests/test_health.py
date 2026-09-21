import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.core.api_contract import BusinessCode
from app.core.config import get_settings
from app.main import app


async def _request_readiness() -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/health/ready")


def _install_ready_clients() -> tuple[AsyncMock, AsyncMock]:
    active_jti_redis = AsyncMock()
    rate_limit_redis = AsyncMock()
    active_jti_redis.ping.return_value = True
    rate_limit_redis.ping.return_value = True
    active_jti_redis.eval.return_value = 1
    rate_limit_redis.eval.return_value = 1
    app.state.redis = active_jti_redis
    app.state.rate_limit_redis = rate_limit_redis
    return active_jti_redis, rate_limit_redis


def _install_postgresql_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: object = True,
    error: Exception | None = None,
) -> AsyncMock:
    connection = AsyncMock()
    if error is None:
        connection.scalar.return_value = result
    else:
        connection.scalar.side_effect = error
    connection_context = MagicMock()
    connection_context.__aenter__ = AsyncMock(return_value=connection)
    connection_context.__aexit__ = AsyncMock(return_value=False)
    probe_engine = MagicMock()
    probe_engine.connect.return_value = connection_context
    monkeypatch.setattr(main_module, "engine", probe_engine)
    return connection


def _assert_standard_readiness_response(
    response: Any,
    *,
    status_code: int,
    business_code: BusinessCode,
) -> dict[str, Any]:
    assert response.status_code == status_code
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(business_code)
    assert response.headers["X-Request-ID"] == body["request_id"]
    return cast(dict[str, Any], body)


async def test_postgresql_probe_requires_one_current_head_and_global_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _install_postgresql_result(monkeypatch)

    await main_module._probe_postgresql()

    statement, parameters = connection.scalar.await_args.args
    normalized_sql = " ".join(str(statement).split())
    assert "NOT pg_is_in_recovery()" in normalized_sql
    assert "current_setting('transaction_read_only') = 'off'" in normalized_sql
    assert "count(*) FROM alembic_version" in normalized_sql
    assert "WHERE version_num = :expected_head" in normalized_sql
    assert "FROM rbac_state" in normalized_sql
    assert "scope = 'global'" in normalized_sql
    assert "public_registration_enabled IN (TRUE, FALSE)" in normalized_sql
    assert parameters == {"expected_head": "0004_password_auth"}


@pytest.mark.parametrize("invalid_result", [False, None])
async def test_postgresql_probe_rejects_wrong_head_or_missing_global_state(
    monkeypatch: pytest.MonkeyPatch,
    invalid_result: object,
) -> None:
    _install_postgresql_result(monkeypatch, result=invalid_result)

    with pytest.raises(main_module._ReadinessDependencyUnavailable):
        await main_module._probe_postgresql()


async def test_postgresql_probe_fails_when_schema_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema_error = RuntimeError(
        "relation alembic_version does not exist at secret database"
    )
    _install_postgresql_result(monkeypatch, error=schema_error)

    with pytest.raises(RuntimeError) as caught:
        await main_module._probe_postgresql()

    assert caught.value is schema_error


async def test_redis_probe_uses_random_atomic_write_read_delete() -> None:
    redis = AsyncMock()
    redis.ping.return_value = True
    redis.eval.return_value = 1

    await main_module._probe_redis(
        cast(Any, redis),
        key_namespace="active-jti",
    )

    redis.ping.assert_awaited_once_with()
    script, key_count, key, value, ttl_ms = redis.eval.await_args.args
    assert script == main_module._REDIS_READINESS_SCRIPT
    assert key_count == 1
    assert key.startswith("readiness:v1:active-jti:")
    assert len(key.removeprefix("readiness:v1:active-jti:")) == 32
    assert len(value) == 32
    assert value not in key
    assert ttl_ms == "5000"
    redis.delete.assert_not_awaited()


async def test_redis_probe_rejects_ping_only_acl_and_attempts_cleanup() -> None:
    redis = AsyncMock()
    redis.ping.return_value = True
    primary_error = PermissionError("EVAL denied at redis://user:password@secret")
    redis.eval.side_effect = primary_error
    redis.delete.return_value = 0

    with pytest.raises(PermissionError) as caught:
        await main_module._probe_redis(
            cast(Any, redis),
            key_namespace="rate-limit",
        )

    assert caught.value is primary_error
    key = redis.eval.await_args.args[2]
    redis.delete.assert_awaited_once_with(key)


@pytest.mark.parametrize(
    "cleanup_error",
    [
        PermissionError("cleanup secret detail"),
        asyncio.CancelledError(),
    ],
)
async def test_redis_cleanup_failure_does_not_replace_probe_failure(
    cleanup_error: BaseException,
) -> None:
    redis = AsyncMock()
    redis.ping.return_value = True
    primary_error = ConnectionError("primary secret connection detail")
    redis.eval.side_effect = primary_error
    redis.delete.side_effect = cleanup_error

    with pytest.raises(ConnectionError) as caught:
        await main_module._probe_redis(
            cast(Any, redis),
            key_namespace="active-jti",
        )

    assert caught.value is primary_error
    redis.delete.assert_awaited_once()


@pytest.fixture(autouse=True)
def _restore_app_state() -> Any:
    old_redis = getattr(app.state, "redis", None)
    old_rate_limit_redis = getattr(app.state, "rate_limit_redis", None)
    yield
    app.state.redis = old_redis
    app.state.rate_limit_redis = old_rate_limit_redis


async def test_readiness_succeeds_only_when_all_dependencies_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_jti_redis, rate_limit_redis = _install_ready_clients()
    postgresql_probe = AsyncMock()
    monkeypatch.setattr(main_module, "_probe_postgresql", postgresql_probe)

    response = await _request_readiness()

    body = _assert_standard_readiness_response(
        response,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert body["data"] == {"status": "ready"}
    postgresql_probe.assert_awaited_once_with()
    active_jti_redis.ping.assert_awaited_once_with()
    rate_limit_redis.ping.assert_awaited_once_with()
    active_jti_redis.eval.assert_awaited_once()
    rate_limit_redis.eval.assert_awaited_once()
    active_jti_redis.delete.assert_not_awaited()
    rate_limit_redis.delete.assert_not_awaited()


@pytest.mark.parametrize(
    "failed_dependency",
    ["postgresql", "active_jti_redis", "rate_limit_redis"],
)
async def test_readiness_fails_closed_for_each_dependency(
    monkeypatch: pytest.MonkeyPatch,
    failed_dependency: str,
) -> None:
    active_jti_redis, rate_limit_redis = _install_ready_clients()

    async def postgresql_probe() -> None:
        if failed_dependency == "postgresql":
            raise ConnectionError("controlled secret connection detail")

    if failed_dependency == "active_jti_redis":
        active_jti_redis.ping.side_effect = ConnectionError(
            "controlled secret Redis detail"
        )
    if failed_dependency == "rate_limit_redis":
        rate_limit_redis.ping.side_effect = ConnectionError(
            "controlled secret limiter detail"
        )
    monkeypatch.setattr(main_module, "_probe_postgresql", postgresql_probe)

    response = await _request_readiness()

    body = _assert_standard_readiness_response(
        response,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )
    assert body["data"] is None
    assert "secret" not in response.text.casefold()


async def test_readiness_timeout_is_a_safe_dependency_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ready_clients()
    settings = get_settings().model_copy(update={"readiness_timeout_seconds": 0.001})

    async def blocked_probe() -> None:
        await asyncio.sleep(0.05)

    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "_probe_postgresql", blocked_probe)

    response = await _request_readiness()

    _assert_standard_readiness_response(
        response,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )


async def test_redis_timeout_attempts_bounded_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_jti_redis, _rate_limit_redis = _install_ready_clients()
    settings = get_settings().model_copy(update={"readiness_timeout_seconds": 0.001})

    async def blocked_command(*_args: object) -> object:
        await asyncio.sleep(0.05)
        return 1

    active_jti_redis.eval.side_effect = blocked_command
    active_jti_redis.delete.side_effect = blocked_command
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(
        main_module,
        "_READINESS_REDIS_CLEANUP_TIMEOUT_SECONDS",
        0.001,
    )
    monkeypatch.setattr(main_module, "_probe_postgresql", AsyncMock())

    response = await _request_readiness()

    _assert_standard_readiness_response(
        response,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )
    active_jti_redis.delete.assert_awaited_once()


async def test_readiness_recovers_after_dependency_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ready_clients()
    attempts = 0

    async def recovering_probe() -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("controlled first failure")

    monkeypatch.setattr(main_module, "_probe_postgresql", recovering_probe)

    failed = await _request_readiness()
    recovered = await _request_readiness()

    _assert_standard_readiness_response(
        failed,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )
    recovered_body = _assert_standard_readiness_response(
        recovered,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert recovered_body["data"] == {"status": "ready"}
    assert attempts == 2


async def test_readiness_logs_dependency_name_without_exception_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ready_clients()

    async def failed_probe() -> None:
        raise ConnectionError("postgresql://user:password@secret-host/database")

    log_spy = MagicMock(return_value=True)
    monkeypatch.setattr(main_module, "_probe_postgresql", failed_probe)
    monkeypatch.setattr(main_module, "safe_log", log_spy)

    response = await _request_readiness()

    _assert_standard_readiness_response(
        response,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )
    readiness_calls = [
        call
        for call in log_spy.call_args_list
        if len(call.args) >= 3 and call.args[2] == "dependency.readiness.unavailable"
    ]
    assert len(readiness_calls) == 1
    assert readiness_calls[0].kwargs["extra"]["dependency"] == "postgresql"
    assert "secret-host" not in str(readiness_calls[0])
    assert "password" not in str(readiness_calls[0])


async def test_redis_probe_and_cleanup_errors_do_not_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_jti_redis, _rate_limit_redis = _install_ready_clients()
    active_jti_redis.eval.side_effect = PermissionError(
        "redis://user:password@secret-host/0"
    )
    active_jti_redis.delete.side_effect = RuntimeError("cleanup-token-at-secret-host")
    log_spy = MagicMock(return_value=True)
    monkeypatch.setattr(main_module, "_probe_postgresql", AsyncMock())
    monkeypatch.setattr(main_module, "safe_log", log_spy)

    response = await _request_readiness()

    _assert_standard_readiness_response(
        response,
        status_code=503,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
    )
    assert "password" not in response.text.casefold()
    assert "secret-host" not in response.text.casefold()
    readiness_calls = [
        call
        for call in log_spy.call_args_list
        if len(call.args) >= 3 and call.args[2] == "dependency.readiness.unavailable"
    ]
    assert len(readiness_calls) == 1
    assert readiness_calls[0].kwargs["extra"]["dependency"] == "active_jti_redis"
    serialized_call = str(readiness_calls[0]).casefold()
    assert "password" not in serialized_call
    assert "secret-host" not in serialized_call
    assert "cleanup-token" not in serialized_call
