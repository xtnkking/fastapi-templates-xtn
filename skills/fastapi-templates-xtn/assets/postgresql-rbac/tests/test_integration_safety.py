import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from redis import Redis as SyncRedis

from alembic import command
from tests.integration import conftest as integration_fixtures
from tests.integration import safety


def configure_disposable_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://test:example@127.0.0.1:15432/fresh_test",
    )
    monkeypatch.setenv("TEST_DISPOSABLE_DATABASE", "fresh_test")
    monkeypatch.setenv("TEST_REDIS_URL", "redis://127.0.0.1:16379/15")
    monkeypatch.setenv("TEST_RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:16380/0")
    monkeypatch.setenv("TEST_REDIS_ISOLATION_CONFIRMED", "yes")


def test_migration_refuses_before_alembic_can_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    steps: list[str] = []

    async def refuse_before_migration(database_url: str) -> None:
        steps.append("verify")
        raise RuntimeError("unsafe test target")

    monkeypatch.setattr(
        integration_fixtures,
        "get_settings",
        lambda: SimpleNamespace(database_url="fake"),
    )
    monkeypatch.setattr(
        integration_fixtures, "verify_fresh_postgresql_target", refuse_before_migration
    )
    monkeypatch.setattr(
        command,
        "upgrade",
        lambda *_args: steps.append("upgrade"),
    )
    with pytest.raises(RuntimeError, match="unsafe test target"):
        fixture: Any = integration_fixtures.migrated_database
        fixture.__wrapped__(None)
    assert steps == ["verify"]


@pytest.mark.parametrize(
    ("database_name", "has_user_objects"),
    [("another_test", False), ("fresh_test", True)],
)
def test_postgresql_preflight_refuses_wrong_or_nonempty_actual_database(
    monkeypatch: pytest.MonkeyPatch,
    database_name: str,
    has_user_objects: bool,
) -> None:
    configure_disposable_targets(monkeypatch)
    statements: list[str] = []

    class Connection:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def scalar(self, statement: object) -> object:
            statements.append(str(statement))
            return (
                database_name
                if "current_database()" in str(statement)
                else has_user_objects
            )

    class Engine:
        def connect(self) -> Connection:
            return Connection()

        async def dispose(self) -> None:
            return None

    monkeypatch.setattr(
        safety, "create_async_engine", lambda *_args, **_kwargs: Engine()
    )
    with pytest.raises(RuntimeError):
        asyncio.run(
            safety.verify_fresh_postgresql_target(
                "postgresql+asyncpg://test:example@127.0.0.1:15432/fresh_test"
            )
        )
    assert len(statements) == (2 if database_name == "fresh_test" else 1)
    assert all(statement.lstrip().startswith("SELECT") for statement in statements)


def test_postgresql_preflight_requires_confirmation_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_disposable_targets(monkeypatch)
    monkeypatch.delenv("TEST_DISPOSABLE_DATABASE")
    monkeypatch.setattr(
        safety,
        "create_async_engine",
        lambda *_args, **_kwargs: pytest.fail("must not connect"),
    )
    with pytest.raises(RuntimeError, match="explicitly confirmed"):
        asyncio.run(
            safety.verify_fresh_postgresql_target(
                "postgresql+asyncpg://test:example@127.0.0.1:15432/fresh_test"
            )
        )


def test_redis_preflight_refuses_existing_keys_without_deleting_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_disposable_targets(monkeypatch)
    commands: list[str] = []

    class Client:
        def dbsize(self) -> int:
            commands.append("DBSIZE")
            return 1

        def close(self) -> None:
            commands.append("CLOSE")

    monkeypatch.setattr(
        SyncRedis,
        "from_url",
        lambda *_args, **_kwargs: Client(),
    )
    with pytest.raises(RuntimeError, match="already contains keys"):
        safety.verify_empty_redis_targets(
            "redis://127.0.0.1:16379/15", "redis://127.0.0.1:16380/0"
        )
    assert commands == ["DBSIZE", "CLOSE"]


def test_redis_preflight_requires_confirmation_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_disposable_targets(monkeypatch)
    monkeypatch.delenv("TEST_REDIS_ISOLATION_CONFIRMED")
    monkeypatch.setattr(
        SyncRedis,
        "from_url",
        lambda *_args, **_kwargs: pytest.fail("must not connect"),
    )
    with pytest.raises(RuntimeError, match="must be confirmed"):
        safety.verify_empty_redis_targets(
            "redis://127.0.0.1:16379/15", "redis://127.0.0.1:16380/0"
        )


def test_unsafe_urls_are_not_echoed_in_error_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_disposable_targets(monkeypatch)
    monkeypatch.setenv(
        "TEST_DATABASE_URL", "postgresql+asyncpg://test:marker@host/real"
    )
    with pytest.raises(RuntimeError) as error:
        safety.confirmed_database_name()
    assert "marker" not in str(error.value)
    assert "://" not in str(error.value)


def test_driver_runtime_error_does_not_echo_connection_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_disposable_targets(monkeypatch)

    class BrokenEngine:
        def connect(self) -> None:
            raise RuntimeError("marker from connection URL")

        async def dispose(self) -> None:
            return None

    monkeypatch.setattr(
        safety, "create_async_engine", lambda *_args, **_kwargs: BrokenEngine()
    )
    with pytest.raises(RuntimeError) as error:
        asyncio.run(
            safety.verify_fresh_postgresql_target(
                "postgresql+asyncpg://test:example@127.0.0.1:15432/fresh_test"
            )
        )
    assert "marker" not in str(error.value)
