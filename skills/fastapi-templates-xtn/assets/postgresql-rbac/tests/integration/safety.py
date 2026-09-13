"""Fail-closed checks for destructive integration test targets."""

import os
from typing import NoReturn
from urllib.parse import urlsplit

from redis import Redis as SyncRedis
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool


class UnsafeTestTarget(RuntimeError):
    """A controlled refusal that contains no connection details."""


def _refuse(message: str) -> NoReturn:
    raise UnsafeTestTarget(message)


def confirmed_database_name() -> str:
    raw_url = os.environ.get("TEST_DATABASE_URL")
    confirmed = os.environ.get("TEST_DISPOSABLE_DATABASE")
    if not raw_url or not confirmed or not confirmed.endswith("_test"):
        _refuse("a disposable PostgreSQL test database must be explicitly confirmed")
    try:
        parsed = make_url(raw_url)
    except Exception:
        _refuse("invalid PostgreSQL test target")
    if parsed.drivername != "postgresql+asyncpg" or parsed.database != confirmed:
        _refuse("PostgreSQL test target does not match the confirmed test database")
    return confirmed


def require_actual_database(
    actual_name: str | None, *, empty: bool | None = None
) -> None:
    if actual_name != confirmed_database_name():
        _refuse("actual PostgreSQL database differs from the disposable test target")
    if empty is False:
        _refuse("disposable PostgreSQL test database is not empty before migration")


async def verify_fresh_postgresql_target(database_url: str) -> None:
    confirmed_database_name()
    if database_url != os.environ["TEST_DATABASE_URL"]:
        _refuse("application PostgreSQL target differs from the disposable test target")
    try:
        engine = create_async_engine(database_url, poolclass=NullPool)
    except Exception:
        _refuse("could not verify the disposable PostgreSQL test target")
    try:
        async with engine.connect() as connection:
            actual_name = await connection.scalar(text("SELECT current_database()"))
            require_actual_database(actual_name)
            has_user_objects = await connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND n.nspname NOT LIKE 'pg_toast%' "
                    "AND n.nspname NOT LIKE 'pg_temp_%' "
                    "AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f'))"
                )
            )
            require_actual_database(actual_name, empty=not has_user_objects)
    except UnsafeTestTarget:
        raise
    except Exception:
        _refuse("could not verify the disposable PostgreSQL test target")
    finally:
        await engine.dispose()


def confirmed_redis_targets() -> tuple[str, str]:
    if os.environ.get("TEST_REDIS_ISOLATION_CONFIRMED") != "yes":
        _refuse("isolated disposable Redis test instances must be confirmed")
    raw_urls = (
        os.environ.get("TEST_REDIS_URL"),
        os.environ.get("TEST_RATE_LIMIT_REDIS_URL"),
    )
    if any(not url for url in raw_urls):
        _refuse("both disposable Redis test targets must be explicitly configured")
    targets = []
    for raw_url in raw_urls:
        try:
            parsed = urlsplit(raw_url or "")
            if (
                parsed.scheme not in {"redis", "rediss"}
                or not parsed.hostname
                or parsed.port == 0
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith("/")
                or not parsed.path[1:].isdigit()
            ):
                raise ValueError
            targets.append(
                (
                    parsed.scheme,
                    parsed.hostname,
                    parsed.port or 6379,
                    int(parsed.path[1:]),
                )
            )
        except ValueError:
            _refuse("invalid disposable Redis test target")
    if targets[0] == targets[1]:
        _refuse("token and limiter Redis tests must use distinct targets")
    return raw_urls[0] or "", raw_urls[1] or ""


def verify_empty_redis_targets(redis_url: str, rate_limit_redis_url: str) -> None:
    urls = confirmed_redis_targets()
    if (redis_url, rate_limit_redis_url) != urls:
        _refuse("application Redis targets differ from the disposable test targets")
    for url in urls:
        try:
            client = SyncRedis.from_url(
                url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True
            )
        except Exception:
            _refuse("could not verify an empty disposable Redis test target")
        try:
            if client.dbsize() != 0:
                _refuse("disposable Redis test target already contains keys")
        except UnsafeTestTarget:
            raise
        except Exception:
            _refuse("could not verify an empty disposable Redis test target")
        finally:
            try:
                client.close()
            except Exception:
                _refuse("could not close a disposable Redis verification connection")
