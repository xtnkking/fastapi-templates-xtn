"""Classify database availability failures without inspecting sensitive messages."""

from typing import Literal

from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

DatabaseErrorCategory = Literal["connection", "pool_exhausted", "timeout"]


class DatabaseUnavailableError(RuntimeError):
    """Wrap raw connect failures at the engine boundary, not arbitrary app errors."""

    def __init__(self, category: DatabaseErrorCategory) -> None:
        super().__init__("database unavailable")
        self.category = category


def database_error_category(exc: BaseException) -> DatabaseErrorCategory | None:
    if isinstance(exc, DatabaseUnavailableError):
        return exc.category
    if isinstance(exc, PoolTimeoutError):
        return "pool_exhausted"
    if isinstance(exc, (IntegrityError, ProgrammingError)):
        return None
    if isinstance(exc, DBAPIError):
        if exc.connection_invalidated:
            return "connection"
        driver_error = exc.orig
    else:
        # The connection hook also receives native asyncpg errors before
        # SQLAlchemy wraps them. HTTP handlers never catch arbitrary app errors.
        driver_error = exc
    sqlstate = getattr(driver_error, "sqlstate", None) or getattr(
        driver_error, "pgcode", None
    )
    if not isinstance(sqlstate, str):
        return None
    if sqlstate.startswith("08") or sqlstate in {"57P01", "57P02", "57P03"}:
        return "connection"
    if sqlstate == "53300":  # too_many_connections
        return "pool_exhausted"
    if sqlstate in {"57014", "55P03"}:  # query_canceled / lock_not_available
        return "timeout"
    return None
