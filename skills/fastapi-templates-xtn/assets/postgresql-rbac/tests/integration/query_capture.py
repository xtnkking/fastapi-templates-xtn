from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import event

from app.db.postgres import engine


@contextmanager
def capture_selects() -> Iterator[list[str]]:
    """Capture this block's SELECTs and always remove its engine listener."""
    statements: list[str] = []

    def capture(*args: object) -> None:
        statement = args[2]
        if isinstance(statement, str) and statement.lstrip().upper().startswith(
            "SELECT"
        ):
            statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        yield statements
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
