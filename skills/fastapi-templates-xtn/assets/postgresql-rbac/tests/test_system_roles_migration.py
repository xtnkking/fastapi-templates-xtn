from unittest.mock import Mock

import pytest
from sqlalchemy.engine import Connection

from app.rbac.domain import RESERVED_ROLE_KEYS, SYSTEM_ROLE_KEYS
from tests.migration_helpers import load_migration


def _normalize_sql(statement: object) -> str:
    return " ".join(str(statement).split())


def test_only_current_system_role_keys_are_reserved() -> None:
    assert RESERVED_ROLE_KEYS == SYSTEM_ROLE_KEYS
    assert "owner" not in RESERVED_ROLE_KEYS


def test_fresh_migration_chain_remains_linear() -> None:
    revisions = (
        ("0001_single_project_rbac.py", "0001_single_project_rbac", None),
        ("0002_system_roles.py", "0002_system_roles", "0001_single_project_rbac"),
        ("0003_business_audit.py", "0003_business_audit", "0002_system_roles"),
        ("0004_password_auth.py", "0004_password_auth", "0003_business_audit"),
    )

    for filename, revision, down_revision in revisions:
        migration = load_migration(filename)
        assert migration.revision == revision
        assert migration.down_revision == down_revision


def test_system_role_downgrade_removes_every_seeded_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = load_migration("0002_system_roles.py")
    connection = Mock(spec=Connection)
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    for operation in (
        "execute",
        "drop_constraint",
        "drop_index",
        "drop_column",
        "create_check_constraint",
    ):
        monkeypatch.setattr(migration.op, operation, Mock())

    migration.downgrade()

    statements = [
        _normalize_sql(call.args[0]) for call in connection.execute.call_args_list
    ]
    system_keys = "('super_admin', 'admin', 'user')"
    assert any(
        statement.startswith("DELETE FROM user_roles USING roles")
        and f"roles.key IN {system_keys}" in statement
        for statement in statements
    )
    assert any(
        statement.startswith("DELETE FROM role_permissions USING roles")
        and f"roles.key IN {system_keys}" in statement
        for statement in statements
    )
    assert f"DELETE FROM roles WHERE key IN {system_keys}" in statements
    assert not any("UPDATE roles SET key = 'owner'" in item for item in statements)


def test_system_role_downgrade_settles_pending_user_constraint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = load_migration("0002_system_roles.py")
    connection = Mock(spec=Connection)
    statements: list[str] = []

    def record(statement: object, *_args: object, **_kwargs: object) -> None:
        statements.append(_normalize_sql(statement))

    connection.execute.side_effect = record
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration.op, "execute", record)
    for operation in (
        "drop_constraint",
        "drop_index",
        "drop_column",
        "create_check_constraint",
    ):
        monkeypatch.setattr(migration.op, operation, Mock())

    migration.downgrade()

    assert (
        statements.index(
            "SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE"
        )
        < statements.index("SET CONSTRAINTS ct_users_require_base_role IMMEDIATE")
        < statements.index("DROP TRIGGER IF EXISTS ct_users_require_base_role ON users")
    )
