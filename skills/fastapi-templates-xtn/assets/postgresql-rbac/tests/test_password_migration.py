from app.rbac.domain import PERMISSION_CATALOG, PermissionKey
from tests.migration_helpers import MIGRATION_VERSIONS, load_migration


def test_password_migration_extends_the_linear_chain() -> None:
    migration = load_migration("0004_password_auth.py")

    assert migration.revision == "0004_password_auth"
    assert migration.down_revision == "0003_business_audit"
    assert migration.PASSWORD_RESET_PERMISSION_KEY == "users:password:reset"
    assert (
        migration.PASSWORD_RESET_PERMISSION_DESCRIPTION
        == PERMISSION_CATALOG[PermissionKey.USERS_PASSWORD_RESET]
    )
    assert migration.PASSWORD_RESET_SYSTEM_ROLES == ("admin", "super_admin")


def test_password_migration_contains_database_security_guards() -> None:
    source = (MIGRATION_VERSIONS / "0004_password_auth.py").read_text(encoding="utf-8")

    for field in ("password_hash", "must_change_password", "password_changed_at"):
        assert f'"users", sa.Column("{field}"' in source or (
            f'"{field}",' in source and "op.add_column(" in source
        )
    assert "ck_users_password_hash_shape" in source
    assert "ck_users_password_state_coherent" in source
    assert "ck_users_deleted_user_no_password" in source
    assert "user_password_credentials" not in source
    assert "trg_account_security_audit_no_update_delete" in source
    assert "trg_account_security_audit_no_truncate" in source
    assert "users:password:reset" in source
