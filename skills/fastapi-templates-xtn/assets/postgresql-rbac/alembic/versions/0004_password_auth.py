"""Add user-local password state and account-security audit.

Revision ID: 0004_password_auth
Revises: 0003_business_audit
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_password_auth"
down_revision: str | None = "0003_business_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PASSWORD_RESET_PERMISSION_KEY = "users:password:reset"
PASSWORD_RESET_PERMISSION_DESCRIPTION = (
    "Reset the local password of a strictly lower user"
)
PASSWORD_RESET_SYSTEM_ROLES = ("admin", "super_admin")


def _permission_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )

    op.add_column(
        "rbac_state",
        sa.Column(
            "public_registration_enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
    )

    op.add_column("users", sa.Column("password_hash", sa.String(512), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True)))
    op.create_check_constraint(
        op.f("ck_users_password_hash_shape"),
        "users",
        "password_hash IS NULL OR password_hash ~ "
        "'^\\$argon2id\\$v=19\\$m=[1-9][0-9]*,t=[1-9][0-9]*,"
        "p=[1-9][0-9]*\\$[A-Za-z0-9+/]{16,}\\$"
        "[A-Za-z0-9+/]{16,}$'",
    )
    op.create_check_constraint(
        op.f("ck_users_password_state_coherent"),
        "users",
        "(password_hash IS NULL AND password_changed_at IS NULL "
        "AND NOT must_change_password) OR "
        "(password_hash IS NOT NULL AND password_changed_at IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_users_deleted_user_no_password"),
        "users",
        "deleted_at IS NULL OR password_hash IS NULL",
    )

    op.create_table(
        "account_security_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("statement_timestamp()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "id::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name=op.f("ck_account_security_audit_events_id_uuid4"),
        ),
        sa.CheckConstraint(
            "char_length(action) BETWEEN 20 AND 120 AND action ~ "
            "'^account_security\\.[a-z][a-z0-9_]*"
            "(\\.[a-z][a-z0-9_]*)+$'",
            name=op.f("ck_account_security_audit_events_action_format"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=op.f("ck_account_security_audit_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "char_length(reason_code) BETWEEN 2 AND 80 AND reason_code ~ "
            "'^[a-z][a-z0-9_]*$'",
            name=op.f("ck_account_security_audit_events_reason_code_format"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('anonymous', 'user', 'operator', 'system')",
            name=op.f("ck_account_security_audit_events_actor_type_valid"),
        ),
        sa.CheckConstraint(
            "(actor_type = 'user' AND actor_user_id IS NOT NULL) OR "
            "(actor_type <> 'user' AND actor_user_id IS NULL)",
            name=op.f("ck_account_security_audit_events_actor_user_shape"),
        ),
        sa.CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name=op.f("ck_account_security_audit_events_source_valid"),
        ),
        sa.CheckConstraint(
            "schema_version = 1",
            name=op.f("ck_account_security_audit_events_schema_version_one"),
        ),
        sa.CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ "
            "'^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name=op.f("ck_account_security_audit_events_request_id_format"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_account_security_audit_events")),
    )
    op.create_index(
        "ix_account_security_audit_created",
        "account_security_audit_events",
        ["created_at", "id"],
    )
    op.create_index(
        "ix_account_security_audit_actor_created",
        "account_security_audit_events",
        ["actor_user_id", "created_at"],
        postgresql_where=sa.text("actor_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_account_security_audit_target_created",
        "account_security_audit_events",
        ["target_user_id", "created_at"],
        postgresql_where=sa.text("target_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_account_security_audit_request_id",
        "account_security_audit_events",
        ["request_id"],
    )
    op.create_index(
        "ix_account_security_audit_action_outcome_created",
        "account_security_audit_events",
        ["action", "outcome", "created_at"],
    )
    op.execute(
        """
        CREATE FUNCTION reject_account_security_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'account security audit events are append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_account_security_audit_no_update_delete
        BEFORE UPDATE OR DELETE ON account_security_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_account_security_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_account_security_audit_no_truncate
        BEFORE TRUNCATE ON account_security_audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION reject_account_security_audit_mutation()
        """
    )

    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("deleted_at", sa.DateTime(timezone=True)),
        sa.column("deleted_by_user_id", postgresql.UUID(as_uuid=True)),
    )
    insert_permission = postgresql.insert(permission_table).values(
        id=_permission_id(PASSWORD_RESET_PERMISSION_KEY),
        key=PASSWORD_RESET_PERMISSION_KEY,
        description=PASSWORD_RESET_PERMISSION_DESCRIPTION,
        deleted_at=None,
        deleted_by_user_id=None,
    )
    connection.execute(
        insert_permission.on_conflict_do_update(
            index_elements=[permission_table.c.key],
            set_={
                "description": insert_permission.excluded.description,
                "deleted_at": None,
                "deleted_by_user_id": None,
            },
        )
    )

    op.execute(
        "ALTER TABLE role_permissions DISABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text(
            "INSERT INTO role_permissions "
            "(role_id, permission_id, assigned_by_user_id) "
            "SELECT roles.id, permissions.id, NULL "
            "FROM roles CROSS JOIN permissions "
            "WHERE roles.key = ANY(:role_keys) "
            "AND roles.is_system AND roles.deleted_at IS NULL "
            "AND permissions.key = :permission_key "
            "AND permissions.deleted_at IS NULL "
            "ON CONFLICT (role_id, permission_id) WHERE deleted_at IS NULL "
            "DO NOTHING"
        ),
        {
            "role_keys": list(PASSWORD_RESET_SYSTEM_ROLES),
            "permission_key": PASSWORD_RESET_PERMISSION_KEY,
        },
    )
    op.execute(
        "ALTER TABLE role_permissions ENABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text(
            "UPDATE roles SET version = version + 1 "
            "WHERE key = ANY(:role_keys) AND is_system AND deleted_at IS NULL"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text(
            "UPDATE users SET authz_version = authz_version + 1 "
            "WHERE deleted_at IS NULL AND EXISTS ("
            "SELECT 1 FROM user_roles JOIN roles ON roles.id = user_roles.role_id "
            "WHERE user_roles.user_id = users.id "
            "AND user_roles.deleted_at IS NULL "
            "AND roles.key = ANY(:role_keys) AND roles.deleted_at IS NULL)"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text("UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global'")
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )
    # Pending deferred triggers from data changes prevent ALTER TABLE on users.
    op.drop_constraint(
        op.f("ck_users_deleted_user_no_password"), "users", type_="check"
    )
    op.drop_constraint(op.f("ck_users_password_state_coherent"), "users", type_="check")
    op.drop_constraint(op.f("ck_users_password_hash_shape"), "users", type_="check")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "must_change_password")
    op.drop_column("users", "password_hash")
    op.drop_column("rbac_state", "public_registration_enabled")
    connection.execute(
        sa.text(
            "UPDATE users SET authz_version = authz_version + 1 "
            "WHERE deleted_at IS NULL AND EXISTS ("
            "SELECT 1 FROM user_roles JOIN roles ON roles.id = user_roles.role_id "
            "WHERE user_roles.user_id = users.id "
            "AND user_roles.deleted_at IS NULL "
            "AND roles.key = ANY(:role_keys) AND roles.deleted_at IS NULL)"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text(
            "UPDATE roles SET version = version + 1 "
            "WHERE key = ANY(:role_keys) AND is_system AND deleted_at IS NULL"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    op.execute(
        "ALTER TABLE role_permissions DISABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions USING permissions "
            "WHERE role_permissions.permission_id = permissions.id "
            "AND permissions.key = :permission_key"
        ),
        {"permission_key": PASSWORD_RESET_PERMISSION_KEY},
    )
    op.execute(
        "ALTER TABLE role_permissions ENABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text("DELETE FROM permissions WHERE key = :permission_key"),
        {"permission_key": PASSWORD_RESET_PERMISSION_KEY},
    )
    connection.execute(
        sa.text("UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global'")
    )

    op.execute(
        "DROP TRIGGER IF EXISTS trg_account_security_audit_no_truncate "
        "ON account_security_audit_events"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_account_security_audit_no_update_delete "
        "ON account_security_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS reject_account_security_audit_mutation()")
    op.drop_table("account_security_audit_events")
