"""Create the PostgreSQL single-project RBAC schema.

Revision ID: 0001_single_project_rbac
Revises: None
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_single_project_rbac"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("roles:read", "Read roles and their permission grants"),
    ("roles:create", "Create an unprotected role"),
    ("roles:assign", "Assign an existing manageable role"),
    ("roles:revoke", "Revoke an existing manageable role"),
    ("users:read", "Read users and their current authority"),
    ("users:status:update", "Activate or suspend a manageable user"),
    ("projects:read", "Read projects"),
    ("projects:update", "Update projects"),
)
MAX_ROLES_PER_USER = 10


def _permission_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_name", sa.String(length=32), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "is_protected",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "token_version",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "authz_version",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint(
            "user_name ~ '^[A-Za-z0-9_]{3,32}$'",
            name="user_name_format",
        ),
        sa.CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        sa.CheckConstraint("authz_version >= 0", name="authz_version_nonnegative"),
        sa.CheckConstraint(
            "deleted_at IS NULL OR NOT is_active", name="deleted_user_inactive"
        ),
        sa.CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_actor_requires_timestamp",
        ),
        sa.ForeignKeyConstraint(
            ["deleted_by_user_id"],
            ["users.id"],
            name="fk_users_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("user_name", name="uq_users_user_name"),
    )
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"])

    op.create_table(
        "permissions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_permission_actor_requires_timestamp",
        ),
        sa.ForeignKeyConstraint(
            ["deleted_by_user_id"],
            ["users.id"],
            name="fk_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
    )
    op.create_index("ix_permissions_deleted_at", "permissions", ["deleted_at"])

    op.create_table(
        "rbac_state",
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column(
            "epoch", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint("scope = 'global'", name="scope_global"),
        sa.CheckConstraint("epoch >= 0", name="epoch_nonnegative"),
        sa.PrimaryKeyConstraint("scope", name="pk_rbac_state"),
    )

    op.create_table(
        "roles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column(
            "management_tier", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "is_protected",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "is_system", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "is_super_admin",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "version", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "management_tier >= 0 AND management_tier <= 1000",
            name="management_tier_range",
        ),
        sa.CheckConstraint(
            "management_tier < 1000 OR is_super_admin", name="super_admin_tier_reserved"
        ),
        sa.CheckConstraint("version >= 0", name="version_nonnegative"),
        sa.CheckConstraint("is_system = is_protected", name="system_protection_match"),
        sa.CheckConstraint(
            "NOT is_super_admin OR (is_system AND is_protected AND is_active "
            "AND management_tier = 1000)",
            name="super_admin_flag_shape",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("key", name="uq_roles_key"),
    )
    op.create_index("ix_roles_active", "roles", ["is_active"])
    op.create_index(
        "uq_roles_single_super_admin",
        "roles",
        ["is_super_admin"],
        unique=True,
        postgresql_where=sa.text("is_super_admin"),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_role_permission_actor_requires_timestamp",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"],
            ["users.id"],
            name="fk_role_permissions_assigned_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["deleted_by_user_id"],
            ["users.id"],
            name="fk_role_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_role_permissions"),
    )
    op.create_index(
        "uq_role_permissions_live",
        "role_permissions",
        ["role_id", "permission_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_role_permissions_permission_role",
        "role_permissions",
        ["permission_id", "role_id"],
    )
    op.create_index(
        "ix_role_permissions_deleted_at", "role_permissions", ["deleted_at"]
    )

    op.create_table(
        "user_roles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_role_actor_requires_timestamp",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id_roles",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"],
            ["users.id"],
            name="fk_user_roles_assigned_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["deleted_by_user_id"],
            ["users.id"],
            name="fk_user_roles_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_roles"),
    )
    op.create_index(
        "uq_user_roles_live",
        "user_roles",
        ["user_id", "role_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index("ix_user_roles_role_user", "user_roles", ["role_id", "user_id"])
    op.create_index("ix_user_roles_deleted_at", "user_roles", ["deleted_at"])

    op.create_table(
        "rbac_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_role_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column(
            "source",
            sa.String(length=16),
            server_default=sa.text("'service'"),
            nullable=False,
        ),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("decision IN ('allowed', 'denied')", name="valid_decision"),
        sa.CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name="valid_source",
        ),
        sa.CheckConstraint("schema_version = 1", name="schema_version_one"),
        sa.CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 "
            "AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name="request_id_format",
        ),
        sa.CheckConstraint(
            "char_length(action) BETWEEN 3 AND 120 "
            "AND action ~ '^[a-z][a-z0-9]*([._:-][a-z0-9]+)*$'",
            name="action_format",
        ),
        sa.CheckConstraint(
            "char_length(reason_code) BETWEEN 2 AND 80 "
            "AND reason_code ~ '^[a-z][a-z0-9_]*$'",
            name="reason_code_format",
        ),
        sa.CheckConstraint(
            "before_state IS NULL OR jsonb_typeof(before_state) = 'object'",
            name="before_state_object",
        ),
        sa.CheckConstraint(
            "after_state IS NULL OR jsonb_typeof(after_state) = 'object'",
            name="after_state_object",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_rbac_audit_events"),
    )
    op.create_index(
        "ix_rbac_audit_actor_created",
        "rbac_audit_events",
        ["actor_user_id", "created_at"],
    )
    op.create_index(
        "ix_rbac_audit_request_id",
        "rbac_audit_events",
        ["request_id"],
    )
    op.create_index(
        "ix_rbac_audit_created_id",
        "rbac_audit_events",
        ["created_at", "id"],
    )
    op.create_index(
        "ix_rbac_audit_target_user_created",
        "rbac_audit_events",
        ["target_user_id", "created_at"],
    )
    op.create_index(
        "ix_rbac_audit_target_role_created",
        "rbac_audit_events",
        ["target_role_id", "created_at"],
    )
    op.execute(
        """
        CREATE FUNCTION reject_rbac_audit_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'rbac_audit_events is append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_rbac_audit_events_append_only
        BEFORE UPDATE OR DELETE ON rbac_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_rbac_audit_event_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_rbac_audit_events_no_truncate
        BEFORE TRUNCATE ON rbac_audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION reject_rbac_audit_event_mutation()
        """
    )
    op.execute(
        """
        CREATE FUNCTION reject_rbac_state_removal()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'rbac_state cannot be removed'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_rbac_state_no_delete
        BEFORE DELETE ON rbac_state
        FOR EACH ROW
        EXECUTE FUNCTION reject_rbac_state_removal()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_rbac_state_no_truncate
        BEFORE TRUNCATE ON rbac_state
        FOR EACH STATEMENT
        EXECUTE FUNCTION reject_rbac_state_removal()
        """
    )

    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
    )
    insert_statement = postgresql.insert(permission_table).values(
        [
            {"id": _permission_id(key), "key": key, "description": description}
            for key, description in PERMISSIONS
        ]
    )
    op.execute(
        insert_statement.on_conflict_do_update(
            index_elements=[permission_table.c.key],
            set_={"description": insert_statement.excluded.description},
        )
    )
    op.bulk_insert(
        sa.table(
            "rbac_state",
            sa.column("scope", sa.String()),
            sa.column("epoch", sa.BigInteger()),
        ),
        [{"scope": "global", "epoch": 0}],
    )
    op.execute(
        """
        CREATE FUNCTION lock_rbac_state_before_user_roles_write()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            PERFORM scope FROM rbac_state
            WHERE scope = 'global' FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'the global rbac_state row is required'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tr_user_roles_lock_rbac_state
        BEFORE INSERT OR UPDATE OR DELETE ON user_roles
        FOR EACH STATEMENT
        EXECUTE FUNCTION lock_rbac_state_before_user_roles_write()
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION assert_user_role_limit(candidate_user_id uuid)
        RETURNS void
        LANGUAGE plpgsql
        AS $$
        DECLARE
            live_role_count integer;
        BEGIN
            PERFORM scope FROM rbac_state
            WHERE scope = 'global' FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'the global rbac_state row is required'
                    USING ERRCODE = '55000';
            END IF;

            SELECT count(*) INTO live_role_count
            FROM user_roles
            WHERE user_id = candidate_user_id
              AND deleted_at IS NULL;
            IF live_role_count > {MAX_ROLES_PER_USER} THEN
                RAISE EXCEPTION
                    'a user may have at most {MAX_ROLES_PER_USER} live role assignments'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'ct_user_roles_max_ten_live';
            END IF;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_user_role_limit()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP IN ('UPDATE', 'DELETE') THEN
                PERFORM assert_user_role_limit(OLD.user_id);
            END IF;
            IF TG_OP = 'INSERT'
               OR (TG_OP = 'UPDATE' AND NEW.user_id IS DISTINCT FROM OLD.user_id) THEN
                PERFORM assert_user_role_limit(NEW.user_id);
            END IF;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER ct_user_roles_max_ten_live
        AFTER INSERT OR UPDATE OR DELETE ON user_roles
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION enforce_user_role_limit()
        """
    )


def downgrade() -> None:
    # A later revision may have deleted assignments in this same migration
    # transaction; settle their deferred checks before dropping user_roles.
    op.get_bind().execute(
        sa.text("SET CONSTRAINTS ct_user_roles_max_ten_live IMMEDIATE")
    )
    op.drop_table("rbac_audit_events")
    op.execute("DROP FUNCTION reject_rbac_audit_event_mutation()")
    op.execute("DROP TRIGGER IF EXISTS ct_user_roles_max_ten_live ON user_roles")
    op.execute("DROP FUNCTION IF EXISTS enforce_user_role_limit()")
    op.execute("DROP FUNCTION IF EXISTS assert_user_role_limit(uuid)")
    op.execute("DROP TRIGGER IF EXISTS tr_user_roles_lock_rbac_state ON user_roles")
    op.execute("DROP FUNCTION IF EXISTS lock_rbac_state_before_user_roles_write()")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("rbac_state")
    op.execute("DROP FUNCTION reject_rbac_state_removal()")
    op.drop_table("permissions")
    op.drop_table("users")
