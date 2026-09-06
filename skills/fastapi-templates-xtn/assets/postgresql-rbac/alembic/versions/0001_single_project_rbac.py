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
    (
        "roles:permissions:update",
        "Replace permission grants on a manageable role",
    ),
    ("roles:delegation:update", "Replace delegable grants on a manageable role"),
    ("users:read", "Read users and their current authority"),
    ("users:status:update", "Activate or suspend a manageable user"),
    ("system_owner:transfer", "Transfer the sole system Owner atomically"),
    ("projects:read", "Read projects"),
    ("projects:update", "Update projects"),
)


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
        sa.Column("email", sa.String(length=320), nullable=False),
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
        sa.CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        sa.CheckConstraint("authz_version >= 0", name="authz_version_nonnegative"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

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
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
    )

    op.create_table(
        "authorization_state",
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column(
            "epoch", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint("scope = 'global'", name="authorization_scope_global"),
        sa.CheckConstraint("epoch >= 0", name="authorization_epoch_nonnegative"),
        sa.PrimaryKeyConstraint("scope", name="pk_authorization_state"),
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
            "is_owner", sa.Boolean(), server_default=sa.text("false"), nullable=False
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
            "management_tier < 1000 OR is_owner", name="owner_tier_reserved"
        ),
        sa.CheckConstraint("version >= 0", name="version_nonnegative"),
        sa.CheckConstraint("is_system = is_protected", name="system_protection_match"),
        sa.CheckConstraint(
            "NOT is_owner OR (is_system AND is_protected AND is_active "
            "AND management_tier = 1000)",
            name="owner_shape",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("key", name="uq_roles_key"),
    )
    op.create_index("ix_roles_active", "roles", ["is_active"])
    op.create_index(
        "uq_roles_single_owner",
        "roles",
        ["is_owner"],
        unique=True,
        postgresql_where=sa.text("is_owner"),
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "can_delegate",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
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
        sa.PrimaryKeyConstraint("role_id", "permission_id", name="pk_role_permissions"),
    )
    op.create_index(
        "ix_role_permissions_permission_role",
        "role_permissions",
        ["permission_id", "role_id"],
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
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
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )
    op.create_index("ix_user_roles_role_user", "user_roles", ["role_id", "user_id"])

    op.create_table(
        "authorization_audit_events",
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
        sa.PrimaryKeyConstraint("id", name="pk_authorization_audit_events"),
    )
    op.create_index(
        "ix_authz_audit_actor_created",
        "authorization_audit_events",
        ["actor_user_id", "created_at"],
    )
    op.create_index(
        "ix_authz_audit_request_id",
        "authorization_audit_events",
        ["request_id"],
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
            "authorization_state",
            sa.column("scope", sa.String()),
            sa.column("epoch", sa.BigInteger()),
        ),
        [{"scope": "global", "epoch": 0}],
    )


def downgrade() -> None:
    op.drop_table("authorization_audit_events")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("authorization_state")
    op.drop_table("permissions")
    op.drop_table("users")
