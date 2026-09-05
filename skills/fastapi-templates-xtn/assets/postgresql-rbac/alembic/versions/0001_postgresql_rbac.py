"""Create the PostgreSQL tenant RBAC schema.

Revision ID: 0001_postgresql_rbac
Revises: None
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_postgresql_rbac"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("roles:read", "Read tenant roles and their permission grants"),
    ("roles:create", "Create an unprotected tenant role"),
    ("roles:assign", "Assign an existing manageable role"),
    ("roles:revoke", "Revoke an existing manageable role"),
    (
        "roles:permissions:update",
        "Replace permission grants on a manageable tenant role",
    ),
    ("memberships:read", "Read visible tenant memberships"),
    ("tenant_ownership:transfer", "Transfer tenant ownership atomically"),
    ("projects:read", "Read tenant projects"),
    ("projects:update", "Update tenant projects"),
)


def _permission_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
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
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )

    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
    )

    op.create_table(
        "tenant_authorization_state",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "epoch", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint("epoch >= 0", name="epoch_nonnegative"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_tenant_authorization_state_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("tenant_id", name="pk_tenant_authorization_state"),
    )

    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column(
            "is_protected",
            sa.Boolean(),
            server_default=sa.text("false"),
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
        sa.CheckConstraint(
            "status IN ('active', 'suspended')",
            name="valid_status",
        ),
        sa.CheckConstraint("authz_version >= 0", name="authz_version_nonnegative"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_memberships_tenant_id_tenants",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_memberships_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_memberships"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_memberships_tenant_id"),
        sa.UniqueConstraint("tenant_id", "user_id", name="uq_memberships_tenant_user"),
    )
    op.create_index(
        "ix_memberships_tenant_status",
        "memberships",
        ["tenant_id", "status"],
    )

    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.CheckConstraint("version >= 0", name="version_nonnegative"),
        sa.CheckConstraint(
            "NOT is_protected OR is_system",
            name="protected_is_system",
        ),
        sa.CheckConstraint(
            "NOT is_owner OR (is_system AND is_protected AND is_active "
            "AND management_tier = 1000)",
            name="owner_shape",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_roles_tenant_id_tenants",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_roles_tenant_id"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_roles_tenant_key"),
    )
    op.create_index("ix_roles_tenant_active", "roles", ["tenant_id", "is_active"])
    op.create_index(
        "uq_roles_one_owner_per_tenant",
        "roles",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("is_owner"),
    )

    op.create_table(
        "role_permissions",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "can_delegate",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            name="fk_role_permissions_role_tenant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "role_id", "permission_id", name="pk_role_permissions"
        ),
    )
    op.create_index(
        "ix_role_permissions_permission_tenant_role",
        "role_permissions",
        ["permission_id", "tenant_id", "role_id"],
    )

    op.create_table(
        "membership_roles",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("membership_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "assigned_by_membership_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "membership_id"],
            ["memberships.tenant_id", "memberships.id"],
            name="fk_membership_roles_membership_tenant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            name="fk_membership_roles_role_tenant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assigned_by_membership_id"],
            ["memberships.tenant_id", "memberships.id"],
            name="fk_membership_roles_assigner_tenant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "membership_id", "role_id", name="pk_membership_roles"
        ),
    )
    op.create_index(
        "ix_membership_roles_tenant_role_membership",
        "membership_roles",
        ["tenant_id", "role_id", "membership_id"],
    )

    op.create_table(
        "authorization_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_membership_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_membership_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.CheckConstraint(
            "decision IN ('allowed', 'denied')",
            name="valid_decision",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_authorization_audit_events_tenant_id_tenants",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authorization_audit_events"),
    )
    op.create_index(
        "ix_authz_audit_actor_created",
        "authorization_audit_events",
        ["actor_membership_id", "created_at"],
    )
    op.create_index(
        "ix_authz_audit_tenant_created",
        "authorization_audit_events",
        ["tenant_id", "created_at"],
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


def downgrade() -> None:
    op.drop_table("authorization_audit_events")
    op.drop_table("membership_roles")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("memberships")
    op.drop_table("tenant_authorization_state")
    op.drop_table("permissions")
    op.drop_table("tenants")
    op.drop_table("users")
