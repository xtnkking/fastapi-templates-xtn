"""Add the generic append-only business audit table.

Revision ID: 0003_business_audit
Revises: 0002_system_roles
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_business_audit"
down_revision: str | None = "0002_system_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "business_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("schema_version", sa.SmallInteger(), nullable=False),
        sa.Column(
            "before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
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
            name=op.f("ck_business_audit_id_uuid4"),
        ),
        sa.CheckConstraint(
            "domain ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=op.f("ck_business_audit_domain_format"),
        ),
        sa.CheckConstraint(
            "action ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){2,}$' "
            "AND length(action) <= 120",
            name=op.f("ck_business_audit_action_format"),
        ),
        sa.CheckConstraint(
            "split_part(action, '.', 1) = domain",
            name=op.f("ck_business_audit_action_domain"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=op.f("ck_business_audit_outcome"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z][a-z0-9_]{1,79}$'",
            name=op.f("ck_business_audit_reason_format"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'service', 'system', 'job', 'operator')",
            name=op.f("ck_business_audit_actor_type"),
        ),
        sa.CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL) "
            "OR (actor_type <> 'system' AND actor_id IS NOT NULL)",
            name=op.f("ck_business_audit_actor_presence"),
        ),
        sa.CheckConstraint(
            "actor_id IS NULL OR actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=op.f("ck_business_audit_actor_id_format"),
        ),
        sa.CheckConstraint(
            "resource_type ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=op.f("ck_business_audit_resource_type_format"),
        ),
        sa.CheckConstraint(
            "resource_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=op.f("ck_business_audit_resource_id_format"),
        ),
        sa.CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name=op.f("ck_business_audit_source"),
        ),
        sa.CheckConstraint(
            "schema_version > 0",
            name=op.f("ck_business_audit_schema_version"),
        ),
        sa.CheckConstraint(
            "before_state IS NULL OR jsonb_typeof(before_state) = 'object'",
            name=op.f("ck_business_audit_before_object"),
        ),
        sa.CheckConstraint(
            "after_state IS NULL OR jsonb_typeof(after_state) = 'object'",
            name=op.f("ck_business_audit_after_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(context) = 'object'",
            name=op.f("ck_business_audit_context_object"),
        ),
        sa.CheckConstraint(
            "before_state IS NULL OR octet_length(before_state::text) <= 16384",
            name=op.f("ck_business_audit_before_size"),
        ),
        sa.CheckConstraint(
            "after_state IS NULL OR octet_length(after_state::text) <= 16384",
            name=op.f("ck_business_audit_after_size"),
        ),
        sa.CheckConstraint(
            "octet_length(context::text) <= 4096",
            name=op.f("ck_business_audit_context_size"),
        ),
        sa.CheckConstraint(
            "outcome = 'succeeded' OR after_state IS NULL",
            name=op.f("ck_business_audit_non_success_after"),
        ),
        sa.CheckConstraint(
            "request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name=op.f("ck_business_audit_request_id_format"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_business_audit_events"),
    )
    op.create_index(
        "ix_business_audit_created",
        "business_audit_events",
        [sa.text("created_at DESC"), sa.text("id DESC")],
    )
    op.create_index(
        "ix_business_audit_domain_created",
        "business_audit_events",
        ["domain", sa.text("created_at DESC"), sa.text("id DESC")],
    )
    op.create_index(
        "ix_business_audit_actor_created",
        "business_audit_events",
        ["actor_id", sa.text("created_at DESC"), sa.text("id DESC")],
        postgresql_where=sa.text("actor_id IS NOT NULL"),
    )
    op.create_index(
        "ix_business_audit_resource_created",
        "business_audit_events",
        [
            "resource_type",
            "resource_id",
            sa.text("created_at DESC"),
            sa.text("id DESC"),
        ],
    )
    op.create_index(
        "ix_business_audit_request", "business_audit_events", ["request_id"]
    )
    op.create_index(
        "ix_business_audit_action_outcome_created",
        "business_audit_events",
        ["action", "outcome", sa.text("created_at DESC"), sa.text("id DESC")],
    )
    op.execute(
        """
        CREATE FUNCTION reject_business_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'business audit events are append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_business_audit_no_update_delete
        BEFORE UPDATE OR DELETE ON business_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_business_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_business_audit_no_truncate
        BEFORE TRUNCATE ON business_audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION reject_business_audit_mutation()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_business_audit_no_truncate ON business_audit_events"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_business_audit_no_update_delete "
        "ON business_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS reject_business_audit_mutation()")
    op.drop_table("business_audit_events")
