"""Append-only business audit persistence model."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, SmallInteger, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, validates
from sqlalchemy.schema import conv

from app.core.audit import AuditSource, validate_audit_reason, validate_audit_request_id
from app.core.business_audit import (
    BUSINESS_AUDIT_ACTION_PATTERN,
    MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
    BusinessAuditActorType,
    BusinessAuditOutcome,
    require_business_event_id,
    require_business_identifier,
    require_business_machine_name,
    sanitize_business_payload,
)
from app.db.base import Base


class BusinessAuditEvent(Base):
    __tablename__ = "business_audit_events"
    __table_args__ = (
        CheckConstraint(
            "id::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name=conv("ck_business_audit_id_uuid4"),
        ),
        CheckConstraint(
            "domain ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=conv("ck_business_audit_domain_format"),
        ),
        CheckConstraint(
            "action ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){2,}$' "
            "AND length(action) <= 120",
            name=conv("ck_business_audit_action_format"),
        ),
        CheckConstraint(
            "split_part(action, '.', 1) = domain",
            name=conv("ck_business_audit_action_domain"),
        ),
        CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=conv("ck_business_audit_outcome"),
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z][a-z0-9_]{1,79}$'",
            name=conv("ck_business_audit_reason_format"),
        ),
        CheckConstraint(
            "actor_type IN ('user', 'service', 'system', 'job', 'operator')",
            name=conv("ck_business_audit_actor_type"),
        ),
        CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL) "
            "OR (actor_type <> 'system' AND actor_id IS NOT NULL)",
            name=conv("ck_business_audit_actor_presence"),
        ),
        CheckConstraint(
            "actor_id IS NULL OR actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=conv("ck_business_audit_actor_id_format"),
        ),
        CheckConstraint(
            "resource_type ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=conv("ck_business_audit_resource_type_format"),
        ),
        CheckConstraint(
            "resource_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=conv("ck_business_audit_resource_id_format"),
        ),
        CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name=conv("ck_business_audit_source"),
        ),
        CheckConstraint(
            "schema_version > 0",
            name=conv("ck_business_audit_schema_version"),
        ),
        CheckConstraint(
            "before_state IS NULL OR jsonb_typeof(before_state) = 'object'",
            name=conv("ck_business_audit_before_object"),
        ),
        CheckConstraint(
            "after_state IS NULL OR jsonb_typeof(after_state) = 'object'",
            name=conv("ck_business_audit_after_object"),
        ),
        CheckConstraint(
            "jsonb_typeof(context) = 'object'",
            name=conv("ck_business_audit_context_object"),
        ),
        CheckConstraint(
            "before_state IS NULL OR octet_length(before_state::text) <= 16384",
            name=conv("ck_business_audit_before_size"),
        ),
        CheckConstraint(
            "after_state IS NULL OR octet_length(after_state::text) <= 16384",
            name=conv("ck_business_audit_after_size"),
        ),
        CheckConstraint(
            "octet_length(context::text) <= 4096",
            name=conv("ck_business_audit_context_size"),
        ),
        CheckConstraint(
            "outcome = 'succeeded' OR after_state IS NULL",
            name=conv("ck_business_audit_non_success_after"),
        ),
        CheckConstraint(
            "request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name=conv("ck_business_audit_request_id_format"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    after_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("statement_timestamp()"),
    )

    @validates("id")
    def validate_id(self, _key: str, value: uuid.UUID) -> uuid.UUID:
        return require_business_event_id(value)

    @validates("domain", "resource_type")
    def validate_machine_name(self, key: str, value: str) -> str:
        return require_business_machine_name(value, field=key.replace("_", " "))

    @validates("action")
    def validate_action(self, _key: str, value: str) -> str:
        if len(value) > 120 or BUSINESS_AUDIT_ACTION_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid business audit action")
        return value

    @validates("outcome")
    def validate_outcome(self, _key: str, value: str | BusinessAuditOutcome) -> str:
        return BusinessAuditOutcome(value).value

    @validates("reason_code")
    def validate_reason_code(self, _key: str, value: str) -> str:
        return validate_audit_reason(value)

    @validates("actor_type")
    def validate_actor_type(
        self, _key: str, value: str | BusinessAuditActorType
    ) -> str:
        return BusinessAuditActorType(value).value

    @validates("actor_id")
    def validate_actor_id(self, _key: str, value: str | None) -> str | None:
        return (
            None
            if value is None
            else require_business_identifier(value, field="actor ID")
        )

    @validates("resource_id")
    def validate_resource_id(self, _key: str, value: str) -> str:
        return require_business_identifier(value, field="resource ID")

    @validates("source")
    def validate_source(self, _key: str, value: str | AuditSource) -> str:
        return AuditSource(value).value

    @validates("schema_version")
    def validate_schema_version(self, _key: str, value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("business audit schema version must be a positive integer")
        return value

    @validates("before_state", "after_state")
    def validate_state(
        self, _key: str, value: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        return sanitize_business_payload(value, max_bytes=16 * 1024)

    @validates("context")
    def validate_context(self, _key: str, value: dict[str, Any]) -> dict[str, Any]:
        sanitized = sanitize_business_payload(
            value, max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES
        )
        assert sanitized is not None
        return sanitized

    @validates("request_id")
    def validate_request_id(self, _key: str, value: str) -> str:
        return validate_audit_request_id(value)


Index(
    "ix_business_audit_created",
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
Index(
    "ix_business_audit_domain_created",
    BusinessAuditEvent.domain,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
Index(
    "ix_business_audit_actor_created",
    BusinessAuditEvent.actor_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
    postgresql_where=BusinessAuditEvent.actor_id.is_not(None),
)
Index(
    "ix_business_audit_resource_created",
    BusinessAuditEvent.resource_type,
    BusinessAuditEvent.resource_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
Index("ix_business_audit_request", BusinessAuditEvent.request_id)
Index(
    "ix_business_audit_action_outcome_created",
    BusinessAuditEvent.action,
    BusinessAuditEvent.outcome,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
