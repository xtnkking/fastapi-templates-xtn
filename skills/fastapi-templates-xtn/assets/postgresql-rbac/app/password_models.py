import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    SmallInteger,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.audit import (
    AuditSource,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.base import Base

_ACCOUNT_SECURITY_ACTION_RE: Final = re.compile(
    r"^account_security\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
)


class AccountSecurityAuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class AccountSecurityActorType(StrEnum):
    ANONYMOUS = "anonymous"
    USER = "user"
    OPERATOR = "operator"
    SYSTEM = "system"


def _require_uuid4(value: uuid.UUID, *, field: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID) or value.version != 4:
        raise ValueError(f"{field} must be UUIDv4")
    return value


class AccountSecurityAuditEvent(Base):
    __tablename__ = "account_security_audit_events"
    __table_args__ = (
        CheckConstraint(
            "id::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name="id_uuid4",
        ),
        CheckConstraint(
            "char_length(action) BETWEEN 20 AND 120 AND action ~ "
            "'^account_security\\.[a-z][a-z0-9_]*"
            "(\\.[a-z][a-z0-9_]*)+$'",
            name="action_format",
        ),
        CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name="outcome_valid",
        ),
        CheckConstraint(
            "char_length(reason_code) BETWEEN 2 AND 80 AND reason_code ~ "
            "'^[a-z][a-z0-9_]*$'",
            name="reason_code_format",
        ),
        CheckConstraint(
            "actor_type IN ('anonymous', 'user', 'operator', 'system')",
            name="actor_type_valid",
        ),
        CheckConstraint(
            "(actor_type = 'user' AND actor_user_id IS NOT NULL) OR "
            "(actor_type <> 'user' AND actor_user_id IS NULL)",
            name="actor_user_shape",
        ),
        CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name="source_valid",
        ),
        CheckConstraint("schema_version = 1", name="schema_version_one"),
        CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ "
            "'^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name="request_id_format",
        ),
        Index(
            "ix_account_security_audit_created",
            "created_at",
            "id",
        ),
        Index(
            "ix_account_security_audit_actor_created",
            "actor_user_id",
            "created_at",
            postgresql_where=text("actor_user_id IS NOT NULL"),
        ),
        Index(
            "ix_account_security_audit_target_created",
            "target_user_id",
            "created_at",
            postgresql_where=text("target_user_id IS NOT NULL"),
        ),
        Index("ix_account_security_audit_request_id", "request_id"),
        Index(
            "ix_account_security_audit_action_outcome_created",
            "action",
            "outcome",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_version: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("statement_timestamp()"),
    )

    @validates("id")
    def validate_id(self, _key: str, value: uuid.UUID) -> uuid.UUID:
        return _require_uuid4(value, field="account security audit ID")

    @validates("action")
    def validate_action(self, _key: str, value: str) -> str:
        if (
            not 20 <= len(value) <= 120
            or _ACCOUNT_SECURITY_ACTION_RE.fullmatch(value) is None
        ):
            raise ValueError("invalid account security audit action")
        return value

    @validates("outcome")
    def validate_outcome(
        self,
        _key: str,
        value: str | AccountSecurityAuditOutcome,
    ) -> str:
        return AccountSecurityAuditOutcome(value).value

    @validates("reason_code")
    def validate_reason_code(self, _key: str, value: str) -> str:
        return validate_audit_reason(value)

    @validates("actor_type")
    def validate_actor_type(
        self,
        _key: str,
        value: str | AccountSecurityActorType,
    ) -> str:
        return AccountSecurityActorType(value).value

    @validates("source")
    def validate_source(self, _key: str, value: str | AuditSource) -> str:
        return AuditSource(value).value

    @validates("request_id")
    def validate_request_id(self, _key: str, value: str) -> str:
        return validate_audit_request_id(value)
