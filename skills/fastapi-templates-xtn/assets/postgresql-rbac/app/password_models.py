import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
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


class PasswordCredential(Base):
    __tablename__ = "user_password_credentials"
    __table_args__ = (
        CheckConstraint(
            "id::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name="id_uuid4",
        ),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(
            "password_hash IS NULL OR password_hash ~ "
            "'^\\$argon2id\\$v=19\\$m=[1-9][0-9]*,t=[1-9][0-9]*,"
            "p=[1-9][0-9]*\\$[A-Za-z0-9+/]{16,}\\$"
            "[A-Za-z0-9+/]{16,}$'",
            name="password_hash_shape",
        ),
        CheckConstraint(
            "(deleted_at IS NULL AND password_hash IS NOT NULL) OR "
            "(deleted_at IS NOT NULL AND password_hash IS NULL)",
            name="live_hash_or_tombstone",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR NOT must_change_password",
            name="tombstone_not_change_required",
        ),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_actor_requires_timestamp",
        ),
        CheckConstraint(
            "password_changed_at >= created_at",
            name="password_changed_after_created",
        ),
        UniqueConstraint(
            "user_id",
            "version",
            name="uq_user_password_credentials_user_version",
        ),
        Index(
            "uq_user_password_credentials_live_user",
            "user_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "ix_user_password_credentials_user_created",
            "user_id",
            "created_at",
        ),
        Index("ix_user_password_credentials_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_user_password_credentials_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_user_password_credentials_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_user_password_credentials_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    @validates("id")
    def validate_id(self, _key: str, value: uuid.UUID) -> uuid.UUID:
        return _require_uuid4(value, field="password credential ID")


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
