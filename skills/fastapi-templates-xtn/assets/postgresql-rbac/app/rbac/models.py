import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.audit import (
    AuditSource,
    sanitize_audit_state,
    validate_audit_action,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.base import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("user_name", name="uq_users_user_name"),
        CheckConstraint(
            "user_name ~ '^[A-Za-z0-9_]{3,32}$'",
            name="user_name_format",
        ),
        CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        CheckConstraint("authz_version >= 0", name="authz_version_nonnegative"),
        CheckConstraint(
            "password_hash IS NULL OR password_hash ~ "
            "'^\\$argon2id\\$v=19\\$m=[1-9][0-9]*,t=[1-9][0-9]*,"
            "p=[1-9][0-9]*\\$[A-Za-z0-9+/]{16,}\\$"
            "[A-Za-z0-9+/]{16,}$'",
            name="password_hash_shape",
        ),
        CheckConstraint(
            "(password_hash IS NULL AND password_changed_at IS NULL "
            "AND NOT must_change_password) OR "
            "(password_hash IS NOT NULL AND password_changed_at IS NOT NULL)",
            name="password_state_coherent",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR password_hash IS NULL",
            name="deleted_user_no_password",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR NOT is_active",
            name="deleted_user_inactive",
        ),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_actor_requires_timestamp",
        ),
        Index("ix_users_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_name: Mapped[str] = mapped_column(String(32), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_protected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    token_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    authz_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_users_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class RbacState(Base):
    __tablename__ = "rbac_state"
    __table_args__ = (
        CheckConstraint("scope = 'global'", name="scope_global"),
        CheckConstraint("epoch >= 0", name="epoch_nonnegative"),
    )

    scope: Mapped[str] = mapped_column(String(16), primary_key=True)
    epoch: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    public_registration_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_permission_actor_requires_timestamp",
        ),
        Index("ix_permissions_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("key", name="uq_roles_key"),
        CheckConstraint(
            "management_tier >= 0 AND management_tier <= 1000",
            name="management_tier_range",
        ),
        CheckConstraint(
            "management_tier < 1000 OR is_super_admin",
            name="super_admin_tier_reserved",
        ),
        CheckConstraint(
            "is_system OR (management_tier >= 1 AND management_tier <= 999)",
            name="custom_role_tier_range",
        ),
        CheckConstraint("version >= 0", name="version_nonnegative"),
        CheckConstraint(
            "NOT is_protected OR is_system",
            name="protected_role_is_system",
        ),
        CheckConstraint(
            "NOT is_system OR (is_active AND deleted_at IS NULL)",
            name="system_role_always_available",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR NOT is_active",
            name="deleted_role_inactive",
        ),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_role_actor_requires_timestamp",
        ),
        CheckConstraint(
            "NOT is_super_admin OR (is_system AND is_protected AND is_active "
            "AND management_tier = 1000 AND key = 'super_admin' "
            "AND deleted_at IS NULL)",
            name="super_admin_flag_shape",
        ),
        CheckConstraint(
            "key <> 'super_admin' OR (is_system AND is_protected AND is_super_admin "
            "AND is_active AND management_tier = 1000 AND deleted_at IS NULL)",
            name="super_admin_role_shape",
        ),
        CheckConstraint(
            "key <> 'admin' OR (is_system AND NOT is_protected AND NOT is_super_admin "
            "AND is_active AND management_tier = 500 AND deleted_at IS NULL)",
            name="admin_role_shape",
        ),
        CheckConstraint(
            "key <> 'user' OR (is_system AND NOT is_protected AND NOT is_super_admin "
            "AND is_active AND management_tier = 0 AND deleted_at IS NULL)",
            name="user_role_shape",
        ),
        Index("ix_roles_active", "is_active"),
        Index("ix_roles_deleted_at", "deleted_at"),
        Index(
            "uq_roles_single_super_admin",
            "is_super_admin",
            unique=True,
            postgresql_where=text("is_super_admin"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    management_tier: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_protected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    is_super_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_roles_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_role_permission_actor_requires_timestamp",
        ),
        Index(
            "uq_role_permissions_live",
            "role_id",
            "permission_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_role_permissions_permission_role", "permission_id", "role_id"),
        Index("ix_role_permissions_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_role_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_role_actor_requires_timestamp",
        ),
        Index(
            "uq_user_roles_live",
            "user_id",
            "role_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_user_roles_role_user", "role_id", "user_id"),
        Index("ix_user_roles_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_user_roles_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class RbacAuditEvent(Base):
    __tablename__ = "rbac_audit_events"
    __table_args__ = (
        CheckConstraint("decision IN ('allowed', 'denied')", name="valid_decision"),
        CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name="valid_source",
        ),
        CheckConstraint("schema_version = 1", name="schema_version_one"),
        CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 "
            "AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name="request_id_format",
        ),
        CheckConstraint(
            "char_length(action) BETWEEN 3 AND 120 "
            "AND action ~ '^[a-z][a-z0-9]*([._:-][a-z0-9]+)*$'",
            name="action_format",
        ),
        CheckConstraint(
            "char_length(reason_code) BETWEEN 2 AND 80 "
            "AND reason_code ~ '^[a-z][a-z0-9_]*$'",
            name="reason_code_format",
        ),
        CheckConstraint(
            "before_state IS NULL OR jsonb_typeof(before_state) = 'object'",
            name="before_state_object",
        ),
        CheckConstraint(
            "after_state IS NULL OR jsonb_typeof(after_state) = 'object'",
            name="after_state_object",
        ),
        Index("ix_rbac_audit_actor_created", "actor_user_id", "created_at"),
        Index("ix_rbac_audit_request_id", "request_id"),
        Index("ix_rbac_audit_created_id", "created_at", "id"),
        Index("ix_rbac_audit_target_user_created", "target_user_id", "created_at"),
        Index("ix_rbac_audit_target_role_created", "target_role_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    actor_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    target_role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AuditSource.SERVICE.value,
        server_default=AuditSource.SERVICE.value,
    )
    schema_version: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    before_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    after_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    @validates("action")
    def validate_action(self, _key: str, value: str) -> str:
        return validate_audit_action(value)

    @validates("reason_code")
    def validate_reason_code(self, _key: str, value: str) -> str:
        return validate_audit_reason(value)

    @validates("request_id")
    def validate_request_id(self, _key: str, value: str) -> str:
        return validate_audit_request_id(value)

    @validates("source")
    def validate_source(self, _key: str, value: str | AuditSource) -> str:
        return AuditSource(value).value

    @validates("before_state", "after_state")
    def validate_state(
        self,
        _key: str,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        return sanitize_audit_state(value)
