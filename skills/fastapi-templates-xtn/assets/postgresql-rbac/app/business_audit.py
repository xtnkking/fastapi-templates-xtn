import ipaddress
import json
import logging
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from sqlalchemy import CheckConstraint, DateTime, Index, SmallInteger, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, validates
from sqlalchemy.schema import conv

from app.audit import (
    AuditJsonValue,
    AuditSource,
    sanitize_audit_state,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.base import Base
from app.observability import safe_log

logger = logging.getLogger(__name__)

_DOMAIN_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ACTION_RE: Final = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$")
_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$")
_EMAIL_RE: Final = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)
_IPV4_CANDIDATE_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.])"
)
_IPV6_CANDIDATE_RE: Final = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?=[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:]))"
    r"(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)"
    r"[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:])"
)
_FORBIDDEN_BUSINESS_KEYS: Final = frozenset(
    {
        "address",
        "bank_account",
        "body",
        "card_number",
        "customer_text",
        "display_name",
        "headers",
        "ip",
        "ip_address",
        "note",
        "phone",
        "postal_address",
        "query",
        "query_string",
        "request_body",
        "response_body",
        "user_agent",
    }
)
_FORBIDDEN_BUSINESS_SUFFIXES: Final = (
    "_address",
    "_bank_account",
    "_card_number",
    "_customer_text",
    "_display_name",
    "_ip",
    "_ip_address",
    "_note",
    "_phone",
    "_user_agent",
)
_MAX_CONTEXT_BYTES: Final = 4 * 1024


class BusinessAuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class BusinessAuditActorType(StrEnum):
    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"
    JOB = "job"
    OPERATOR = "operator"


def _require_machine_name(value: str, *, field: str) -> str:
    if _DOMAIN_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def _require_identifier(value: str, *, field: str) -> str:
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def _require_uuid4(value: uuid.UUID) -> uuid.UUID:
    if not isinstance(value, uuid.UUID) or value.version != 4:
        raise ValueError("business audit event ID must be UUIDv4")
    return value


def _contains_network_identifier(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return True

    for match in _IPV4_CANDIDATE_RE.finditer(value):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            continue
        return True

    for match in _IPV6_CANDIDATE_RE.finditer(value):
        try:
            ipaddress.IPv6Address(match.group())
        except ipaddress.AddressValueError:
            continue
        return True
    return False


def _reject_business_sensitive_data(value: object) -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                continue
            normalized = raw_key.casefold().replace("-", "_")
            if normalized in _FORBIDDEN_BUSINESS_KEYS or normalized.endswith(
                _FORBIDDEN_BUSINESS_SUFFIXES
            ):
                raise ValueError("business audit payload contains forbidden data")
            _reject_business_sensitive_data(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            _reject_business_sensitive_data(item)
        return
    if isinstance(value, str):
        if _EMAIL_RE.search(value) is not None:
            raise ValueError("business audit payload contains an email address")
        if _contains_network_identifier(value):
            raise ValueError("business audit payload contains a network identifier")


def _sanitize_business_payload(
    state: Mapping[str, object] | None,
    *,
    max_bytes: int,
) -> dict[str, AuditJsonValue] | None:
    if state is None:
        return None
    _reject_business_sensitive_data(state)
    sanitized = sanitize_audit_state(state)
    assert sanitized is not None
    encoded = json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("business audit payload exceeds its size limit")
    return sanitized


@dataclass(frozen=True, slots=True)
class BusinessAuditActor:
    actor_type: BusinessAuditActorType
    id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.actor_type, BusinessAuditActorType):
            raise TypeError("business audit actor type must use BusinessAuditActorType")
        if self.actor_type is BusinessAuditActorType.SYSTEM:
            if self.id is not None:
                raise ValueError("system business audit actor must not have an ID")
        elif self.id is None:
            raise ValueError("non-system business audit actor requires an ID")
        else:
            _require_identifier(self.id, field="actor ID")


@dataclass(frozen=True, slots=True)
class BusinessAuditActionSpec:
    domain: str
    action: str
    resource_type: str
    allowed_outcomes: frozenset[BusinessAuditOutcome]
    reason_codes: frozenset[str]
    actor_types: frozenset[BusinessAuditActorType]
    before_fields: frozenset[str] = frozenset()
    after_fields: frozenset[str] = frozenset()
    context_fields: frozenset[str] = frozenset()
    schema_version: int = 1

    def __post_init__(self) -> None:
        collection_fields = (
            self.allowed_outcomes,
            self.reason_codes,
            self.actor_types,
            self.before_fields,
            self.after_fields,
            self.context_fields,
        )
        if any(not isinstance(value, frozenset) for value in collection_fields):
            raise TypeError("business audit catalog collections must be frozenset")
        _require_machine_name(self.domain, field="domain")
        if len(self.action) > 120 or _ACTION_RE.fullmatch(self.action) is None:
            raise ValueError("invalid business audit action")
        if self.action.split(".", 1)[0] != self.domain:
            raise ValueError("business audit action must start with its domain")
        _require_machine_name(self.resource_type, field="resource type")
        if not self.allowed_outcomes:
            raise ValueError("business audit action requires an allowed outcome")
        if any(
            not isinstance(outcome, BusinessAuditOutcome)
            for outcome in self.allowed_outcomes
        ):
            raise TypeError("allowed outcomes must use BusinessAuditOutcome")
        if not self.reason_codes:
            raise ValueError("business audit action requires a reason code")
        if not self.actor_types:
            raise ValueError("business audit action requires an actor type")
        if any(
            not isinstance(actor_type, BusinessAuditActorType)
            for actor_type in self.actor_types
        ):
            raise TypeError("actor types must use BusinessAuditActorType")
        for reason_code in self.reason_codes:
            validate_audit_reason(reason_code)
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version < 1
        ):
            raise ValueError("business audit schema version must be a positive integer")
        for field_name in self.before_fields | self.after_fields | self.context_fields:
            _sanitize_business_payload({field_name: None}, max_bytes=_MAX_CONTEXT_BYTES)


@dataclass(frozen=True, slots=True)
class BusinessAuditFacts:
    event_id: uuid.UUID
    action: str
    actor: BusinessAuditActor
    resource_id: str
    reason_code: str
    source: AuditSource
    request_id: str
    before_state: Mapping[str, object] | None = None
    after_state: Mapping[str, object] | None = None
    context: Mapping[str, object] | None = None


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
        return _require_uuid4(value)

    @validates("domain", "resource_type")
    def validate_machine_name(self, key: str, value: str) -> str:
        return _require_machine_name(value, field=key.replace("_", " "))

    @validates("action")
    def validate_action(self, _key: str, value: str) -> str:
        if len(value) > 120 or _ACTION_RE.fullmatch(value) is None:
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
        return None if value is None else _require_identifier(value, field="actor ID")

    @validates("resource_id")
    def validate_resource_id(self, _key: str, value: str) -> str:
        return _require_identifier(value, field="resource ID")

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
        return _sanitize_business_payload(value, max_bytes=16 * 1024)

    @validates("context")
    def validate_context(self, _key: str, value: dict[str, Any]) -> dict[str, Any]:
        sanitized = _sanitize_business_payload(value, max_bytes=_MAX_CONTEXT_BYTES)
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


class BusinessAuditWriter:
    """Build catalog-owned events; callers own successful transactions."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        action_specs: Mapping[str, BusinessAuditActionSpec],
    ) -> None:
        self._session_factory = session_factory
        self._action_specs = dict(action_specs)
        if not self._action_specs:
            raise ValueError("business audit action catalog cannot be empty")
        for action, spec in self._action_specs.items():
            if action != spec.action:
                raise ValueError("business audit catalog key must match its action")

    @staticmethod
    def _safe_payload(
        state: Mapping[str, object] | None,
        *,
        allowed_fields: frozenset[str],
        max_bytes: int,
    ) -> dict[str, AuditJsonValue] | None:
        if state is None:
            return None
        if set(state) - allowed_fields:
            raise ValueError("business audit payload contains a non-allowlisted field")
        return _sanitize_business_payload(state, max_bytes=max_bytes)

    def build_event(
        self,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> BusinessAuditEvent:
        spec = self._action_specs.get(facts.action)
        if spec is None:
            raise ValueError("business audit action is not registered")
        outcome = BusinessAuditOutcome(outcome)
        if outcome not in spec.allowed_outcomes:
            raise ValueError("business audit outcome is not allowed for this action")
        if facts.reason_code not in spec.reason_codes:
            raise ValueError("business audit reason is not registered for this action")
        if facts.actor.actor_type not in spec.actor_types:
            raise ValueError("business audit actor type is not allowed for this action")
        if (
            outcome is not BusinessAuditOutcome.SUCCEEDED
            and facts.after_state is not None
        ):
            raise ValueError("denied and failed events cannot claim an after state")
        _require_uuid4(facts.event_id)
        _require_identifier(facts.resource_id, field="resource ID")
        source = AuditSource(facts.source)
        request_id = validate_audit_request_id(facts.request_id)
        before_state = self._safe_payload(
            facts.before_state,
            allowed_fields=spec.before_fields,
            max_bytes=16 * 1024,
        )
        after_state = self._safe_payload(
            facts.after_state,
            allowed_fields=spec.after_fields,
            max_bytes=16 * 1024,
        )
        context = self._safe_payload(
            facts.context or {},
            allowed_fields=spec.context_fields,
            max_bytes=_MAX_CONTEXT_BYTES,
        )
        assert context is not None
        return BusinessAuditEvent(
            id=facts.event_id,
            domain=spec.domain,
            action=spec.action,
            outcome=outcome.value,
            reason_code=facts.reason_code,
            actor_type=facts.actor.actor_type.value,
            actor_id=facts.actor.id,
            resource_type=spec.resource_type,
            resource_id=facts.resource_id,
            source=source.value,
            schema_version=spec.schema_version,
            before_state=before_state,
            after_state=after_state,
            context=context,
            request_id=request_id,
        )

    def add_succeeded(
        self,
        session: AsyncSession,
        facts: BusinessAuditFacts,
    ) -> BusinessAuditEvent:
        if not session.in_transaction():
            raise RuntimeError(
                "successful business audit requires a caller-owned transaction"
            )
        event = self.build_event(facts, outcome=BusinessAuditOutcome.SUCCEEDED)
        session.add(event)
        return event

    def add_after_savepoint_rollback(
        self,
        session: AsyncSession,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> BusinessAuditEvent:
        """Stage evidence after the caller has rolled back its nested attempt."""
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        if not session.in_transaction():
            raise RuntimeError("savepoint audit requires a caller-owned transaction")
        if session.in_nested_transaction():
            raise RuntimeError("savepoint audit requires the nested rollback to finish")
        event = self.build_event(facts, outcome=outcome)
        session.add(event)
        return event

    async def write_after_rollback(
        self,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> bool:
        """Best-effort catalog-required denial/failure evidence after rollback."""
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    session.add(self.build_event(facts, outcome=outcome))
            return True
        except Exception as exc:
            safe_log(
                logger,
                logging.ERROR,
                "audit.write.failed",
                extra={
                    "audit_domain": "business",
                    "exception_type": type(exc).__name__,
                },
            )
            return False
