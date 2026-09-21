"""Business audit catalog types and payload validation rules."""

import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from app.core.audit import (
    AuditJsonValue,
    AuditSource,
    sanitize_audit_state,
    validate_audit_reason,
)

_DOMAIN_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
BUSINESS_AUDIT_ACTION_PATTERN: Final = re.compile(
    r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$"
)
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
MAX_BUSINESS_AUDIT_CONTEXT_BYTES: Final = 4 * 1024


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


def require_business_machine_name(value: str, *, field: str) -> str:
    if _DOMAIN_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def require_business_identifier(value: str, *, field: str) -> str:
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def require_business_event_id(value: uuid.UUID) -> uuid.UUID:
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


def sanitize_business_payload(
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
            require_business_identifier(self.id, field="actor ID")


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
        require_business_machine_name(self.domain, field="domain")
        if (
            len(self.action) > 120
            or BUSINESS_AUDIT_ACTION_PATTERN.fullmatch(self.action) is None
        ):
            raise ValueError("invalid business audit action")
        if self.action.split(".", 1)[0] != self.domain:
            raise ValueError("business audit action must start with its domain")
        require_business_machine_name(self.resource_type, field="resource type")
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
            sanitize_business_payload(
                {field_name: None}, max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES
            )


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
