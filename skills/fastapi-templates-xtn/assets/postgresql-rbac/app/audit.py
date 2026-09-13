import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Final

type AuditJsonValue = (
    None
    | bool
    | int
    | float
    | str
    | list["AuditJsonValue"]
    | dict[str, "AuditJsonValue"]
)


class AuditSource(StrEnum):
    HTTP = "http"
    SERVICE = "service"
    JOB = "job"
    OPERATOR = "operator"
    MIGRATION = "migration"


_ACTION_RE: Final = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_REASON_RE: Final = re.compile(r"^[a-z][a-z0-9_]*$")
_REQUEST_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
_SENSITIVE_TEXT_RE: Final = re.compile(
    r"(?i)(?:\bbearer\s+\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:password|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+|"
    r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)"
)
_SAFE_AUDIT_IDENTIFIERS: Final = frozenset({"users:password:reset"})
_MAX_DEPTH: Final = 6
_MAX_COLLECTION_ITEMS: Final = 100
_MAX_STATE_BYTES: Final = 16 * 1024
_SENSITIVE_KEYS: Final = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credentials",
        "database_url",
        "email",
        "id_token",
        "jti",
        "jwt",
        "jwt_secret",
        "password",
        "password_hash",
        "private_key",
        "proxy_url",
        "redis_url",
        "secret",
        "set_cookie",
        "token",
        "username",
    }
)
_SENSITIVE_SUFFIXES: Final = (
    "_api_key",
    "_cookie",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)


def _normalized_key(key: str) -> str:
    return key.casefold().replace("-", "_")


def _require_safe_key(key: str) -> None:
    normalized = _normalized_key(key)
    if normalized in _SENSITIVE_KEYS or normalized.endswith(_SENSITIVE_SUFFIXES):
        raise ValueError(f"audit state contains forbidden sensitive field: {key}")
    if not key or len(key) > 120:
        raise ValueError("audit state keys must contain 1 to 120 characters")


def _audit_json(value: object, *, depth: int) -> AuditJsonValue:
    if depth > _MAX_DEPTH:
        raise ValueError("audit state exceeds the maximum nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if value not in _SAFE_AUDIT_IDENTIFIERS and _SENSITIVE_TEXT_RE.search(value):
            raise ValueError("audit state contains sensitive text")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("audit state cannot contain non-finite numbers")
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("audit timestamps must include a timezone")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _audit_json(value.value, depth=depth + 1)
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("audit state contains too many object fields")
        result: dict[str, AuditJsonValue] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("audit state object keys must be strings")
            _require_safe_key(raw_key)
            result[raw_key] = _audit_json(item, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("audit state contains too many array items")
        return [_audit_json(item, depth=depth + 1) for item in value]
    raise ValueError(f"unsupported audit state value: {type(value).__name__}")


def sanitize_audit_state(
    state: Mapping[str, object] | None,
) -> dict[str, AuditJsonValue] | None:
    if state is None:
        return None
    value = _audit_json(state, depth=0)
    if not isinstance(value, dict):
        raise ValueError("audit state must be a JSON object")
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > _MAX_STATE_BYTES:
        raise ValueError("audit state exceeds 16 KiB")
    return value


def validate_audit_action(value: str) -> str:
    if not 3 <= len(value) <= 120 or _ACTION_RE.fullmatch(value) is None:
        raise ValueError("invalid audit action")
    return value


def validate_audit_reason(value: str) -> str:
    if not 2 <= len(value) <= 80 or _REASON_RE.fullmatch(value) is None:
        raise ValueError("invalid audit reason code")
    return value


def validate_audit_request_id(value: str) -> str:
    if not 1 <= len(value) <= 128 or _REQUEST_ID_RE.fullmatch(value) is None:
        raise ValueError("invalid audit request or correlation ID")
    return value
