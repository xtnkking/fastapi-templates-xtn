import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects.postgresql.base import PGDialect

from app.audit import (
    sanitize_audit_state,
    validate_audit_action,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.rbac.models import RbacAuditEvent


@pytest.mark.parametrize("field", ["before_state", "after_state"])
def test_optional_audit_state_binds_none_as_sql_null(field: str) -> None:
    column = RbacAuditEvent.__table__.c[field]
    processor = column.type.bind_processor(PGDialect())  # type: ignore[no-untyped-call]

    assert processor is not None
    assert processor(None) is None


def test_audit_state_accepts_bounded_json_and_normalizes_protocol_values() -> None:
    entity_id = uuid.uuid4()
    occurred_at = datetime.now(UTC)

    state = sanitize_audit_state(
        {
            "user_id": entity_id,
            "occurred_at": occurred_at,
            "roles": ["user", "manager"],
            "changed": True,
        }
    )

    assert state is not None
    assert state["user_id"] == str(entity_id)
    assert state["occurred_at"] == occurred_at.isoformat().replace("+00:00", "Z")


def test_audit_state_accepts_fixed_password_reset_permission_identifier() -> None:
    state = sanitize_audit_state(
        {"permissions": ["users:password:reset"], "delegable_permissions": []}
    )

    assert state == {
        "permissions": ["users:password:reset"],
        "delegable_permissions": [],
    }


@pytest.mark.parametrize(
    "state",
    [
        {"password": "not-for-audit"},
        {"nested": {"access_token": "not-for-audit"}},
        {"jti": str(uuid.uuid4())},
        {"email": "person@example.test"},
    ],
)
def test_audit_state_rejects_credentials_tokens_and_direct_identifiers(
    state: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="forbidden sensitive field"):
        sanitize_audit_state(state)


def test_audit_state_rejects_unbounded_or_non_json_values() -> None:
    with pytest.raises(ValueError, match="too many array items"):
        sanitize_audit_state({"items": list(range(101))})
    with pytest.raises(ValueError, match="unsupported audit state value"):
        sanitize_audit_state({"value": object()})
    with pytest.raises(ValueError, match="16 KiB"):
        sanitize_audit_state({"value": "x" * (16 * 1024)})


@pytest.mark.parametrize(
    "value",
    [
        "Bearer raw-token",
        "password=raw-password",
        "password:raw-password",
        "token=raw-token",
        "users:password=raw-password",
        "users:token=raw-token",
        "users:password:reset password=raw-password",
        "https://user:password@example.test/path",
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
def test_audit_state_rejects_obvious_sensitive_values(value: str) -> None:
    with pytest.raises(ValueError, match="sensitive text"):
        sanitize_audit_state({"note": value})


def test_audit_labels_and_correlation_ids_use_stable_machine_formats() -> None:
    assert validate_audit_action("role.permissions.bind") == "role.permissions.bind"
    assert validate_audit_reason("permissions_bound") == "permissions_bound"
    assert validate_audit_request_id(str(uuid.uuid4()))
    assert validate_audit_request_id("job:daily_access_review:20260910")

    with pytest.raises(ValueError, match="invalid audit action"):
        validate_audit_action("Role changed")
    with pytest.raises(ValueError, match="invalid audit reason"):
        validate_audit_reason("not allowed")
    with pytest.raises(ValueError, match="correlation ID"):
        validate_audit_request_id("person@example.test")


def test_rbac_audit_model_applies_safe_validators() -> None:
    event = RbacAuditEvent(
        actor_user_id=uuid.uuid4(),
        action="role.update",
        decision="allowed",
        reason_code="role_updated",
        source="service",
        schema_version=1,
        before_state={"version": 1},
        after_state={"version": 2},
        request_id=str(uuid.uuid4()),
    )

    assert event.source == "service"
    assert event.schema_version == 1
    with pytest.raises(ValueError, match="forbidden sensitive field"):
        event.after_state = {"jwt_secret": "not-for-audit"}
