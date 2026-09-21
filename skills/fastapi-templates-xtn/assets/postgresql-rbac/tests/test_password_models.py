import uuid
from typing import cast

import pytest
from sqlalchemy import CheckConstraint, Table

from app.core.audit import AuditSource
from app.db.base import Base
from app.models.access import User
from app.models.account_security import (
    AccountSecurityActorType,
    AccountSecurityAuditEvent,
    AccountSecurityAuditOutcome,
)


def test_user_model_owns_nullable_password_state_without_an_episode_table() -> None:
    table = cast(Table, User.__table__)

    assert table.name == "users"
    assert "user_password_credentials" not in Base.metadata.tables
    assert table.c.password_hash.nullable
    assert table.c.password_changed_at.nullable
    assert not table.c.must_change_password.nullable
    assert table.c.must_change_password.server_default is not None
    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert "ck_users_password_hash_shape" in checks
    assert "ck_users_password_state_coherent" in checks
    assert "ck_users_deleted_user_no_password" in checks
    assert "password_changed_at IS NULL" in checks["ck_users_password_state_coherent"]
    assert "must_change_password" in checks["ck_users_password_state_coherent"]


def test_account_security_audit_model_is_narrow_and_unambiguous() -> None:
    table = cast(Table, AccountSecurityAuditEvent.__table__)

    assert table.name == "account_security_audit_events"
    assert set(table.columns) == {
        table.c.id,
        table.c.action,
        table.c.outcome,
        table.c.reason_code,
        table.c.actor_type,
        table.c.actor_user_id,
        table.c.target_user_id,
        table.c.source,
        table.c.schema_version,
        table.c.request_id,
        table.c.created_at,
    }
    assert "password_hash" not in table.c
    assert "context" not in table.c
    assert "before_state" not in table.c
    assert "after_state" not in table.c


def test_account_security_audit_accepts_enum_or_value_strings() -> None:
    actor_id = uuid.uuid4()
    event = AccountSecurityAuditEvent(
        action="account_security.password.changed",
        outcome=AccountSecurityAuditOutcome.SUCCEEDED.value,
        reason_code="password_changed",
        actor_type=AccountSecurityActorType.USER,
        actor_user_id=actor_id,
        target_user_id=actor_id,
        source=AuditSource.HTTP.value,
        request_id=str(uuid.uuid4()),
    )

    assert event.outcome == "succeeded"
    assert event.actor_type == "user"
    assert event.source == "http"


def test_models_reject_non_uuid4_event_ids() -> None:
    with pytest.raises(ValueError, match="UUIDv4"):
        AccountSecurityAuditEvent(
            id=uuid.uuid1(),
            action="account_security.password.changed",
            outcome="succeeded",
            reason_code="password_changed",
            actor_type="user",
            actor_user_id=uuid.uuid4(),
            target_user_id=uuid.uuid4(),
            source="http",
            request_id=str(uuid.uuid4()),
        )
