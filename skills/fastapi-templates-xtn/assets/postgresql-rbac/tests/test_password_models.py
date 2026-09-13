import uuid
from typing import cast

import pytest
from sqlalchemy import Table

from app.audit import AuditSource
from app.password_models import (
    AccountSecurityActorType,
    AccountSecurityAuditEvent,
    AccountSecurityAuditOutcome,
    PasswordCredential,
)
from app.passwords import DUMMY_PASSWORD_HASH


def test_password_credential_model_has_episode_constraints() -> None:
    table = cast(Table, PasswordCredential.__table__)

    assert table.name == "user_password_credentials"
    assert table.primary_key.name == "pk_user_password_credentials"
    assert {constraint.name for constraint in table.constraints} == {
        "ck_user_password_credentials_deleted_actor_requires_timestamp",
        "ck_user_password_credentials_id_uuid4",
        "ck_user_password_credentials_live_hash_or_tombstone",
        "ck_user_password_credentials_password_changed_after_created",
        "ck_user_password_credentials_password_hash_shape",
        "ck_user_password_credentials_tombstone_not_change_required",
        "ck_user_password_credentials_version_positive",
        "fk_user_password_credentials_created_by_user_id_users",
        "fk_user_password_credentials_deleted_by_user_id_users",
        "fk_user_password_credentials_user_id_users",
        "pk_user_password_credentials",
        "uq_user_password_credentials_user_version",
    }
    assert {index.name for index in table.indexes} == {
        "ix_user_password_credentials_deleted_at",
        "ix_user_password_credentials_user_created",
        "uq_user_password_credentials_live_user",
    }


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

    with pytest.raises(ValueError, match="UUIDv4"):
        PasswordCredential(
            id=uuid.uuid1(),
            user_id=uuid.uuid4(),
            password_hash=DUMMY_PASSWORD_HASH,
        )
