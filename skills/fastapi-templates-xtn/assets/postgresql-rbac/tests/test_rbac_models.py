from typing import cast

from sqlalchemy import Table

from app.rbac.models import RbacAuditEvent, RbacState


def test_rbac_state_model_uses_clear_database_names() -> None:
    table = cast(Table, RbacState.__table__)

    assert table.name == "rbac_state"
    assert table.primary_key.name == "pk_rbac_state"
    assert {constraint.name for constraint in table.constraints} == {
        "ck_rbac_state_epoch_nonnegative",
        "ck_rbac_state_scope_global",
        "pk_rbac_state",
    }


def test_rbac_audit_model_uses_unambiguous_database_names() -> None:
    table = cast(Table, RbacAuditEvent.__table__)

    assert table.name == "rbac_audit_events"
    assert table.primary_key.name == "pk_rbac_audit_events"
    assert {constraint.name for constraint in table.constraints} == {
        "ck_rbac_audit_events_action_format",
        "ck_rbac_audit_events_after_state_object",
        "ck_rbac_audit_events_before_state_object",
        "ck_rbac_audit_events_reason_code_format",
        "ck_rbac_audit_events_request_id_format",
        "ck_rbac_audit_events_schema_version_one",
        "ck_rbac_audit_events_valid_decision",
        "ck_rbac_audit_events_valid_source",
        "pk_rbac_audit_events",
    }
    assert {index.name for index in table.indexes} == {
        "ix_rbac_audit_actor_created",
        "ix_rbac_audit_created_id",
        "ix_rbac_audit_request_id",
        "ix_rbac_audit_target_role_created",
        "ix_rbac_audit_target_user_created",
    }
