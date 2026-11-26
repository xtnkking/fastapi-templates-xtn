from typing import cast

from sqlalchemy import Table

from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.rbac_state import RbacState


def test_rbac_state_model_uses_clear_database_names() -> None:
    table = cast(Table, RbacState.__table__)

    assert table.name == "rbac_state"
    assert table.primary_key.name == "pk_rbac_state"
    assert {constraint.name for constraint in table.constraints} == {
        "ck_rbac_state_scope_global",
        "pk_rbac_state",
    }


def test_operation_audit_model_uses_unambiguous_database_names() -> None:
    table = cast(Table, OperationAuditEvent.__table__)

    assert table.name == "operation_audit_events"
    assert table.primary_key.name == "pk_operation_audit_events"
    assert all(
        isinstance(constraint.name, str)
        and constraint.name.startswith(("ck_operation_audit_events_", "pk_operation_audit_events"))
        for constraint in table.constraints
    )
    assert all(index.name is not None and index.name.startswith("ix_operation_audit_") for index in table.indexes)
    assert not {"decision", "schema_version", "operator_type"} & set(table.columns.keys())
