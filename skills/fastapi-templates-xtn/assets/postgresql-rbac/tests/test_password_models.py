#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证用户密码字段和账号安全审计的模型元数据。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        补充文件记录并检查无临时密码状态字段
# 2026/10/10    XTN       V1.001        统一用户 ID 与当前用户命名
# --------------------------------------------------------------------------------------------------

import uuid
from typing import cast

import pytest
from sqlalchemy import CheckConstraint, Table

from app.core.audit import AuditOutcome, AuditSource
from app.core.ids import new_entity_id
from app.models.postgres.base import Base
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.user import User


def test_user_model_owns_nullable_password_state_without_an_episode_table() -> None:
    table = cast(Table, User.__table__)

    assert table.name == "users"
    assert "user_password_credentials" not in Base.metadata.tables
    assert table.c.password_hash.nullable
    assert table.c.password_changed_at.nullable
    assert "must_change_password" not in table.c
    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert "ck_users_password_hash_shape" in checks
    assert "ck_users_password_state_coherent" in checks
    assert "ck_users_deleted_user_no_password" in checks
    assert "password_changed_at IS NULL" in checks["ck_users_password_state_coherent"]


def test_operation_audit_model_has_the_approved_sixteen_fields() -> None:
    table = cast(Table, OperationAuditEvent.__table__)

    assert table.name == "operation_audit_events"
    assert set(table.columns) == {
        table.c.id,
        table.c.category,
        table.c.action,
        table.c.outcome,
        table.c.reason_code,
        table.c.user_id,
        table.c.target_user_id,
        table.c.target_role_id,
        table.c.source,
        table.c.request_data,
        table.c.response_data,
        table.c.password_fingerprint,
        table.c.before_state,
        table.c.after_state,
        table.c.request_id,
        table.c.created_at,
    }
    assert "password_hash" not in table.c
    assert "context" not in table.c
    assert "operator_type" not in table.c
    assert "schema_version" not in table.c


def test_operation_audit_accepts_enum_or_value_strings() -> None:
    user_id = new_entity_id("U")
    event = OperationAuditEvent(
        category="account",
        action="account_security.password.changed",
        outcome=AuditOutcome.SUCCEEDED.value,
        reason_code="password_changed",
        user_id=user_id,
        target_user_id=user_id,
        source=AuditSource.HTTP.value,
        request_id=str(uuid.uuid4()),
    )

    assert event.outcome == "succeeded"
    assert event.category == "account"
    assert event.source == "http"


def test_models_reject_non_prefixed_event_ids() -> None:
    with pytest.raises(ValueError, match="invalid audit ID"):
        OperationAuditEvent(
            id=uuid.uuid1(),
            category="account",
            action="account_security.password.changed",
            outcome="succeeded",
            reason_code="password_changed",
            user_id=new_entity_id("U"),
            target_user_id=new_entity_id("U"),
            source="http",
            request_id=str(uuid.uuid4()),
        )
