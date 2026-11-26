#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查业务审计操作人、被操作人、动作目录和事务边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/10    XTN       V1.000        对齐审计 operator 命名并补充文件职责记录
# 2026/10/10    XTN       V1.001        区分操作用户、被操作用户和非用户执行来源
# 2026/10/16    XTN       V1.002        审计关联 ID 由显式请求上下文提供
# --------------------------------------------------------------------------------------------------

import uuid
from dataclasses import replace
from typing import cast
from unittest.mock import Mock

import pytest
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit import AuditSource
from app.core.business_audit import (
    BusinessAuditActionSpec,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    BusinessAuditSourceType,
)
from app.core.ids import new_audit_id, new_entity_id
from app.db.postgres_db import SessionFactory
from app.models.postgres.base import Base
from app.models.postgres.business_audit import BusinessAuditEvent
from app.services import business_audit_service as business_audit
from app.services.business_audit_service import BusinessAuditService

pytestmark = pytest.mark.usefixtures("audit_request_context")

ACTION = "project.settings.update"
SPEC = BusinessAuditActionSpec(
    domain="project",
    action=ACTION,
    target_type="project",
    allowed_outcomes=frozenset(BusinessAuditOutcome),
    reason_codes=frozenset({"settings_updated", "policy_denied"}),
    source_types=frozenset({BusinessAuditSourceType.USER}),
    before_fields=frozenset({"enabled", "version"}),
    after_fields=frozenset(
        {"enabled", "version", "status_code", "contact", "metadata"}
    ),
    context_fields=frozenset({"channel"}),
)


def writer() -> BusinessAuditService:
    return BusinessAuditService(SessionFactory, {ACTION: SPEC})


def facts(*, before_state: dict[str, object] | None = None,
          after_state: dict[str, object] | None = None) -> BusinessAuditFacts:
    """
        准备用户修改项目设置的审计事实；这里的 user_id 只表示操作人。

    :param before_state: 变更前允许记录的项目字段，未提供时没有前态。
    :param after_state: 变更后允许记录的项目字段，失败或拒绝时应为空。
    :return: 带独立事件 ID、操作用户和目标项目的审计事实。
    """
    return BusinessAuditFacts(
        event_id=new_audit_id("BA"),
        action=ACTION,
        source_type=BusinessAuditSourceType.USER,
        user_id=new_entity_id("U"),
        target_id=str(uuid.uuid4()),
        reason_code="settings_updated",
        entrypoint=AuditSource.HTTP,
        before_state=before_state,
        after_state=after_state,
        context={"channel": "admin_console"},
    )


def test_business_audit_model_registers_on_shared_metadata() -> None:
    assert Base.metadata.tables["business_audit_events"] is BusinessAuditEvent.__table__


@pytest.mark.parametrize("field", ["before_state", "after_state"])
def test_absent_business_audit_states_bind_as_sql_null(field: str) -> None:
    column = BusinessAuditEvent.__table__.c[field]
    processor = column.type.bind_processor(PGDialect())  # type: ignore[no-untyped-call]

    assert processor is not None
    assert processor(None) is None


def test_writer_builds_catalog_owned_event_shape() -> None:
    event = writer().build_event(
        facts(
            before_state={"enabled": False, "version": 4},
            after_state={"enabled": True, "version": 5},
        ),
        outcome=BusinessAuditOutcome.SUCCEEDED,
    )

    assert event.action == ACTION
    assert event.domain == "project"
    assert event.target_type == "project"
    assert event.source_type == "user"
    assert event.user_id is not None
    assert event.source_id is None
    assert event.target_user_id is None
    assert event.entrypoint == "http"
    assert event.outcome == BusinessAuditOutcome.SUCCEEDED.value
    assert event.schema_version == 1
    assert event.before_state == {"enabled": False, "version": 4}
    assert event.after_state == {"enabled": True, "version": 5}
    assert event.context == {"channel": "admin_console"}


@pytest.mark.parametrize(
    "after_state",
    [
        {"not_allowlisted": "value"},
        {"status_code": "Bearer durable-secret"},
        {"status_code": "password=durable-secret"},
        {"status_code": "postgresql://user:password@database.example/app"},
    ],
)
def test_writer_rejects_non_allowlisted_or_sensitive_snapshots(after_state: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        writer().build_event(
            facts(after_state=after_state),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


@pytest.mark.parametrize(
    ("after_state", "message"),
    [
        ({"contact": "person@example.test"}, "email address"),
        (
            {"metadata": {"delivery": {"contact": "send to person@example.test"}}},
            "email address",
        ),
        (
            {"metadata": {"network": ["proxy exit: 203.0.113.7 (verified)"]}},
            "network identifier",
        ),
        (
            {"metadata": {"network": ["proxy exit [2001:db8::7] verified"]}},
            "network identifier",
        ),
    ],
)
def test_writer_rejects_nested_email_and_network_values(after_state: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        writer().build_event(
            facts(after_state=after_state),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


def test_writer_preserves_non_pii_business_values() -> None:
    after_state: dict[str, object] = {
        "status_code": "PAYMENT_APPROVED",
        "version": "v1.2.3.4",
        "metadata": {
            "amount": "USD 1,234.56",
            "business_id": "ORDER-2026-09-ABC123",
            "correlation_code": "PAY:ABCD:1234",
        },
    }

    event = writer().build_event(
        facts(after_state=after_state),
        outcome=BusinessAuditOutcome.SUCCEEDED,
    )

    assert event.after_state == after_state


def test_non_success_event_cannot_claim_after_state() -> None:
    with pytest.raises(ValueError, match="cannot claim an after state"):
        writer().build_event(
            facts(after_state={"enabled": True}),
            outcome=BusinessAuditOutcome.DENIED,
        )


def test_successful_event_requires_caller_owned_transaction() -> None:
    session = Mock(spec=AsyncSession)
    session.in_transaction.return_value = False

    with pytest.raises(RuntimeError, match="caller-owned transaction"):
        writer().add_succeeded(session, facts())

    session.in_transaction.return_value = True
    event = writer().add_succeeded(session, facts())
    session.add.assert_called_once_with(event)


def test_savepoint_event_requires_finished_nested_rollback() -> None:
    session = Mock(spec=AsyncSession)
    session.in_transaction.return_value = False
    session.in_nested_transaction.return_value = False

    with pytest.raises(RuntimeError, match="caller-owned transaction"):
        writer().add_after_savepoint_rollback(
            session,
            facts(),
            outcome=BusinessAuditOutcome.DENIED,
        )

    session.in_transaction.return_value = True
    session.in_nested_transaction.return_value = True
    with pytest.raises(RuntimeError, match="nested rollback to finish"):
        writer().add_after_savepoint_rollback(
            session,
            facts(),
            outcome=BusinessAuditOutcome.DENIED,
        )

    session.in_nested_transaction.return_value = False
    with pytest.raises(ValueError, match="must use the protected transaction"):
        writer().add_after_savepoint_rollback(
            session,
            facts(),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )

    event = writer().add_after_savepoint_rollback(
        session,
        facts(),
        outcome=BusinessAuditOutcome.DENIED,
    )
    session.add.assert_called_once_with(event)


def test_source_and_catalog_reject_untrusted_labels() -> None:
    """
        拒绝把邮箱当作操作用户 ID，也拒绝不符合机器命名规则的动作。

    :return: 无返回值；非法来源和动作均已被拒绝。
    """
    with pytest.raises(ValueError):
        writer().build_event(
            replace(facts(), user_id="person@example.test"),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )
    with pytest.raises(ValueError, match="invalid business audit action"):
        BusinessAuditActionSpec(
            domain="project",
            action="Project Changed",
            target_type="project",
            allowed_outcomes=frozenset({BusinessAuditOutcome.SUCCEEDED}),
            reason_codes=frozenset({"changed"}),
            source_types=frozenset({BusinessAuditSourceType.USER}),
        )


@pytest.mark.parametrize(
    "event_facts",
    [
        replace(facts(), before_state={"not_allowlisted": True}),
        replace(facts(), context={"not_allowlisted": True}),
    ],
)
def test_each_payload_section_enforces_its_own_top_level_allowlist(event_facts: BusinessAuditFacts) -> None:
    with pytest.raises(ValueError, match="non-allowlisted"):
        writer().build_event(
            event_facts,
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


def test_context_size_uses_postgresql_jsonb_text_spacing() -> None:
    event_facts = replace(facts(), context={"channel": "x" * 4082})

    with pytest.raises(ValueError, match="exceeds its size limit"):
        writer().build_event(
            event_facts,
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


@pytest.mark.parametrize("same_user", [False, True])
def test_user_action_records_performer_and_affected_user(same_user: bool) -> None:
    """
        管理员操作别人时分别保存两个用户 ID；本人操作时允许两者相同。

    :param same_user: True 表示本人操作；False 表示操作另一个用户。
    :return: 无返回值；操作人与被操作人的字段含义已核对。
    """
    event_facts = facts()
    assert event_facts.user_id is not None
    target_user_id = event_facts.user_id if same_user else new_entity_id("U")
    user_spec = replace(SPEC, target_type="user")
    audit_writer = BusinessAuditService(SessionFactory, {ACTION: user_spec})

    event = audit_writer.build_event(
        replace(event_facts, target_id=target_user_id, target_user_id=target_user_id),
        outcome=BusinessAuditOutcome.SUCCEEDED,
    )

    assert event.user_id == event_facts.user_id
    assert event.target_user_id == target_user_id
    assert event.target_id == target_user_id
    assert (event.user_id == event.target_user_id) is same_user


def test_non_user_target_can_record_an_affected_user() -> None:
    """
        操作项目等其他对象时，仍可单独记录受影响的用户，不能替代目标对象 ID。

    :return: 无返回值；操作用户、目标项目与受影响用户分别保存。
    """
    event_facts = facts()
    affected_user_id = new_entity_id("U")
    event = writer().build_event(
        replace(event_facts, target_user_id=affected_user_id),
        outcome=BusinessAuditOutcome.SUCCEEDED,
    )

    assert event.user_id == event_facts.user_id
    assert event.target_type == "project"
    assert event.target_id == event_facts.target_id
    assert event.target_user_id == affected_user_id


@pytest.mark.parametrize(
    ("source_type", "source_id"),
    [
        (BusinessAuditSourceType.SYSTEM, None),
        (BusinessAuditSourceType.SERVICE, "billing-service"),
        (BusinessAuditSourceType.JOB, "nightly-reconcile"),
        (BusinessAuditSourceType.MAINTENANCE, "maintenance-console"),
    ],
)
def test_non_user_sources_do_not_impersonate_a_user(source_type: BusinessAuditSourceType,
                                                    source_id: str | None) -> None:
    """
        系统行为不编造操作用户；服务、任务和维护操作保存各自的来源标识。

    :param source_type: 当前自动化或维护操作的来源类别。
    :param source_id: 该来源自己的标识；纯系统操作没有标识。
    :return: 无返回值；来源标识与用户标识已分开保存。
    """
    source_spec = replace(SPEC, source_types=frozenset({source_type}))
    audit_writer = BusinessAuditService(SessionFactory, {ACTION: source_spec})
    event = audit_writer.build_event(
        replace(facts(), source_type=source_type, user_id=None, source_id=source_id),
        outcome=BusinessAuditOutcome.SUCCEEDED,
    )

    assert event.source_type == source_type.value
    assert event.user_id is None
    assert event.source_id == source_id


@pytest.mark.parametrize(
    ("source_type", "user_id", "source_id"),
    [
        (BusinessAuditSourceType.USER, None, None),
        (BusinessAuditSourceType.USER, new_entity_id("U"), "billing-service"),
        (BusinessAuditSourceType.SYSTEM, new_entity_id("U"), None),
        (BusinessAuditSourceType.SYSTEM, None, "system-name"),
        (BusinessAuditSourceType.SERVICE, None, None),
        (BusinessAuditSourceType.JOB, new_entity_id("U"), "nightly-reconcile"),
        (BusinessAuditSourceType.MAINTENANCE, None, "person@example.test"),
    ],
)
def test_source_rejects_missing_or_mixed_identity(source_type: BusinessAuditSourceType,
                                                  user_id: str | None,
                                                  source_id: str | None) -> None:
    """
        拒绝漏填操作用户，或把用户身份与服务、系统身份混在同一事件里。

    :param source_type: 需要核对身份字段的操作来源类别。
    :param user_id: 拟记录的操作用户 ID，非用户来源必须为空。
    :param source_id: 拟记录的非用户来源标识，用户和纯系统来源必须为空。
    :return: 无返回值；不符合来源身份配对规则的事件已被拒绝。
    """
    source_spec = replace(SPEC, source_types=frozenset({source_type}))
    with pytest.raises(ValueError):
        BusinessAuditService(SessionFactory, {ACTION: source_spec}).build_event(
            replace(facts(), source_type=source_type, user_id=user_id, source_id=source_id),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


@pytest.mark.parametrize("target_user_id", [None, new_entity_id("U")])
def test_user_target_requires_the_same_affected_user_id(target_user_id: str | None) -> None:
    """
        操作对象是用户时，目标对象 ID 必须与被操作用户 ID 完全相同。

    :param target_user_id: 缺失或与目标对象不同的被操作用户 ID。
    :return: 无返回值；不能确定被操作用户的事件已被拒绝。
    """
    user_spec = replace(SPEC, target_type="user")
    with pytest.raises(ValueError):
        BusinessAuditService(SessionFactory, {ACTION: user_spec}).build_event(
            replace(facts(), target_id=new_entity_id("U"), target_user_id=target_user_id),
            outcome=BusinessAuditOutcome.SUCCEEDED,
        )


def test_catalog_requires_frozen_sets_and_two_character_reason() -> None:
    with pytest.raises(TypeError, match="collections must be frozenset"):
        BusinessAuditActionSpec(
            domain="project",
            action=ACTION,
            target_type="project",
            allowed_outcomes={BusinessAuditOutcome.SUCCEEDED},  # type: ignore[arg-type]
            reason_codes=frozenset({"changed"}),
            source_types=frozenset({BusinessAuditSourceType.USER}),
        )
    with pytest.raises(ValueError, match="invalid audit reason"):
        BusinessAuditActionSpec(
            domain="project",
            action=ACTION,
            target_type="project",
            allowed_outcomes=frozenset({BusinessAuditOutcome.SUCCEEDED}),
            reason_codes=frozenset({"x"}),
            source_types=frozenset({BusinessAuditSourceType.USER}),
        )


async def test_string_success_cannot_use_after_rollback_writer() -> None:
    with pytest.raises(ValueError, match="must use the protected transaction"):
        await writer().write_after_rollback(
            facts(),
            outcome="succeeded",  # type: ignore[arg-type]
        )


async def test_denied_audit_failure_is_best_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    broken_factory = Mock(side_effect=RuntimeError("database-password"))
    log = Mock(return_value=False)
    monkeypatch.setattr(business_audit, "safe_log", log)
    audit_writer = BusinessAuditService(
        cast(async_sessionmaker[AsyncSession], broken_factory),
        {ACTION: SPEC},
    )

    written = await audit_writer.write_after_rollback(
        facts(after_state=None),
        outcome=BusinessAuditOutcome.DENIED,
    )

    assert written is False
    log.assert_called_once()
    assert log.call_args.kwargs["extra"] == {
        "audit_domain": "business",
        "exception_type": "RuntimeError",
    }
