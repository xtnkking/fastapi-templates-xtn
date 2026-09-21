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
    BusinessAuditActor,
    BusinessAuditActorType,
    BusinessAuditFacts,
    BusinessAuditOutcome,
)
from app.db.base import Base
from app.db.postgres import SessionFactory
from app.models.business_audit import BusinessAuditEvent
from app.services import business_audit
from app.services.business_audit import BusinessAuditWriter

ACTION = "project.settings.update"
SPEC = BusinessAuditActionSpec(
    domain="project",
    action=ACTION,
    resource_type="project",
    allowed_outcomes=frozenset(BusinessAuditOutcome),
    reason_codes=frozenset({"settings_updated", "policy_denied"}),
    actor_types=frozenset({BusinessAuditActorType.USER}),
    before_fields=frozenset({"enabled", "version"}),
    after_fields=frozenset(
        {"enabled", "version", "status_code", "contact", "metadata"}
    ),
    context_fields=frozenset({"channel"}),
)


def writer() -> BusinessAuditWriter:
    return BusinessAuditWriter(SessionFactory, {ACTION: SPEC})


def facts(
    *,
    before_state: dict[str, object] | None = None,
    after_state: dict[str, object] | None = None,
) -> BusinessAuditFacts:
    return BusinessAuditFacts(
        event_id=uuid.uuid4(),
        action=ACTION,
        actor=BusinessAuditActor(
            actor_type=BusinessAuditActorType.USER,
            id=str(uuid.uuid4()),
        ),
        resource_id=str(uuid.uuid4()),
        reason_code="settings_updated",
        source=AuditSource.HTTP,
        request_id=str(uuid.uuid4()),
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
    assert event.resource_type == "project"
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
def test_writer_rejects_non_allowlisted_or_sensitive_snapshots(
    after_state: dict[str, object],
) -> None:
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
def test_writer_rejects_nested_email_and_network_values(
    after_state: dict[str, object],
    message: str,
) -> None:
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


def test_actor_and_catalog_reject_untrusted_labels() -> None:
    with pytest.raises(ValueError, match="invalid business audit actor ID"):
        BusinessAuditActor(
            actor_type=BusinessAuditActorType.USER,
            id="person@example.test",
        )
    with pytest.raises(ValueError, match="invalid business audit action"):
        BusinessAuditActionSpec(
            domain="project",
            action="Project Changed",
            resource_type="project",
            allowed_outcomes=frozenset({BusinessAuditOutcome.SUCCEEDED}),
            reason_codes=frozenset({"changed"}),
            actor_types=frozenset({BusinessAuditActorType.USER}),
        )


@pytest.mark.parametrize(
    "event_facts",
    [
        replace(facts(), before_state={"not_allowlisted": True}),
        replace(facts(), context={"not_allowlisted": True}),
    ],
)
def test_each_payload_section_enforces_its_own_top_level_allowlist(
    event_facts: BusinessAuditFacts,
) -> None:
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


def test_system_actor_has_no_presentation_identifier() -> None:
    actor = BusinessAuditActor(actor_type=BusinessAuditActorType.SYSTEM, id=None)
    assert actor.id is None
    with pytest.raises(ValueError, match="must not have an ID"):
        BusinessAuditActor(
            actor_type=BusinessAuditActorType.SYSTEM,
            id="system-name",
        )


def test_catalog_requires_frozen_sets_and_two_character_reason() -> None:
    with pytest.raises(TypeError, match="collections must be frozenset"):
        BusinessAuditActionSpec(
            domain="project",
            action=ACTION,
            resource_type="project",
            allowed_outcomes={BusinessAuditOutcome.SUCCEEDED},  # type: ignore[arg-type]
            reason_codes=frozenset({"changed"}),
            actor_types=frozenset({BusinessAuditActorType.USER}),
        )
    with pytest.raises(ValueError, match="invalid audit reason"):
        BusinessAuditActionSpec(
            domain="project",
            action=ACTION,
            resource_type="project",
            allowed_outcomes=frozenset({BusinessAuditOutcome.SUCCEEDED}),
            reason_codes=frozenset({"x"}),
            actor_types=frozenset({BusinessAuditActorType.USER}),
        )


async def test_string_success_cannot_use_after_rollback_writer() -> None:
    with pytest.raises(ValueError, match="must use the protected transaction"):
        await writer().write_after_rollback(
            facts(),
            outcome="succeeded",  # type: ignore[arg-type]
        )


async def test_denied_audit_failure_is_best_effort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_factory = Mock(side_effect=RuntimeError("database-password"))
    log = Mock(return_value=False)
    monkeypatch.setattr(business_audit, "safe_log", log)
    audit_writer = BusinessAuditWriter(
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
