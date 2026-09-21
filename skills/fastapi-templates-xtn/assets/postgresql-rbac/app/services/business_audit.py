"""Catalog-owned business audit events and transaction-aware writes."""

import logging
from collections.abc import Mapping

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit import AuditJsonValue, AuditSource, validate_audit_request_id
from app.core.business_audit import (
    MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
    BusinessAuditActionSpec,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    require_business_event_id,
    require_business_identifier,
    sanitize_business_payload,
)
from app.core.observability import safe_log
from app.models.business_audit import BusinessAuditEvent

logger = logging.getLogger(__name__)


class BusinessAuditWriter:
    """Build catalog-owned events; callers own successful transactions."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        action_specs: Mapping[str, BusinessAuditActionSpec],
    ) -> None:
        self._session_factory = session_factory
        self._action_specs = dict(action_specs)
        if not self._action_specs:
            raise ValueError("business audit action catalog cannot be empty")
        for action, spec in self._action_specs.items():
            if action != spec.action:
                raise ValueError("business audit catalog key must match its action")

    @staticmethod
    def _safe_payload(
        state: Mapping[str, object] | None,
        *,
        allowed_fields: frozenset[str],
        max_bytes: int,
    ) -> dict[str, AuditJsonValue] | None:
        if state is None:
            return None
        if set(state) - allowed_fields:
            raise ValueError("business audit payload contains a non-allowlisted field")
        return sanitize_business_payload(state, max_bytes=max_bytes)

    def build_event(
        self,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> BusinessAuditEvent:
        spec = self._action_specs.get(facts.action)
        if spec is None:
            raise ValueError("business audit action is not registered")
        outcome = BusinessAuditOutcome(outcome)
        if outcome not in spec.allowed_outcomes:
            raise ValueError("business audit outcome is not allowed for this action")
        if facts.reason_code not in spec.reason_codes:
            raise ValueError("business audit reason is not registered for this action")
        if facts.actor.actor_type not in spec.actor_types:
            raise ValueError("business audit actor type is not allowed for this action")
        if (
            outcome is not BusinessAuditOutcome.SUCCEEDED
            and facts.after_state is not None
        ):
            raise ValueError("denied and failed events cannot claim an after state")
        require_business_event_id(facts.event_id)
        require_business_identifier(facts.resource_id, field="resource ID")
        source = AuditSource(facts.source)
        request_id = validate_audit_request_id(facts.request_id)
        before_state = self._safe_payload(
            facts.before_state,
            allowed_fields=spec.before_fields,
            max_bytes=16 * 1024,
        )
        after_state = self._safe_payload(
            facts.after_state,
            allowed_fields=spec.after_fields,
            max_bytes=16 * 1024,
        )
        context = self._safe_payload(
            facts.context or {},
            allowed_fields=spec.context_fields,
            max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
        )
        assert context is not None
        return BusinessAuditEvent(
            id=facts.event_id,
            domain=spec.domain,
            action=spec.action,
            outcome=outcome.value,
            reason_code=facts.reason_code,
            actor_type=facts.actor.actor_type.value,
            actor_id=facts.actor.id,
            resource_type=spec.resource_type,
            resource_id=facts.resource_id,
            source=source.value,
            schema_version=spec.schema_version,
            before_state=before_state,
            after_state=after_state,
            context=context,
            request_id=request_id,
        )

    def add_succeeded(
        self,
        session: AsyncSession,
        facts: BusinessAuditFacts,
    ) -> BusinessAuditEvent:
        if not session.in_transaction():
            raise RuntimeError(
                "successful business audit requires a caller-owned transaction"
            )
        event = self.build_event(facts, outcome=BusinessAuditOutcome.SUCCEEDED)
        session.add(event)
        return event

    def add_after_savepoint_rollback(
        self,
        session: AsyncSession,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> BusinessAuditEvent:
        """Stage evidence after the caller has rolled back its nested attempt."""
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        if not session.in_transaction():
            raise RuntimeError("savepoint audit requires a caller-owned transaction")
        if session.in_nested_transaction():
            raise RuntimeError("savepoint audit requires the nested rollback to finish")
        event = self.build_event(facts, outcome=outcome)
        session.add(event)
        return event

    async def write_after_rollback(
        self,
        facts: BusinessAuditFacts,
        *,
        outcome: BusinessAuditOutcome,
    ) -> bool:
        """Best-effort catalog-required denial/failure evidence after rollback."""
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    session.add(self.build_event(facts, outcome=outcome))
            return True
        except Exception as exc:
            safe_log(
                logger,
                logging.ERROR,
                "audit.write.failed",
                extra={
                    "audit_domain": "business",
                    "exception_type": type(exc).__name__,
                },
            )
            return False
