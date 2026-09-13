import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit import AuditSource
from app.business_audit import (
    BusinessAuditActionSpec,
    BusinessAuditActor,
    BusinessAuditActorType,
    BusinessAuditEvent,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    BusinessAuditWriter,
)
from app.database import SessionFactory, engine
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql

ACTION = "subscription.lifecycle.update"
SPEC = BusinessAuditActionSpec(
    domain="subscription",
    action=ACTION,
    resource_type="subscription",
    allowed_outcomes=frozenset(BusinessAuditOutcome),
    reason_codes=frozenset(
        {"subscription_paused", "policy_denied", "domain_failed", "no_change"}
    ),
    actor_types=frozenset({BusinessAuditActorType.USER}),
    before_fields=frozenset({"status"}),
    after_fields=frozenset({"status"}),
    context_fields=frozenset({"policy_code"}),
)

TEMP_BUSINESS_RESOURCE_TABLE = "test_business_resources"

RAW_BUSINESS_AUDIT_INSERT = text(
    """
    INSERT INTO business_audit_events (
        id, domain, action, outcome, reason_code, actor_type, actor_id,
        resource_type, resource_id, source, schema_version, before_state,
        after_state, context, request_id
    ) VALUES (
        CAST(:id AS uuid), :domain, :action, :outcome, :reason_code,
        :actor_type, :actor_id, :resource_type, :resource_id, :source,
        :schema_version, CAST(:before_state AS jsonb),
        CAST(:after_state AS jsonb), CAST(:context AS jsonb), :request_id
    )
    """
)


@dataclass(frozen=True, slots=True)
class BusinessResourceStore:
    sessions: async_sessionmaker[AsyncSession]
    resource_id: uuid.UUID


@pytest_asyncio.fixture
async def business_resource_store() -> AsyncIterator[BusinessResourceStore]:
    resource_id = uuid.uuid4()
    async with engine.connect() as connection:
        await connection.execute(
            text(f"DROP TABLE IF EXISTS pg_temp.{TEMP_BUSINESS_RESOURCE_TABLE}")
        )
        await connection.execute(
            text(
                f"""
                CREATE TEMPORARY TABLE {TEMP_BUSINESS_RESOURCE_TABLE} (
                    id uuid PRIMARY KEY,
                    status text NOT NULL,
                    CONSTRAINT ck_test_business_resource_status
                        CHECK (status IN ('active', 'paused'))
                ) ON COMMIT PRESERVE ROWS
                """
            )
        )
        await connection.execute(
            text(
                f"INSERT INTO {TEMP_BUSINESS_RESOURCE_TABLE} (id, status) "
                "VALUES (CAST(:resource_id AS uuid), 'active')"
            ),
            {"resource_id": str(resource_id)},
        )
        await connection.commit()
        sessions = async_sessionmaker(connection, expire_on_commit=False)
        try:
            yield BusinessResourceStore(
                sessions=sessions,
                resource_id=resource_id,
            )
        finally:
            if connection.in_transaction():
                await connection.rollback()
            await connection.execute(
                text(f"DROP TABLE IF EXISTS pg_temp.{TEMP_BUSINESS_RESOURCE_TABLE}")
            )
            await connection.commit()


def writer(
    session_factory: async_sessionmaker[AsyncSession],
) -> BusinessAuditWriter:
    return BusinessAuditWriter(session_factory, {ACTION: SPEC})


async def business_resource_status(store: BusinessResourceStore) -> str:
    async with store.sessions() as session:
        status = await session.scalar(
            text(
                f"SELECT status FROM {TEMP_BUSINESS_RESOURCE_TABLE} "
                "WHERE id = CAST(:resource_id AS uuid)"
            ),
            {"resource_id": str(store.resource_id)},
        )
    assert isinstance(status, str)
    return status


async def pause_business_resource(
    session: AsyncSession,
    store: BusinessResourceStore,
) -> None:
    await session.execute(
        text(
            f"UPDATE {TEMP_BUSINESS_RESOURCE_TABLE} SET status = 'paused' "
            "WHERE id = CAST(:resource_id AS uuid)"
        ),
        {"resource_id": str(store.resource_id)},
    )


def raw_event_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "domain": "subscription",
        "action": ACTION,
        "outcome": "succeeded",
        "reason_code": "subscription_paused",
        "actor_type": "user",
        "actor_id": str(uuid.uuid4()),
        "resource_type": "subscription",
        "resource_id": str(uuid.uuid4()),
        "source": "http",
        "schema_version": 1,
        "before_state": None,
        "after_state": None,
        "context": "{}",
        "request_id": str(uuid.uuid4()),
    }
    params.update(overrides)
    return params


def facts(
    world: World,
    resource_id: uuid.UUID,
    *,
    request_id: str,
    before_state: dict[str, object] | None,
    after_state: dict[str, object] | None,
    reason_code: str,
) -> BusinessAuditFacts:
    return BusinessAuditFacts(
        event_id=uuid.uuid4(),
        action=ACTION,
        actor=BusinessAuditActor(
            actor_type=BusinessAuditActorType.USER,
            id=str(world.users["super_admin"].id),
        ),
        resource_id=str(resource_id),
        reason_code=reason_code,
        source=AuditSource.HTTP,
        request_id=request_id,
        before_state=before_state,
        after_state=after_state,
        context={"policy_code": "subscription_lifecycle"},
    )


async def test_successful_business_mutation_and_audit_commit_together(
    world: World,
    business_resource_store: BusinessResourceStore,
) -> None:
    request_id = str(uuid.uuid4())
    audit_writer = writer(business_resource_store.sessions)
    async with business_resource_store.sessions() as session:
        async with session.begin():
            await pause_business_resource(session, business_resource_store)
            event = audit_writer.add_succeeded(
                session,
                facts(
                    world,
                    business_resource_store.resource_id,
                    request_id=request_id,
                    before_state={"status": "active"},
                    after_state={"status": "paused"},
                    reason_code="subscription_paused",
                ),
            )

    async with business_resource_store.sessions() as session:
        persisted = await session.scalar(
            select(BusinessAuditEvent).where(
                BusinessAuditEvent.request_id == request_id
            )
        )

    assert await business_resource_status(business_resource_store) == "paused"
    assert persisted is not None
    assert persisted.id == event.id
    assert persisted.id.version == 4
    assert persisted.created_at.tzinfo is not None
    assert persisted.domain == "subscription"
    assert persisted.actor_type == "user"
    assert persisted.actor_id == str(world.users["super_admin"].id)
    assert persisted.action == ACTION
    assert persisted.resource_type == "subscription"
    assert persisted.resource_id == str(business_resource_store.resource_id)
    assert persisted.outcome == "succeeded"
    assert persisted.reason_code == "subscription_paused"
    assert persisted.source == "http"
    assert persisted.schema_version == 1
    assert persisted.context == {"policy_code": "subscription_lifecycle"}
    assert persisted.request_id == request_id


async def test_unsafe_required_audit_rolls_back_business_mutation(
    world: World,
    business_resource_store: BusinessResourceStore,
) -> None:
    request_id = str(uuid.uuid4())
    with pytest.raises(ValueError, match="non-allowlisted"):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await pause_business_resource(session, business_resource_store)
                writer(business_resource_store.sessions).add_succeeded(
                    session,
                    facts(
                        world,
                        business_resource_store.resource_id,
                        request_id=request_id,
                        before_state={"status": "active"},
                        after_state={"password": "must-never-persist"},
                        reason_code="subscription_paused",
                    ),
                )

    async with business_resource_store.sessions() as session:
        persisted = await session.scalar(
            select(BusinessAuditEvent).where(
                BusinessAuditEvent.request_id == request_id
            )
        )

    assert await business_resource_status(business_resource_store) == "active"
    assert persisted is None


@pytest.mark.parametrize(
    ("outcome", "reason_code"),
    [
        (BusinessAuditOutcome.DENIED, "policy_denied"),
        (BusinessAuditOutcome.FAILED, "domain_failed"),
    ],
)
async def test_non_success_is_written_only_after_business_rollback(
    world: World,
    business_resource_store: BusinessResourceStore,
    outcome: BusinessAuditOutcome,
    reason_code: str,
) -> None:
    class BusinessDidNotCommit(Exception):
        pass

    request_id = str(uuid.uuid4())
    with pytest.raises(BusinessDidNotCommit):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await pause_business_resource(session, business_resource_store)
                raise BusinessDidNotCommit

    written = await writer(business_resource_store.sessions).write_after_rollback(
        facts(
            world,
            business_resource_store.resource_id,
            request_id=request_id,
            before_state={"status": "active"},
            after_state=None,
            reason_code=reason_code,
        ),
        outcome=outcome,
    )

    async with business_resource_store.sessions() as session:
        persisted = await session.scalar(
            select(BusinessAuditEvent).where(
                BusinessAuditEvent.request_id == request_id
            )
        )

    assert written is True
    assert await business_resource_status(business_resource_store) == "active"
    assert persisted is not None
    assert persisted.outcome == outcome.value
    assert persisted.after_state is None


async def test_required_denial_commits_after_nested_savepoint_rollback(
    world: World,
    business_resource_store: BusinessResourceStore,
) -> None:
    class PolicyDenied(Exception):
        pass

    request_id = str(uuid.uuid4())
    audit_writer = writer(business_resource_store.sessions)

    async with business_resource_store.sessions() as session:
        async with session.begin():
            with pytest.raises(PolicyDenied):
                async with session.begin_nested():
                    await pause_business_resource(session, business_resource_store)
                    raise PolicyDenied
            audit_writer.add_after_savepoint_rollback(
                session,
                facts(
                    world,
                    business_resource_store.resource_id,
                    request_id=request_id,
                    before_state={"status": "active"},
                    after_state=None,
                    reason_code="policy_denied",
                ),
                outcome=BusinessAuditOutcome.DENIED,
            )

    async with business_resource_store.sessions() as session:
        persisted = await session.scalar(
            select(BusinessAuditEvent).where(
                BusinessAuditEvent.request_id == request_id
            )
        )

    assert await business_resource_status(business_resource_store) == "active"
    assert persisted is not None
    assert persisted.outcome == BusinessAuditOutcome.DENIED.value
    assert persisted.after_state is None


async def test_business_audit_rows_are_append_only(
    world: World,
    business_resource_store: BusinessResourceStore,
) -> None:
    request_id = str(uuid.uuid4())
    async with business_resource_store.sessions() as session:
        async with session.begin():
            event = writer(business_resource_store.sessions).add_succeeded(
                session,
                facts(
                    world,
                    business_resource_store.resource_id,
                    request_id=request_id,
                    before_state={"status": "active"},
                    after_state={"status": "active"},
                    reason_code="no_change",
                ),
            )

    with pytest.raises(DBAPIError):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE business_audit_events "
                        "SET reason_code = 'rewritten' WHERE id = :event_id"
                    ),
                    {"event_id": event.id},
                )

    with pytest.raises(DBAPIError):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await session.execute(
                    text("DELETE FROM business_audit_events WHERE id = :event_id"),
                    {"event_id": event.id},
                )

    with pytest.raises(DBAPIError):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await session.execute(text("TRUNCATE TABLE business_audit_events"))

    async with business_resource_store.sessions() as session:
        persisted = await session.get(BusinessAuditEvent, event.id)
    assert persisted is not None


@pytest.mark.parametrize(
    ("overrides", "constraint_name"),
    [
        (
            {"action": "payment.refund.approve"},
            "ck_business_audit_action_domain",
        ),
        ({"outcome": "unknown"}, "ck_business_audit_outcome"),
        (
            {"actor_type": "system", "actor_id": "system-1"},
            "ck_business_audit_actor_presence",
        ),
        (
            {"actor_type": "user", "actor_id": None},
            "ck_business_audit_actor_presence",
        ),
        (
            {"outcome": "failed", "after_state": '{"status": "changed"}'},
            "ck_business_audit_non_success_after",
        ),
        ({"context": "[]"}, "ck_business_audit_context_object"),
        (
            {
                "context": json.dumps(
                    {"policy_code": "x" * 4090},
                    ensure_ascii=False,
                    sort_keys=True,
                )
            },
            "ck_business_audit_context_size",
        ),
        ({"reason_code": "x"}, "ck_business_audit_reason_format"),
        ({"id": str(uuid.uuid1())}, "ck_business_audit_id_uuid4"),
    ],
)
async def test_database_rejects_invalid_raw_business_audit_events(
    overrides: dict[str, object],
    constraint_name: str,
) -> None:
    with pytest.raises(DBAPIError) as exc_info:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    RAW_BUSINESS_AUDIT_INSERT,
                    raw_event_params(**overrides),
                )

    assert constraint_name in str(exc_info.value)


async def test_database_accepts_raw_system_business_audit_event() -> None:
    event_id = uuid.uuid4()
    params = raw_event_params(
        id=str(event_id),
        actor_type="system",
        actor_id=None,
    )

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(RAW_BUSINESS_AUDIT_INSERT, params)

    async with SessionFactory() as session:
        event = await session.get(BusinessAuditEvent, event_id)

    assert event is not None
    assert event.actor_type == "system"
    assert event.actor_id is None
