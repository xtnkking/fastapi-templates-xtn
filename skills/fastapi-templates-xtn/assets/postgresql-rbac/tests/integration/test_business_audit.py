#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在使用者准备的数据库中检查业务审计持久化与约束。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/10    XTN       V1.000        对齐审计 operator 字段与约束并补充文件职责记录
# 2026/10/10    XTN       V1.001        区分操作用户、被操作用户及非用户来源并对齐业务审计 ID
# 2026/10/16    XTN       V1.002        持久化用例显式绑定审计请求上下文
# --------------------------------------------------------------------------------------------------

import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit import AuditSource
from app.core.business_audit import (
    BusinessAuditActionSpec,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    BusinessAuditSourceType,
)
from app.core.ids import new_audit_id, new_entity_id
from app.db.postgres_db import SessionFactory, engine
from app.models.postgres.business_audit import BusinessAuditEvent
from app.services.business_audit_service import BusinessAuditService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql

ACTION = "subscription.lifecycle.update"
SPEC = BusinessAuditActionSpec(
    domain="subscription",
    action=ACTION,
    target_type="subscription",
    allowed_outcomes=frozenset(BusinessAuditOutcome),
    reason_codes=frozenset(
        {"subscription_paused", "policy_denied", "domain_failed", "no_change"}
    ),
    source_types=frozenset({BusinessAuditSourceType.USER}),
    before_fields=frozenset({"status"}),
    after_fields=frozenset({"status"}),
    context_fields=frozenset({"policy_code"}),
)

TEMP_BUSINESS_RESOURCE_TABLE = "test_business_resources"

RAW_BUSINESS_AUDIT_INSERT = text(
    """
    INSERT INTO business_audit_events (
        id, domain, action, outcome, reason_code, source_type, user_id, source_id,
        target_type, target_id, target_user_id, entrypoint, schema_version, before_state,
        after_state, context, request_id
    ) VALUES (
        :id, :domain, :action, :outcome, :reason_code,
        :source_type, :user_id, :source_id, :target_type, :target_id, :target_user_id, :entrypoint,
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


def writer(session_factory: async_sessionmaker[AsyncSession]) -> BusinessAuditService:
    return BusinessAuditService(session_factory, {ACTION: SPEC})


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


async def pause_business_resource(session: AsyncSession, store: BusinessResourceStore) -> None:
    await session.execute(
        text(
            f"UPDATE {TEMP_BUSINESS_RESOURCE_TABLE} SET status = 'paused' "
            "WHERE id = CAST(:resource_id AS uuid)"
        ),
        {"resource_id": str(store.resource_id)},
    )


def raw_event_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "id": new_audit_id("BA"),
        "domain": "subscription",
        "action": ACTION,
        "outcome": "succeeded",
        "reason_code": "subscription_paused",
        "source_type": "user",
        "user_id": new_entity_id("U"),
        "source_id": None,
        "target_type": "subscription",
        "target_id": str(uuid.uuid4()),
        "target_user_id": None,
        "entrypoint": "http",
        "schema_version": 1,
        "before_state": None,
        "after_state": None,
        "context": "{}",
        "request_id": str(uuid.uuid4()),
    }
    params.update(overrides)
    return params


def facts(world: World, resource_id: uuid.UUID, *, before_state: dict[str, object] | None,
          after_state: dict[str, object] | None, reason_code: str) -> BusinessAuditFacts:
    return BusinessAuditFacts(
        event_id=new_audit_id("BA"),
        action=ACTION,
        source_type=BusinessAuditSourceType.USER,
        user_id=world.users["super_admin"].user_id,
        target_id=str(resource_id),
        reason_code=reason_code,
        entrypoint=AuditSource.HTTP,
        before_state=before_state,
        after_state=after_state,
        context={"policy_code": "subscription_lifecycle"},
    )


async def test_successful_business_mutation_and_audit_commit_together(
    world: World,
    business_resource_store: BusinessResourceStore,
    audit_request_context: str,
) -> None:
    request_id = audit_request_context
    audit_writer = writer(business_resource_store.sessions)
    async with business_resource_store.sessions() as session:
        async with session.begin():
            await pause_business_resource(session, business_resource_store)
            event = audit_writer.add_succeeded(
                session,
                facts(
                    world,
                    business_resource_store.resource_id,
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
    assert persisted.id.startswith("BA")
    assert len(persisted.id) == 22
    assert persisted.created_at.tzinfo is not None
    assert persisted.domain == "subscription"
    assert persisted.source_type == "user"
    assert persisted.user_id == world.users["super_admin"].user_id
    assert persisted.source_id is None
    assert persisted.action == ACTION
    assert persisted.target_type == "subscription"
    assert persisted.target_id == str(business_resource_store.resource_id)
    assert persisted.target_user_id is None
    assert persisted.outcome == "succeeded"
    assert persisted.reason_code == "subscription_paused"
    assert persisted.entrypoint == "http"
    assert persisted.schema_version == 1
    assert persisted.context == {"policy_code": "subscription_lifecycle"}
    assert persisted.request_id == request_id


async def test_unsafe_required_audit_rolls_back_business_mutation(
    world: World,
    business_resource_store: BusinessResourceStore,
    audit_request_context: str,
) -> None:
    request_id = audit_request_context
    with pytest.raises(ValueError, match="non-allowlisted"):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await pause_business_resource(session, business_resource_store)
                writer(business_resource_store.sessions).add_succeeded(
                    session,
                    facts(
                        world,
                        business_resource_store.resource_id,
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
    audit_request_context: str,
) -> None:
    class BusinessDidNotCommit(Exception):
        pass

    request_id = audit_request_context
    with pytest.raises(BusinessDidNotCommit):
        async with business_resource_store.sessions() as session:
            async with session.begin():
                await pause_business_resource(session, business_resource_store)
                raise BusinessDidNotCommit

    written = await writer(business_resource_store.sessions).write_after_rollback(
        facts(
            world,
            business_resource_store.resource_id,
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
    audit_request_context: str,
) -> None:
    class PolicyDenied(Exception):
        pass

    request_id = audit_request_context
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


@pytest.mark.usefixtures("audit_request_context")
async def test_business_audit_rows_are_append_only(world: World,
                                                   business_resource_store: BusinessResourceStore) -> None:
    async with business_resource_store.sessions() as session:
        async with session.begin():
            event = writer(business_resource_store.sessions).add_succeeded(
                session,
                facts(
                    world,
                    business_resource_store.resource_id,
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
            {"source_type": "system", "user_id": None, "source_id": "system-1"},
            "ck_business_audit_source_identity",
        ),
        (
            {"source_type": "user", "user_id": None},
            "ck_business_audit_source_identity",
        ),
        (
            {"user_id": "invalid-user-id"},
            "ck_business_audit_user_id_format",
        ),
        (
            {"source_type": "service", "user_id": None, "source_id": "person@example.test"},
            "ck_business_audit_source_id_format",
        ),
        (
            {"target_user_id": "invalid-user-id"},
            "ck_business_audit_target_user_id_format",
        ),
        (
            {"target_type": "user", "target_id": new_entity_id("U"), "target_user_id": None},
            "ck_business_audit_user_target",
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
        ({"id": str(uuid.uuid1())}, "ck_business_audit_id_format"),
    ],
)
async def test_database_rejects_invalid_raw_business_audit_events(overrides: dict[str, object],
                                                                  constraint_name: str) -> None:
    with pytest.raises(DBAPIError) as exc_info:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    RAW_BUSINESS_AUDIT_INSERT,
                    raw_event_params(**overrides),
                )

    assert constraint_name in str(exc_info.value)


async def test_database_accepts_raw_system_business_audit_event() -> None:
    event_id = new_audit_id("BA")
    params = raw_event_params(
        id=str(event_id),
        source_type="system",
        user_id=None,
        source_id=None,
    )

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(RAW_BUSINESS_AUDIT_INSERT, params)

    async with SessionFactory() as session:
        event = await session.get(BusinessAuditEvent, event_id)

    assert event is not None
    assert event.source_type == "system"
    assert event.user_id is None
    assert event.source_id is None
