"""Prove authorization releases its connection before writes and denied audits."""

from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.db.postgres import get_session
from app.dependencies import authentication
from app.main import app
from app.models.access import RbacAuditEvent, Role, User
from app.services.access import RbacService, get_rbac_service
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


@pytest.mark.parametrize(
    ("actor", "status_code", "decision"),
    [("super_admin", 201, "allowed"), ("blank", 403, "denied")],
)
async def test_management_request_and_audit_complete_with_one_pool_connection(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
    monkeypatch: pytest.MonkeyPatch,
    actor: str,
    status_code: int,
    decision: str,
) -> None:
    # Integration fixtures verify this database is disposable before this runs.
    engine = create_async_engine(
        get_settings().database_url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.1,
        isolation_level="READ COMMITTED",
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = RbacService(factory)

    async def request_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session

    # Both a legacy request-scoped dependency and the short authorization read
    # must use this same pool, so retaining either connection breaks the test.
    token = await access_token(world.users[actor])
    app.dependency_overrides[get_session] = request_session
    app.dependency_overrides[get_rbac_service] = lambda: service
    monkeypatch.setattr(authentication, "SessionFactory", factory)
    try:
        response = await client.post(
            "/api/v1/roles",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "key": "single-connection-role",
                "name": "Single connection role",
                "description": "Pool lifetime regression",
                "management_tier": 10,
            },
        )
        assert response.status_code == status_code, response.text
        async with factory() as session:
            role = await session.scalar(
                select(Role).where(Role.key == "single-connection-role")
            )
            audit = await session.scalar(
                select(RbacAuditEvent).where(
                    RbacAuditEvent.request_id == response.json()["request_id"]
                )
            )
            assert (role is not None) == (decision == "allowed")
            assert audit is not None
            assert audit.decision == decision
            assert audit.actor_user_id == world.users[actor].id
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_rbac_service, None)
        await engine.dispose()
