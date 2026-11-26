#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证认证查询在业务写入和拒绝审计之前释放数据库连接。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/19    XTN       V1.000        直接替换角色路由共享业务服务，保留单连接事务验证
# --------------------------------------------------------------------------------------------------

from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.api.v1.endpoints.roles as role_api_module
import app.dependencies.auth as auth_dependencies
from app.core.config import get_settings
from app.db.postgres_db import get_postgres_session
from app.main import app
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.role import Role
from app.models.postgres.user import User
from app.services.role_service import RoleService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


@pytest.mark.parametrize(
    ("current_user", "status_code", "decision"),
    [("super_admin", 201, "allowed"), ("blank", 403, "denied")],
)
async def test_management_request_and_audit_complete_with_one_pool_connection(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
    monkeypatch: pytest.MonkeyPatch,
    current_user: str,
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
    service = RoleService(factory)

    async def request_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session

    # Both a legacy request-scoped dependency and the short authorization read
    # must use this same pool, so retaining either connection breaks the test.
    token = await access_token(world.users[current_user])
    app.dependency_overrides[get_postgres_session] = request_session
    monkeypatch.setattr(role_api_module, "role_service", service)
    monkeypatch.setattr(auth_dependencies, "SessionFactory", factory)
    try:
        response = await client.post(
            '/api/v1/roles/create',
            headers={"Authorization": f"Bearer {token}"},
            json={
                "key": "single-connection-role",
                "name": "Single connection role",
                "description": "Pool lifetime regression",
                "level": 10,
            },
        )
        assert response.status_code == status_code, response.text
        async with factory() as session:
            role = await session.scalar(
                select(Role).where(Role.key == "single-connection-role")
            )
            audit = await session.scalar(
                select(OperationAuditEvent).where(
                    OperationAuditEvent.request_id == response.json()["request_id"]
                )
            )
            assert (role is not None) == (decision == "allowed")
            assert audit is not None
            assert audit.outcome == ("succeeded" if decision == "allowed" else "denied")
            assert audit.user_id == world.users[current_user].user_id
    finally:
        app.dependency_overrides.pop(get_postgres_session, None)
        await engine.dispose()
