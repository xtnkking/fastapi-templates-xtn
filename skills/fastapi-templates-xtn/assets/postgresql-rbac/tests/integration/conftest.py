import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import cast

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from alembic import command
from app.core.config import get_settings
from app.core.security.domain import (
    PermissionKey,
    SystemRoleKey,
)
from app.core.security.tokens import issue_access_token
from app.db.postgres import SessionFactory, engine
from app.main import app
from app.models.access import Permission, Role, RolePermission, User, UserRole
from tests.integration.safety import (
    require_actual_database,
    verify_empty_redis_targets,
    verify_fresh_postgresql_target,
)
from tests.migration_helpers import alembic_config

pytestmark = pytest.mark.postgresql


@dataclass(slots=True)
class World:
    users: dict[str, User]
    roles: dict[str, Role]
    permissions: dict[str, Permission]


@pytest.fixture(scope="session", autouse=True)
def verified_redis_targets() -> None:
    settings = get_settings()
    assert settings.redis_url is not None  # This fixture owns standalone test targets.
    verify_empty_redis_targets(
        settings.redis_url,
        settings.effective_rate_limit_redis_url,
    )


@pytest.fixture(scope="session", autouse=True)
def migrated_database(verified_redis_targets: None) -> None:
    asyncio.run(verify_fresh_postgresql_target(get_settings().database_url))
    command.upgrade(alembic_config(), "head")


@pytest_asyncio.fixture(autouse=True)
async def clean_database(migrated_database: None) -> AsyncIterator[None]:
    settings = get_settings()
    assert settings.redis_url is not None
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        async with engine.begin() as connection:
            database_name = await connection.scalar(text("SELECT current_database()"))
            require_actual_database(database_name)
            # Only the database owner used by this disposable test profile may
            # bypass the production append-only control during fixture cleanup.
            await connection.execute(
                text(
                    "ALTER TABLE business_audit_events DISABLE TRIGGER "
                    "trg_business_audit_no_truncate"
                )
            )
            await connection.execute(text("TRUNCATE TABLE business_audit_events"))
            await connection.execute(
                text(
                    "ALTER TABLE business_audit_events ENABLE TRIGGER "
                    "trg_business_audit_no_truncate"
                )
            )
            await connection.execute(
                text(
                    "ALTER TABLE account_security_audit_events DISABLE TRIGGER "
                    "trg_account_security_audit_no_truncate"
                )
            )
            await connection.execute(
                text("TRUNCATE TABLE account_security_audit_events")
            )
            await connection.execute(
                text(
                    "ALTER TABLE account_security_audit_events ENABLE TRIGGER "
                    "trg_account_security_audit_no_truncate"
                )
            )
            await connection.execute(
                text(
                    "ALTER TABLE rbac_audit_events DISABLE TRIGGER "
                    "trg_rbac_audit_events_no_truncate"
                )
            )
            await connection.execute(text("TRUNCATE TABLE rbac_audit_events"))
            await connection.execute(
                text(
                    "ALTER TABLE rbac_audit_events ENABLE TRIGGER "
                    "trg_rbac_audit_events_no_truncate"
                )
            )
            # Test isolation intentionally resets the pre-bootstrap state without
            # exercising the deferred production invariant.
            await connection.execute(text("TRUNCATE TABLE user_roles"))
            await connection.execute(
                text(
                    "DELETE FROM role_permissions USING roles "
                    "WHERE role_permissions.role_id = roles.id "
                    "AND NOT roles.is_system"
                )
            )
            await connection.execute(text("DELETE FROM roles WHERE NOT is_system"))
            await connection.execute(
                delete(Permission).where(
                    Permission.key.not_in(tuple(item.value for item in PermissionKey))
                )
            )
            await connection.execute(text("DELETE FROM users"))
            await connection.execute(
                text(
                    "UPDATE rbac_state SET epoch = 0, "
                    "public_registration_enabled = true WHERE scope = 'global'"
                )
            )
        keys = [
            key
            async for key in redis.scan_iter(
                match=f"auth:sessions:v2:{settings.app_environment}:*"
            )
        ]
        for key in keys:
            await redis.delete(key)
        yield
    finally:
        await redis.aclose()
        await engine.dispose()


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as test_client:
            yield test_client


@pytest.fixture
def access_token() -> Callable[[User], Awaitable[str]]:
    settings = get_settings()

    async def make_token(user: User) -> str:
        return await issue_access_token(
            cast(Redis, app.state.redis),
            user_id=user.id,
            user_token_version=user.token_version,
            settings=settings,
        )

    return make_token


@pytest_asyncio.fixture
async def world() -> World:
    async with SessionFactory() as session:
        async with session.begin():
            permissions = {
                permission.key: permission
                for permission in (await session.scalars(select(Permission))).all()
            }
            assert permissions, "Alembic permission seed did not run"
            system_roles = {
                role.key: role
                for role in (
                    await session.scalars(select(Role).where(Role.is_system.is_(True)))
                ).all()
            }
            assert set(system_roles) == {item.value for item in SystemRoleKey}

            users = {
                name: User(
                    user_name="platform_owner" if name == "super_admin" else name
                )
                for name in (
                    "super_admin",
                    "manager",
                    "peer",
                    "junior",
                    "higher",
                    "lower",
                    "blank",
                    "hidden_higher",
                    "newcomer",
                    "disabled",
                )
            }
            users["disabled"].is_active = False
            session.add_all(users.values())
            await session.flush()

            roles = {
                "super_admin": system_roles[SystemRoleKey.SUPER_ADMIN.value],
                "admin": system_roles[SystemRoleKey.ADMIN.value],
                "user": system_roles[SystemRoleKey.USER.value],
                "junior_admin": Role(
                    key="junior-admin",
                    name="Junior admin",
                    management_tier=100,
                ),
                "higher": Role(
                    key="higher",
                    name="Higher",
                    management_tier=700,
                ),
                "viewer": Role(
                    key="viewer",
                    name="Viewer",
                    management_tier=20,
                ),
                "auditor": Role(
                    key="auditor",
                    name="Auditor",
                    management_tier=30,
                ),
            }
            roles["manager"] = roles["admin"]
            session.add_all(
                role
                for key, role in roles.items()
                if key not in {"super_admin", "admin", "user", "manager"}
            )
            await session.flush()

            def grant(
                role_name: str,
                keys: set[str],
            ) -> list[RolePermission]:
                role = roles[role_name]
                return [
                    RolePermission(
                        role_id=role.id,
                        permission_id=permissions[key].id,
                    )
                    for key in keys
                ]

            session.add_all(
                grant(
                    "junior_admin",
                    {
                        PermissionKey.ROLES_ASSIGN.value,
                        PermissionKey.ROLES_REVOKE.value,
                        PermissionKey.PROJECTS_READ.value,
                    },
                )
                + grant("higher", {PermissionKey.PROJECTS_READ.value})
                + grant("viewer", {PermissionKey.PROJECTS_READ.value})
                + grant("auditor", {PermissionKey.USERS_READ.value})
            )

            assignments = tuple((user_name, "user") for user_name in users) + (
                ("super_admin", "super_admin"),
                ("manager", "admin"),
                ("peer", "admin"),
                ("junior", "junior_admin"),
                ("higher", "higher"),
                ("lower", "viewer"),
                ("hidden_higher", "viewer"),
                ("hidden_higher", "higher"),
            )
            session.add_all(
                UserRole(
                    user_id=users[user_name].id,
                    role_id=roles[role_name].id,
                    assigned_by_user_id=None,
                )
                for user_name, role_name in assignments
            )
        return World(users=users, roles=roles, permissions=permissions)
