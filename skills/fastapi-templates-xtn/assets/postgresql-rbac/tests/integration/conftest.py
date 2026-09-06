import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
import pytest_asyncio
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from alembic import command
from app.database import SessionFactory, engine
from app.main import app
from app.rbac.domain import (
    OWNER_DELEGABLE_PERMISSION_KEYS,
    OWNER_PERMISSION_KEYS,
    PermissionKey,
)
from app.rbac.models import Permission, Role, RolePermission, User, UserRole
from app.settings import get_settings

pytestmark = pytest.mark.postgresql


@dataclass(slots=True)
class World:
    users: dict[str, User]
    roles: dict[str, Role]
    permissions: dict[str, Permission]


@pytest.fixture(scope="session", autouse=True)
def migrated_database() -> None:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(config, "head")


@pytest_asyncio.fixture(autouse=True)
async def clean_database(migrated_database: None) -> AsyncIterator[None]:
    try:
        async with engine.begin() as connection:
            database_name = await connection.scalar(text("SELECT current_database()"))
            if not isinstance(database_name, str) or not database_name.endswith(
                "_test"
            ):
                raise RuntimeError(
                    "refusing to truncate a non-test PostgreSQL database"
                )
            await connection.execute(
                text(
                    "TRUNCATE TABLE authorization_audit_events, user_roles, "
                    "role_permissions, roles, users CASCADE"
                )
            )
            await connection.execute(
                text("UPDATE authorization_state SET epoch = 0 WHERE scope = 'global'")
            )
        yield
    finally:
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
def access_token() -> Callable[[User], str]:
    settings = get_settings()

    def make_token(user: User) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "sub": str(user.id),
                "ver": user.token_version,
                "jti": str(uuid.uuid4()),
                "token_type": "access",
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(minutes=5),
                "iss": settings.jwt_issuer,
                "aud": settings.jwt_audience,
            },
            settings.jwt_secret.get_secret_value(),
            algorithm="HS256",
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

            users = {
                name: User(email=f"{name}@example.test")
                for name in (
                    "owner",
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
                "owner": Role(
                    key="owner",
                    name="Owner",
                    management_tier=1000,
                    is_system=True,
                    is_protected=True,
                    is_owner=True,
                ),
                "manager": Role(
                    key="manager",
                    name="Manager",
                    management_tier=500,
                ),
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
                "nondelegable": Role(
                    key="nondelegable",
                    name="Nondelegable",
                    management_tier=30,
                ),
            }
            session.add_all(roles.values())
            await session.flush()

            def grant(
                role_name: str,
                keys: set[str],
                *,
                delegable: set[str] | None = None,
            ) -> list[RolePermission]:
                role = roles[role_name]
                delegable = delegable or set()
                return [
                    RolePermission(
                        role_id=role.id,
                        permission_id=permissions[key].id,
                        can_delegate=key in delegable,
                    )
                    for key in keys
                ]

            session.add_all(
                grant(
                    "owner",
                    set(OWNER_PERMISSION_KEYS),
                    delegable=set(OWNER_DELEGABLE_PERMISSION_KEYS),
                )
                + grant(
                    "manager",
                    {
                        PermissionKey.ROLES_READ.value,
                        PermissionKey.ROLES_CREATE.value,
                        PermissionKey.ROLES_ASSIGN.value,
                        PermissionKey.ROLES_REVOKE.value,
                        PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
                        PermissionKey.USERS_READ.value,
                        PermissionKey.USERS_STATUS_UPDATE.value,
                        PermissionKey.PROJECTS_READ.value,
                        PermissionKey.PROJECTS_UPDATE.value,
                    },
                    delegable={
                        PermissionKey.PROJECTS_READ.value,
                        PermissionKey.PROJECTS_UPDATE.value,
                    },
                )
                + grant(
                    "junior_admin",
                    {
                        PermissionKey.ROLES_ASSIGN.value,
                        PermissionKey.ROLES_REVOKE.value,
                        PermissionKey.PROJECTS_READ.value,
                    },
                    delegable={PermissionKey.PROJECTS_READ.value},
                )
                + grant("higher", {PermissionKey.PROJECTS_READ.value})
                + grant("viewer", {PermissionKey.PROJECTS_READ.value})
                + grant("nondelegable", {PermissionKey.USERS_READ.value})
            )

            assignments = (
                ("owner", "owner"),
                ("manager", "manager"),
                ("peer", "manager"),
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
