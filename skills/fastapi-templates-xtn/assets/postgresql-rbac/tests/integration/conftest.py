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
    TENANT_OWNER_DELEGABLE_PERMISSION_KEYS,
    TENANT_OWNER_PERMISSION_KEYS,
    PermissionKey,
)
from app.rbac.models import (
    Membership,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantAuthorizationState,
    User,
)
from app.settings import get_settings

pytestmark = pytest.mark.postgresql


@dataclass(slots=True)
class World:
    tenant: Tenant
    second_tenant: Tenant
    users: dict[str, User]
    memberships: dict[str, Membership]
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
                    "TRUNCATE TABLE authorization_audit_events, membership_roles, "
                    "role_permissions, roles, memberships, "
                    "tenant_authorization_state, tenants, users CASCADE"
                )
            )
        yield
    finally:
        # The application engine is module-scoped while pytest uses one event loop
        # per test. Dispose pooled asyncpg connections before that loop closes.
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
def access_token() -> Callable[[User, Tenant], str]:
    settings = get_settings()

    def make_token(user: User, tenant: Tenant) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "sub": str(user.id),
                "tid": str(tenant.id),
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
                    "outsider",
                    "newcomer",
                    "disabled",
                )
            }
            users["disabled"].is_active = False
            tenant = Tenant(slug="primary", name="Primary")
            second_tenant = Tenant(slug="secondary", name="Secondary")
            session.add_all([*users.values(), tenant, second_tenant])
            await session.flush()
            session.add_all(
                [
                    TenantAuthorizationState(tenant_id=tenant.id),
                    TenantAuthorizationState(tenant_id=second_tenant.id),
                ]
            )

            memberships = {
                name: Membership(tenant_id=tenant.id, user_id=users[name].id)
                for name in (
                    "owner",
                    "manager",
                    "peer",
                    "junior",
                    "higher",
                    "lower",
                    "blank",
                    "hidden_higher",
                )
            }
            memberships["outsider"] = Membership(
                tenant_id=second_tenant.id,
                user_id=users["outsider"].id,
            )
            session.add_all(memberships.values())

            roles = {
                "owner": Role(
                    tenant_id=tenant.id,
                    key="owner",
                    name="Owner",
                    management_tier=1000,
                    is_system=True,
                    is_protected=True,
                    is_owner=True,
                ),
                "manager": Role(
                    tenant_id=tenant.id,
                    key="manager",
                    name="Manager",
                    management_tier=500,
                ),
                "junior_admin": Role(
                    tenant_id=tenant.id,
                    key="junior-admin",
                    name="Junior admin",
                    management_tier=100,
                ),
                "higher": Role(
                    tenant_id=tenant.id,
                    key="higher",
                    name="Higher",
                    management_tier=700,
                ),
                "viewer": Role(
                    tenant_id=tenant.id,
                    key="viewer",
                    name="Viewer",
                    management_tier=20,
                ),
                "nondelegable": Role(
                    tenant_id=tenant.id,
                    key="nondelegable",
                    name="Nondelegable",
                    management_tier=30,
                ),
                "outsider": Role(
                    tenant_id=second_tenant.id,
                    key="outsider",
                    name="Outsider",
                    management_tier=20,
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
                        tenant_id=role.tenant_id,
                        role_id=role.id,
                        permission_id=permissions[key].id,
                        can_delegate=key in delegable,
                    )
                    for key in keys
                ]

            session.add_all(
                grant(
                    "owner",
                    set(TENANT_OWNER_PERMISSION_KEYS),
                    delegable=set(TENANT_OWNER_DELEGABLE_PERMISSION_KEYS),
                )
                + grant(
                    "manager",
                    {
                        PermissionKey.ROLES_READ.value,
                        PermissionKey.ROLES_CREATE.value,
                        PermissionKey.ROLES_ASSIGN.value,
                        PermissionKey.ROLES_REVOKE.value,
                        PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
                        PermissionKey.MEMBERSHIPS_READ.value,
                        PermissionKey.MEMBERSHIPS_CREATE.value,
                        PermissionKey.MEMBERSHIPS_STATUS_UPDATE.value,
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
                + grant("nondelegable", {PermissionKey.MEMBERSHIPS_READ.value})
                + grant("outsider", {PermissionKey.PROJECTS_READ.value})
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
                ("outsider", "outsider"),
            )
            session.add_all(
                MembershipRole(
                    tenant_id=memberships[member].tenant_id,
                    membership_id=memberships[member].id,
                    role_id=roles[role_name].id,
                    assigned_by_membership_id=None,
                )
                for member, role_name in assignments
            )
        return World(
            tenant=tenant,
            second_tenant=second_tenant,
            users=users,
            memberships=memberships,
            roles=roles,
            permissions=permissions,
        )
