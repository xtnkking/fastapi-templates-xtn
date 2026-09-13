import uuid
from collections.abc import AsyncIterator
from typing import Literal, cast
from unittest.mock import AsyncMock

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from httpx import ASGITransport, AsyncClient, Response
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.api_contract import BusinessCode
from app.database import get_session
from app.main import app
from app.rbac.dependencies import (
    get_authorization_context,
    get_current_principal,
    require_permissions,
)
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)
from app.rbac.errors import RbacError, not_found, unavailable
from app.rbac.models import RbacState
from app.rbac.security import issue_access_token
from app.settings import get_settings


def assert_error_response(response: Response, expected_code: BusinessCode) -> None:
    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(expected_code)
    assert body["data"] is None
    request_id = uuid.UUID(body["request_id"])
    assert request_id.version == 4
    assert response.headers["X-Request-ID"] == body["request_id"]


def authorization_context(*permission_groups: set[str]) -> AuthorizationContext:
    user_id = uuid.uuid4()
    roles = tuple(
        RoleGrant(
            role_id=uuid.uuid4(),
            key=f"role_{index}",
            management_tier=index + 1,
            permissions=frozenset(permissions),
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        )
        for index, permissions in enumerate(permission_groups)
    )
    authority = AuthoritySnapshot.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=roles,
    )
    return AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="dependency-test",
    )


async def test_require_permissions_all_accepts_union_across_roles() -> None:
    context = authorization_context(
        {PermissionKey.ROLES_READ.value},
        {PermissionKey.PROJECTS_READ.value},
    )
    dependency = require_permissions(
        PermissionKey.ROLES_READ,
        PermissionKey.PROJECTS_READ,
        mode="all",
    )

    request = Request({"type": "http", "method": "GET", "headers": []})
    assert await dependency(context, request) is context


async def test_require_permissions_any_accepts_one_and_denies_none() -> None:
    dependency = require_permissions(
        PermissionKey.ROLES_READ,
        PermissionKey.PROJECTS_READ,
        mode="any",
    )

    allowed = authorization_context({PermissionKey.PROJECTS_READ.value})
    denied = authorization_context({PermissionKey.PROJECTS_UPDATE.value})
    request = Request({"type": "http", "method": "GET", "headers": []})

    assert await dependency(allowed, request) is allowed
    with pytest.raises(RbacError) as caught:
        await dependency(denied, request)
    assert caught.value.status_code == 403
    assert caught.value.business_code == BusinessCode.ACCESS_FORBIDDEN


async def test_post_permission_denial_attempts_an_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = authorization_context({PermissionKey.PROJECTS_READ.value})
    dependency = require_permissions(PermissionKey.ROLES_DELETE)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [],
            "path": "/api/v1/roles/example/delete",
            "route": type("Route", (), {"operation_id": "delete_role"})(),
        }
    )
    write_audit = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies._write_permission_denial_audit",
        write_audit,
    )

    with pytest.raises(RbacError) as caught:
        await dependency(context, request)

    assert caught.value.status_code == 403
    write_audit.assert_awaited_once_with(
        context=context,
        action="api.delete_role",
    )


def test_require_permissions_rejects_empty_and_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="at least one permission"):
        require_permissions()

    invalid_mode = cast(Literal["all", "any"], "neither")
    with pytest.raises(ValueError, match="mode must be"):
        require_permissions(PermissionKey.ROLES_READ, mode=invalid_mode)


@pytest.mark.parametrize("authorization", [None, "Basic credentials", "Bearer invalid"])
async def test_http_authentication_failures_return_bearer_challenge(
    authorization: str | None,
) -> None:
    request_headers = {} if authorization is None else {"Authorization": authorization}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/me/access", headers=request_headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert_error_response(response, BusinessCode.INVALID_AUTHENTICATION)


def test_missing_authoritative_state_maps_to_service_unavailable() -> None:
    error = unavailable("rbac_state_missing")

    assert error.status_code == 503
    assert error.business_code == BusinessCode.SERVICE_UNAVAILABLE


async def test_disappearing_authenticated_user_remains_a_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    session = AsyncMock()
    session.scalar.return_value = RbacState(scope="global", epoch=0)

    async def missing_authority(*_args: object, **_kwargs: object) -> AuthoritySnapshot:
        raise not_found("user_not_found")

    monkeypatch.setattr(
        "app.rbac.dependencies.load_authority_snapshot",
        missing_authority,
    )
    request = Request({"type": "http", "headers": []})

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(request, principal, session)

    assert caught.value.status_code == 401
    assert caught.value.business_code == BusinessCode.INVALID_AUTHENTICATION


async def test_postgresql_authority_failure_maps_to_service_unavailable() -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    session = AsyncMock()
    session.scalar.side_effect = SQLAlchemyError("database unavailable")

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(
            Request({"type": "http", "headers": []}),
            principal,
            session,
        )

    assert caught.value.status_code == 503
    assert caught.value.business_code == BusinessCode.SERVICE_UNAVAILABLE


async def test_bearer_size_limit_runs_before_redis_lookup() -> None:
    redis = AsyncMock()
    app.state.redis = redis
    request = Request({"type": "http", "headers": [], "app": app})
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="x" * 4097,
    )
    try:
        with pytest.raises(RbacError) as caught:
            await get_current_principal(request, credentials, get_settings())
    finally:
        del app.state.redis

    assert caught.value.status_code == 401
    redis.eval.assert_not_awaited()


async def test_redis_outage_prevents_postgresql_authority_query() -> None:
    redis = AsyncMock()
    redis.eval.return_value = 1
    settings = get_settings()
    token = await issue_access_token(
        cast(Redis, redis),
        user_id=uuid.uuid4(),
        user_token_version=0,
        settings=settings,
    )
    redis.reset_mock()
    redis.eval.side_effect = RedisConnectionError("registry unavailable")
    session = AsyncMock()

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    app.state.redis = redis
    app.dependency_overrides[get_session] = override_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/me/access",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        app.dependency_overrides.pop(get_session, None)
        del app.state.redis

    assert response.status_code == 503
    assert_error_response(response, BusinessCode.SERVICE_UNAVAILABLE)
    redis.eval.assert_awaited_once()
    session.scalar.assert_not_awaited()


async def test_postgresql_snapshot_rejects_stale_redis_token_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    authority = AuthoritySnapshot.build(
        user_id=principal.user_id,
        user_is_active=True,
        user_is_protected=False,
        token_version=5,
        authz_version=0,
        roles=(),
    )
    session = AsyncMock()
    session.scalar.return_value = RbacState(scope="global", epoch=0)

    async def current_authority(
        *_args: object,
        **_kwargs: object,
    ) -> AuthoritySnapshot:
        return authority

    monkeypatch.setattr(
        "app.rbac.dependencies.load_authority_snapshot",
        current_authority,
    )

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(
            Request({"type": "http", "headers": []}),
            principal,
            session,
        )

    assert caught.value.status_code == 401
