import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Literal, cast
from unittest.mock import AsyncMock, Mock

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
from app.rate_limit import RateLimitResult
from app.rate_limit_dependencies import RateLimitExceeded
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
from app.rbac.errors import RbacError, not_found, unauthenticated, unavailable
from app.rbac.models import RbacState
from app.rbac.security import AccessTokenClaims, issue_access_token
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
    revoke = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies._best_effort_revoke_invalid_principal",
        revoke,
    )
    request = Request({"type": "http", "headers": []})

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(request, principal, session, get_settings())

    assert caught.value.status_code == 401
    assert caught.value.business_code == BusinessCode.INVALID_AUTHENTICATION
    revoke.assert_awaited_once_with(
        request=request,
        principal=principal,
        settings=get_settings(),
    )


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
            get_settings(),
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


async def test_forged_token_is_rejected_before_redis_and_postgresql() -> None:
    redis = AsyncMock()
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
                headers={"Authorization": "Bearer not-a-signed-jwt"},
            )
    finally:
        app.dependency_overrides.pop(get_session, None)
        del app.state.redis

    assert response.status_code == 401
    assert_error_response(response, BusinessCode.INVALID_AUTHENTICATION)
    redis.eval.assert_not_awaited()
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
    revoke = AsyncMock()
    actor_limit = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies._best_effort_revoke_invalid_principal",
        revoke,
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.enforce_principal_rate_limit",
        actor_limit,
    )
    request = Request({"type": "http", "headers": []})

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(
            request,
            principal,
            session,
            get_settings(),
        )

    assert caught.value.status_code == 401
    revoke.assert_awaited_once()
    actor_limit.assert_not_awaited()


async def test_exhausted_actor_window_is_rejected_before_postgresql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    session = AsyncMock()
    precheck = AsyncMock(
        side_effect=RateLimitExceeded(
            policy_name="get_my_access",
            result=RateLimitResult(False, 600, 0, 750, 750),
        )
    )
    actor_limit = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies.precheck_principal_rate_limit",
        precheck,
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.enforce_principal_rate_limit",
        actor_limit,
    )
    request = Request({"type": "http", "headers": []})

    with pytest.raises(RateLimitExceeded):
        await get_authorization_context(
            request,
            principal,
            session,
            get_settings(),
        )

    precheck.assert_awaited_once()
    session.scalar.assert_not_awaited()
    actor_limit.assert_not_awaited()


async def test_exhausted_private_captcha_scene_skips_postgresql() -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    redis = AsyncMock()
    redis.eval.return_value = [10, 120_000]
    application = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=redis))
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {
            "type": "http.request",
            "body": b'{"scene":"admin_reset"}',
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/json")],
            "app": application,
            "route": SimpleNamespace(operation_id="create_authenticated_captcha"),
        },
        receive,
    )
    session = AsyncMock()
    settings = get_settings().model_copy(update={"rate_limit_enabled": True})

    with pytest.raises(RateLimitExceeded) as caught:
        await get_authorization_context(
            request,
            principal,
            session,
            settings,
        )

    assert caught.value.policy_name == "captcha_create_admin_reset"
    session.scalar.assert_not_awaited()
    key = redis.eval.await_args.args[2]
    assert ":captcha_create_admin_reset:actor:" in key


async def test_text_plain_rejection_limit_skips_postgresql() -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=4,
        token_id=uuid.uuid4(),
        issued_at=0,
        expires_at=1,
    )
    redis = AsyncMock()
    redis.eval.return_value = [10, 120_000]
    application = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=redis))
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {
            "type": "http.request",
            "body": b'{"scene":"admin_reset"}',
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"text/plain")],
            "app": application,
            "route": SimpleNamespace(operation_id="create_authenticated_captcha"),
        },
        receive,
    )
    session = AsyncMock()
    settings = get_settings().model_copy(update={"rate_limit_enabled": True})

    with pytest.raises(RateLimitExceeded) as caught:
        await get_authorization_context(
            request,
            principal,
            session,
            settings,
        )

    assert caught.value.policy_name == "captcha_rejected_scene"
    session.scalar.assert_not_awaited()
    key = redis.eval.await_args.args[2]
    assert ":captcha_rejected_scene:actor:" in key


async def test_database_rejected_jti_is_revoked_before_redis_rejects_its_next_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = get_settings()
    token_claims = AccessTokenClaims(
        user_id=uuid.uuid4(),
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    require_jti = AsyncMock(side_effect=[3, unauthenticated("inactive_access_token")])
    revoke_jti = AsyncMock()
    load_authority = AsyncMock(
        return_value=AuthoritySnapshot.build(
            user_id=token_claims.user_id,
            user_is_active=False,
            user_is_protected=False,
            token_version=3,
            authz_version=0,
            roles=(),
        )
    )
    actor_limit = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies.decode_access_token",
        Mock(return_value=token_claims),
    )
    monkeypatch.setattr("app.rbac.dependencies.require_active_jti", require_jti)
    monkeypatch.setattr("app.rbac.dependencies.revoke_active_jti", revoke_jti)
    monkeypatch.setattr("app.rbac.dependencies.get_redis", Mock(return_value=object()))
    monkeypatch.setattr(
        "app.rbac.dependencies.load_authority_snapshot",
        load_authority,
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.enforce_principal_rate_limit",
        actor_limit,
    )
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="signed-token",
    )
    first_request = Request({"type": "http", "headers": []})
    principal = await get_current_principal(first_request, credentials, settings)
    session = AsyncMock()
    session.scalar.return_value = RbacState(scope="global", epoch=0)

    with pytest.raises(RbacError) as first_denial:
        await get_authorization_context(
            first_request,
            principal,
            session,
            settings,
        )

    with pytest.raises(RbacError) as second_denial:
        await get_current_principal(
            Request({"type": "http", "headers": []}),
            credentials,
            settings,
        )

    assert first_denial.value.status_code == 401
    assert second_denial.value.status_code == 401
    load_authority.assert_awaited_once()
    revoke_jti.assert_awaited_once()
    actor_limit.assert_not_awaited()


async def test_inactive_jti_cleanup_failure_preserves_401_and_skips_actor_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=3,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    authority = AuthoritySnapshot.build(
        user_id=principal.user_id,
        user_is_active=False,
        user_is_protected=False,
        token_version=3,
        authz_version=0,
        roles=(),
    )
    session = AsyncMock()
    session.scalar.return_value = RbacState(scope="global", epoch=0)
    actor_limit = AsyncMock()
    log = Mock()
    monkeypatch.setattr(
        "app.rbac.dependencies.load_authority_snapshot",
        AsyncMock(return_value=authority),
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.get_redis",
        Mock(return_value=object()),
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.revoke_active_jti",
        AsyncMock(side_effect=RuntimeError("controlled cleanup failure")),
    )
    monkeypatch.setattr(
        "app.rbac.dependencies.enforce_principal_rate_limit",
        actor_limit,
    )
    monkeypatch.setattr("app.rbac.dependencies.safe_log", log)
    monkeypatch.setattr(
        "app.rbac.dependencies.safe_exception_metadata",
        Mock(
            return_value={"error_id": "cleanup-test", "exception_type": "RuntimeError"}
        ),
    )

    with pytest.raises(RbacError) as caught:
        await get_authorization_context(
            Request({"type": "http", "headers": []}),
            principal,
            session,
            get_settings(),
        )

    assert caught.value.status_code == 401
    actor_limit.assert_not_awaited()
    log.assert_called_once()
