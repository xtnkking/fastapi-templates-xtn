import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.rbac import dependencies, security
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
)
from app.rbac.errors import RbacError
from app.rbac.models import RbacState
from app.rbac.security import AccessTokenClaims
from app.settings import get_settings


def request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/test", "headers": []})


def principal(*, token_version: int = 3) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        token_version=token_version,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


def authority(
    principal: Principal,
    *,
    active: bool = True,
    token_version: int | None = None,
) -> AuthoritySnapshot:
    return AuthoritySnapshot.build(
        user_id=principal.user_id,
        user_is_active=active,
        user_is_protected=False,
        token_version=(
            principal.token_version if token_version is None else token_version
        ),
        authz_version=0,
        roles=(),
    )


def session_with_state() -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    session.scalar.return_value = RbacState(scope="global", epoch=7)
    return session


def claims() -> AccessTokenClaims:
    return AccessTokenClaims(
        user_id=uuid.uuid4(),
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


async def test_principal_only_path_does_not_mark_authenticated_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_request = request()
    current_claims = claims()
    monkeypatch.setattr(
        dependencies, "decode_access_token", Mock(return_value=current_claims)
    )
    monkeypatch.setattr(dependencies, "get_redis", Mock(return_value=AsyncMock()))
    monkeypatch.setattr(dependencies, "require_active_jti", AsyncMock(return_value=3))
    actor_limit = AsyncMock()
    monkeypatch.setattr(dependencies, "enforce_principal_rate_limit", actor_limit)

    result = await dependencies.get_current_principal(
        current_request,
        HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token"),
        get_settings(),
    )

    assert result.user_id == current_claims.user_id
    assert not hasattr(current_request.state, "actor_user_id")
    actor_limit.assert_not_awaited()


@pytest.mark.parametrize(
    ("active", "authority_token_version"),
    [(False, 3), (True, 4)],
)
async def test_rejected_postgresql_identity_does_not_mark_actor(
    monkeypatch: pytest.MonkeyPatch,
    active: bool,
    authority_token_version: int,
) -> None:
    current_request = request()
    current_principal = principal()
    monkeypatch.setattr(
        dependencies,
        "load_authority_snapshot",
        AsyncMock(
            return_value=authority(
                current_principal,
                active=active,
                token_version=authority_token_version,
            )
        ),
    )
    revoke = AsyncMock()
    actor_limit = AsyncMock()
    monkeypatch.setattr(
        dependencies,
        "_best_effort_revoke_invalid_principal",
        revoke,
    )
    monkeypatch.setattr(dependencies, "enforce_principal_rate_limit", actor_limit)

    with pytest.raises(RbacError) as caught:
        await dependencies.get_authorization_context(
            current_request,
            current_principal,
            cast(AsyncSession, session_with_state()),
            get_settings(),
        )

    assert caught.value.status_code == 401
    assert not hasattr(current_request.state, "actor_user_id")
    revoke.assert_awaited_once()
    actor_limit.assert_not_awaited()


async def test_database_failure_logs_once_without_marking_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_request = request()
    current_principal = principal()
    session = session_with_state()
    session.scalar.side_effect = OperationalError(
        "SELECT secret FROM users", {}, RuntimeError("database-password")
    )
    log = Mock(return_value=True)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "OperationalError",
    }
    monkeypatch.setattr(dependencies, "safe_log", log)
    monkeypatch.setattr(
        dependencies,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )

    with pytest.raises(RbacError) as caught:
        await dependencies.get_authorization_context(
            current_request,
            current_principal,
            cast(AsyncSession, session),
            get_settings(),
        )

    assert caught.value.status_code == 503
    assert not hasattr(current_request.state, "actor_user_id")
    log.assert_called_once_with(
        dependencies.logger,
        logging.ERROR,
        "dependency.database.unavailable",
        extra={
            "dependency": "postgresql",
            "dependency_operation": "load_authorization_context",
            "error_category": "connection",
            **exception_metadata,
        },
    )


async def test_successful_authorization_context_marks_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_request = request()
    current_principal = principal()
    events: list[str] = []

    async def load_current_authority(
        *_args: object,
        **_kwargs: object,
    ) -> AuthoritySnapshot:
        events.append("database")
        return authority(current_principal)

    monkeypatch.setattr(
        dependencies,
        "load_authority_snapshot",
        load_current_authority,
    )

    async def actor_limit(*_args: object, **_kwargs: object) -> None:
        events.append("actor_limit")

    monkeypatch.setattr(dependencies, "enforce_principal_rate_limit", actor_limit)

    context = await dependencies.get_authorization_context(
        current_request,
        current_principal,
        cast(AsyncSession, session_with_state()),
        get_settings(),
    )

    assert context.principal == current_principal
    assert current_request.state.actor_user_id == str(current_principal.user_id)
    assert events == ["database", "actor_limit"]


async def test_audit_log_failure_does_not_replace_permission_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_principal = principal()
    context = AuthorizationContext(
        principal=current_principal,
        authorization_epoch=0,
        authority=authority(current_principal),
        request_id=str(uuid.uuid4()),
    )
    current_request = Request(
        {"type": "http", "method": "POST", "path": "/test", "headers": []}
    )
    write_audit = AsyncMock(side_effect=RuntimeError("audit-database-password"))
    log = Mock(return_value=False)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "RuntimeError",
    }
    monkeypatch.setattr(dependencies, "_write_permission_denial_audit", write_audit)
    monkeypatch.setattr(dependencies, "safe_log", log)
    monkeypatch.setattr(
        dependencies,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )
    require_read = dependencies.require_permissions(PermissionKey.ROLES_READ)

    with pytest.raises(RbacError) as caught:
        await require_read(context, current_request)

    assert caught.value.status_code == 403
    log.assert_called_once_with(
        dependencies.logger,
        logging.ERROR,
        "audit.write.failed",
        extra={
            "audit_action": "api.protected_write",
            **exception_metadata,
        },
    )


@pytest.mark.parametrize(
    ("operation", "dependency_operation"),
    [
        ("issue", "register_active_jti"),
        ("require", "read_active_jti"),
        ("revoke", "revoke_active_jti"),
    ],
)
async def test_redis_failure_logs_once_before_503_conversion(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    dependency_operation: str,
) -> None:
    redis = AsyncMock()
    error = RedisConnectionError("redis://user:password@example.test/0")
    if operation == "require":
        redis.eval.side_effect = error
    else:
        redis.eval.side_effect = error
    log = Mock(return_value=True)
    exception_metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "ConnectionError",
    }
    monkeypatch.setattr(security, "safe_log", log)
    monkeypatch.setattr(
        security,
        "safe_exception_metadata",
        Mock(return_value=exception_metadata),
    )
    settings = get_settings()
    current_claims = claims()

    calls: dict[str, Callable[[], Awaitable[object]]] = {
        "issue": lambda: security.issue_access_token(
            cast(Redis, redis),
            user_id=current_claims.user_id,
            user_token_version=3,
            settings=settings,
        ),
        "require": lambda: security.require_active_jti(
            cast(Redis, redis), claims=current_claims, settings=settings
        ),
        "revoke": lambda: security.revoke_active_jti(
            cast(Redis, redis),
            claims=current_claims,
            user_token_version=3,
            settings=settings,
        ),
    }

    with pytest.raises(RbacError) as caught:
        await calls[operation]()

    assert caught.value.status_code == 503
    log.assert_called_once_with(
        security.logger,
        logging.ERROR,
        "dependency.redis.unavailable",
        extra={
            "dependency": "redis",
            "dependency_operation": dependency_operation,
            "error_category": "connection",
            **exception_metadata,
        },
    )
