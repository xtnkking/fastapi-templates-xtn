import uuid
from typing import Literal, cast
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app.main import app
from app.rbac.dependencies import get_authorization_context, require_permissions
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)
from app.rbac.errors import RbacError, not_found, unavailable
from app.rbac.models import AuthorizationState


def authorization_context(*permission_groups: set[str]) -> AuthorizationContext:
    user_id = uuid.uuid4()
    roles = tuple(
        RoleGrant(
            role_id=uuid.uuid4(),
            management_tier=index + 1,
            permissions=frozenset(permissions),
            delegable_permissions=frozenset(),
            is_protected=False,
            is_owner=False,
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

    assert await dependency(context) is context


async def test_require_permissions_any_accepts_one_and_denies_none() -> None:
    dependency = require_permissions(
        PermissionKey.ROLES_READ,
        PermissionKey.PROJECTS_READ,
        mode="any",
    )

    allowed = authorization_context({PermissionKey.PROJECTS_READ.value})
    denied = authorization_context({PermissionKey.PROJECTS_UPDATE.value})

    assert await dependency(allowed) is allowed
    with pytest.raises(RbacError) as caught:
        await dependency(denied)
    assert caught.value.status_code == 403
    assert caught.value.public_code == "rbac_forbidden"


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
        response = await client.get("/rbac/me", headers=request_headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {"detail": {"code": "invalid_authentication"}}


def test_missing_authoritative_state_maps_to_service_unavailable() -> None:
    error = unavailable("authorization_state_missing")

    assert error.status_code == 503
    assert error.public_code == "authorization_unavailable"


async def test_disappearing_authenticated_user_remains_a_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=0,
        token_id=uuid.uuid4(),
    )
    session = AsyncMock()
    session.scalar.return_value = AuthorizationState(scope="global", epoch=0)

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
    assert caught.value.public_code == "invalid_authentication"
