import uuid
from typing import Literal, cast

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.rbac.dependencies import get_current_principal, require_permissions
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)
from app.rbac.errors import RbacError


def authorization_context(*permission_groups: set[str]) -> AuthorizationContext:
    tenant_id = uuid.uuid4()
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
        membership_id=uuid.uuid4(),
        user_id=user_id,
        membership_status="active",
        membership_is_protected=False,
        user_is_protected=False,
        authz_version=0,
        roles=roles,
    )
    return AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_tenant_id=tenant_id,
            token_version=0,
            token_id=str(uuid.uuid4()),
        ),
        tenant_id=tenant_id,
        tenant_authz_epoch=0,
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
        response = await client.get(
            f"/tenants/{uuid.uuid4()}/rbac/me",
            headers=request_headers,
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {"detail": {"code": "invalid_authentication"}}


async def test_http_token_tenant_mismatch_is_concealed() -> None:
    token_tenant_id = uuid.uuid4()
    principal = Principal(
        user_id=uuid.uuid4(),
        token_tenant_id=token_tenant_id,
        token_version=0,
        token_id=str(uuid.uuid4()),
    )

    app.dependency_overrides[get_current_principal] = lambda: principal
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/tenants/{uuid.uuid4()}/rbac/me")
    finally:
        app.dependency_overrides.pop(get_current_principal, None)

    assert response.status_code == 404
    assert response.json() == {"detail": {"code": "not_found"}}
