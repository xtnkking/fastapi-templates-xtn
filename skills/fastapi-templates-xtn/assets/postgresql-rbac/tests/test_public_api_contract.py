import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.rbac.api import _expected_role_version, _role_etag
from app.rbac.api import router as public_router
from app.rbac.dependencies import get_authorization_context
from app.rbac.domain import (
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    Principal,
    RoleGrant,
)
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    precondition_failed,
    precondition_required,
    unauthenticated,
    unavailable,
)
from app.rbac.models import Role
from app.rbac.schemas import RoleMutationResponse, RoleResponse
from app.rbac.service import get_rbac_service

REQUIRED_ROUTES = {
    ("GET", "/api/v1/permissions"),
    ("GET", "/api/v1/permissions/{permission_id}"),
    ("GET", "/api/v1/roles"),
    ("GET", "/api/v1/roles/{role_id}"),
    ("POST", "/api/v1/roles"),
    ("POST", "/api/v1/roles/{role_id}/update"),
    ("POST", "/api/v1/roles/{role_id}/disable"),
    ("POST", "/api/v1/roles/{role_id}/enable"),
    ("POST", "/api/v1/roles/{role_id}/delete"),
    ("POST", "/api/v1/roles/{role_id}/permissions/bind"),
    ("POST", "/api/v1/roles/{role_id}/permissions/unbind"),
    ("POST", "/api/v1/users/{user_id}/roles/bind"),
    ("POST", "/api/v1/users/{user_id}/roles/unbind"),
}
ROLE_MUTATION_PATHS = {
    "/api/v1/roles/{role_id}/update",
    "/api/v1/roles/{role_id}/disable",
    "/api/v1/roles/{role_id}/enable",
    "/api/v1/roles/{role_id}/delete",
    "/api/v1/roles/{role_id}/permissions/bind",
    "/api/v1/roles/{role_id}/permissions/unbind",
    "/api/v1/roles/{role_id}/delegable-permissions/bind",
    "/api/v1/roles/{role_id}/delegable-permissions/unbind",
}


def _public_routes() -> list[APIRoute]:
    return [
        route
        for route in public_router.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1")
    ]


def test_public_contract_contains_required_routes_and_only_get_or_post() -> None:
    routes = _public_routes()
    actual = {
        (method, route.path) for route in routes for method in route.methods or set()
    }

    assert REQUIRED_ROUTES <= actual
    assert {method for method, _path in actual} <= {"GET", "POST"}


def test_public_contract_does_not_name_the_authorization_implementation() -> None:
    assert "rbac" not in app.title.casefold()

    for route in _public_routes():
        public_metadata = " ".join(
            [
                route.path,
                route.operation_id or "",
                *(str(tag) for tag in route.tags or []),
            ]
        )
        assert "rbac" not in public_metadata.casefold()

    public_errors = [
        unauthenticated("test"),
        not_found("test"),
        forbidden("test"),
        conflict("test"),
        unavailable("test"),
        invalid_request("test"),
        precondition_required("test"),
        precondition_failed("test"),
    ]
    assert all("rbac" not in error.public_code.casefold() for error in public_errors)


def test_public_response_schemas_include_management_state() -> None:
    schemas = app.openapi()["components"]["schemas"]

    assert "id" in schemas["PermissionResponse"]["properties"]
    assert {
        "description",
        "deleted_at",
    } <= schemas["RoleResponse"]["properties"].keys()
    assert "changed" in schemas["RoleMutationResponse"]["properties"]
    assert "permissions" not in schemas["RoleCreateRequest"]["properties"]


def test_role_mutations_document_if_match_as_required() -> None:
    paths = app.openapi()["paths"]

    for path in ROLE_MUTATION_PATHS:
        parameters = paths[path]["post"]["parameters"]
        if_match = next(item for item in parameters if item["name"] == "If-Match")
        assert if_match["in"] == "header"
        assert if_match["required"] is True


def test_role_etag_round_trip() -> None:
    role_id = uuid.uuid4()
    role = Role(id=role_id, version=7)
    etag = _role_etag(role)

    assert etag == f'"role:{role_id}:v7"'
    assert _expected_role_version(role_id=role_id, if_match=etag) == 7


def test_role_if_match_is_required_and_strict() -> None:
    role_id = uuid.uuid4()

    with pytest.raises(RbacError) as missing:
        _expected_role_version(role_id=role_id, if_match=None)
    assert missing.value.status_code == 428

    for invalid in ("*", 'W/"role:test:v1"', "not-an-etag"):
        with pytest.raises(RbacError) as malformed:
            _expected_role_version(role_id=role_id, if_match=invalid)
        assert malformed.value.status_code == 422

    other_role_id = uuid.uuid4()
    with pytest.raises(RbacError) as mismatched:
        _expected_role_version(
            role_id=role_id,
            if_match=f'"role:{other_role_id}:v1"',
        )
    assert mismatched.value.status_code == 422


async def test_role_delete_uses_the_committed_service_snapshot() -> None:
    actor_id = uuid.uuid4()
    role_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=actor_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(
            RoleGrant(
                role_id=uuid.uuid4(),
                key="test-admin",
                management_tier=100,
                permissions=frozenset({PermissionKey.ROLES_DELETE.value}),
                delegable_permissions=frozenset(),
                is_system=False,
                is_protected=False,
                is_owner=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="transaction-snapshot-test",
    )
    result = RoleMutationResponse(
        changed=True,
        role=RoleResponse(
            id=role_id,
            key="deleted-role",
            name="Deleted role",
            description="",
            management_tier=10,
            is_active=False,
            is_system=False,
            is_protected=False,
            is_owner=False,
            permissions=("projects:read",),
            delegable_permissions=(),
            version=8,
            deleted_at=datetime.now(UTC),
        ),
    )

    class SnapshotService:
        async def soft_delete_role(self, **_kwargs: object) -> RoleMutationResponse:
            return result

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_rbac_service] = SnapshotService
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/roles/{role_id}/delete",
                headers={"If-Match": f'"role:{role_id}:v7"'},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["etag"] == f'"role:{role_id}:v8"'
    assert response.json()["role"]["permissions"] == ["projects:read"]
    assert response.json()["role"]["deleted_at"] is not None


async def test_unprivileged_user_cannot_call_required_management_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_version=0,
            token_id=uuid.uuid4(),
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="public-contract-test",
    )

    async def unprivileged_context() -> AuthorizationContext:
        return context

    write_audit = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.dependencies._write_permission_denial_audit",
        write_audit,
    )

    role_id = uuid.uuid4()
    permission_id = uuid.uuid4()
    target_user_id = uuid.uuid4()
    etag = f'"role:{role_id}:v1"'
    requests: list[tuple[str, str, dict[str, Any]]] = [
        ("GET", "/api/v1/permissions", {}),
        ("GET", f"/api/v1/permissions/{permission_id}", {}),
        ("GET", "/api/v1/roles", {}),
        ("GET", f"/api/v1/roles/{role_id}", {}),
        (
            "POST",
            "/api/v1/roles",
            {
                "json": {
                    "key": "manager",
                    "name": "Manager",
                    "management_tier": 100,
                }
            },
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/update",
            {"json": {"name": "Renamed"}, "headers": {"If-Match": etag}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/disable",
            {"headers": {"If-Match": etag}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/enable",
            {"headers": {"If-Match": etag}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/delete",
            {"headers": {"If-Match": etag}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/permissions/bind",
            {
                "json": {"permission_ids": [str(permission_id)]},
                "headers": {"If-Match": etag},
            },
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/permissions/unbind",
            {
                "json": {"permission_ids": [str(permission_id)]},
                "headers": {"If-Match": etag},
            },
        ),
        (
            "POST",
            f"/api/v1/users/{target_user_id}/roles/bind",
            {"json": {"role_ids": [str(role_id)]}},
        ),
        (
            "POST",
            f"/api/v1/users/{target_user_id}/roles/unbind",
            {"json": {"role_ids": [str(role_id)]}},
        ),
    ]

    app.dependency_overrides[get_authorization_context] = unprivileged_context
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for method, path, kwargs in requests:
                response = await client.request(method, path, **kwargs)
                assert response.status_code == 403, (method, path, response.text)
                assert response.json() == {"detail": {"code": "access_forbidden"}}
    finally:
        app.dependency_overrides.clear()
