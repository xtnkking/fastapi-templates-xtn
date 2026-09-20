import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient, Response
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

import app.rbac.api as rbac_api_module
from app.abuse_flow import InvalidLoginCredentialsError
from app.api_contract import ApiResponse, BusinessCode, PageData
from app.database import get_session
from app.main import (
    app,
    handle_database_unavailable,
    handle_http_error,
    handle_invalid_login_credentials,
    handle_rate_limit_exceeded,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.rate_limit import RateLimitResult
from app.rate_limit_dependencies import RateLimitExceeded
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
    conflict,
    forbidden,
    invalid_request,
    not_found,
    stale_resource_version,
    unauthenticated,
    unavailable,
)
from app.rbac.schemas import (
    RoleMutationResponse,
    RoleResponse,
    UserResponse,
    UserRoleMutationResponse,
)
from app.rbac.service import get_rbac_service

REQUIRED_ROUTES = {
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/users/{user_id}/sessions/revoke"),
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
}


def _public_routes() -> list[APIRoute]:
    return [
        route
        for route in public_router.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1")
    ]


def assert_standard_response(
    response: Response,
    *,
    status_code: int,
    business_code: BusinessCode,
) -> dict[str, Any]:
    assert response.status_code == status_code
    body: dict[str, Any] = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert type(body["code"]) is int
    assert body["code"] == int(business_code)
    assert body["code"] // 1000 == status_code
    request_id = uuid.UUID(body["request_id"])
    assert request_id.version == 4
    assert response.headers["X-Request-ID"] == body["request_id"]
    return body


def test_public_contract_contains_required_routes_and_only_get_or_post() -> None:
    routes = _public_routes()
    actual = {
        (method, route.path) for route in routes for method in route.methods or set()
    }

    assert REQUIRED_ROUTES <= actual
    assert {method for method, _path in actual} <= {"GET", "POST"}


async def test_user_name_query_normalizes_before_exact_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=actor_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(
            RoleGrant(
                role_id=uuid.uuid4(),
                key="user-reader",
                management_tier=1,
                permissions=frozenset({PermissionKey.USERS_READ.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="user-name-query-test",
    )
    received_user_names: list[str | None] = []

    async def current_context() -> AuthorizationContext:
        return context

    async def current_session() -> object:
        return object()

    async def list_users_page(
        *_args: Any,
        **kwargs: Any,
    ) -> tuple[tuple[Any, ...], int]:
        received_user_names.append(kwargs["user_name"])
        return (), 0

    async def load_access_views(*_args: Any, **_kwargs: Any) -> dict[Any, Any]:
        return {}

    monkeypatch.setattr(
        rbac_api_module,
        "list_visible_users_page",
        list_users_page,
    )
    monkeypatch.setattr(
        rbac_api_module,
        "load_user_access_views",
        load_access_views,
    )
    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_session] = current_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            normalized = await client.get(
                "/api/v1/users",
                params={"user_name": "  Alice_1  "},
            )
            invalid = await client.get(
                "/api/v1/users",
                params={"user_name": "  Alice-1  "},
            )
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        normalized,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert normalized.json()["data"] == {
        "items": [],
        "page": 1,
        "page_size": 20,
        "total": 0,
    }
    assert received_user_names == ["Alice_1"]
    assert_standard_response(
        invalid,
        status_code=422,
        business_code=BusinessCode.VALIDATION_FAILED,
    )


async def test_admin_session_revocation_uses_authoritative_context() -> None:
    user_id = uuid.uuid4()
    target_id = uuid.uuid4()
    context = AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_version=3,
            token_id=uuid.uuid4(),
            issued_at=1,
            expires_at=2,
        ),
        authorization_epoch=4,
        authority=AuthoritySnapshot.build(
            user_id=user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=3,
            authz_version=5,
            roles=(
                RoleGrant(
                    role_id=uuid.uuid4(),
                    key="session_manager",
                    management_tier=100,
                    permissions=frozenset({PermissionKey.USERS_SESSIONS_REVOKE.value}),
                    is_system=False,
                    is_protected=False,
                    is_super_admin=False,
                ),
            ),
        ),
        request_id=str(uuid.uuid4()),
    )
    revoke_all = AsyncMock()

    async def current_context() -> AuthorizationContext:
        return context

    class RevocationService:
        revoke_user_sessions = revoke_all

    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_rbac_service] = RevocationService
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(f"/api/v1/users/{target_id}/sessions/revoke")
    finally:
        app.dependency_overrides.clear()

    body = assert_standard_response(
        response,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert body["data"] == {"changed": True}
    assert revoke_all.await_count == 1
    awaited_call = revoke_all.await_args
    assert awaited_call is not None
    assert awaited_call.kwargs["context"] is context
    assert awaited_call.kwargs["target_user_id"] == target_id


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
        stale_resource_version("test"),
    ]
    assert all(
        "rbac" not in error.message_key.value.casefold() for error in public_errors
    )

    semantic_error = invalid_request("test")
    assert semantic_error.status_code == 400
    assert semantic_error.business_code == BusinessCode.BAD_REQUEST


def test_removed_capabilities_are_not_seeded_or_exposed() -> None:
    assert "super_admin:transfer" not in {
        permission.value for permission in PermissionKey
    }
    assert "roles:delegation:update" not in {
        permission.value for permission in PermissionKey
    }
    paths = app.openapi()["paths"]
    assert "/api/v1/system/super-admin/transfer" not in paths
    assert not any("delegable-permissions" in path for path in paths)


def test_public_response_schemas_include_management_state() -> None:
    schemas = app.openapi()["components"]["schemas"]

    response_schema = schemas["ApiResponse_Any_"]
    assert response_schema["additionalProperties"] is False
    assert set(response_schema["properties"]) == {
        "code",
        "message",
        "data",
        "request_id",
    }
    page_schema = schemas["PageData_RoleResponse_"]
    assert page_schema["additionalProperties"] is False
    assert set(page_schema["properties"]) == {
        "items",
        "page",
        "page_size",
        "total",
    }
    assert "id" in schemas["PermissionResponse"]["properties"]
    assert {
        "description",
        "deleted_at",
    } <= schemas["RoleResponse"]["properties"].keys()
    assert "is_super_admin" not in schemas["RoleResponse"]["properties"]
    assert "changed" in schemas["RoleMutationResponse"]["properties"]
    assert "permissions" not in schemas["RoleCreateRequest"]["properties"]
    assert "expected_version" in schemas["RoleUpdateRequest"]["required"]
    assert "expected_version" in schemas["RoleVersionRequest"]["required"]
    assert "expected_version" in schemas["PermissionIdsRequest"]["required"]
    role_update_schema = schemas["RoleUpdateRequest"]
    assert role_update_schema["anyOf"] == [
        {"required": ["name"]},
        {"required": ["description"]},
    ]
    assert role_update_schema["properties"]["name"]["type"] == "string"
    assert role_update_schema["properties"]["description"]["type"] == "string"

    role_list_responses = app.openapi()["paths"]["/api/v1/roles"]["get"]["responses"]
    assert role_list_responses["422"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ApiResponse_Any_"
    }
    assert "/api/v1/system/super-admin/transfer" not in app.openapi()["paths"]
    assert "/api/v1/auth/logout-all" not in app.openapi()["paths"]
    assert not any("delegable-permissions" in path for path in app.openapi()["paths"])


def test_openapi_declares_request_id_on_every_public_response() -> None:
    schema = app.openapi()

    for path_item in schema["paths"].values():
        for method in ("get", "post"):
            operation = path_item.get(method)
            if operation is None:
                continue
            assert not {"413", "415"} & operation["responses"].keys()
            rate_limited = operation["responses"]["429"]
            assert {
                "X-Request-ID",
                "Retry-After",
                "RateLimit-Limit",
                "RateLimit-Remaining",
                "RateLimit-Reset",
            } <= rate_limited["headers"].keys()
            for response in operation["responses"].values():
                request_id = response["headers"]["X-Request-ID"]
                assert request_id["schema"] == {
                    "type": "string",
                    "format": "uuid",
                }


def test_response_models_reject_coercion_and_extra_fields() -> None:
    request_id = str(uuid.uuid4())
    valid = {
        "code": 200000,
        "message": "ok",
        "data": None,
        "request_id": request_id,
    }

    assert ApiResponse[dict[str, object]].model_validate(valid).code == 200000
    with pytest.raises(ValidationError):
        ApiResponse[dict[str, object]].model_validate({**valid, "code": "200000"})
    with pytest.raises(ValidationError):
        ApiResponse[dict[str, object]].model_validate({**valid, "extra": True})
    with pytest.raises(ValidationError):
        PageData[int].model_validate(
            {"items": [], "page": 1, "page_size": 20, "total": 0, "extra": True}
        )


def test_role_mutations_document_expected_version_in_the_body() -> None:
    paths = app.openapi()["paths"]

    for path in ROLE_MUTATION_PATHS:
        operation = paths[path]["post"]
        assert not any(
            parameter["name"].casefold() == "if-match"
            for parameter in operation.get("parameters", [])
        )
        assert operation["requestBody"]["required"] is True


def test_numeric_business_codes_match_their_http_prefix() -> None:
    values = [int(code) for code in BusinessCode]

    assert len(values) == len(set(values))
    assert all(100000 <= value <= 599999 for value in values)
    assert int(BusinessCode.STALE_RESOURCE_VERSION) == 409002


async def test_success_uses_server_request_id_in_body_and_header() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/health/live",
            headers={"X-Request-ID": "caller-controlled"},
        )

    body = assert_standard_response(
        response,
        status_code=200,
        business_code=BusinessCode.OK,
    )
    assert body["request_id"] != "caller-controlled"
    assert body["data"] == {"status": "ok"}


async def test_framework_404_and_405_use_the_standard_envelope() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.get("/not-present")
        wrong_method = await client.post("/health/live")

    assert_standard_response(
        missing,
        status_code=404,
        business_code=BusinessCode.NOT_FOUND,
    )
    assert_standard_response(
        wrong_method,
        status_code=405,
        business_code=BusinessCode.METHOD_NOT_ALLOWED,
    )


async def test_uncommon_framework_error_preserves_its_real_http_status() -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/controlled-test",
            "headers": [],
        }
    )

    response = await handle_http_error(
        request,
        StarletteHTTPException(status_code=418),
    )

    assert response.status_code == 418
    body = json.loads(bytes(response.body))
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == 418001
    assert body["code"] // 1000 == response.status_code
    assert response.headers["X-Request-ID"] == body["request_id"]


@pytest.mark.parametrize(
    ("status_code", "business_code"),
    [
        (401, BusinessCode.INVALID_AUTHENTICATION),
        (500, BusinessCode.INTERNAL_ERROR),
    ],
)
async def test_framework_error_uses_registered_contract(
    status_code: int,
    business_code: BusinessCode,
) -> None:
    request = Request(
        {"type": "http", "method": "GET", "path": "/controlled-test", "headers": []}
    )

    response = await handle_http_error(
        request,
        StarletteHTTPException(status_code=status_code),
    )

    assert response.status_code == status_code
    body = json.loads(bytes(response.body))
    assert body["code"] == int(business_code)
    assert body["code"] // 1000 == status_code
    if status_code == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_database_operational_error_is_dependency_unavailable() -> None:
    request = Request(
        {"type": "http", "method": "GET", "path": "/controlled-test", "headers": []}
    )
    error = OperationalError("controlled statement", {}, RuntimeError("offline"))

    response = await handle_database_unavailable(request, error)

    assert response.status_code == 503
    body = json.loads(bytes(response.body))
    assert body["code"] == int(BusinessCode.SERVICE_UNAVAILABLE)
    assert "controlled statement" not in str(body)
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert response.headers["Cache-Control"] == "no-store"


async def test_semantic_rate_limit_exposes_deciding_result_not_bucket_identity() -> (
    None
):
    request = Request(
        {"type": "http", "method": "POST", "path": "/api/v1/login", "headers": []}
    )
    error = RateLimitExceeded(
        policy_name="login_pair",
        result=RateLimitResult(
            allowed=False,
            limit=5,
            remaining=0,
            retry_after_ms=1_001,
            reset_after_ms=900_000,
        ),
    )

    response = await handle_rate_limit_exceeded(request, error)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "2"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["RateLimit-Limit"] == "5"
    assert response.headers["RateLimit-Remaining"] == "0"
    assert response.headers["RateLimit-Reset"] == "900"
    assert "login_pair" not in str(response.headers).casefold()


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (
            handle_request_validation_error,
            RequestValidationError([]),
        ),
        (handle_http_error, StarletteHTTPException(status_code=400)),
        (handle_unexpected_error, RuntimeError("controlled failure")),
    ],
)
async def test_global_error_handlers_prevent_sensitive_response_caching(
    handler: Any,
    error: BaseException,
) -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [],
        }
    )

    response = await handler(request, error)

    assert response.headers["Cache-Control"] == "no-store"


async def test_invalid_login_credentials_use_one_non_leaking_contract() -> None:
    request = Request(
        {"type": "http", "method": "POST", "path": "/api/v1/login", "headers": []}
    )

    response = await handle_invalid_login_credentials(
        request,
        InvalidLoginCredentialsError(),
    )

    assert response.status_code == 401
    body = json.loads(bytes(response.body))
    assert body["code"] == int(BusinessCode.INVALID_AUTHENTICATION)
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"] == body["request_id"]


@pytest.mark.parametrize("expected_version", ["1", 1.0, True])
async def test_role_mutation_rejects_coerced_expected_version(
    expected_version: object,
) -> None:
    actor_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=actor_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(
            RoleGrant(
                role_id=uuid.uuid4(),
                key="status-manager",
                management_tier=100,
                permissions=frozenset({PermissionKey.ROLES_STATUS_UPDATE.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="strict-version-test",
    )

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/roles/{uuid.uuid4()}/disable",
                json={"expected_version": expected_version},
            )
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        response,
        status_code=422,
        business_code=BusinessCode.VALIDATION_FAILED,
    )


async def test_validation_and_unexpected_errors_use_the_standard_envelope() -> None:
    actor_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=actor_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(
            RoleGrant(
                role_id=uuid.uuid4(),
                key="reader",
                management_tier=1,
                permissions=frozenset({PermissionKey.ROLES_READ.value}),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="overridden-context",
    )

    async def current_context() -> AuthorizationContext:
        return context

    app.dependency_overrides[get_authorization_context] = current_context
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            invalid = await client.get("/api/v1/roles/not-a-uuid")
    finally:
        app.dependency_overrides.clear()

    validation_body = assert_standard_response(
        invalid,
        status_code=422,
        business_code=BusinessCode.VALIDATION_FAILED,
    )
    assert validation_body["data"]["errors"]

    async def explode() -> AuthorizationContext:
        raise RuntimeError("controlled-test-failure")

    app.dependency_overrides[get_authorization_context] = explode
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            failed = await client.get("/api/v1/me/access")
    finally:
        app.dependency_overrides.clear()

    assert_standard_response(
        failed,
        status_code=500,
        business_code=BusinessCode.INTERNAL_ERROR,
    )


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
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
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
            permissions=("projects:read",),
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
                json={"expected_version": 7},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "etag" not in response.headers
    assert response.json()["data"]["role"]["permissions"] == ["projects:read"]
    assert response.json()["data"]["role"]["deleted_at"] is not None


async def test_user_write_routes_use_service_transaction_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_id = uuid.uuid4()
    target_user_id = uuid.uuid4()
    role_id = uuid.uuid4()
    authority = AuthoritySnapshot.build(
        user_id=actor_id,
        user_is_active=True,
        user_is_protected=False,
        authz_version=0,
        roles=(
            RoleGrant(
                role_id=uuid.uuid4(),
                key="user-manager",
                management_tier=100,
                permissions=frozenset(
                    {
                        PermissionKey.ROLES_ASSIGN.value,
                        PermissionKey.ROLES_REVOKE.value,
                        PermissionKey.USERS_STATUS_UPDATE.value,
                    }
                ),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
            ),
        ),
    )
    context = AuthorizationContext(
        principal=Principal(
            user_id=actor_id,
            token_version=0,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id="user-transaction-snapshot-test",
    )
    active_user = UserResponse(
        id=target_user_id,
        user_name="managed_user",
        is_active=True,
        assigned_role_ids=(role_id,),
        effective_role_ids=(role_id,),
        effective_management_tier=10,
        effective_permissions=(PermissionKey.PROJECTS_READ.value,),
        authz_version=7,
    )
    role_mutation = UserRoleMutationResponse(changed=True, user=active_user)
    disabled_user = active_user.model_copy(
        update={"is_active": False, "authz_version": 8}
    )
    enabled_user = active_user.model_copy(update={"authz_version": 9})

    class SnapshotService:
        def __init__(self) -> None:
            self.change_user_roles = AsyncMock(
                side_effect=(role_mutation, role_mutation)
            )
            self.update_user_status = AsyncMock(
                side_effect=(disabled_user, enabled_user)
            )

    service = SnapshotService()

    async def current_context() -> AuthorizationContext:
        return context

    def snapshot_service() -> SnapshotService:
        return service

    post_transaction_reload = AsyncMock(
        side_effect=AssertionError(
            "user write route reloaded state after service return"
        )
    )
    monkeypatch.setattr(
        "app.rbac.api.load_user_access_views",
        post_transaction_reload,
    )
    app.dependency_overrides[get_authorization_context] = current_context
    app.dependency_overrides[get_rbac_service] = snapshot_service
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            bound = await client.post(
                f"/api/v1/users/{target_user_id}/roles/bind",
                json={"role_ids": [str(role_id)]},
            )
            unbound = await client.post(
                f"/api/v1/users/{target_user_id}/roles/unbind",
                json={"role_ids": [str(role_id)]},
            )
            disabled = await client.post(f"/api/v1/users/{target_user_id}/disable")
            enabled = await client.post(f"/api/v1/users/{target_user_id}/enable")
    finally:
        app.dependency_overrides.clear()

    assert [
        response.status_code for response in (bound, unbound, disabled, enabled)
    ] == [
        200,
        200,
        200,
        200,
    ]
    assert bound.json()["data"] == json.loads(role_mutation.model_dump_json())
    assert unbound.json()["data"] == json.loads(role_mutation.model_dump_json())
    assert disabled.json()["data"] == json.loads(disabled_user.model_dump_json())
    assert enabled.json()["data"] == json.loads(enabled_user.model_dump_json())
    post_transaction_reload.assert_not_awaited()

    role_calls = service.change_user_roles.await_args_list
    assert [item.kwargs["operation"] for item in role_calls] == ["bind", "unbind"]
    assert all(item.kwargs["context"] is context for item in role_calls)
    assert all(item.kwargs["target_user_id"] == target_user_id for item in role_calls)
    assert all(item.kwargs["role_ids"] == [role_id] for item in role_calls)

    status_calls = service.update_user_status.await_args_list
    assert [item.kwargs["request"].is_active for item in status_calls] == [False, True]
    assert all(item.kwargs["context"] is context for item in status_calls)
    assert all(item.kwargs["target_user_id"] == target_user_id for item in status_calls)


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
            issued_at=0,
            expires_at=1,
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
            {"json": {"name": "Renamed", "expected_version": 1}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/disable",
            {"json": {"expected_version": 1}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/enable",
            {"json": {"expected_version": 1}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/delete",
            {"json": {"expected_version": 1}},
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/permissions/bind",
            {
                "json": {
                    "permission_ids": [str(permission_id)],
                    "expected_version": 1,
                },
            },
        ),
        (
            "POST",
            f"/api/v1/roles/{role_id}/permissions/unbind",
            {
                "json": {
                    "permission_ids": [str(permission_id)],
                    "expected_version": 1,
                },
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
        ("POST", f"/api/v1/users/{target_user_id}/sessions/revoke", {}),
    ]

    app.dependency_overrides[get_authorization_context] = unprivileged_context
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for method, path, kwargs in requests:
                response = await client.request(method, path, **kwargs)
                assert response.status_code == 403, (method, path, response.text)
                body = response.json()
                assert set(body) == {"code", "message", "data", "request_id"}
                assert body["code"] == 403001
                assert body["data"] is None
                assert response.headers["X-Request-ID"] == body["request_id"]
    finally:
        app.dependency_overrides.clear()
