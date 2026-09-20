import asyncio
import json

import pytest
from fastapi.exceptions import RequestValidationError
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response

from app.api_contract import BusinessCode
from app.i18n import (
    CATALOGS,
    DEFAULT_LOCALE,
    SUPPORTED_LOCALES,
    MessageKey,
    apply_language_headers,
    select_locale,
)
from app.main import (
    app,
    handle_access_error,
    handle_database_unavailable,
    handle_http_error,
    handle_rate_limit_exceeded,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.rate_limit import RateLimitResult
from app.rate_limit_dependencies import RateLimitExceeded
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    password_change_required,
    stale_resource_version,
    unauthenticated,
    unavailable,
)


def _request(*, accept_language: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if accept_language is not None:
        headers.append((b"accept-language", accept_language.encode("latin-1")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/controlled-test",
            "headers": headers,
        }
    )


def _body(response: Response) -> dict[str, object]:
    raw_body = response.body
    assert isinstance(raw_body, bytes)
    parsed = json.loads(raw_body)
    assert isinstance(parsed, dict)
    return parsed


def test_catalogs_are_complete_bounded_and_safe() -> None:
    expected_keys = {key.value for key in MessageKey}

    assert DEFAULT_LOCALE == "zh-CN"
    assert SUPPORTED_LOCALES == ("zh-CN", "en")
    assert set(CATALOGS) == set(SUPPORTED_LOCALES)
    for catalog in CATALOGS.values():
        assert set(catalog) == expected_keys
        assert all(value == value.strip() for value in catalog.values())
        assert all(0 < len(value) <= 200 for value in catalog.values())
        assert all(
            "\r" not in value
            and "\n" not in value
            and not any(ord(character) < 32 for character in value)
            for value in catalog.values()
        )


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, "zh-CN"),
        ("", "zh-CN"),
        ("   ", "zh-CN"),
        ("*", "zh-CN"),
        ("zh", "zh-CN"),
        ("ZH-cn", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("en", "en"),
        ("EN-us", "en"),
        ("fr", "zh-CN"),
        ("fr;q=1, en;q=.8", "en"),
        ("en;q=.4, zh-CN;q=.9", "zh-CN"),
        ("en;q=.8, zh-CN;q=.8", "en"),
        ("en;q=0, zh-CN;q=.2", "zh-CN"),
        ("zh-CN;q=0, *;q=1", "en"),
        ("zh-CN;q=0, zh;q=1", "en"),
        ("zh;q=0, *;q=1", "en"),
        ("zh;q=0", "en"),
        ("en;q=0, *;q=1", "zh-CN"),
        ("zh;q=0, en;q=0", "zh-CN"),
        ("*;q=1, en;q=1", "en"),
        ("en-US;q=.1, en-GB;q=1, zh;q=.5", "en"),
        ("en;q=not-a-number, zh-CN;q=.2", "zh-CN"),
        ("en;q=NaN", "zh-CN"),
        ("en;q=Infinity", "zh-CN"),
        ("en;q=-1", "zh-CN"),
        ("en;q=2", "zh-CN"),
        (",".join(["fr"] * 19 + ["en"]), "en"),
        (",".join(["fr"] * 20 + ["en"]), "zh-CN"),
    ],
)
def test_accept_language_negotiation(header: str | None, expected: str) -> None:
    assert select_locale(header) == expected


@pytest.mark.parametrize(
    "malicious_header",
    [
        "en\x00zh-CN",
        "../../en",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "en\u202ezh-CN",
        "en," * 300,
        "en;q=" + "9" * 600,
    ],
)
def test_untrusted_language_values_never_escape_supported_locales(
    malicious_header: str,
) -> None:
    assert select_locale(malicious_header) == DEFAULT_LOCALE


def test_language_headers_preserve_existing_vary_once() -> None:
    message: dict[str, object] = {
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"vary", b"Origin, Accept-Encoding")],
    }
    headers = MutableHeaders(scope=message)

    apply_language_headers(headers, "en")
    apply_language_headers(headers, "en")

    assert headers["Content-Language"] == "en"
    vary = [part.strip().casefold() for part in headers["Vary"].split(",")]
    assert vary == ["origin", "accept-encoding", "accept-language"]


@pytest.mark.parametrize(
    ("accept_language", "expected_locale", "expected_message"),
    [
        (None, "zh-CN", "服务正常"),
        ("zh-CN", "zh-CN", "服务正常"),
        ("en", "en", "Service is live"),
        ("fr;q=1,en-US;q=.8", "en", "Service is live"),
    ],
)
async def test_http_response_localizes_only_human_message(
    accept_language: str | None,
    expected_locale: str,
    expected_message: str,
) -> None:
    headers = {"Accept-Language": accept_language} if accept_language else None
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health/live", headers=headers)

    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(BusinessCode.OK)
    assert body["message"] == expected_message
    assert body["data"] == {"status": "ok"}
    assert response.headers["Content-Language"] == expected_locale
    assert [
        item.strip().casefold() for item in response.headers["Vary"].split(",")
    ].count("accept-language") == 1
    assert response.headers["X-Request-ID"] == body["request_id"]


async def test_concurrent_requests_do_not_share_locale() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        responses = await asyncio.gather(
            *(
                client.get(
                    "/health/live",
                    headers={"Accept-Language": "en" if index % 2 else "zh-CN"},
                )
                for index in range(20)
            )
        )

    for index, response in enumerate(responses):
        expected_locale = "en" if index % 2 else "zh-CN"
        expected_message = "Service is live" if index % 2 else "服务正常"
        assert response.headers["Content-Language"] == expected_locale
        assert response.json()["message"] == expected_message


async def test_validation_outer_and_field_messages_are_localized() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        zh_response, en_response = await asyncio.gather(
            client.post("/api/v1/auth/login", json={}),
            client.post(
                "/api/v1/auth/login",
                json={},
                headers={"Accept-Language": "en"},
            ),
        )

    zh_body = zh_response.json()
    en_body = en_response.json()
    assert zh_response.status_code == en_response.status_code == 422
    assert zh_body["code"] == en_body["code"] == int(BusinessCode.VALIDATION_FAILED)
    assert zh_body["message"] == "请求参数校验失败"
    assert en_body["message"] == "Request validation failed"
    assert {error["message"] for error in zh_body["data"]["errors"]} == {
        "此字段为必填项"
    }
    assert {error["message"] for error in en_body["data"]["errors"]} == {
        "This field is required"
    }
    assert [error["field"] for error in zh_body["data"]["errors"]] == [
        error["field"] for error in en_body["data"]["errors"]
    ]
    assert zh_response.headers["Content-Language"] == "zh-CN"
    assert en_response.headers["Content-Language"] == "en"


async def test_custom_and_unknown_validation_types_do_not_echo_raw_messages() -> None:
    request = _request(accept_language="en")
    response = await handle_request_validation_error(
        request,
        RequestValidationError(
            [
                {
                    "type": "username_reserved",
                    "loc": ("body", "user_name"),
                    "msg": "raw framework message",
                    "input": "admin",
                },
                {
                    "type": "future_unknown_type",
                    "loc": ("body", "password"),
                    "msg": "sensitive raw detail",
                    "input": "secret-value",
                },
            ]
        ),
    )

    rendered = str(_body(response))
    assert "This username cannot be used" in rendered
    assert "Invalid value" in rendered
    assert "raw framework message" not in rendered
    assert "sensitive raw detail" not in rendered
    assert "secret-value" not in rendered


async def test_validation_fields_do_not_echo_untrusted_keys() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        extra_field_response = await client.post(
            "/api/v1/auth/login",
            json={"leaked-secret-as-key": "do-not-reflect"},
            headers={"Accept-Language": "en"},
        )

    extra_field_rendered = extra_field_response.text
    assert extra_field_response.status_code == 422
    assert "leaked-secret-as-key" not in extra_field_rendered
    assert "do-not-reflect" not in extra_field_rendered

    nested_key_response = await handle_request_validation_error(
        _request(accept_language="en"),
        RequestValidationError(
            [
                {
                    "type": "int_parsing",
                    "loc": ("body", "metadata", "private-dict-key"),
                    "msg": "private raw message",
                    "input": "private-value",
                }
            ]
        ),
    )
    nested_body = _body(nested_key_response)
    assert nested_body["data"] == {
        "errors": [{"field": "body.metadata", "message": "Must be an integer"}]
    }
    assert "private-dict-key" not in str(nested_body)
    assert "private raw message" not in str(nested_body)
    assert "private-value" not in str(nested_body)


async def test_domain_rate_limit_database_and_unexpected_errors_translate() -> None:
    request = _request(accept_language="en")
    domain = await handle_access_error(request, forbidden("private_reason"))
    limited = await handle_rate_limit_exceeded(
        request,
        RateLimitExceeded(
            policy_name="private_policy",
            result=RateLimitResult(
                allowed=False,
                limit=5,
                remaining=0,
                retry_after_ms=1_001,
                reset_after_ms=2_000,
            ),
        ),
    )
    unavailable = await handle_database_unavailable(
        request,
        OperationalError("private statement", {}, RuntimeError("offline")),
    )
    unexpected = await handle_unexpected_error(request, RuntimeError("private"))

    assert _body(domain)["message"] == "You are not allowed to perform this operation"
    assert _body(limited)["message"] == "Too many requests; try again later"
    assert _body(unavailable)["message"] == "Service temporarily unavailable"
    assert _body(unexpected)["message"] == "Internal server error"
    combined = " ".join(
        str(_body(response)) for response in (domain, limited, unavailable, unexpected)
    )
    assert "private_reason" not in combined
    assert "private_policy" not in combined
    assert "private statement" not in combined


@pytest.mark.parametrize(
    ("error", "status_code", "business_code", "english_message"),
    [
        (
            unauthenticated("private"),
            401,
            BusinessCode.INVALID_AUTHENTICATION,
            "Authentication failed",
        ),
        (
            forbidden("private"),
            403,
            BusinessCode.ACCESS_FORBIDDEN,
            "You are not allowed to perform this operation",
        ),
        (
            password_change_required("private"),
            403,
            BusinessCode.PASSWORD_CHANGE_REQUIRED,
            "You must change your password first",
        ),
        (not_found("private"), 404, BusinessCode.NOT_FOUND, "Resource not found"),
        (
            conflict("private"),
            409,
            BusinessCode.CONFLICT,
            "The current resource state conflicts with this operation",
        ),
        (
            stale_resource_version("private"),
            409,
            BusinessCode.STALE_RESOURCE_VERSION,
            "The resource was updated; refresh and try again",
        ),
        (
            invalid_request("private"),
            400,
            BusinessCode.BAD_REQUEST,
            "Invalid request",
        ),
        (
            unavailable("private"),
            503,
            BusinessCode.SERVICE_UNAVAILABLE,
            "Service temporarily unavailable",
        ),
    ],
)
async def test_all_domain_error_categories_translate_by_key(
    error: RbacError,
    status_code: int,
    business_code: BusinessCode,
    english_message: str,
) -> None:
    response = await handle_access_error(_request(accept_language="en"), error)

    body = _body(response)
    assert response.status_code == status_code
    assert body["code"] == int(business_code)
    assert body["message"] == english_message
    assert "private" not in str(body)


@pytest.mark.parametrize(
    ("status_code", "business_code", "english_message"),
    [
        (400, BusinessCode.BAD_REQUEST, "Invalid request"),
        (401, BusinessCode.INVALID_AUTHENTICATION, "Authentication failed"),
        (
            403,
            BusinessCode.ACCESS_FORBIDDEN,
            "You are not allowed to perform this operation",
        ),
        (404, BusinessCode.NOT_FOUND, "Resource not found"),
        (405, BusinessCode.METHOD_NOT_ALLOWED, "Method not allowed"),
        (
            409,
            BusinessCode.CONFLICT,
            "The current resource state conflicts with this operation",
        ),
        (413, BusinessCode.PAYLOAD_TOO_LARGE, "Request content is too large"),
        (415, BusinessCode.UNSUPPORTED_MEDIA_TYPE, "Unsupported request media type"),
        (422, BusinessCode.VALIDATION_FAILED, "Request validation failed"),
        (429, BusinessCode.RATE_LIMITED, "Too many requests"),
        (500, BusinessCode.INTERNAL_ERROR, "Internal server error"),
        (503, BusinessCode.SERVICE_UNAVAILABLE, "Service temporarily unavailable"),
    ],
)
async def test_framework_error_catalog_is_complete(
    status_code: int,
    business_code: BusinessCode,
    english_message: str,
) -> None:
    response = await handle_http_error(
        _request(accept_language="en"),
        StarletteHTTPException(status_code=status_code),
    )

    body = _body(response)
    assert response.status_code == status_code
    assert body["code"] == int(business_code)
    assert body["message"] == english_message


async def test_missing_bearer_token_uses_english_and_keeps_security_headers() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/me/access", headers={"Accept-Language": "en"}
        )

    assert response.status_code == 401
    assert response.json()["code"] == int(BusinessCode.INVALID_AUTHENTICATION)
    assert response.json()["message"] == "Authentication failed"
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Content-Language"] == "en"


async def test_framework_404_and_405_are_localized_without_contract_changes() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing, method = await asyncio.gather(
            client.get("/not-present", headers={"Accept-Language": "en"}),
            client.post("/health/live", headers={"Accept-Language": "en"}),
        )

    assert missing.status_code == 404
    assert missing.json()["code"] == int(BusinessCode.NOT_FOUND)
    assert missing.json()["message"] == "Resource not found"
    assert method.status_code == 405
    assert method.json()["code"] == int(BusinessCode.METHOD_NOT_ALLOWED)
    assert method.json()["message"] == "Method not allowed"


async def test_unhandled_500_keeps_language_headers() -> None:
    from app.rbac.dependencies import get_authorization_context

    async def explode() -> None:
        raise RuntimeError("private-unhandled-failure")

    app.dependency_overrides[get_authorization_context] = explode
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/me/access",
                headers={"Accept-Language": "en"},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error"
    assert response.headers["Content-Language"] == "en"
    assert [
        item.strip().casefold() for item in response.headers["Vary"].split(",")
    ].count("accept-language") == 1
