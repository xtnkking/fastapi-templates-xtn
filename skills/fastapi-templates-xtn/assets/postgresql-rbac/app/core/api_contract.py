import uuid
from collections.abc import Mapping
from enum import IntEnum
from typing import Any

from fastapi import Request
from fastapi.routing import APIRoute
from pydantic import UUID4, BaseModel, ConfigDict, Field
from starlette.datastructures import MutableHeaders

from app.core.i18n import (
    MessageKey,
    apply_language_headers,
    locale_for_request,
    translate,
)


class BusinessCode(IntEnum):
    OK = 200000
    CREATED = 201000
    BAD_REQUEST = 400001
    INVALID_AUTHENTICATION = 401001
    ACCESS_FORBIDDEN = 403001
    PASSWORD_CHANGE_REQUIRED = 403002
    NOT_FOUND = 404001
    METHOD_NOT_ALLOWED = 405001
    CONFLICT = 409001
    STALE_RESOURCE_VERSION = 409002
    PAYLOAD_TOO_LARGE = 413001
    UNSUPPORTED_MEDIA_TYPE = 415001
    VALIDATION_FAILED = 422001
    RATE_LIMITED = 429001
    INTERNAL_ERROR = 500000
    SERVICE_UNAVAILABLE = 503001


class ApiResponse[T](BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: int = Field(strict=True, ge=100000, le=599999)
    message: str = Field(min_length=1)
    data: T | None
    request_id: UUID4


class PageData[T](BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: list[T]
    page: int = Field(strict=True, ge=1)
    page_size: int = Field(strict=True, ge=1, le=200)
    total: int = Field(strict=True, ge=0)


class ValidationErrorItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    message: str


class ValidationErrorData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    errors: list[ValidationErrorItem]


REQUEST_ID_OPENAPI_HEADER: dict[str, Any] = {
    "description": "Server-generated request correlation ID",
    "schema": {"type": "string", "format": "uuid"},
}
NO_STORE_OPENAPI_HEADER: dict[str, Any] = {
    "description": "Prevents storage of security-sensitive error responses",
    "schema": {"type": "string", "enum": ["no-store"]},
}

RATE_LIMIT_OPENAPI_HEADERS: dict[str, dict[str, Any]] = {
    "Retry-After": {
        "description": "Whole seconds before the client should retry",
        "schema": {"type": "integer", "minimum": 1},
    },
    "RateLimit-Limit": {
        "description": "Burst capacity of the rate-limit policy that decided",
        "schema": {"type": "integer", "minimum": 1},
    },
    "RateLimit-Remaining": {
        "description": "Whole requests remaining in the deciding bucket",
        "schema": {"type": "integer", "minimum": 0},
    },
    "RateLimit-Reset": {
        "description": "Whole seconds until the deciding bucket is full",
        "schema": {"type": "integer", "minimum": 0},
    },
}


STANDARD_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status_code: {
        "model": ApiResponse[Any],
        "description": description,
        "headers": {
            "X-Request-ID": REQUEST_ID_OPENAPI_HEADER,
            "Cache-Control": NO_STORE_OPENAPI_HEADER,
        },
    }
    for status_code, description in {
        400: "Invalid request",
        401: "Authentication failed",
        403: "Operation forbidden",
        404: "Resource not found",
        405: "Method not allowed",
        409: "Resource state conflict",
        422: "Request validation failed",
        500: "Unexpected internal failure",
        503: "Required dependency unavailable",
    }.items()
}

RATE_LIMIT_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    429: {
        "model": ApiResponse[Any],
        "description": "Request rate limited",
        "headers": {
            "X-Request-ID": dict(REQUEST_ID_OPENAPI_HEADER),
            "Cache-Control": dict(NO_STORE_OPENAPI_HEADER),
            **{
                name: dict(definition)
                for name, definition in RATE_LIMIT_OPENAPI_HEADERS.items()
            },
        },
    }
}


class RequestIdRoute(APIRoute):
    """Declare the mandatory response header on success and error responses."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raw_responses = kwargs.get("responses")
        responses: dict[int | str, dict[str, Any]] = {}
        if isinstance(raw_responses, dict):
            responses = {
                key: dict(value)
                for key, value in raw_responses.items()
                if isinstance(value, dict)
            }

        raw_status_code = kwargs.get("status_code")
        success_status = raw_status_code if isinstance(raw_status_code, int) else 200
        responses.setdefault(success_status, {})
        for response in responses.values():
            headers = dict(response.get("headers") or {})
            headers.setdefault("X-Request-ID", dict(REQUEST_ID_OPENAPI_HEADER))
            response["headers"] = headers
        kwargs["responses"] = responses
        super().__init__(*args, **kwargs)


def request_id_for(request: Request) -> str:
    request_id = getattr(request.state, "request_id", None)
    try:
        parsed = uuid.UUID(request_id) if isinstance(request_id, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.version != 4 or str(parsed) != request_id:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
    return request_id


def request_id_headers(
    request: Request,
    headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    result = dict(headers or {})
    result["X-Request-ID"] = request_id_for(request)
    localized_headers = MutableHeaders(headers=result)
    apply_language_headers(localized_headers, locale_for_request(request))
    return dict(localized_headers.items())


def api_response[T](
    request: Request,
    *,
    code: BusinessCode,
    message_key: MessageKey,
    data: T | None,
) -> ApiResponse[T]:
    request.state.business_code = int(code)
    return ApiResponse(
        code=int(code),
        message=translate(request, message_key),
        data=data,
        request_id=uuid.UUID(request_id_for(request)),
    )


def error_content(
    request: Request,
    *,
    code: int | BusinessCode,
    message_key: MessageKey,
    data: Any = None,
) -> dict[str, Any]:
    request.state.business_code = int(code)
    response = ApiResponse[Any](
        code=int(code),
        message=translate(request, message_key),
        data=data,
        request_id=uuid.UUID(request_id_for(request)),
    )
    return response.model_dump(mode="json")


def generic_error_code(status_code: int) -> int:
    """Return the centrally reserved generic code for an uncommon HTTP error."""
    if not 400 <= status_code <= 599:
        raise ValueError("generic error codes require an HTTP 4xx or 5xx status")
    if status_code == 500:
        return int(BusinessCode.INTERNAL_ERROR)
    return status_code * 1000 + 1
