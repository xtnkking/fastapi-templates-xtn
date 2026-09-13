import json
import logging
import uuid
from typing import Protocol, cast

from httpx import ASGITransport, AsyncClient

from app.main import app
from app.observability import (
    SafeJsonFormatter,
    bind_request_context,
    current_request_id,
    request_log_level,
    reset_request_context,
)


class CompletionRecord(Protocol):
    request_id: str
    http_status_code: int
    business_code: int
    route: str
    outcome: str
    exception_type: str


def formatter(*, include_exception_details: bool = False) -> SafeJsonFormatter:
    return SafeJsonFormatter(
        service_name="example-service",
        service_version="test",
        environment="test",
        include_exception_details=include_exception_details,
    )


def test_json_log_contains_stable_context_and_redacts_nested_secrets() -> None:
    request_id = str(uuid.uuid4())
    token = bind_request_context(request_id)
    try:
        record = logging.LogRecord(
            name="app.example",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="user.access.checked",
            args=(),
            exc_info=None,
        )
        record.actor_user_id = str(uuid.uuid4())
        record.details = {
            "authorization": "Bearer raw-token",
            "nested": {"password": "raw-password", "safe": "kept"},
        }
        rendered = formatter().format(record)
    finally:
        reset_request_context(token)

    payload = json.loads(rendered)
    assert payload["event"] == "user.access.checked"
    assert payload["request_id"] == request_id
    assert payload["service"] == "example-service"
    assert payload["details"]["authorization"] == "[REDACTED]"
    assert payload["details"]["nested"] == {
        "password": "[REDACTED]",
        "safe": "kept",
    }
    assert "raw-token" not in rendered
    assert "raw-password" not in rendered
    assert current_request_id() is None


def test_formatter_does_not_stringify_unknown_objects() -> None:
    record = logging.LogRecord(
        name="app.example",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="safe.event",
        args=(),
        exc_info=None,
    )
    record.unknown = object()

    payload = json.loads(formatter().format(record))

    assert payload["unknown"] == "[UNSUPPORTED]"


def test_invalid_log_message_omits_bearer_and_url_credentials() -> None:
    record = logging.LogRecord(
        name="app.example",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="failed Bearer secret-token at https://user:password@example.test/path",
        args=(),
        exc_info=None,
    )

    rendered = formatter().format(record)

    assert "secret-token" not in rendered
    assert "user:password" not in rendered
    assert "failed Bearer" not in rendered
    assert "[OMITTED]" in rendered


def test_status_code_selects_operational_log_level() -> None:
    assert request_log_level(200) == logging.INFO
    assert request_log_level(404) == logging.WARNING
    assert request_log_level(503) == logging.ERROR


async def test_request_completion_log_uses_response_request_id() -> None:
    records: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = CaptureHandler()
    async with app.router.lifespan_context(app):
        application_logger = logging.getLogger("app")
        application_logger.addHandler(handler)
        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                response = await client.get(
                    "/health/live",
                    headers={"X-Request-ID": "caller-controlled"},
                )
        finally:
            application_logger.removeHandler(handler)

    completion = [
        record for record in records if record.msg == "http.request.completed"
    ]
    assert len(completion) == 1
    completion_record = cast(CompletionRecord, completion[0])
    request_id = response.json()["request_id"]
    assert request_id != "caller-controlled"
    assert completion_record.request_id == request_id
    assert completion_record.http_status_code == 200
    assert completion_record.business_code == 200000
    assert completion_record.route == "/health/live"
    assert current_request_id() is None


async def test_unexpected_error_emits_one_final_completion_event() -> None:
    from app.rbac.dependencies import get_authorization_context

    records: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    async def explode() -> None:
        raise RuntimeError("controlled-observability-failure")

    handler = CaptureHandler()
    app.dependency_overrides[get_authorization_context] = explode
    try:
        async with app.router.lifespan_context(app):
            application_logger = logging.getLogger("app")
            application_logger.addHandler(handler)
            try:
                transport = ASGITransport(app=app, raise_app_exceptions=False)
                async with AsyncClient(
                    transport=transport,
                    base_url="http://test",
                ) as client:
                    response = await client.get("/api/v1/me/access")
            finally:
                application_logger.removeHandler(handler)
    finally:
        app.dependency_overrides.clear()

    completion = [
        record for record in records if record.msg == "http.request.completed"
    ]
    assert len(completion) == 1
    completion_record = cast(CompletionRecord, completion[0])
    assert response.status_code == 500
    assert completion_record.request_id == response.json()["request_id"]
    assert completion_record.http_status_code == 500
    assert completion_record.business_code == 500000
    assert completion_record.outcome == "error"
    assert completion_record.exception_type == "RuntimeError"
    assert current_request_id() is None
