import asyncio
import json
import logging
import uuid
from pathlib import Path

import pytest

from app.api_contract import generic_error_code
from app.observability import (
    SafeJsonFormatter,
    bind_request_context,
    create_detached_task,
    current_request_id,
    reset_request_context,
    safe_exception_metadata,
    safe_log,
)


def formatter(*, include_exception_details: bool = False) -> SafeJsonFormatter:
    return SafeJsonFormatter(
        service_name="trusted-service",
        service_version="test-version",
        environment="test",
        include_exception_details=include_exception_details,
    )


class StringificationTrap:
    def __init__(self) -> None:
        self.str_called = False
        self.repr_called = False

    def __str__(self) -> str:
        self.str_called = True
        raise AssertionError("__str__ must not run")

    def __repr__(self) -> str:
        self.repr_called = True
        raise AssertionError("__repr__ must not run")


def record(
    *,
    message: object = "safe.event",
    args: tuple[object, ...] | dict[str, object] = (),
    exc_info: tuple[type[BaseException], BaseException, object] | None = None,
) -> logging.LogRecord:
    return logging.LogRecord(
        name="app.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=args,
        exc_info=exc_info,  # type: ignore[arg-type]
    )


def test_safe_log_contains_logger_failures() -> None:
    class BrokenLogger(logging.Logger):
        def log(self, level: int, msg: object, *args: object, **kwargs: object) -> None:
            raise RuntimeError("logging unavailable")

    assert safe_log(BrokenLogger("broken"), logging.INFO, "safe.event") is False

    working = logging.Logger("working")
    working.disabled = True
    assert safe_log(working, logging.INFO, "safe.event") is True


def test_sensitive_field_fragments_are_redacted_at_any_position() -> None:
    log_record = record()
    log_record.details = {
        "user_email": "email-secret",
        "user_password_hash": "password-secret",
        "request_authorization": "authorization-secret",
        "token_version": 17,
        "safe_value": "kept",
    }

    rendered = formatter().format(log_record)
    payload = json.loads(rendered)

    assert payload["details"] == {
        "user_email": "[REDACTED]",
        "user_password_hash": "[REDACTED]",
        "request_authorization": "[REDACTED]",
        "token_version": "[REDACTED]",
        "safe_value": "kept",
    }
    assert "email-secret" not in rendered
    assert "password-secret" not in rendered
    assert "authorization-secret" not in rendered


def test_formatter_keeps_valid_event_without_formatting_parameters() -> None:
    trap = StringificationTrap()
    log_record = record(message="worker.task_completed", args=(trap,))

    payload = json.loads(formatter().format(log_record))

    assert payload["event"] == "worker.task_completed"
    assert payload["message_template"] == "worker.task_completed"
    assert payload["message_parameters"] == "[OMITTED]"
    assert trap.str_called is False
    assert trap.repr_called is False


def test_formatter_omits_invalid_message_templates_and_parameters() -> None:
    trap = StringificationTrap()
    unsafe_template = "Login failed authorization=Bearer-secret for %s"

    rendered = formatter().format(record(message=unsafe_template, args=(trap,)))
    payload = json.loads(rendered)

    assert payload["event"] == "logging.invalid_event"
    assert payload["message_template"] == "[OMITTED]"
    assert payload["message_parameters"] == "[OMITTED]"
    assert "Login failed" not in rendered
    assert "Bearer-secret" not in rendered
    assert trap.str_called is False
    assert trap.repr_called is False

    non_string_message = StringificationTrap()
    payload = json.loads(formatter().format(record(message=non_string_message)))
    assert payload["event"] == "logging.invalid_event"
    assert payload["message_template"] == "[OMITTED]"
    assert non_string_message.str_called is False
    assert non_string_message.repr_called is False


def test_mapping_non_string_key_is_omitted_without_stringification() -> None:
    trap = StringificationTrap()
    log_record = record()
    log_record.details = {trap: "must-not-be-serialized", "safe": "kept"}

    payload = json.loads(formatter().format(log_record))

    assert payload["details"] == {
        "safe": "kept",
        "_non_string_keys_omitted": 1,
    }
    assert trap.str_called is False
    assert trap.repr_called is False


def test_oversized_field_names_are_omitted_before_values_are_read() -> None:
    oversized_key = f"{'x' * 129}_password"
    log_record = record()
    log_record.details = {oversized_key: "nested-secret", "safe": "kept"}
    setattr(log_record, oversized_key, "top-level-secret")

    rendered = formatter().format(log_record)
    payload = json.loads(rendered)

    assert payload["details"] == {
        "safe": "kept",
        "_oversized_keys_omitted": 1,
    }
    assert payload["_oversized_fields_omitted"] == 1
    assert "nested-secret" not in rendered
    assert "top-level-secret" not in rendered


def test_formatter_bounds_cycles_depth_collections_numbers_and_lines() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(8):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child

    log_record = record()
    log_record.details = {
        "cycle": cycle,
        "deep": deep,
        "many": list(range(101)),
        "nan": float("nan"),
        "positive_infinity": float("inf"),
        "negative_infinity": float("-inf"),
        "long_line": f"first\nsecond{'z' * 3000}",
    }

    rendered = formatter().format(log_record)
    payload = json.loads(rendered)
    details = payload["details"]

    assert "\n" not in rendered
    assert details["cycle"]["self"] == "[CYCLE]"
    assert "[MAX_DEPTH]" in json.dumps(details["deep"])
    assert details["many"][-1] == "[TRUNCATED]"
    assert len(details["many"]) == 101
    assert details["nan"] == "NaN"
    assert details["positive_infinity"] == "Infinity"
    assert details["negative_infinity"] == "-Infinity"
    assert details["long_line"].endswith("...[TRUNCATED]")


def test_extra_cannot_override_base_payload_fields() -> None:
    log_record = record()
    overrides = {
        "timestamp": "forged timestamp",
        "level": "FORGED",
        "event": "forged.event",
        "logger": "forged-logger",
        "service": "forged-service",
        "service_version": "forged-version",
        "environment": "forged-environment",
        "request_id": "forged-request-id",
    }
    for key, value in overrides.items():
        setattr(log_record, key, value)

    context_token = bind_request_context("trusted-request-id")
    try:
        payload = json.loads(formatter().format(log_record))
    finally:
        reset_request_context(context_token)

    assert payload["timestamp"] != "forged timestamp"
    assert payload["level"] == "INFO"
    assert payload["event"] == "safe.event"
    assert payload["logger"] == "app.test"
    assert payload["service"] == "trusted-service"
    assert payload["service_version"] == "test-version"
    assert payload["environment"] == "test"
    assert payload["request_id"] == "trusted-request-id"


def _raise_nested_secret() -> None:
    secret_local = "must-not-appear"
    if not secret_local:
        raise AssertionError
    raise ValueError("exception-message-secret")


def test_safe_exception_metadata_is_unique_and_omits_message_and_locals() -> None:
    try:
        _raise_nested_secret()
    except ValueError as exc:
        first = safe_exception_metadata(exc)
        second = safe_exception_metadata(exc)
        log_record = record(
            exc_info=(type(exc), exc, exc.__traceback__),
        )

    assert isinstance(first["error_id"], str)
    assert isinstance(second["error_id"], str)
    first_id = uuid.UUID(first["error_id"])
    second_id = uuid.UUID(second["error_id"])
    assert first_id.version == 4
    assert second_id.version == 4
    assert first_id != second_id
    assert first["exception_type"] == "ValueError"
    assert first["exception_module"] == "builtins"
    assert "exception_location" not in first
    assert "exception-message-secret" not in json.dumps(first)
    assert "must-not-appear" not in json.dumps(first)

    rendered = formatter(include_exception_details=True).format(log_record)
    assert "exception-message-secret" not in rendered
    assert "must-not-appear" not in rendered
    assert "exception_traceback" not in json.loads(rendered)


def test_safe_exception_metadata_uses_only_an_application_frame() -> None:
    try:
        generic_error_code(200)
    except ValueError as exc:
        metadata = safe_exception_metadata(exc)

    location = metadata.get("exception_location")
    assert isinstance(location, dict)
    assert location["module"] == "app.api_contract"
    assert location["function"] == "generic_error_code"
    assert isinstance(location["line"], int)
    assert Path(__file__).name not in json.dumps(metadata)


async def test_detached_task_clears_request_context_and_reports_failure() -> None:
    records: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, log_record: logging.LogRecord) -> None:
            records.append(log_record)

    async def fail_detached() -> None:
        assert current_request_id() is None
        raise RuntimeError("detached-task-secret")

    application_logger = logging.getLogger("app.observability")
    handler = CaptureHandler()
    application_logger.addHandler(handler)
    context_token = bind_request_context(str(uuid.uuid4()))
    try:
        task = create_detached_task(fail_detached())
        with pytest.raises(RuntimeError):
            await task
        await asyncio.sleep(0)
    finally:
        reset_request_context(context_token)
        application_logger.removeHandler(handler)

    failures = [
        log_record
        for log_record in records
        if log_record.msg == "background.task.failed"
    ]
    assert len(failures) == 1
    assert failures[0].exception_type == "RuntimeError"  # type: ignore[attr-defined]
    assert not hasattr(failures[0], "request_id")
