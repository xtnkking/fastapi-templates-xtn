import asyncio
import contextvars
import json
import logging
import math
import queue
import re
import socket
import ssl
import sys
import threading
import uuid
from collections.abc import Coroutine, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Final, TextIO, cast

type JsonValue = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
type LogExcInfo = (
    None
    | bool
    | BaseException
    | tuple[type[BaseException], BaseException, TracebackType | None]
    | tuple[None, None, None]
)


@dataclass(slots=True)
class _RequestLogContext:
    request_id: str
    active: bool = True


_REQUEST_CONTEXT: ContextVar[_RequestLogContext | None] = ContextVar(
    "request_log_context", default=None
)
_REDACTED: Final = "[REDACTED]"
_MAX_STRING_LENGTH: Final = 2048
_MAX_EVENT_NAME_LENGTH: Final = 128
_MAX_FIELD_NAME_LENGTH: Final = 128
_MAX_COLLECTION_ITEMS: Final = 100
_MAX_NESTING_DEPTH: Final = 5
_INVALID_EVENT: Final = "logging.invalid_event"
_OMITTED: Final = "[OMITTED]"
_UNSUPPORTED: Final = "[UNSUPPORTED]"
_OUT_OF_RANGE: Final = "[OUT_OF_RANGE]"
_CYCLE: Final = "[CYCLE]"
_SIGNED_BIGINT_MIN: Final = -(2**63)
_SIGNED_BIGINT_MAX: Final = 2**63 - 1
_EVENT_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_SENSITIVE_FIELD_NAMES: Final = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credentials",
        "database_url",
        "email",
        "id_token",
        "jti",
        "jwt",
        "jwt_secret",
        "password",
        "password_hash",
        "private_key",
        "proxy_url",
        "redis_url",
        "secret",
        "set_cookie",
        "token",
        "username",
    }
)
_BEARER_RE: Final = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_URL_CREDENTIAL_RE: Final = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@"
)
_KEY_VALUE_SECRET_RE: Final = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|authorization)\s*([=:])\s*"
    r"([^\s,;]+)"
)
_STANDARD_RECORD_FIELDS: Final = frozenset(
    logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__
) | {"asctime", "message"}
_BASE_PAYLOAD_FIELDS: Final = frozenset(
    {
        "timestamp",
        "level",
        "event",
        "logger",
        "service",
        "service_version",
        "environment",
        "request_id",
        "message_template",
        "message_parameters",
        "_oversized_fields_omitted",
    }
)
_THIRD_PARTY_LOGGERS: Final = (
    "asyncio",
    "fastapi",
    "httpcore",
    "httpx",
    "redis",
    "sqlalchemy",
    "sqlalchemy.engine",
    "uvicorn",
    "uvicorn.access",
    "uvicorn.error",
)
logger = logging.getLogger(__name__)


def bind_request_context(
    request_id: str,
) -> Token[_RequestLogContext | None]:
    """Bind one server request ID for logs emitted during the request."""
    return _REQUEST_CONTEXT.set(_RequestLogContext(request_id=request_id))


def deactivate_request_context() -> None:
    """Make copied request contexts stop exposing an already-completed ID."""
    context = _REQUEST_CONTEXT.get()
    if context is not None:
        context.active = False


def reset_request_context(token: Token[_RequestLogContext | None]) -> None:
    _REQUEST_CONTEXT.reset(token)


def current_request_id() -> str | None:
    context = _REQUEST_CONTEXT.get()
    return context.request_id if context is not None and context.active else None


def request_log_level(status_code: int) -> int:
    if status_code >= 500:
        return logging.ERROR
    if status_code >= 400:
        return logging.WARNING
    return logging.INFO


def _is_sensitive_field(name: str) -> bool:
    normalized = name.casefold().replace("-", "_")
    return any(fragment in normalized for fragment in _SENSITIVE_FIELD_NAMES)


def _redact_text(value: str, *, limit: int = _MAX_STRING_LENGTH) -> str:
    truncated = len(value) > limit
    bounded = value[:limit]
    bounded = _BEARER_RE.sub("Bearer [REDACTED]", bounded)
    bounded = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", bounded)
    bounded = _KEY_VALUE_SECRET_RE.sub(r"\1\2[REDACTED]", bounded)
    return f"{bounded}...[TRUNCATED]" if truncated else bounded


def _safe_value(
    value: object,
    *,
    field_name: str,
    depth: int = 0,
    seen: set[int] | None = None,
) -> JsonValue:
    if _is_sensitive_field(field_name):
        return _REDACTED
    if depth > _MAX_NESTING_DEPTH:
        return "[MAX_DEPTH]"
    value_type = type(value)
    if value is None:
        return None
    if value_type is bool:
        return cast(bool, value)
    if value_type is int:
        integer = cast(int, value)
        return (
            integer
            if _SIGNED_BIGINT_MIN <= integer <= _SIGNED_BIGINT_MAX
            else _OUT_OF_RANGE
        )
    if value_type is float:
        number = cast(float, value)
        if math.isfinite(number):
            return number
        if math.isnan(number):
            return "NaN"
        return "Infinity" if number > 0 else "-Infinity"
    if value_type is str:
        return _redact_text(cast(str, value))
    if value_type is uuid.UUID or value_type is datetime:
        return str(value)
    if value_type is dict:
        mapping = cast(dict[object, object], value)
        if seen is None:
            seen = set()
        identity = id(value)
        if identity in seen:
            return _CYCLE
        seen.add(identity)
        mapping_result: dict[str, JsonValue] = {}
        omitted_keys = 0
        oversized_keys = 0
        try:
            for index, (key, item) in enumerate(mapping.items()):
                if index >= _MAX_COLLECTION_ITEMS:
                    mapping_result["_truncated"] = True
                    break
                if type(key) is not str:
                    omitted_keys += 1
                    continue
                if len(key) > _MAX_FIELD_NAME_LENGTH:
                    oversized_keys += 1
                    continue
                mapping_result[key] = _safe_value(
                    item,
                    field_name=key,
                    depth=depth + 1,
                    seen=seen,
                )
            if omitted_keys:
                mapping_result["_non_string_keys_omitted"] = omitted_keys
            if oversized_keys:
                mapping_result["_oversized_keys_omitted"] = oversized_keys
            return mapping_result
        finally:
            seen.remove(identity)
    if value_type is list or value_type is tuple:
        sequence = cast(list[object] | tuple[object, ...], value)
        if seen is None:
            seen = set()
        identity = id(value)
        if identity in seen:
            return _CYCLE
        seen.add(identity)
        try:
            result = [
                _safe_value(
                    item,
                    field_name=field_name,
                    depth=depth + 1,
                    seen=seen,
                )
                for item in sequence[:_MAX_COLLECTION_ITEMS]
            ]
            if len(sequence) > _MAX_COLLECTION_ITEMS:
                result.append("[TRUNCATED]")
            return result
        finally:
            seen.remove(identity)
    return _UNSUPPORTED


def safe_exception_metadata(exc: BaseException) -> dict[str, object]:
    """Return exception identity and an allowlisted app location only."""
    exception_type = type(exc)
    traceback = exc.__traceback__
    application_location: dict[str, object] | None = None
    while traceback is not None:
        frame = traceback.tb_frame
        module_name = frame.f_globals.get("__name__")
        function_name = frame.f_code.co_name
        if (
            type(module_name) is str
            and (module_name == "app" or module_name.startswith("app."))
            and type(function_name) is str
        ):
            application_location = {
                "module": module_name[:256],
                "function": function_name[:128],
                "line": traceback.tb_lineno,
            }
        traceback = traceback.tb_next

    metadata: dict[str, object] = {
        "error_id": str(uuid.uuid4()),
        "exception_type": exception_type.__name__[:_MAX_FIELD_NAME_LENGTH],
        "exception_module": exception_type.__module__[:256],
    }
    if application_location is not None:
        metadata["exception_location"] = application_location
    return metadata


def dependency_error_category(exc: BaseException) -> str:
    """Map dependency exceptions to a stable category without reading messages."""
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, ConnectionError):
        return "connection"

    name = type(exc).__name__.casefold()
    module = type(exc).__module__.casefold()
    if name == "operationalerror" and module.startswith("sqlalchemy."):
        return "connection"
    if name == "timeouterror" and module.startswith("sqlalchemy."):
        return "pool_exhausted"
    if name in {"pooltimeout", "timeouterror"}:
        return "pool_exhausted" if name == "pooltimeout" else "timeout"
    if name in {"connecterror", "connectionerror", "connectionrefusederror"}:
        return "connection"
    if name in {"connecttimeout", "readtimeout", "writetimeout"}:
        return "timeout"
    if name in {"sslerror", "certificateerror"}:
        return "tls"
    if name in {"protocolerror", "remoteprotocolerror", "localprotocolerror"}:
        return "protocol"
    if name in {"ratelimiterror", "toomanyrequestserror"}:
        return "rate_limited"
    return "unknown"


def safe_log(
    logger: logging.Logger,
    level: int,
    event: str,
    extra: Mapping[str, object] | None = None,
    exc_info: LogExcInfo = None,
) -> bool:
    """Emit a log record without allowing logging failures into business flow."""
    try:
        safe_extra: dict[str, object] = {}
        if type(extra) is dict:
            for key, value in extra.items():
                if type(key) is str and key not in _STANDARD_RECORD_FIELDS:
                    safe_extra[key] = value

        exception: BaseException | None = None
        if isinstance(exc_info, BaseException):
            exception = exc_info
        elif type(exc_info) is tuple and len(exc_info) >= 2:
            candidate = exc_info[1]
            if isinstance(candidate, BaseException):
                exception = candidate
        if exception is not None:
            for key, value in safe_exception_metadata(exception).items():
                safe_extra.setdefault(key, value)

        safe_event = event if type(event) is str else _INVALID_EVENT
        logger.log(level, safe_event, extra=safe_extra or None, exc_info=None)
    except Exception:
        return False
    return True


def _observe_detached_task(task: asyncio.Task[object]) -> None:
    """Report a detached-task failure without leaking context or exceptions."""
    try:
        exception = task.exception()
    except asyncio.CancelledError:
        return
    except Exception as exc:
        safe_log(
            logger,
            logging.ERROR,
            "background.task.observation_failed",
            exc_info=exc,
        )
        return
    if exception is not None:
        safe_log(
            logger,
            logging.ERROR,
            "background.task.failed",
            exc_info=exception,
        )


def create_detached_task[T](
    coroutine: Coroutine[Any, Any, T],
    *,
    name: str | None = None,
) -> asyncio.Task[T]:
    """Create detached work without inheriting the ambient request ID."""
    context = contextvars.copy_context()
    context.run(_REQUEST_CONTEXT.set, None)
    task = asyncio.create_task(coroutine, name=name, context=context)
    task.add_done_callback(_observe_detached_task)
    return task


def _message_fields(record: logging.LogRecord) -> tuple[str, dict[str, JsonValue]]:
    message = record.msg
    fields: dict[str, JsonValue] = {}
    if (
        type(message) is str
        and len(message) <= _MAX_EVENT_NAME_LENGTH
        and _EVENT_NAME_RE.fullmatch(message)
    ):
        fields["message_template"] = message
        event = message
    else:
        event = _INVALID_EVENT
        fields["message_template"] = _OMITTED

    args = record.args
    if not (type(args) is tuple and len(args) == 0):
        fields["message_parameters"] = _OMITTED
    return event, fields


class SafeJsonFormatter(logging.Formatter):
    """One-line JSON formatter that never stringifies arbitrary extra objects."""

    def __init__(
        self,
        *,
        service_name: str,
        service_version: str,
        environment: str,
        include_exception_details: bool,
    ) -> None:
        super().__init__()
        self._service_name = service_name
        self._service_version = service_version
        self._environment = environment
        self._include_exception_details = include_exception_details

    def format(self, record: logging.LogRecord) -> str:
        event, message_fields = _message_fields(record)
        payload: dict[str, JsonValue] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "event": event,
            "logger": record.name,
            "service": self._service_name,
            "service_version": self._service_version,
            "environment": self._environment,
            **message_fields,
        }
        request_id = current_request_id() or getattr(record, "request_id", None)
        if isinstance(request_id, str) and request_id:
            payload["request_id"] = _redact_text(request_id, limit=128)

        oversized_fields = 0
        for key, value in record.__dict__.items():
            if not isinstance(key, str):
                continue
            if key in _STANDARD_RECORD_FIELDS or key in _BASE_PAYLOAD_FIELDS:
                continue
            if len(key) > _MAX_FIELD_NAME_LENGTH:
                oversized_fields += 1
                continue
            payload[key] = _safe_value(value, field_name=key)
        if oversized_fields:
            payload["_oversized_fields_omitted"] = oversized_fields

        exc_info = record.exc_info
        if (
            self._include_exception_details
            and type(exc_info) is tuple
            and len(exc_info) >= 2
            and isinstance(exc_info[1], BaseException)
        ):
            for key, value in safe_exception_metadata(exc_info[1]).items():
                if key not in payload:
                    payload[key] = _safe_value(value, field_name=key)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class BufferedLogHandler(logging.Handler):
    """Bounded best-effort output; only sanitized JSON crosses the thread boundary."""

    MAX_LINE_BYTES = 16_384

    def __init__(self, stream: TextIO, *, capacity: int = 1_000) -> None:
        super().__init__()
        if type(capacity) is not int or not 1 <= capacity <= 10_000:
            raise ValueError("log queue capacity must be within 1..10000")
        self._stream = stream
        self._queue: queue.Queue[str] = queue.Queue(maxsize=capacity)
        self._stopping = threading.Event()
        self._written = 0
        self._dropped = 0
        self._write_failures = 0
        self._format_failures = 0
        self._thread = threading.Thread(
            target=self._write_loop, name="application-log-writer", daemon=True
        )
        try:
            self._thread.start()
        except Exception:
            # Observability startup failure must not prevent serving requests.
            self._write_failures += 1
            self._stopping.set()

    def emit(self, record: logging.LogRecord) -> None:
        # logging.Handler.handle holds the handler lock only during serialization
        # and non-blocking enqueue. The consumer never holds it during sink I/O.
        if self._stopping.is_set():
            self._dropped += 1
            return
        try:
            line = self.format(record)
            if len(line.encode("utf-8")) > self.MAX_LINE_BYTES:
                self._dropped += 1
                return
            self._queue.put_nowait(line)
        except queue.Full:
            self._dropped += 1
        except Exception:
            self._format_failures += 1

    def _write_loop(self) -> None:
        while not (self._stopping.is_set() and self._queue.empty()):
            try:
                line = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            failed = False
            try:
                output = line + "\n"
                failed = self._stream.write(output) != len(output)
                self._stream.flush()
            except Exception:
                failed = True
            finally:
                self.acquire()
                try:
                    if failed:
                        self._write_failures += 1
                    else:
                        self._written += 1
                finally:
                    self.release()
                self._queue.task_done()

    def snapshot(self) -> dict[str, int | bool]:
        """Internal observation hook; never recursively log through a failing sink."""
        self.acquire()
        try:
            return {
                "queue_size": self._queue.qsize(),
                "written": self._written,
                "dropped": self._dropped,
                "write_failures": self._write_failures,
                "format_failures": self._format_failures,
                "writer_alive": self._thread.is_alive(),
            }
        finally:
            self.release()

    def close(self) -> None:
        # logging.shutdown() can call close synchronously. Never join a blocked
        # sink here or acquire its stream lock; this handler does not own stdout.
        self.acquire()
        try:
            self._stopping.set()
        finally:
            self.release()
        super().close()

    async def shutdown(self, *, timeout_seconds: float) -> None:
        if not math.isfinite(timeout_seconds) or not 0 <= timeout_seconds <= 30:
            raise ValueError("log shutdown timeout must be within 0..30 seconds")
        self.close()
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            while self._thread.is_alive():
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(0.01, remaining))
        finally:
            # A native write already in progress cannot safely be interrupted.
            # Drop pending observations at the deadline rather than hanging the
            # application or retaining a large queue behind the blocked daemon.
            self.acquire()
            try:
                while True:
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        break
                    self._queue.task_done()
                    self._dropped += 1
            finally:
                self.release()


def configure_logging(
    *,
    service_name: str,
    service_version: str,
    environment: str,
    log_level: str,
    include_exception_details: bool,
    queue_capacity: int = 1_000,
) -> BufferedLogHandler:
    """Configure application and framework logs for one process."""
    handler = BufferedLogHandler(sys.stdout, capacity=queue_capacity)
    handler.setFormatter(
        SafeJsonFormatter(
            service_name=service_name,
            service_version=service_version,
            environment=environment,
            include_exception_details=include_exception_details,
        )
    )

    application_logger = logging.getLogger("app")
    for previous in application_logger.handlers:
        if isinstance(previous, BufferedLogHandler):
            previous.close()
    application_logger.handlers.clear()
    application_logger.addHandler(handler)
    application_logger.setLevel(log_level)
    application_logger.propagate = False
    application_logger.disabled = False

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(logging.NullHandler())

    # These sources may emit raw URLs, statements, parameters, or duplicate
    # access lines. Re-enable one only through a field-safe adapter.
    for logger_name in _THIRD_PARTY_LOGGERS:
        third_party_logger = logging.getLogger(logger_name)
        third_party_logger.handlers.clear()
        third_party_logger.propagate = False
        third_party_logger.disabled = True
    return handler
