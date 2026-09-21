import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Literal, cast

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.access import router as access_router
from app.api.authentication import authentication_routers
from app.core.api_contract import (
    ApiResponse,
    BusinessCode,
    ValidationErrorData,
    ValidationErrorItem,
    api_response,
    error_content,
    generic_error_code,
    request_id_for,
    request_id_headers,
)
from app.core.config import get_settings
from app.core.errors import RbacError
from app.core.i18n import (
    MessageKey,
    apply_language_headers,
    locale_for_request,
    validation_field,
    validation_message,
)
from app.core.middleware.rate_limit import semantic_rate_limit_headers
from app.core.observability import (
    bind_request_context,
    configure_logging,
    deactivate_request_context,
    dependency_error_category,
    request_log_level,
    reset_request_context,
    safe_exception_metadata,
    safe_log,
)
from app.core.security.policies import SecurityPolicies
from app.core.security.rate_limit import RateLimitExceeded, RateLimitUnavailable
from app.db.errors import DatabaseUnavailableError, database_error_category
from app.db.postgres import engine
from app.db.redis import (
    RedisClient,
    close_redis_client,
    create_rate_limit_redis_client,
    create_redis_client,
)
from app.services.abuse_flow import InvalidLoginCredentialsError

logger = logging.getLogger(__name__)

HTTP_ERROR_CONTRACT: dict[int, tuple[BusinessCode, MessageKey]] = {
    400: (BusinessCode.BAD_REQUEST, MessageKey.ERROR_BAD_REQUEST),
    401: (BusinessCode.INVALID_AUTHENTICATION, MessageKey.ERROR_UNAUTHENTICATED),
    403: (BusinessCode.ACCESS_FORBIDDEN, MessageKey.ERROR_FORBIDDEN),
    404: (BusinessCode.NOT_FOUND, MessageKey.ERROR_NOT_FOUND),
    405: (BusinessCode.METHOD_NOT_ALLOWED, MessageKey.ERROR_METHOD_NOT_ALLOWED),
    409: (BusinessCode.CONFLICT, MessageKey.ERROR_CONFLICT),
    413: (BusinessCode.PAYLOAD_TOO_LARGE, MessageKey.ERROR_PAYLOAD_TOO_LARGE),
    415: (
        BusinessCode.UNSUPPORTED_MEDIA_TYPE,
        MessageKey.ERROR_UNSUPPORTED_MEDIA_TYPE,
    ),
    422: (BusinessCode.VALIDATION_FAILED, MessageKey.ERROR_VALIDATION_FAILED),
    429: (BusinessCode.RATE_LIMITED, MessageKey.ERROR_RATE_LIMITED),
    500: (BusinessCode.INTERNAL_ERROR, MessageKey.ERROR_INTERNAL),
    503: (BusinessCode.SERVICE_UNAVAILABLE, MessageKey.ERROR_SERVICE_UNAVAILABLE),
}


def _log_request_completion(
    request: Request,
    *,
    status_code: int | None,
    outcome: str,
    response_started: bool,
    response_completed: bool,
    client_disconnected: bool,
    exception: BaseException | None = None,
    failure_phase: str | None = None,
) -> None:
    try:
        if getattr(request.state, "request_completion_recorded", False):
            return
        request.state.request_completion_recorded = True

        route = request.scope.get("route")
        started_at = getattr(request.state, "request_started_at", None)
        duration_ms = (
            round((perf_counter() - started_at) * 1000, 3)
            if isinstance(started_at, float)
            else None
        )
        extra: dict[str, object] = {
            "request_id": request_id_for(request),
            "http_method": request.method,
            "route": getattr(route, "path", "<unmatched>"),
            "http_status_code": status_code,
            "business_code": getattr(request.state, "business_code", None),
            "duration_ms": duration_ms,
            "outcome": outcome,
            "response_started": response_started,
            "response_completed": response_completed,
            "client_disconnected": client_disconnected,
            "actor_user_id": getattr(request.state, "actor_user_id", None),
        }
        if failure_phase is not None:
            extra["failure_phase"] = failure_phase
        exc_info = None
        if exception is not None:
            exc_info = (type(exception), exception, exception.__traceback__)
        safe_log(
            logger,
            logging.ERROR
            if outcome == "error" or status_code is None
            else request_log_level(status_code),
            "http.request.completed",
            extra=extra,
            exc_info=exc_info,
        )
    except Exception:
        # Observation must never replace the response or application exception.
        return


def _log_post_response_failure(
    request: Request,
    *,
    status_code: int | None,
    response_started: bool,
    response_completed: bool,
    client_disconnected: bool,
    exception: BaseException,
    failure_phase: str,
) -> None:
    try:
        route = request.scope.get("route")
        started_at = getattr(request.state, "request_started_at", None)
        duration_ms = (
            round((perf_counter() - started_at) * 1000, 3)
            if isinstance(started_at, float)
            else None
        )
        extra: dict[str, object] = {
            "request_id": request_id_for(request),
            "http_method": request.method,
            "route": getattr(route, "path", "<unmatched>"),
            "http_status_code": status_code,
            "business_code": getattr(request.state, "business_code", None),
            "duration_ms": duration_ms,
            "actor_user_id": getattr(request.state, "actor_user_id", None),
            "response_started": response_started,
            "response_completed": response_completed,
            "client_disconnected": client_disconnected,
            "failure_phase": failure_phase,
        }
        safe_log(
            logger,
            logging.ERROR,
            "http.request.post_response_failed",
            extra=extra,
            exc_info=(type(exception), exception, exception.__traceback__),
        )
    except Exception:
        return


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    SecurityPolicies.from_settings(settings)
    log_handler = configure_logging(
        service_name=settings.service_name,
        service_version=settings.service_version,
        environment=settings.app_environment,
        log_level=settings.log_level,
        include_exception_details=settings.log_include_exception_details,
        queue_capacity=settings.log_queue_capacity,
    )
    app.state.log_handler = log_handler
    try:
        redis = create_redis_client(settings)
        try:
            rate_limit_redis = create_rate_limit_redis_client(settings)
            try:
                app.state.redis = redis
                app.state.rate_limit_redis = rate_limit_redis
                safe_log(logger, logging.INFO, "application.started")
                yield
            finally:
                await close_redis_client(rate_limit_redis)
        finally:
            await close_redis_client(redis)
    finally:
        try:
            await engine.dispose()
        finally:
            safe_log(logger, logging.INFO, "application.stopped")
            logging.getLogger("app").removeHandler(log_handler)
            await log_handler.shutdown(
                timeout_seconds=settings.log_shutdown_timeout_seconds
            )


app = FastAPI(title="PostgreSQL Access Control Example", lifespan=lifespan)
for authentication_router in authentication_routers():
    app.include_router(authentication_router)
app.include_router(access_router)


class _ReadinessDependencyUnavailable(RuntimeError):
    """Represent missing or malformed readiness authority without secret detail."""


EXPECTED_ALEMBIC_HEAD = "0004_password_auth"
_READINESS_REDIS_KEY_TTL_MS = 5_000
_READINESS_REDIS_CLEANUP_TIMEOUT_SECONDS = 0.1
_POSTGRESQL_READINESS_QUERY = text(
    """
    SELECT
        NOT pg_is_in_recovery()
        AND current_setting('transaction_read_only') = 'off'
        AND (SELECT count(*) FROM alembic_version) = 1
        AND EXISTS (
            SELECT 1
            FROM alembic_version
            WHERE version_num = :expected_head
        )
        AND EXISTS (
            SELECT 1
            FROM rbac_state
            WHERE scope = 'global'
              AND epoch >= 0
              AND public_registration_enabled IN (TRUE, FALSE)
        )
    """
)
_REDIS_READINESS_SCRIPT = """
local probe_key = KEYS[1]
local probe_value = ARGV[1]
local ttl_ms = tonumber(ARGV[2])
if not ttl_ms or ttl_ms <= 0 then
    return 0
end
redis.call('PSETEX', probe_key, ttl_ms, probe_value)
if redis.call('GET', probe_key) ~= probe_value then
    redis.call('DEL', probe_key)
    return 0
end
return redis.call('DEL', probe_key)
"""


async def _probe_postgresql() -> None:
    async with engine.connect() as connection:
        ready = await connection.scalar(
            _POSTGRESQL_READINESS_QUERY,
            {"expected_head": EXPECTED_ALEMBIC_HEAD},
        )
        if ready is not True:
            raise _ReadinessDependencyUnavailable


async def _best_effort_delete_readiness_key(client: RedisClient, key: str) -> None:
    try:
        async with asyncio.timeout(_READINESS_REDIS_CLEANUP_TIMEOUT_SECONDS):
            await cast(Awaitable[int], client.delete(key))
    except asyncio.CancelledError:
        # This helper runs only while the primary probe exception is unwinding.
        # A second cancellation from cleanup must not replace that exception.
        return
    except Exception:
        # The probe key has a short TTL; cleanup must not replace the probe failure.
        return


async def _probe_redis(
    client: RedisClient | None,
    *,
    key_namespace: Literal["active-jti", "rate-limit"],
) -> None:
    if client is None:
        raise _ReadinessDependencyUnavailable
    key = f"readiness:v1:{key_namespace}:{uuid.uuid4().hex}"
    value = uuid.uuid4().hex
    cleanup_needed = True
    try:
        if await cast(Awaitable[bool], client.ping()) is not True:
            raise _ReadinessDependencyUnavailable
        result = await cast(
            Awaitable[object],
            client.eval(
                _REDIS_READINESS_SCRIPT,
                1,
                key,
                value,
                str(_READINESS_REDIS_KEY_TTL_MS),
            ),
        )
        if type(result) is not int or result != 1:
            raise _ReadinessDependencyUnavailable
        cleanup_needed = False
    finally:
        if cleanup_needed:
            await _best_effort_delete_readiness_key(client, key)


async def _run_readiness_check(
    *,
    request: Request,
    dependency: str,
    timeout_seconds: float,
    operation: Callable[[], Awaitable[None]],
) -> bool:
    try:
        async with asyncio.timeout(timeout_seconds):
            await operation()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.readiness.unavailable",
            extra={
                "request_id": request_id_for(request),
                "http_status_code": 503,
                "business_code": int(BusinessCode.SERVICE_UNAVAILABLE),
                "dependency": dependency,
                "dependency_operation": "readiness_check",
                "error_category": dependency_error_category(exc),
                **safe_exception_metadata(exc),
            },
        )
        return False
    return True


class RequestObservabilityMiddleware:
    """Correlate and complete-log an HTTP request at the ASGI send boundary."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        request.state.request_id = str(uuid.uuid4())
        request.state.locale = locale_for_request(request)
        request.state.request_started_at = perf_counter()
        request.state.request_completion_recorded = False
        context_token = bind_request_context(request.state.request_id)
        context_is_bound = True
        response_status_code: int | None = None
        response_started = False
        response_completed = False
        client_disconnected = False
        send_failed = False
        receive_failed = False

        def release_request_context() -> None:
            nonlocal context_is_bound
            if context_is_bound:
                reset_request_context(context_token)
                context_is_bound = False

        async def receive_with_observability() -> Message:
            nonlocal client_disconnected, receive_failed
            try:
                message = await receive()
            except asyncio.CancelledError:
                raise
            except Exception:
                receive_failed = True
                raise
            if message["type"] == "http.disconnect":
                client_disconnected = True
            return message

        async def send_with_observability(message: Message) -> None:
            nonlocal response_completed, response_started, response_status_code
            nonlocal send_failed
            pending_status_code: int | None = None
            if message["type"] == "http.response.start":
                pending_status_code = int(message["status"])
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request.state.request_id
                apply_language_headers(response_headers, request.state.locale)

            try:
                await send(message)
            except (asyncio.CancelledError, Exception):
                send_failed = True
                raise

            if pending_status_code is not None:
                response_status_code = pending_status_code
                response_started = True

            if message["type"] == "http.response.body" and not message.get(
                "more_body", False
            ):
                response_completed = True
                status_code = response_status_code if response_started else None
                _log_request_completion(
                    request,
                    status_code=status_code,
                    outcome=(
                        "error"
                        if status_code is None
                        else ("success" if status_code < 400 else "failure")
                    ),
                    response_started=response_started,
                    response_completed=True,
                    client_disconnected=client_disconnected,
                    failure_phase=(
                        "response_without_start" if status_code is None else None
                    ),
                )
                deactivate_request_context()

        try:
            await self.app(scope, receive_with_observability, send_with_observability)
            if not request.state.request_completion_recorded:
                _log_request_completion(
                    request,
                    status_code=response_status_code,
                    outcome="error",
                    response_started=response_started,
                    response_completed=response_completed,
                    client_disconnected=client_disconnected,
                    failure_phase=(
                        "client_disconnect"
                        if client_disconnected
                        else "response_incomplete"
                    ),
                )
        except asyncio.CancelledError as exc:
            if request.state.request_completion_recorded:
                _log_post_response_failure(
                    request,
                    status_code=response_status_code,
                    response_started=response_started,
                    response_completed=response_completed,
                    client_disconnected=client_disconnected,
                    exception=exc,
                    failure_phase="request_cancelled_after_response",
                )
            else:
                _log_request_completion(
                    request,
                    status_code=response_status_code,
                    outcome="error",
                    response_started=response_started,
                    response_completed=response_completed,
                    client_disconnected=client_disconnected,
                    exception=exc,
                    failure_phase=(
                        "send"
                        if send_failed
                        else (
                            "receive"
                            if receive_failed
                            else (
                                "client_disconnect"
                                if client_disconnected
                                else "request_cancelled"
                            )
                        )
                    ),
                )
            raise
        except Exception as exc:
            if request.state.request_completion_recorded:
                _log_post_response_failure(
                    request,
                    status_code=response_status_code,
                    response_started=response_started,
                    response_completed=response_completed,
                    client_disconnected=client_disconnected,
                    exception=exc,
                    failure_phase="post_response",
                )
            else:
                if not send_failed and not response_started:
                    request.state.business_code = int(BusinessCode.INTERNAL_ERROR)
                _log_request_completion(
                    request,
                    status_code=(
                        response_status_code if response_started or send_failed else 500
                    ),
                    outcome="error",
                    response_started=response_started,
                    response_completed=response_completed,
                    client_disconnected=client_disconnected,
                    exception=exc,
                    failure_phase=(
                        "send"
                        if send_failed
                        else (
                            "receive"
                            if receive_failed
                            else (
                                "client_disconnect"
                                if client_disconnected
                                else (
                                    "response_body"
                                    if response_started
                                    else "application"
                                )
                            )
                        )
                    ),
                )
            raise
        finally:
            release_request_context()


app.add_middleware(RequestObservabilityMiddleware)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
) -> Response:
    errors = ValidationErrorData(
        errors=[
            ValidationErrorItem(
                field=validation_field(error),
                message=validation_message(request, error),
            )
            for error in exc.errors()
        ]
    )
    return JSONResponse(
        status_code=422,
        content=error_content(
            request,
            code=BusinessCode.VALIDATION_FAILED,
            message_key=MessageKey.ERROR_VALIDATION_FAILED,
            data=errors,
        ),
        headers=request_id_headers(request, {"Cache-Control": "no-store"}),
    )


@app.exception_handler(RbacError)
async def handle_access_error(request: Request, exc: RbacError) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=exc.status_code,
        content=error_content(
            request,
            code=exc.business_code,
            message_key=exc.message_key,
        ),
        headers=request_id_headers(request, headers),
    )


@app.exception_handler(RateLimitExceeded)
async def handle_rate_limit_exceeded(
    request: Request,
    exc: RateLimitExceeded,
) -> JSONResponse:
    safe_log(
        logger,
        logging.WARNING,
        "rate_limit.denied",
        extra={"rate_limit_policy": exc.policy_name},
    )
    return JSONResponse(
        status_code=429,
        content=error_content(
            request,
            code=BusinessCode.RATE_LIMITED,
            message_key=MessageKey.ERROR_RATE_LIMITED_RETRY,
        ),
        headers=request_id_headers(
            request,
            semantic_rate_limit_headers(exc.result),
        ),
    )


@app.exception_handler(InvalidLoginCredentialsError)
async def handle_invalid_login_credentials(
    request: Request,
    exc: InvalidLoginCredentialsError,
) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content=error_content(
            request,
            code=BusinessCode.INVALID_AUTHENTICATION,
            message_key=MessageKey.ERROR_UNAUTHENTICATED,
        ),
        headers=request_id_headers(
            request,
            {
                "WWW-Authenticate": "Bearer",
                "Cache-Control": "no-store",
            },
        ),
    )


@app.exception_handler(RateLimitUnavailable)
async def handle_rate_limit_unavailable(
    request: Request,
    exc: RateLimitUnavailable,
) -> JSONResponse:
    safe_log(
        logger,
        logging.ERROR,
        "dependency.rate_limit.unavailable",
        extra={
            "dependency": "rate_limit_redis",
            "dependency_operation": "security_admission",
            **safe_exception_metadata(exc),
        },
    )
    return JSONResponse(
        status_code=503,
        content=error_content(
            request,
            code=BusinessCode.SERVICE_UNAVAILABLE,
            message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
        ),
        headers=request_id_headers(request, {"Cache-Control": "no-store"}),
    )


@app.exception_handler(StarletteHTTPException)
async def handle_http_error(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    known_contract = HTTP_ERROR_CONTRACT.get(exc.status_code)
    status_code = exc.status_code
    contract: tuple[int | BusinessCode, MessageKey]
    if known_contract is not None:
        contract = known_contract
    else:
        if 400 <= status_code <= 599:
            contract = (
                generic_error_code(status_code),
                MessageKey.ERROR_REQUEST_FAILED,
            )
        else:
            status_code = 500
            contract = (BusinessCode.INTERNAL_ERROR, MessageKey.ERROR_INTERNAL)
    code, message_key = contract
    headers = dict(exc.headers or {})
    headers.setdefault("Cache-Control", "no-store")
    if status_code == 401:
        headers.setdefault("WWW-Authenticate", "Bearer")
    return JSONResponse(
        status_code=status_code,
        content=error_content(request, code=code, message_key=message_key),
        headers=request_id_headers(request, headers),
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_content(
            request,
            code=BusinessCode.INTERNAL_ERROR,
            message_key=MessageKey.ERROR_INTERNAL,
        ),
        headers=request_id_headers(request, {"Cache-Control": "no-store"}),
    )


@app.exception_handler(SQLAlchemyError)
@app.exception_handler(DatabaseUnavailableError)
async def handle_database_unavailable(
    request: Request,
    exc: SQLAlchemyError | DatabaseUnavailableError,
) -> JSONResponse:
    category = database_error_category(exc)
    if category is None:
        # Keep the ordinary unhandled-error/logging path for SQL mistakes and
        # integrity failures; only recognized availability failures become 503.
        raise exc
    safe_log(
        logger,
        logging.ERROR,
        "dependency.database.unavailable",
        extra={
            "request_id": request_id_for(request),
            "http_status_code": 503,
            "business_code": int(BusinessCode.SERVICE_UNAVAILABLE),
            "dependency": "postgresql",
            "dependency_operation": "request_database_operation",
            "error_category": category,
            **safe_exception_metadata(exc),
        },
    )
    return JSONResponse(
        status_code=503,
        content=error_content(
            request,
            code=BusinessCode.SERVICE_UNAVAILABLE,
            message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
        ),
        headers=request_id_headers(request, {"Cache-Control": "no-store"}),
    )


@app.get(
    "/health/live",
    response_model=ApiResponse[dict[str, str]],
    include_in_schema=False,
)
async def liveness(request: Request) -> ApiResponse[dict[str, str]]:
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.HEALTH_LIVE,
        data={"status": "ok"},
    )


@app.get(
    "/health/ready",
    response_model=ApiResponse[dict[str, str]],
    include_in_schema=False,
)
async def readiness(
    request: Request,
    response: Response,
) -> ApiResponse[dict[str, str]] | JSONResponse:
    settings = get_settings()
    active_jti_redis = getattr(request.app.state, "redis", None)
    rate_limit_redis = getattr(request.app.state, "rate_limit_redis", None)
    results = await asyncio.gather(
        _run_readiness_check(
            request=request,
            dependency="postgresql",
            timeout_seconds=settings.readiness_timeout_seconds,
            operation=_probe_postgresql,
        ),
        _run_readiness_check(
            request=request,
            dependency="active_jti_redis",
            timeout_seconds=settings.readiness_timeout_seconds,
            operation=lambda: _probe_redis(
                active_jti_redis,
                key_namespace="active-jti",
            ),
        ),
        _run_readiness_check(
            request=request,
            dependency="rate_limit_redis",
            timeout_seconds=settings.readiness_timeout_seconds,
            operation=lambda: _probe_redis(
                rate_limit_redis,
                key_namespace="rate-limit",
            ),
        ),
    )
    if not all(results):
        return JSONResponse(
            status_code=503,
            content=error_content(
                request,
                code=BusinessCode.SERVICE_UNAVAILABLE,
                message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
            ),
            headers=request_id_headers(request, {"Cache-Control": "no-store"}),
        )

    response.headers["Cache-Control"] = "no-store"
    return api_response(
        request,
        code=BusinessCode.OK,
        message_key=MessageKey.HEALTH_READY,
        data={"status": "ready"},
    )
