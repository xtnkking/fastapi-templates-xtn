import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.abuse_flow import InvalidLoginCredentialsError
from app.api_contract import (
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
from app.authentication_api import authentication_routers
from app.database import engine
from app.observability import (
    bind_request_context,
    configure_logging,
    deactivate_request_context,
    dependency_error_category,
    request_log_level,
    reset_request_context,
    safe_exception_metadata,
    safe_log,
)
from app.rate_limit import RateLimitUnavailable
from app.rate_limit_dependencies import RateLimitExceeded
from app.rate_limit_middleware import semantic_rate_limit_headers
from app.rbac.api import router as access_router
from app.rbac.errors import RbacError
from app.redis_client import create_rate_limit_redis_client, create_redis_client
from app.security_policies import SecurityPolicies
from app.settings import get_settings

logger = logging.getLogger(__name__)

HTTP_ERROR_CONTRACT: dict[int, tuple[BusinessCode, str]] = {
    400: (BusinessCode.BAD_REQUEST, "请求内容不合法"),
    401: (BusinessCode.INVALID_AUTHENTICATION, "身份验证失败"),
    403: (BusinessCode.ACCESS_FORBIDDEN, "无权执行该操作"),
    404: (BusinessCode.NOT_FOUND, "资源不存在"),
    405: (BusinessCode.METHOD_NOT_ALLOWED, "请求方法不允许"),
    409: (BusinessCode.CONFLICT, "当前资源状态存在冲突"),
    413: (BusinessCode.PAYLOAD_TOO_LARGE, "请求内容过大"),
    415: (BusinessCode.UNSUPPORTED_MEDIA_TYPE, "请求媒体类型不支持"),
    422: (BusinessCode.VALIDATION_FAILED, "请求参数校验失败"),
    429: (BusinessCode.RATE_LIMITED, "请求过于频繁"),
    500: (BusinessCode.INTERNAL_ERROR, "服务器内部错误"),
    503: (BusinessCode.SERVICE_UNAVAILABLE, "服务暂时不可用"),
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
    configure_logging(
        service_name=settings.service_name,
        service_version=settings.service_version,
        environment=settings.app_environment,
        log_level=settings.log_level,
        include_exception_details=settings.log_include_exception_details,
    )
    redis = create_redis_client(settings)
    rate_limit_redis = create_rate_limit_redis_client(settings)
    app.state.redis = redis
    app.state.rate_limit_redis = rate_limit_redis
    safe_log(logger, logging.INFO, "application.started")
    try:
        yield
    finally:
        try:
            try:
                await rate_limit_redis.aclose()
            finally:
                await redis.aclose()
        finally:
            await engine.dispose()
            safe_log(logger, logging.INFO, "application.stopped")


app = FastAPI(title="PostgreSQL Access Control Example", lifespan=lifespan)
for authentication_router in authentication_routers():
    app.include_router(authentication_router)
app.include_router(access_router)


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
                MutableHeaders(scope=message)["X-Request-ID"] = request.state.request_id

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
                field=".".join(str(part) for part in error.get("loc", ())),
                message=str(error.get("msg", "Invalid value")),
            )
            for error in exc.errors()
        ]
    )
    return JSONResponse(
        status_code=422,
        content=error_content(
            request,
            code=BusinessCode.VALIDATION_FAILED,
            message="请求参数校验失败",
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
            message=exc.public_message,
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
            message="请求过于频繁，请稍后重试",
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
            message="身份验证失败",
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
            message="服务暂时不可用",
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
    contract: tuple[int | BusinessCode, str]
    if known_contract is not None:
        contract = known_contract
    else:
        if 400 <= status_code <= 599:
            contract = (generic_error_code(status_code), "请求失败")
        else:
            status_code = 500
            contract = (BusinessCode.INTERNAL_ERROR, "服务器内部错误")
    code, message = contract
    headers = dict(exc.headers or {})
    headers.setdefault("Cache-Control", "no-store")
    if status_code == 401:
        headers.setdefault("WWW-Authenticate", "Bearer")
    return JSONResponse(
        status_code=status_code,
        content=error_content(request, code=code, message=message),
        headers=request_id_headers(request, headers),
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_content(
            request,
            code=BusinessCode.INTERNAL_ERROR,
            message="服务器内部错误",
        ),
        headers=request_id_headers(request, {"Cache-Control": "no-store"}),
    )


@app.exception_handler(OperationalError)
async def handle_database_unavailable(
    request: Request,
    exc: OperationalError,
) -> JSONResponse:
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
            "error_category": dependency_error_category(exc),
            **safe_exception_metadata(exc),
        },
    )
    return JSONResponse(
        status_code=503,
        content=error_content(
            request,
            code=BusinessCode.SERVICE_UNAVAILABLE,
            message="服务暂时不可用",
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
        message="服务正常",
        data={"status": "ok"},
    )
