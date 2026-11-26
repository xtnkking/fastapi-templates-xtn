#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    请求日志、异常和响应完成状态的离线回归测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        测试直接引用请求日志中间件及异常处理模块
# 2026/09/29    XTN       V1.001        用隔离测试应用的成功路由验证日志失败不影响响应
# 2026/09/29    XTN       V1.002        从请求上下文模块读取关联 ID
# 2026/10/02    XTN       V1.003        核对完成与响应后失败事件共用的请求字段
# 2026/10/10    XTN       V1.004        统一用户 ID 与当前用户命名
# 2026/10/15    XTN       V1.005        验证统一响应集中记录业务结果且发送失败不会覆盖
# 2026/10/16    XTN       V1.006        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.007        验证登录日志身份复用请求上下文并在并发及响应故障下保持正确
# --------------------------------------------------------------------------------------------------

import asyncio
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from contextvars import copy_context
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Message, Receive, Scope, Send

import app.core.middleware.request_logging as request_logging_module
from app.core.codes import BusinessCode
from app.core.config import get_settings
from app.core.exception_handlers import (
    handle_access_error,
    handle_database_unavailable,
    handle_http_error,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.core.exceptions import AppError, forbidden_403
from app.core.i18n.messages import MessageKey
from app.core.ids import new_entity_id
from app.core.logging.context import (
    bind_request_context,
    current_http_details,
    current_request_id,
    deactivate_request_context,
    reset_request_context,
    set_log_user_id,
)
from app.core.logging.details import HttpLogDetails
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.response import ApiResponse, api_response, error_content
from app.core.security.passwords import PasswordVerification
from app.models.postgres.user import User
from app.repositories.postgres.user_repository import user_repository
from app.services.auth_service import AuthService


class CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class StructuredRecord(Protocol):
    """列出断言会读取的结构化日志字段，便于静态类型检查。"""

    request_id: str
    http_method: str
    route: str
    http_status_code: int | None
    business_code: int | None
    duration_ms: float | None
    user_id: str | None
    outcome: str
    operation_outcome: str
    failure_phase: str
    exception_type: str
    response_started: bool
    response_completed: bool
    client_disconnected: bool


@contextmanager
def capture_application_logs() -> Iterator[list[logging.LogRecord]]:
    application_logger = logging.getLogger("app")
    previous_level = application_logger.level
    previous_disabled = application_logger.disabled
    handler = CaptureHandler()
    application_logger.setLevel(logging.INFO)
    application_logger.disabled = False
    application_logger.addHandler(handler)
    try:
        yield handler.records
    finally:
        application_logger.removeHandler(handler)
        application_logger.setLevel(previous_level)
        application_logger.disabled = previous_disabled


def records_for(records: list[logging.LogRecord], event: str) -> list[StructuredRecord]:
    return cast(
        list[StructuredRecord],
        [record for record in records if record.msg == event],
    )


def build_test_app() -> FastAPI:
    test_app = FastAPI()
    test_app.add_middleware(RequestLoggingMiddleware)

    @test_app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> Any:
        return await handle_request_validation_error(request, exc)

    @test_app.exception_handler(AppError)
    async def access_handler(request: Request, exc: AppError) -> Any:
        return await handle_access_error(request, exc)

    @test_app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException) -> Any:
        return await handle_http_error(request, exc)

    @test_app.exception_handler(OperationalError)
    async def database_handler(request: Request, exc: OperationalError) -> Any:
        return await handle_database_unavailable(request, exc)

    @test_app.exception_handler(Exception)
    async def unexpected_handler(request: Request, exc: Exception) -> Any:
        return await handle_unexpected_error(request, exc)

    @test_app.get("/ok", response_model=ApiResponse[dict[str, str]])
    async def ok(request: Request) -> ApiResponse[dict[str, str]]:
        return api_response(
            request,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"status": "ok"},
        )

    @test_app.post("/created", status_code=201, response_model=ApiResponse[dict[str, str]])
    async def created(request: Request) -> ApiResponse[dict[str, str]]:
        return api_response(
            request,
            code=BusinessCode.CREATED,
            message_key=MessageKey.COMMON_CREATED,
            data={"status": "created"},
        )

    @test_app.get("/validated", response_model=ApiResponse[dict[str, int]])
    async def validated(request: Request, value: int) -> ApiResponse[dict[str, int]]:
        return api_response(
            request,
            code=BusinessCode.OK,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"value": value},
        )

    @test_app.get("/denied")
    async def denied() -> None:
        raise forbidden_403("controlled_denial")

    @test_app.get("/database")
    async def database_failure() -> None:
        raise OperationalError(
            "controlled statement",
            {},
            RuntimeError("offline"),
            connection_invalidated=True,
        )

    @test_app.get("/stream")
    async def stream() -> StreamingResponse:
        async def content() -> AsyncIterator[bytes]:
            yield b"partial"
            raise RuntimeError("controlled stream failure")

        return StreamingResponse(content(), media_type="text/plain")

    @test_app.get("/stream-ok")
    async def successful_stream() -> StreamingResponse:
        request_id = current_request_id()
        assert request_id is not None

        async def content() -> AsyncIterator[bytes]:
            assert current_request_id() == request_id
            yield b"first"
            await asyncio.sleep(0)
            assert current_request_id() == request_id
            yield b"second"

        return StreamingResponse(content(), media_type="text/plain")

    @test_app.get("/background", response_model=ApiResponse[dict[str, str]])
    async def background(request: Request, tasks: BackgroundTasks) -> ApiResponse[dict[str, str]]:
        def fail_after_response() -> None:
            assert current_request_id() is None
            raise RuntimeError("controlled background failure")

        tasks.add_task(fail_after_response)
        return api_response(
            request,
            code=BusinessCode.OK,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"status": "scheduled"},
        )

    @test_app.get("/context", response_model=ApiResponse[dict[str, str]])
    async def context(request: Request) -> ApiResponse[dict[str, str]]:
        await asyncio.sleep(0)
        observed = current_request_id()
        assert observed is not None
        return api_response(
            request,
            code=BusinessCode.OK,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"context_request_id": observed},
        )

    return test_app


async def test_logging_failure_never_changes_a_successful_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        验证日志输出抛错不会改变隔离测试路由的成功响应。

    :param monkeypatch: 临时将请求日志方法替换为主动抛错的测试实现。
    :return: 无返回值；成功状态、业务码和请求 ID 必须保持正确。
    """
    def broken_log(*_args: object, **_kwargs: object) -> None:
        """
            模拟日志输出失败，不参与响应内容的生成。

        :param _args: 原日志方法收到的位置参数。
        :param _kwargs: 原日志方法收到的关键字参数。
        :return: 不会正常返回；固定抛出受控日志异常。
        :raises OSError: 模拟日志输出端不可用。
        """
        raise OSError("controlled logging failure")

    monkeypatch.setattr(request_logging_module.logger, "log", broken_log)
    transport = ASGITransport(app=build_test_app(), raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ok")

    assert response.status_code == 200
    assert response.json()["code"] == int(BusinessCode.OK)
    assert response.headers["X-Request-ID"] == response.json()["request_id"]


async def test_known_error_paths_each_emit_one_completion_event() -> None:
    test_app = build_test_app()
    transport = ASGITransport(app=test_app, raise_app_exceptions=False)
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            responses = [
                await client.get("/missing"),
                await client.post("/ok"),
                await client.get("/validated", params={"value": "not-an-int"}),
                await client.get("/denied"),
                await client.get("/database"),
            ]

    expected = [
        (404, BusinessCode.NOT_FOUND),
        (405, BusinessCode.METHOD_NOT_ALLOWED),
        (422, BusinessCode.VALIDATION_FAILED),
        (403, BusinessCode.ACCESS_FORBIDDEN),
        (503, BusinessCode.SERVICE_UNAVAILABLE),
    ]
    completions = records_for(records, "http.request.completed")
    assert len(completions) == len(expected)
    for response, completion, (status_code, business_code) in zip(
        responses, completions, expected, strict=True
    ):
        body = response.json()
        assert response.status_code == status_code
        assert body["code"] == int(business_code)
        assert response.headers["X-Request-ID"] == body["request_id"]
        assert completion.request_id == body["request_id"]
        assert completion.http_status_code == status_code
        assert completion.business_code == int(business_code)
        assert completion.operation_outcome == completion.outcome == "failure"
        assert completion.response_started is True
        assert completion.response_completed is True


@pytest.mark.parametrize(
    ("method", "path", "status_code", "business_code"),
    [("GET", "/ok", 200, BusinessCode.OK), ("POST", "/created", 201, BusinessCode.CREATED)],
)
async def test_unified_success_response_records_operation_outcome(
    method: str, path: str, status_code: int, business_code: BusinessCode,
) -> None:
    transport = ASGITransport(app=build_test_app())
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.request(method, path)

    completions = records_for(records, "http.request.completed")
    assert response.status_code == status_code
    assert len(completions) == 1
    assert completions[0].business_code == response.json()["code"] == int(business_code)
    assert completions[0].operation_outcome == completions[0].outcome == "success"
    assert completions[0].response_started is True
    assert completions[0].response_completed is True


async def test_stream_failure_emits_one_error_completion_with_started_status() -> None:
    test_app = build_test_app()
    transport = ASGITransport(app=test_app, raise_app_exceptions=False)
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/stream")

    completions = records_for(records, "http.request.completed")
    assert response.status_code == 200
    assert len(completions) == 1
    assert completions[0].request_id == response.headers["X-Request-ID"]
    assert completions[0].http_status_code == 200
    assert completions[0].outcome == "error"
    assert completions[0].failure_phase == "response_body"
    assert completions[0].exception_type == "RuntimeError"
    assert completions[0].response_started is True
    assert completions[0].response_completed is False
    assert not records_for(records, "http.request.post_response_failed")


async def test_multichunk_stream_emits_one_successful_completion() -> None:
    test_app = build_test_app()
    transport = ASGITransport(app=test_app)
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/stream-ok")

    completions = records_for(records, "http.request.completed")
    assert response.content == b"firstsecond"
    assert len(completions) == 1
    assert completions[0].http_status_code == 200
    assert completions[0].outcome == "success"
    assert completions[0].response_started is True
    assert completions[0].response_completed is True
    assert current_request_id() is None


async def test_background_failure_uses_a_separate_post_response_event() -> None:
    test_app = build_test_app()
    transport = ASGITransport(app=test_app, raise_app_exceptions=False)
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/background")

    completions = records_for(records, "http.request.completed")
    post_response = records_for(records, "http.request.post_response_failed")
    assert response.status_code == 200
    assert response.json()["code"] == int(BusinessCode.OK)
    assert len(completions) == 1
    assert completions[0].http_status_code == 200
    assert completions[0].business_code == int(BusinessCode.OK)
    assert completions[0].outcome == "success"
    assert completions[0].response_started is True
    assert completions[0].response_completed is True
    assert len(post_response) == 1
    assert post_response[0].request_id == response.json()["request_id"]
    assert post_response[0].http_method == completions[0].http_method == "GET"
    assert post_response[0].route == completions[0].route == "/background"
    assert post_response[0].business_code == completions[0].business_code
    assert completions[0].user_id is None
    assert post_response[0].user_id is None
    assert isinstance(post_response[0].duration_ms, float)
    assert isinstance(completions[0].duration_ms, float)
    assert post_response[0].failure_phase == "post_response"
    assert post_response[0].exception_type == "RuntimeError"


async def test_concurrent_requests_keep_request_context_isolated() -> None:
    test_app = build_test_app()
    transport = ASGITransport(app=test_app)
    with capture_application_logs() as records:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            first, second = await asyncio.gather(
                client.get("/context"),
                client.get("/context"),
            )

    response_ids = {first.json()["request_id"], second.json()["request_id"]}
    observed_ids = {
        first.json()["data"]["context_request_id"],
        second.json()["data"]["context_request_id"],
    }
    completion_ids = {
        record.request_id for record in records_for(records, "http.request.completed")
    }
    assert len(response_ids) == 2
    assert observed_ids == response_ids
    assert completion_ids == response_ids
    assert current_request_id() is None


def test_log_user_update_ignores_missing_http_or_expired_context() -> None:
    assert current_http_details() is None
    set_log_user_id("U11111111111111")
    operation_token = bind_request_context("operation-without-http")
    try:
        set_log_user_id("U11111111111111")
        assert current_http_details() is None
    finally:
        reset_request_context(operation_token)

    request = Request(bare_http_scope())
    token = bind_request_context("request-with-http", http_details=HttpLogDetails(request, None))
    copied_context = copy_context()
    try:
        set_log_user_id("U11111111111111")
        assert request.state.user_id == "U11111111111111"
        deactivate_request_context()
        copied_context.run(set_log_user_id, "U22222222222222")
        assert copied_context.run(current_http_details) is None
        assert request.state.user_id == "U11111111111111"
    finally:
        reset_request_context(token)


async def test_concurrent_log_user_updates_use_their_own_http_request() -> None:
    async def record_user(user_id: str) -> str:
        request = Request(bare_http_scope())
        token = bind_request_context(user_id, http_details=HttpLogDetails(request, None))
        try:
            set_log_user_id(user_id)
            await asyncio.sleep(0)
            details = current_http_details()
            assert details is not None and details.request is request
            return cast(str, request.state.user_id)
        finally:
            deactivate_request_context()
            reset_request_context(token)

    users = ["U11111111111111", "U22222222222222"]
    assert await asyncio.gather(*(record_user(user_id) for user_id in users)) == users
    assert current_http_details() is None


@pytest.mark.parametrize("response_mode", ["success", "send_failure", "post_response_failure"])
async def test_service_login_identity_reaches_request_logs_without_route_assignment(
    monkeypatch: pytest.MonkeyPatch, response_mode: str,
) -> None:
    user = User(user_id=new_entity_id("U"), user_name="alice", password_hash="$argon2id$current",
                password_changed_at=datetime.now(UTC), is_active=True, deleted_at=None, token_version=4)
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    session.begin = Mock(return_value=AsyncMock())
    service = AuthService(
        cast(async_sessionmaker[AsyncSession], Mock(return_value=session)),
        Mock(verify_or_dummy=AsyncMock(return_value=PasswordVerification(True, False, False))),
    )
    monkeypatch.setattr(user_repository, "get_user", AsyncMock(return_value=user))
    monkeypatch.setattr(user_repository, "lock_users", AsyncMock(return_value={user.user_id: user}))
    issuer = AsyncMock(return_value="signed-access-token")
    monkeypatch.setattr("app.services.auth_service.AuthService.issue_access_token", issuer)

    async def login_app(scope: Scope, receive: Receive, send: Send) -> None:
        result = await service.login(user_name="alice", password="current-password",
                                     redis=cast(Any, object()), settings=get_settings())
        response = api_response(Request(scope), message_key=MessageKey.AUTH_LOGIN_SUCCEEDED,
                                data={"access_token": result.access_token, "expires_in": result.expires_in})
        await JSONResponse(response.model_dump(mode="json"))(scope, receive, send)
        if response_mode == "post_response_failure":
            raise RuntimeError("controlled failure after login response")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        if response_mode == "send_failure" and message["type"] == "http.response.body":
            raise OSError("controlled login response send failure")

    middleware = RequestLoggingMiddleware(login_app)
    with capture_application_logs() as records:
        if response_mode == "success":
            await middleware(bare_http_scope("/api/v1/auth/login"), receive, send)
        else:
            with pytest.raises(OSError if response_mode == "send_failure" else RuntimeError):
                await middleware(bare_http_scope("/api/v1/auth/login"), receive, send)

    issuer.assert_awaited_once()
    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].user_id == user.user_id
    assert completions[0].operation_outcome == "success"
    assert completions[0].outcome == ("error" if response_mode == "send_failure" else "success")
    assert completions[0].response_completed is (response_mode != "send_failure")
    post_response = records_for(records, "http.request.post_response_failed")
    assert len(post_response) == (1 if response_mode == "post_response_failure" else 0)
    if post_response:
        assert post_response[0].user_id == user.user_id
    assert current_http_details() is None


async def test_cancelled_request_is_logged_and_reraised() -> None:
    async def cancelled_app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        raise asyncio.CancelledError

    middleware = RequestLoggingMiddleware(cancelled_app)
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/cancelled",
        "raw_path": b"/cancelled",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    with capture_application_logs() as records:
        with pytest.raises(asyncio.CancelledError):
            await middleware(scope, receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code is None
    assert completions[0].outcome == "error"
    assert completions[0].failure_phase == "request_cancelled"
    assert completions[0].exception_type == "CancelledError"
    assert completions[0].response_started is False
    assert completions[0].response_completed is False
    assert current_request_id() is None


def bare_http_scope(path: str = "/controlled") -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }


@pytest.mark.parametrize(
    ("failed_message", "expected_started"),
    [("http.response.start", False), ("http.response.body", True)],
)
@pytest.mark.parametrize(
    ("status_code", "business_code", "message_key", "operation_outcome"),
    [
        (200, BusinessCode.OK, MessageKey.COMMON_SUCCESS, "success"),
        (403, BusinessCode.ACCESS_FORBIDDEN, MessageKey.ERROR_FORBIDDEN, "failure"),
        (500, BusinessCode.INTERNAL_ERROR, MessageKey.ERROR_INTERNAL, "failure"),
    ],
)
async def test_send_failure_records_the_observed_response_boundary(
    failed_message: str, expected_started: bool, status_code: int, business_code: BusinessCode,
    message_key: MessageKey, operation_outcome: str,
) -> None:
    async def controlled_app(scope: Scope, receive: Receive, send: Send) -> None:
        response: ApiResponse[None] = api_response(
            Request(scope), code=business_code, message_key=message_key, data=None,
        )
        await JSONResponse(response.model_dump(mode="json"), status_code=status_code)(scope, receive, send)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def failing_send(message: Message) -> None:
        if message["type"] == failed_message:
            raise OSError("controlled send failure")

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        with pytest.raises(OSError):
            await middleware(bare_http_scope(), receive, failing_send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == (status_code if expected_started else None)
    assert completions[0].business_code == int(business_code)
    assert completions[0].outcome == "error"
    assert completions[0].operation_outcome == operation_outcome
    assert completions[0].failure_phase == "send"
    assert completions[0].response_started is expected_started
    assert completions[0].response_completed is False
    assert current_request_id() is None


@pytest.mark.parametrize(
    ("business_code", "message_key"),
    [
        (BusinessCode.ACCESS_FORBIDDEN, MessageKey.ERROR_FORBIDDEN),
        (BusinessCode.INTERNAL_ERROR, MessageKey.ERROR_INTERNAL),
    ],
)
def test_error_content_preserves_an_already_successful_operation(
    business_code: BusinessCode, message_key: MessageKey,
) -> None:
    request = Request(bare_http_scope())
    success = api_response(request, message_key=MessageKey.COMMON_SUCCESS, data={"changed": True})
    error = error_content(request, code=business_code, message_key=message_key)

    assert success.code == int(BusinessCode.OK)
    assert error["code"] == request.state.business_code == int(business_code)
    assert request.state.operation_outcome == "success"
    assert error["request_id"] == str(success.request_id)


async def test_receive_failure_is_distinct_from_application_failure() -> None:
    async def controlled_app(_scope: Scope, receive: Receive, _send: Send) -> None:
        await receive()

    async def failing_receive() -> Message:
        raise OSError("controlled receive failure")

    async def send(_message: Message) -> None:
        return None

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        with pytest.raises(OSError):
            await middleware(bare_http_scope(), failing_receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == 500
    assert completions[0].business_code == int(BusinessCode.INTERNAL_ERROR)
    assert completions[0].failure_phase == "receive"
    assert completions[0].response_started is False
    assert completions[0].response_completed is False


async def test_client_disconnect_without_response_is_recorded() -> None:
    async def controlled_app(_scope: Scope, receive: Receive, _send: Send) -> None:
        await receive()

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code is None
    assert completions[0].failure_phase == "client_disconnect"
    assert completions[0].client_disconnected is True
    assert completions[0].response_completed is False


async def test_application_return_without_final_body_is_recorded() -> None:
    async def controlled_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == 200
    assert completions[0].failure_phase == "response_incomplete"
    assert completions[0].response_started is True
    assert completions[0].response_completed is False


async def test_response_body_without_start_is_a_protocol_failure() -> None:
    async def controlled_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send({"type": "http.response.body", "body": b"unexpected"})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code is None
    assert completions[0].outcome == "error"
    assert completions[0].failure_phase == "response_without_start"
    assert completions[0].response_started is False
    assert completions[0].response_completed is True


async def test_application_failure_replaces_a_stale_success_business_code() -> None:
    async def controlled_app(scope: Scope, _receive: Receive, _send: Send) -> None:
        scope["state"]["business_code"] = int(BusinessCode.OK)
        raise RuntimeError("controlled application failure")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestLoggingMiddleware(controlled_app)
    with capture_application_logs() as records:
        with pytest.raises(RuntimeError):
            await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == 500
    assert completions[0].business_code == int(BusinessCode.INTERNAL_ERROR)
