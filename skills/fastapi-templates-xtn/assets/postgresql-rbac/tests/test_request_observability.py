import asyncio
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from typing import Any, Protocol, cast

import pytest
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Message, Receive, Scope, Send

import app.main as main_module
from app.api_contract import ApiResponse, BusinessCode, api_response
from app.i18n import MessageKey
from app.main import (
    RequestObservabilityMiddleware,
    handle_access_error,
    handle_database_unavailable,
    handle_http_error,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.observability import current_request_id
from app.rbac.errors import RbacError, forbidden


class CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class StructuredRecord(Protocol):
    request_id: str
    http_status_code: int | None
    business_code: int | None
    outcome: str
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
    test_app.add_middleware(RequestObservabilityMiddleware)

    @test_app.exception_handler(RequestValidationError)
    async def validation_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> Any:
        return await handle_request_validation_error(request, exc)

    @test_app.exception_handler(RbacError)
    async def access_handler(request: Request, exc: RbacError) -> Any:
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
            code=BusinessCode.OK,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"status": "ok"},
        )

    @test_app.get("/validated", response_model=ApiResponse[dict[str, int]])
    async def validated(
        request: Request,
        value: int,
    ) -> ApiResponse[dict[str, int]]:
        return api_response(
            request,
            code=BusinessCode.OK,
            message_key=MessageKey.COMMON_SUCCESS,
            data={"value": value},
        )

    @test_app.get("/denied")
    async def denied() -> None:
        raise forbidden("controlled_denial")

    @test_app.get("/database")
    async def database_failure() -> None:
        raise OperationalError("controlled statement", {}, RuntimeError("offline"))

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
    async def background(
        request: Request,
        tasks: BackgroundTasks,
    ) -> ApiResponse[dict[str, str]]:
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


async def test_logging_failure_never_changes_a_successful_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_log(*_args: object, **_kwargs: object) -> None:
        raise OSError("controlled logging failure")

    monkeypatch.setattr(main_module.logger, "log", broken_log)
    transport = ASGITransport(app=main_module.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health/live")

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
        assert completion.response_started is True
        assert completion.response_completed is True


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


async def test_cancelled_request_is_logged_and_reraised() -> None:
    async def cancelled_app(
        _scope: Scope,
        _receive: Receive,
        _send: Send,
    ) -> None:
        raise asyncio.CancelledError

    middleware = RequestObservabilityMiddleware(cancelled_app)
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
    ("failed_message", "expected_status", "expected_started"),
    [("http.response.start", None, False), ("http.response.body", 200, True)],
)
async def test_send_failure_records_the_observed_response_boundary(
    failed_message: str,
    expected_status: int | None,
    expected_started: bool,
) -> None:
    async def controlled_app(
        _scope: Scope,
        _receive: Receive,
        send: Send,
    ) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def failing_send(message: Message) -> None:
        if message["type"] == failed_message:
            raise OSError("controlled send failure")

    middleware = RequestObservabilityMiddleware(controlled_app)
    with capture_application_logs() as records:
        with pytest.raises(OSError):
            await middleware(bare_http_scope(), receive, failing_send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == expected_status
    assert completions[0].outcome == "error"
    assert completions[0].failure_phase == "send"
    assert completions[0].response_started is expected_started
    assert completions[0].response_completed is False
    assert current_request_id() is None


async def test_receive_failure_is_distinct_from_application_failure() -> None:
    async def controlled_app(
        _scope: Scope,
        receive: Receive,
        _send: Send,
    ) -> None:
        await receive()

    async def failing_receive() -> Message:
        raise OSError("controlled receive failure")

    async def send(_message: Message) -> None:
        return None

    middleware = RequestObservabilityMiddleware(controlled_app)
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
    async def controlled_app(
        _scope: Scope,
        receive: Receive,
        _send: Send,
    ) -> None:
        await receive()

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestObservabilityMiddleware(controlled_app)
    with capture_application_logs() as records:
        await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code is None
    assert completions[0].failure_phase == "client_disconnect"
    assert completions[0].client_disconnected is True
    assert completions[0].response_completed is False


async def test_application_return_without_final_body_is_recorded() -> None:
    async def controlled_app(
        _scope: Scope,
        _receive: Receive,
        send: Send,
    ) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestObservabilityMiddleware(controlled_app)
    with capture_application_logs() as records:
        await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == 200
    assert completions[0].failure_phase == "response_incomplete"
    assert completions[0].response_started is True
    assert completions[0].response_completed is False


async def test_response_body_without_start_is_a_protocol_failure() -> None:
    async def controlled_app(
        _scope: Scope,
        _receive: Receive,
        send: Send,
    ) -> None:
        await send({"type": "http.response.body", "body": b"unexpected"})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestObservabilityMiddleware(controlled_app)
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
    async def controlled_app(
        scope: Scope,
        _receive: Receive,
        _send: Send,
    ) -> None:
        scope["state"]["business_code"] = int(BusinessCode.OK)
        raise RuntimeError("controlled application failure")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    middleware = RequestObservabilityMiddleware(controlled_app)
    with capture_application_logs() as records:
        with pytest.raises(RuntimeError):
            await middleware(bare_http_scope(), receive, send)

    completions = records_for(records, "http.request.completed")
    assert len(completions) == 1
    assert completions[0].http_status_code == 500
    assert completions[0].business_code == int(BusinessCode.INTERNAL_ERROR)
