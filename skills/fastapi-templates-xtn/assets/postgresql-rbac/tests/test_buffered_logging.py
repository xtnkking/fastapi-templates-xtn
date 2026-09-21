import asyncio
import io
import json
import logging
import threading
from time import perf_counter
from typing import TextIO
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.core.observability import (
    BufferedLogHandler,
    SafeJsonFormatter,
    bind_request_context,
    deactivate_request_context,
    reset_request_context,
)


class BlockingSink(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release_write = threading.Event()
        self.safety_timeout = False

    def write(self, value: str) -> int:
        self.entered.set()
        # Bound a broken test too; production behavior is tested before release.
        if not self.release_write.wait(timeout=5):
            self.safety_timeout = True
        return super().write(value)


def make_logger(
    stream: TextIO, *, capacity: int = 1000
) -> tuple[logging.Logger, BufferedLogHandler]:
    handler = BufferedLogHandler(stream, capacity=capacity)
    handler.setFormatter(
        SafeJsonFormatter(
            service_name="test",
            service_version="test",
            environment="test",
            include_exception_details=True,
        )
    )
    logger = logging.Logger("app.buffer_test", level=logging.INFO)
    logger.addHandler(handler)
    return logger, handler


async def wait_for_write(sink: BlockingSink) -> None:
    assert await asyncio.to_thread(sink.entered.wait, 1)


async def test_stuck_sink_and_full_queue_do_not_block_http_or_other_coroutines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = BlockingSink()
    logger, handler = make_logger(sink, capacity=2)
    monkeypatch.setattr(main_module, "logger", logger)
    logger.info("test.first")
    try:
        await wait_for_write(sink)
        callback_ran = asyncio.Event()
        asyncio.get_running_loop().call_soon(callback_ran.set)
        async with AsyncClient(
            transport=ASGITransport(app=main_module.app), base_url="http://test"
        ) as client:
            async with asyncio.timeout(1):
                responses = await asyncio.gather(
                    *(client.get("/health/live") for _ in range(20))
                )
                await callback_ran.wait()
        assert all(response.status_code == 200 for response in responses)
        assert not sink.release_write.is_set()
        assert sink.safety_timeout is False
        assert handler.snapshot()["queue_size"] == 2
        assert handler.snapshot()["dropped"] == 18
    finally:
        sink.release_write.set()
        await handler.shutdown(timeout_seconds=1)
    assert handler.snapshot()["written"] == 3
    assert handler.snapshot()["writer_alive"] is False
    lines = [json.loads(line) for line in sink.getvalue().splitlines()]
    completion_ids = {
        line["request_id"]
        for line in lines
        if line["event"] == "http.request.completed"
    }
    assert len(completion_ids) == 2
    assert completion_ids <= {response.json()["request_id"] for response in responses}


async def test_queue_freezes_context_and_mutable_values_and_excludes_secrets() -> None:
    sink = BlockingSink()
    logger, handler = make_logger(sink)
    logger.info("test.first")
    details = {"result": "original", "password": "password-secret"}
    context = bind_request_context("request-at-emission")
    try:
        await wait_for_write(sink)
        try:
            raise RuntimeError("exception-secret")
        except RuntimeError:
            logger.exception("test.snapshot", extra={"details": details})
        details["result"] = "mutated"
        deactivate_request_context()
    finally:
        reset_request_context(context)
        sink.release_write.set()
        await handler.shutdown(timeout_seconds=1)
    rendered = sink.getvalue()
    event = json.loads(rendered.splitlines()[1])
    assert event["request_id"] == "request-at-emission"
    assert event["details"] == {"result": "original", "password": "[REDACTED]"}
    assert "password-secret" not in rendered
    assert "exception-secret" not in rendered
    assert "mutated" not in rendered


@pytest.mark.parametrize("phase", ["write", "flush", "partial"])
async def test_output_failure_is_counted_without_recursive_logging(phase: str) -> None:
    class FailingSink(io.StringIO):
        def write(self, value: str) -> int:
            if phase == "write":
                raise OSError("private-sink-error")
            if phase == "partial":
                return super().write(value[:3])
            return super().write(value)

        def flush(self) -> None:
            if phase == "flush":
                raise OSError("private-sink-error")

    sink = FailingSink()
    logger, handler = make_logger(sink)
    for _ in range(3):
        logger.info("test.failure")
    await handler.shutdown(timeout_seconds=1)
    assert handler.snapshot()["write_failures"] == 3
    assert handler.snapshot()["written"] == 0
    assert handler.snapshot()["writer_alive"] is False
    assert "private-sink-error" not in sink.getvalue()


async def test_bad_formatter_and_oversized_records_are_contained() -> None:
    class BrokenFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            raise RuntimeError("format-secret")

    sink = io.StringIO()
    logger, handler = make_logger(sink)
    logger.info("test.oversized", extra={"items": ["x" * 2048] * 100})
    handler.setFormatter(BrokenFormatter())
    logger.info("test.format_failure")
    await handler.shutdown(timeout_seconds=1)
    assert handler.snapshot()["dropped"] == 1
    assert handler.snapshot()["format_failures"] == 1
    assert sink.getvalue() == ""


async def test_shutdown_is_bounded_and_drops_pending_records() -> None:
    sink = BlockingSink()
    logger, handler = make_logger(sink)
    logger.info("test.inflight")
    try:
        await wait_for_write(sink)
        logger.info("test.pending")
        start = perf_counter()
        await handler.shutdown(timeout_seconds=0.02)
        assert perf_counter() - start < 0.5
        assert handler.snapshot()["writer_alive"] is True
        assert handler.snapshot()["queue_size"] == 0
        assert handler.snapshot()["dropped"] == 1
        logger.info("test.after_close")
        assert handler.snapshot()["dropped"] == 2
        assert sink.safety_timeout is False
    finally:
        sink.release_write.set()
        await handler.shutdown(timeout_seconds=1)
    assert [json.loads(line)["event"] for line in sink.getvalue().splitlines()] == [
        "test.inflight"
    ]


async def test_cancelled_shutdown_discards_queue_and_preserves_cancellation() -> None:
    sink = BlockingSink()
    logger, handler = make_logger(sink)
    logger.info("test.inflight")
    try:
        await wait_for_write(sink)
        logger.info("test.pending")
        shutdown = asyncio.create_task(handler.shutdown(timeout_seconds=1))
        await asyncio.sleep(0)
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shutdown
        assert handler.snapshot()["queue_size"] == 0
        assert handler.snapshot()["dropped"] == 1
    finally:
        sink.release_write.set()
        await handler.shutdown(timeout_seconds=1)


async def test_writer_start_failure_does_not_break_logging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_start(self: threading.Thread) -> None:
        raise RuntimeError("no thread resources")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    sink = io.StringIO()
    logger, handler = make_logger(sink)
    logger.info("test.unavailable")
    await handler.shutdown(timeout_seconds=0)
    assert handler.snapshot()["write_failures"] == 1
    assert handler.snapshot()["dropped"] == 1
    assert handler.snapshot()["writer_alive"] is False


@pytest.mark.parametrize("fail_setup", [False, True])
async def test_lifespan_cleans_log_writer_and_clients_on_exit_or_setup_failure(
    monkeypatch: pytest.MonkeyPatch, fail_setup: bool
) -> None:
    sink = io.StringIO()
    logger, handler = make_logger(sink)
    redis_client = AsyncMock()
    rate_client = AsyncMock()
    fake_engine = MagicMock()
    fake_engine.dispose = AsyncMock()
    monkeypatch.setattr(main_module, "configure_logging", lambda **kwargs: handler)
    monkeypatch.setattr(main_module, "logger", logger)
    monkeypatch.setattr(main_module, "engine", fake_engine)
    monkeypatch.setattr(
        main_module, "create_redis_client", lambda settings: redis_client
    )

    def rate_client_factory(settings: object) -> object:
        if fail_setup:
            raise RuntimeError("setup failed")
        return rate_client

    monkeypatch.setattr(
        main_module, "create_rate_limit_redis_client", rate_client_factory
    )
    application = FastAPI()
    if fail_setup:
        with pytest.raises(RuntimeError, match="setup failed"):
            async with main_module.lifespan(application):
                pytest.fail("failed setup cannot serve requests")
        rate_client.aclose.assert_not_awaited()
    else:
        async with main_module.lifespan(application):
            assert application.state.log_handler is handler
        rate_client.aclose.assert_awaited_once()
    redis_client.aclose.assert_awaited_once()
    fake_engine.dispose.assert_awaited_once()
    assert handler.snapshot()["writer_alive"] is False
    assert sink.closed is False


async def test_normal_shutdown_drains_records_without_closing_stdout() -> None:
    sink = io.StringIO()
    logger, handler = make_logger(sink)
    for index in range(100):
        logger.info("test.drain", extra={"index": index})
    await handler.shutdown(timeout_seconds=1)
    assert handler.snapshot()["written"] == 100
    assert handler.snapshot()["dropped"] == 0
    assert handler.snapshot()["writer_alive"] is False
    assert sink.closed is False
    assert [json.loads(line)["index"] for line in sink.getvalue().splitlines()] == list(
        range(100)
    )
