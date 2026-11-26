#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证控制台和按日期保存的文件日志、脱敏、故障隔离及应用退出清理。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        替代已删除的后台队列测试
# 2026/10/14    XTN       V1.001        验证文件落盘、跨天追加、故障隔离和两类处理器清理
# 2026/10/14    XTN       V1.002        验证 UTF-8 字节阈值拆分、连续编号、重启及轮转故障
# 2026/10/14    XTN       V1.003        控制台和文件日志均不写入服务名、版本和环境标识
# 2026/10/14    XTN       V1.004        验证跨中国午夜的日志时间、目录日期与真实时刻一致
# --------------------------------------------------------------------------------------------------

import io
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.core.logging.output as output_module
import app.core.middleware.request_logging as request_logging_module
import app.main as main_module
from app.core.config import get_settings
from app.core.logging.events import SafeJsonFormatter, safe_log
from app.core.logging.output import DailyFileHandler, SafeStreamHandler
from app.core.middleware.request_logging import RequestLoggingMiddleware


def make_logger(stream: io.StringIO) -> tuple[logging.Logger, SafeStreamHandler]:
    """
        构造隔离的应用日志器，避免测试改动进程全局配置。

    :param stream: 接收测试日志的内存输出流。
    :return: 测试日志器及其安全输出处理器。
    """
    handler = SafeStreamHandler(stream)
    handler.setFormatter(
        SafeJsonFormatter(
            include_exception_details=False,
        )
    )
    logger = logging.Logger("app.logging_test", level=logging.INFO)
    logger.addHandler(handler)
    return logger, handler


def make_file_logger(log_root_dir: Path, *, max_file_bytes: int = 10_000
                     ) -> tuple[logging.Logger, DailyFileHandler]:
    handler = DailyFileHandler(log_root_dir, max_file_bytes)
    handler.setFormatter(SafeJsonFormatter(include_exception_details=False))
    logger = logging.Logger("app.file_logging_test", level=logging.INFO)
    logger.addHandler(handler)
    return logger, handler


def test_safe_output_is_json_and_redacts_sensitive_fields() -> None:
    """
        验证普通事件写成单行 JSON，敏感字段不会进入输出。

    :return: 无返回值；输出形状与脱敏结果均已断言。
    """
    stream = io.StringIO()
    logger, handler = make_logger(stream)
    safe_log(logger, logging.INFO, "test.event", extra={
        "password": "secret", "count": 2,
        "service": "forged-service", "service_version": "forged-version", "environment": "forged-env",
    })

    event = json.loads(stream.getvalue())
    assert event["event"] == "test.event"
    assert event["password"] == "[REDACTED]"
    assert event["count"] == 2
    assert {"service", "service_version", "environment"}.isdisjoint(event)
    assert len(stream.getvalue().splitlines()) == 1
    handler.close()
    assert not stream.closed


def test_failing_or_oversized_output_does_not_break_business_logging() -> None:
    """
        验证输出流故障和超长日志只丢弃该条记录，不抛给调用方。

    :return: 无返回值；安全日志调用保持非抛出行为。
    """
    class FailingStream(io.StringIO):
        """模拟故障输出流，不回显任何原始日志内容。"""

        def write(self, text: str) -> int:
            """
                模拟操作系统输出故障。

            :param text: 准备写出的安全 JSON 日志。
            :return: 无正常返回；始终抛出输出故障。
            :raises OSError: 模拟标准输出不可用。
            """
            raise OSError("stdout unavailable")

    broken_logger, broken_handler = make_logger(FailingStream())
    assert safe_log(broken_logger, logging.ERROR, "test.failure")
    broken_handler.close()

    stream = io.StringIO()
    logger, handler = make_logger(stream)
    assert safe_log(logger, logging.INFO, "test.large", extra={"values": ["x" * 2000] * 100})
    assert stream.getvalue() == ""
    handler.close()


def test_configuration_changes_only_application_logging(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """
        验证配置不清空根日志器，也不禁用 Uvicorn 的错误日志。

    :param monkeypatch: 为配置函数提供隔离的日志器与内存输出流。
    :return: 无返回值；只关闭原始 Uvicorn 访问日志。
    """
    app_logger = logging.Logger("app")
    access_logger = logging.Logger("uvicorn.access")
    real_get_logger = logging.getLogger
    root_handlers = list(real_get_logger().handlers)
    error_logger = real_get_logger("uvicorn.error")
    error_disabled = error_logger.disabled
    selected = {"app": app_logger, "uvicorn.access": access_logger}
    with monkeypatch.context() as patch:
        patch.setattr(logging, "getLogger", lambda name=None: selected[name]
                      if name in selected else real_get_logger(name))
        patch.setattr(sys, "stdout", io.StringIO())
        handlers = output_module.configure_logging(
            log_level="INFO", include_exception_details=False, log_file_max_mb=2,
            log_root_dir=tmp_path / "logs",
        )

    assert app_logger.handlers == list(handlers)
    assert isinstance(handlers[0], SafeStreamHandler)
    assert isinstance(handlers[1], DailyFileHandler)
    assert handlers[1].max_file_bytes == 2 * 1024 * 1024
    assert not app_logger.propagate
    assert access_logger.disabled
    assert error_logger.disabled == error_disabled
    assert real_get_logger().handlers == root_handlers
    for handler in handlers:
        handler.close()


def test_file_logging_creates_safe_json_only_when_needed(tmp_path: Path) -> None:
    log_root = tmp_path / "logs"
    logger, handler = make_file_logger(log_root)
    assert not log_root.exists()
    try:
        safe_log(logger, logging.INFO, "test.file", extra={
            "password": "secret", "count": 2,
            "service": "forged-service", "service_version": "forged-version", "environment": "forged-env",
        })
        paths = list(log_root.glob("*/app.log"))
        assert len(paths) == 1
        content = paths[0].read_text(encoding="utf-8")
        event = json.loads(content)
        assert event["event"] == "test.file" and event["count"] == 2
        assert event["password"] == "[REDACTED]" and "secret" not in content
        assert {"service", "service_version", "environment"}.isdisjoint(event)
        assert len(content.splitlines()) == 1
        safe_log(logger, logging.INFO, "test.large", extra={"values": ["x" * 2000] * 100})
        assert paths[0].read_text(encoding="utf-8") == content
    finally:
        handler.close()


def test_file_logging_switches_beijing_day_and_appends_after_restart(tmp_path: Path) -> None:
    logger, handler = make_file_logger(tmp_path)
    first = logger.makeRecord(logger.name, logging.INFO, __file__, 0, "test.before_midnight", (), None)
    first.created = datetime(2026, 10, 14, 15, 59, 59, 123000, tzinfo=UTC).timestamp()
    second = logger.makeRecord(logger.name, logging.INFO, __file__, 0, "test.after_midnight", (), None)
    second.created = datetime(2026, 10, 14, 16, 0, 0, tzinfo=UTC).timestamp()
    try:
        logger.handle(first)
        old_stream = handler.stream
        logger.handle(second)
        assert old_stream is not None and old_stream.closed
        first_event = json.loads((tmp_path / "2026-10-14" / "app.log").read_text(encoding="utf-8"))
        assert first_event["event"] == "test.before_midnight"
        assert first_event["timestamp"] == "2026-10-14T23:59:59.123+08:00"
        assert datetime.fromisoformat(first_event["timestamp"]).timestamp() == first.created
    finally:
        handler.close()

    restarted_logger, restarted_handler = make_file_logger(tmp_path)
    try:
        restarted_logger.handle(second)
    finally:
        restarted_handler.close()
    events = [json.loads(line) for line in (tmp_path / "2026-10-15" / "app.log").read_text(
        encoding="utf-8",
    ).splitlines()]
    assert [event["event"] for event in events] == ["test.after_midnight", "test.after_midnight"]
    assert all(event["timestamp"] == "2026-10-15T00:00:00.000+08:00" for event in events)


@pytest.mark.parametrize("message", ["ASCII", "汉字"])
def test_file_size_boundary_counts_utf8_bytes_and_single_lf(tmp_path: Path, message: str) -> None:
    expected_line = (message + "\n").encode("utf-8")
    limit = len(expected_line) * 2
    logger, handler = make_file_logger(tmp_path, max_file_bytes=limit)
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        logger.info(message)
        logger.info(message)
        day_directory = next(tmp_path.iterdir())
        assert (day_directory / "app.log").read_bytes() == expected_line * 2
        assert not (day_directory / "app.1.log").exists()
        logger.info(message)
        assert (day_directory / "app.log").stat().st_size == limit
        assert (day_directory / "app.1.log").read_bytes() == expected_line
    finally:
        handler.close()


def test_file_splits_preserve_every_line_and_restart_continues_highest_number(tmp_path: Path) -> None:
    logger, handler = make_file_logger(tmp_path, max_file_bytes=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        for index in range(13):
            logger.info("%02d", index)
    finally:
        handler.close()

    restarted_logger, restarted_handler = make_file_logger(tmp_path, max_file_bytes=3)
    restarted_handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        restarted_logger.info("13")
    finally:
        restarted_handler.close()

    day_directory = next(tmp_path.iterdir())
    expected_names = ["app.log", *(f"app.{index}.log" for index in range(1, 14))]
    assert {path.name for path in day_directory.iterdir()} == set(expected_names)
    contents = [(day_directory / name).read_bytes() for name in expected_names]
    assert contents == [f"{index:02d}\n".encode() for index in range(14)]
    assert all(len(content) == 3 for content in contents)


def test_file_segment_number_resets_on_new_beijing_day(tmp_path: Path) -> None:
    logger, handler = make_file_logger(tmp_path, max_file_bytes=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        for message, timestamp in (
            ("00", datetime(2026, 10, 14, 15, 59, 59, tzinfo=UTC)),
            ("01", datetime(2026, 10, 14, 15, 59, 59, tzinfo=UTC)),
            ("02", datetime(2026, 10, 14, 16, 0, 0, tzinfo=UTC)),
        ):
            record = logger.makeRecord(logger.name, logging.INFO, __file__, 0, message, (), None)
            record.created = timestamp.timestamp()
            logger.handle(record)
    finally:
        handler.close()

    assert (tmp_path / "2026-10-14" / "app.log").read_bytes() == b"00\n"
    assert (tmp_path / "2026-10-14" / "app.1.log").read_bytes() == b"01\n"
    assert (tmp_path / "2026-10-15" / "app.log").read_bytes() == b"02\n"
    assert not (tmp_path / "2026-10-15" / "app.1.log").exists()


def test_smaller_file_limit_after_restart_preserves_large_existing_segment(tmp_path: Path) -> None:
    logger, handler = make_file_logger(tmp_path, max_file_bytes=9)
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        for index in range(3):
            logger.info("%02d", index)
    finally:
        handler.close()

    restarted_logger, restarted_handler = make_file_logger(tmp_path, max_file_bytes=3)
    restarted_handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        restarted_logger.info("03")
    finally:
        restarted_handler.close()

    day_directory = next(tmp_path.iterdir())
    assert (day_directory / "app.log").read_bytes() == b"00\n01\n02\n"
    assert (day_directory / "app.1.log").read_bytes() == b"03\n"


def test_rotation_open_failure_keeps_stdout_and_can_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    logger, stdout_handler = make_logger(stream)
    _, file_handler = make_file_logger(tmp_path, max_file_bytes=4)
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    try:
        logger.info("e.a")
        old_stream = file_handler.stream
        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", MagicMock(side_effect=OSError("disk unavailable")))
            logger.info("e.b")
        assert old_stream is not None and old_stream.closed
        logger.info("e.c")
        day_directory = next(tmp_path.iterdir())
        assert (day_directory / "app.log").read_bytes() == b"e.a\n"
        assert (day_directory / "app.1.log").read_bytes() == b"e.c\n"
        assert [json.loads(line)["event"] for line in stream.getvalue().splitlines()] == ["e.a", "e.b", "e.c"]
    finally:
        stdout_handler.close()
        file_handler.close()


def test_reconfiguration_closes_old_handlers_without_duplicate_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    app_logger = logging.Logger("app")
    access_logger = logging.Logger("uvicorn.access")
    real_get_logger = logging.getLogger
    selected = {"app": app_logger, "uvicorn.access": access_logger}
    stream = io.StringIO()
    monkeypatch.setattr(logging, "getLogger", lambda name=None: selected[name]
                        if name in selected else real_get_logger(name))
    monkeypatch.setattr(sys, "stdout", stream)
    old_handlers = output_module.configure_logging(
        log_level="INFO", include_exception_details=False, log_file_max_mb=1, log_root_dir=tmp_path,
    )
    safe_log(app_logger, logging.INFO, "test.before_reconfigure")
    old_file_stream = old_handlers[1].stream
    handlers = output_module.configure_logging(
        log_level="INFO", include_exception_details=False, log_file_max_mb=1, log_root_dir=tmp_path,
    )
    try:
        assert all(vars(handler)["_closed"] for handler in old_handlers)
        assert old_file_stream is not None and old_file_stream.closed
        assert app_logger.handlers == list(handlers)
        safe_log(app_logger, logging.INFO, "test.after_reconfigure")
        assert len(stream.getvalue().splitlines()) == 2
        file_lines = next(tmp_path.glob("*/app.log")).read_text(encoding="utf-8").splitlines()
        assert [json.loads(line)["event"] for line in file_lines] == [
            "test.before_reconfigure", "test.after_reconfigure",
        ]
    finally:
        for handler in handlers:
            app_logger.removeHandler(handler)
            handler.close()
    assert not stream.closed


@pytest.mark.asyncio
async def test_file_failure_keeps_stdout_and_http_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    blocked_root = tmp_path / "blocked"
    blocked_root.write_text("not a directory", encoding="utf-8")
    stream = io.StringIO()
    logger, stdout_handler = make_logger(stream)
    _, file_handler = make_file_logger(blocked_root)
    logger.addHandler(file_handler)
    monkeypatch.setattr(request_logging_module, "logger", logger)
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/sample")
    async def sample() -> dict[str, str]:
        return {"status": "ok"}

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/sample")
        assert response.status_code == 200 and response.json() == {"status": "ok"}
        event = json.loads(stream.getvalue())
        assert event["event"] == "http.request.completed"
        assert event["request_id"] == response.headers["X-Request-ID"]
        assert not file_handler.stream
    finally:
        stdout_handler.close()
        file_handler.close()


@pytest.mark.asyncio
async def test_lifespan_closes_log_handler_after_setup_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """
        验证 Redis 初始化失败时仍释放数据库池和日志处理器。

    :param monkeypatch: 替换外部资源，避免连接真实 PostgreSQL 或 Redis。
    :return: 无返回值；失败资源和清理顺序已断言。
    """
    stream = io.StringIO()
    logger, handler = make_logger(stream)
    _, file_handler = make_file_logger(tmp_path)
    logger.addHandler(file_handler)
    handlers = (handler, file_handler)
    engine = MagicMock()
    engine.dispose = AsyncMock()
    real_get_logger = logging.getLogger
    monkeypatch.setattr(logging, "getLogger", lambda name=None: logger if name == "app"
                        else real_get_logger(name))
    monkeypatch.setattr(main_module, "logger", logger)
    monkeypatch.setattr(main_module, "configure_logging", lambda **kwargs: handlers)
    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "create_redis_client", MagicMock(side_effect=RuntimeError("setup failed")))

    with pytest.raises(RuntimeError, match="setup failed"):
        async with main_module.lifespan(FastAPI()):
            pytest.fail("初始化失败后不应处理请求")

    engine.dispose.assert_awaited_once()
    assert all(vars(item)["_closed"] for item in handlers)
    assert logger.handlers == []
    assert not stream.closed


@pytest.mark.asyncio
async def test_lifespan_reuses_redis_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """
        验证默认复用主 Redis，并在退出时关闭客户端与日志处理器。

    :param monkeypatch: 替换外部客户端及配置，不连接实际数据库。
    :return: 无返回值；共享连接和退出清理均已断言。
    """
    stream = io.StringIO()
    logger, handler = make_logger(stream)
    _, file_handler = make_file_logger(tmp_path)
    logger.addHandler(file_handler)
    handlers = (handler, file_handler)
    redis_client = AsyncMock()
    engine = MagicMock()
    engine.dispose = AsyncMock()
    rate_factory = MagicMock()
    settings = get_settings().model_copy(update={"rate_limit_redis_url": None})
    real_get_logger = logging.getLogger
    monkeypatch.setattr(logging, "getLogger", lambda name=None: logger if name == "app"
                        else real_get_logger(name))
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "logger", logger)
    monkeypatch.setattr(main_module, "configure_logging", lambda **kwargs: handlers)
    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "create_redis_client", lambda settings: redis_client)
    monkeypatch.setattr(main_module, "create_rate_limit_redis_client", rate_factory)

    app = FastAPI()
    async with main_module.lifespan(app):
        assert app.state.rate_limit_redis is redis_client
        assert app.state.log_handlers == handlers
        file_stream = file_handler.stream

    rate_factory.assert_not_called()
    redis_client.aclose.assert_awaited_once()
    engine.dispose.assert_awaited_once()
    assert all(vars(item)["_closed"] for item in handlers)
    assert file_stream is not None and file_stream.closed
    assert logger.handlers == []
    assert not stream.closed
