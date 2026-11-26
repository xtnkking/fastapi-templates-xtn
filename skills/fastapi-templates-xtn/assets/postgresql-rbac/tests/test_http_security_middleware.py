#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    请求体限制与基础安全响应头中间件测试。
#    验证声明长度、实际分块、统一双语错误、请求 ID 和非 HTTP 放行。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/27    XTN       V1.000        新增
# 2026/09/29    XTN       V1.001        覆盖 API 成功与错误响应的禁缓存边界
# 2026/10/02    XTN       V1.002        覆盖未捕获异常的外层 500 安全响应头
# --------------------------------------------------------------------------------------------------

import json
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.codes import BusinessCode
from app.core.exception_handlers import register_exception_handlers
from app.core.middleware.request_body_limit import RequestBodyLimitMiddleware
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


def http_scope(*, headers: list[tuple[bytes, bytes]] | None = None,
               path: str = "/upload") -> Scope:
    """
        构造中间件单元测试所需的最小 HTTP ASGI 连接信息。

    :param headers: 原始请求头列表，省略时使用空列表。
    :param path: 当前请求路径，默认使用非 API 上传路径。
    :return: 含独立 state 字典的 HTTP Scope。
    """
    return cast(
        Scope,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": headers or [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
        },
    )


async def invoke_asgi(app: ASGIApp, scope: Scope,
                      incoming: list[Message]
                      ) -> list[Message]:
    """
        使用给定请求消息调用 ASGI 应用，并收集全部响应消息。

    :param app: 待测试的中间件链或 ASGI 应用。
    :param scope: 当前测试连接信息。
    :param incoming: receive 按顺序返回的请求消息。
    :return: send 实际收到的全部响应消息。
    """
    remaining = list(incoming)
    sent: list[Message] = []

    async def receive() -> Message:
        """
            返回下一条测试请求消息，消息用尽时暴露测试接线错误。

        :return: 下一条预先准备的 ASGI 消息。
        :raises AssertionError: 中间件读取次数超出测试准备范围。
        """
        if not remaining:
            raise AssertionError("ASGI application read beyond prepared messages")
        return remaining.pop(0)

    async def send(message: Message) -> None:
        """
            收集应用发出的响应消息供断言使用。

        :param message: 应用发出的 ASGI 响应消息。
        :return: 无返回值，消息已加入结果列表。
        """
        sent.append(message)

    await app(scope, receive, send)
    return sent


def response_headers(messages: list[Message]) -> dict[str, str]:
    """
        将响应开始消息中的字节请求头转换为便于断言的小写字符串字典。

    :param messages: ASGI 应用发出的响应消息列表。
    :return: 响应头名称小写后的字典。
    """
    start = next(message for message in messages if message["type"] == "http.response.start")
    return {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in start["headers"]
    }


def response_json(messages: list[Message]) -> dict[str, object]:
    """
        解析 ASGI 响应体中的 JSON 对象。

    :param messages: ASGI 应用发出的响应消息列表。
    :return: 解析后的 JSON 对象。
    """
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return cast(dict[str, object], json.loads(body))


@pytest.mark.asyncio
async def test_declared_oversized_body_returns_standard_413_without_calling_app() -> None:
    """
        Content-Length 已超限时立即返回 41301，不能调用业务应用。
    """
    called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            标记不应执行的业务应用。
        """
        nonlocal called
        called = True

    app = SecurityHeadersMiddleware(
        RequestBodyLimitMiddleware(downstream, max_body_bytes=5)
    )
    messages = await invoke_asgi(
        app,
        http_scope(
            headers=[
                (b"content-length", b"6"),
                (b"accept-language", b"zh-CN"),
            ]
        ),
        [],
    )

    assert called is False
    assert messages[0]["status"] == 413
    assert response_json(messages)["code"] == int(BusinessCode.PAYLOAD_TOO_LARGE)
    assert response_json(messages)["message"] == "请求内容过大"
    headers = response_headers(messages)
    assert headers["cache-control"] == "no-store"
    assert response_json(messages)["request_id"] == headers["x-request-id"]
    assert {name: headers[name] for name in SECURITY_HEADERS} == SECURITY_HEADERS


@pytest.mark.asyncio
async def test_chunked_body_uses_actual_bytes_and_returns_english_413() -> None:
    """
        没有 Content-Length 时累计实际分块，超过上限后返回英文统一错误。
    """

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            超限测试中的业务应用不得执行。
        """
        raise AssertionError("oversized request reached downstream application")

    app = RequestBodyLimitMiddleware(downstream, max_body_bytes=5)
    messages = await invoke_asgi(
        app,
        http_scope(headers=[(b"accept-language", b"en")]),
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ],
    )

    assert messages[0]["status"] == 413
    assert response_json(messages)["message"] == "Request content is too large"
    assert response_headers(messages)["content-language"] == "en"


@pytest.mark.asyncio
async def test_boundary_sized_body_is_replayed_without_changes() -> None:
    """
        实际请求体刚好等于上限时，全部 ASGI 消息必须按原顺序原样交给业务应用。
    """
    incoming: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cde", "more_body": False},
    ]
    received: list[Message] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            读取两条回放消息并返回空的成功响应。
        """
        received.extend([await receive(), await receive()])
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = RequestBodyLimitMiddleware(downstream, max_body_bytes=5)
    messages = await invoke_asgi(app, http_scope(), incoming)

    assert received == incoming
    assert messages[0]["status"] == 204


@pytest.mark.asyncio
async def test_security_headers_are_added_to_normal_http_response() -> None:
    """
        普通 HTTP 成功响应也必须带固定基础安全头。
    """

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            返回不含安全头的最小成功响应。
        """
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = await invoke_asgi(
        SecurityHeadersMiddleware(downstream),
        http_scope(),
        [],
    )
    headers = response_headers(messages)

    assert {name: headers[name] for name in SECURITY_HEADERS} == SECURITY_HEADERS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "status_code", "cache_control"),
    [
        ("/api/v1/roles/list", 200, "no-store"),
        ("/api/v1/auth/login", 401, "no-store"),
        ("/outside", 200, None),
    ],
)
async def test_only_api_responses_are_forced_not_to_cache(
    path: str, status_code: int, cache_control: str | None
) -> None:
    """
        API 的成功与错误响应都禁止缓存；非 API 响应不被强制改写。

    :param path: 模拟请求的 URL 路径。
    :param status_code: 下游应用返回的 HTTP 状态码。
    :param cache_control: 预期的缓存响应头；None 表示不应新增。
    :return: 无返回值，通过断言验证中间件边界。
    """

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            按测试参数返回最小响应，由中间件决定是否补充缓存头。

        :param scope: 当前测试请求信息。
        :param receive: 请求消息接收回调，本测试无需读取。
        :param send: 响应消息发送回调。
        :return: 无返回值，响应已发送。
        """
        await send({"type": "http.response.start", "status": status_code, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = await invoke_asgi(
        SecurityHeadersMiddleware(downstream), http_scope(path=path), []
    )
    assert response_headers(messages).get("cache-control") == cache_control


@pytest.mark.asyncio
async def test_middlewares_pass_non_http_scope_through_unchanged() -> None:
    """
        WebSocket 等非 HTTP 连接不读取请求体，也不写 HTTP 安全响应头。
    """
    observed_scope: Scope | None = None

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        """
            记录实际收到的非 HTTP Scope。
        """
        nonlocal observed_scope
        observed_scope = scope

    scope = cast(
        Scope,
        {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "scheme": "ws",
            "path": "/ws",
            "raw_path": b"/ws",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "subprotocols": [],
            "state": {},
        },
    )

    async def unused_receive() -> Message:
        """
            非 HTTP 放行测试不应读取消息。
        """
        raise AssertionError("non-HTTP pass-through unexpectedly called receive")

    async def unused_send(message: Message) -> None:
        """
            非 HTTP 放行测试下游不发送消息。
        """
        raise AssertionError("non-HTTP pass-through unexpectedly called send")

    app = SecurityHeadersMiddleware(
        RequestBodyLimitMiddleware(downstream, max_body_bytes=5)
    )
    await app(scope, unused_receive, unused_send)

    assert observed_scope is scope


def test_unhandled_api_error_keeps_security_headers() -> None:
    """
        未捕获异常由外层错误处理器返回 500 时，仍保留统一安全响应头。

    :return: 无返回值，通过断言确认外层 500 的请求 ID、禁缓存和安全头。
    """
    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/api/v1/controlled-error")
    async def controlled_error(request: Request) -> None:
        """
            模拟路由内未捕获的程序错误。

        :param request: 测试请求；无需读取内容。
        :return: 不正常返回，始终抛出模拟异常。
        """
        raise RuntimeError("controlled failure")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/controlled-error")

    assert response.status_code == 500
    assert response.json()["code"] == int(BusinessCode.INTERNAL_ERROR)
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"
    assert {name: response.headers[name] for name in SECURITY_HEADERS} == SECURITY_HEADERS
