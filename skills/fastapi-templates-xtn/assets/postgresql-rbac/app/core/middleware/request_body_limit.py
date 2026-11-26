#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    HTTP 请求体大小限制中间件。
#    在业务代码执行前同时检查 Content-Length 和实际接收字节数，超限统一返回 413。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/27    XTN       V1.000        新增统一请求体大小限制
# 2026/10/13    XTN       V1.001        补充大小上限、请求缓冲回放和 413 返回的通俗步骤
# --------------------------------------------------------------------------------------------------

from fastapi import Request, status
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey
from app.core.response import (
    error_content,
    request_id_headers,
)


class RequestBodyLimitMiddleware:
    """
        在进入路由前限制单个 HTTP 请求体的真实字节数。
        先拒绝已声明超限的请求，再缓冲并核对实际分块，防止伪造 Content-Length 绕过。
    """

    def __init__(self, app: ASGIApp,
                 max_body_bytes: int
                 ) -> None:
        """
            保存下游应用和请求体上限，配置错误在应用装配时立即暴露。

        :param app: 下一个中间件或最终 ASGI 应用。
        :param max_body_bytes: 允许接收的最大请求体字节数，必须大于 0。
        :return: 无返回值，完成中间件初始化。
        :raises ValueError: 请求体上限不是正整数。
        """
        # 上限配置错误立即拒绝；保存的是字节上限，不是字符串长度或单个分块的上限。
        if isinstance(max_body_bytes, bool) or max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be a positive integer")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope,
                       receive: Receive,
                       send: Send
                       ) -> None:
        """
            检查 HTTP 请求体声明大小和实际大小，未超限时原样回放全部消息。
            非 HTTP 连接直接交给下游；超限请求返回统一双语错误且不执行路由。

        :param scope: ASGI 连接信息，包含请求方法、路径和请求头。
        :param receive: 接收原始请求消息的异步回调。
        :param send: 发送响应消息的异步回调。
        :return: 无返回值，请求已交给下游或已经返回 HTTP 413。
        """
        # 1. 非 HTTP 连接直接转交，HTTP 才需要读取并限制请求体。
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 2. Content-Length 明确超限就立即拒绝，无需等待读取请求正文。
        content_length = self._content_length(scope)
        if content_length is not None and content_length > self.max_body_bytes:
            await self._send_payload_too_large(scope, receive, send)
            return

        # 3. 累计真实分块后才允许下游执行，避免相信伪造长度或在业务写入后才发现超限。
        buffered_messages: list[Message] = []
        received_bytes = 0
        while True:
            message = await receive()
            buffered_messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue

            received_bytes += len(message.get("body", b""))
            if received_bytes > self.max_body_bytes:
                await self._send_payload_too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> Message:
            """
                按原顺序向下游回放已缓冲消息，之后继续读取真实连接消息。

            :return: 一条未经修改的 ASGI 请求或断开消息。
            """
            # 下游实际读取时先按原顺序取缓冲，读完才继续读连接；每条缓冲消息只交付一次。
            nonlocal message_index
            if message_index < len(buffered_messages):
                message = buffered_messages[message_index]
                message_index += 1
                return message
            return await receive()

        # 4. 大小检查全部通过后，下游从回放入口读取同一份消息，正文不被改写。
        await self.app(scope, replay_receive, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        """
            从 HTTP 请求头读取非负的 Content-Length，缺失或无效时改查真实字节数。

        :param scope: 含原始请求头的 HTTP ASGI 连接信息。
        :return: 有效的非负声明字节数；缺失、负数或格式无效时返回 None。
        """
        # 只把合法非负整数当作声明长度；缺失或非法仍会在主流程核对真实字节数。
        raw_value = Headers(scope=scope).get("content-length")
        if raw_value is None:
            return None
        try:
            value = int(raw_value)
        except ValueError:
            return None
        return value if value >= 0 else None

    @staticmethod
    async def _send_payload_too_large(scope: Scope,
                                      receive: Receive,
                                      send: Send
                                      ) -> None:
        """
            返回统一的双语 413 响应，并补请求 ID 与禁止缓存响应头。

        :param scope: 当前 HTTP ASGI 连接信息。
        :param receive: 当前请求接收回调，用于构造请求对象和读取语言偏好。
        :param send: 发送 413 响应的异步回调。
        :return: 无返回值，完整错误响应已经发送。
        """
        # 用当前请求的语言和关联 ID 构造统一错误，再发送完整 413 响应，不调用业务路由。
        request = Request(scope, receive=receive)
        response = JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content=error_content(
                request,
                code=BusinessCode.PAYLOAD_TOO_LARGE,
                message_key=MessageKey.ERROR_PAYLOAD_TOO_LARGE,
            ),
            headers=request_id_headers(
                request,
                {"Cache-Control": "no-store"},
            ),
        )
        await response(scope, receive, send)
