#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    HTTP 基础安全响应头中间件。
#    对所有 HTTP 响应强制写入一致的浏览器安全策略，API 响应禁止缓存。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/27    XTN       V1.000        新增统一基础安全响应头
# 2026/09/29    XTN       V1.001        集中禁止缓存 API 响应
# 2026/10/02    XTN       V1.002        供外层未捕获异常响应共用安全头规则
# 2026/10/13    XTN       V1.003        补充浏览器策略和响应发送回调的通俗步骤
# --------------------------------------------------------------------------------------------------

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def apply_security_headers(headers: MutableHeaders, *, path: str) -> None:
    """
        给一个 HTTP 响应写入统一安全头，业务 API 额外禁止缓存。
        普通响应由中间件调用；外层未捕获异常的 500 由兜底处理器调用。

    :param headers: 即将发出的可修改响应头。
    :param path: 当前请求路径，用于判断是否属于业务 API。
    :return: 无返回值，安全头已写入响应。
    """
    # 限制浏览器猜测内容类型、嵌入页面和使用设备能力；业务 API 另外禁止保存响应缓存。
    headers["X-Content-Type-Options"] = "nosniff"
    headers["X-Frame-Options"] = "DENY"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if path.startswith("/api/"):
        headers["Cache-Control"] = "no-store"


class SecurityHeadersMiddleware:
    """
        为每个 HTTP 响应补齐基础浏览器安全响应头。
        中间件不判断业务权限，也不改变响应状态码、响应体或非 HTTP 连接。
    """

    def __init__(self, app: ASGIApp) -> None:
        """
            保存下游 ASGI 应用；安全响应头始终启用，没有运行时关闭开关。

        :param app: 下一个中间件或最终 ASGI 应用。
        :return: 无返回值，完成中间件初始化。
        """
        # 保存下游应用，实际响应产生后才由发送回调补安全头。
        self.app = app

    async def __call__(self, scope: Scope,
                       receive: Receive,
                       send: Send
                       ) -> None:
        """
            拦截 HTTP 响应开始消息并强制写入安全头，其他消息保持原样。

        :param scope: ASGI 连接信息，用于区分 HTTP 与其他连接类型。
        :param receive: 接收请求消息的异步回调。
        :param send: 发送响应消息的异步回调。
        :return: 无返回值，下游应用执行完成。
        """
        # 1. 只有 HTTP 响应需要这些头，其他连接类型直接交给下游。
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            """
                在响应头真正发出前写入固定安全策略，再发送原消息。

            :param message: 下游应用准备发送的 ASGI 响应消息。
            :return: 无返回值，消息已交给上游发送回调。
            """
            # 下游真正调用发送回调时，只在响应头消息上补策略，响应体和其他消息原样发送。
            if message["type"] == "http.response.start":
                apply_security_headers(MutableHeaders(scope=message), path=scope["path"])
            await send(message)

        # 2. 下游仍负责生成响应，只把发送入口替换成刚声明的安全头回调。
        await self.app(scope, receive, send_with_security_headers)
