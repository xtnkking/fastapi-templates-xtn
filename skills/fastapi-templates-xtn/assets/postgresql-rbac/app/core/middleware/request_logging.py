#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    HTTP 请求日志中间件，负责请求 ID、响应语言头和安全请求日志。
#    记录真实收发、取消和响应后异常；不负责登录、权限校验或业务错误响应。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        从启动入口拆出职责，保留现有行为并补充模块导读
# 2026/09/26    XTN       V1.001        内部收发函数统一使用 logging 业务词
# 2026/09/26    XTN       V1.002        文件说明统一使用请求日志职责名称
# 2026/09/29    XTN       V1.003        请求关联上下文改从专名模块导入
# 2026/09/30    XTN       V1.004        直接使用语言协商模块设置请求与响应语言
# 2026/10/02    XTN       V1.005        明确请求收发失败阶段，减少嵌套条件表达式
# 2026/10/02    XTN       V1.006        统一两类请求日志共用的安全关联字段
# 2026/10/10    XTN       V1.007        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.008        补充请求日志字段、回调时机和失败阶段的通俗步骤
# 2026/10/14    XTN       V1.009        补齐统一脱敏正文、被操作人及设置新密码指纹
# 2026/10/16    XTN       V1.010        让同事务审计复用本次请求的有限正文和语言
# --------------------------------------------------------------------------------------------------

import asyncio
import logging
import uuid
from time import perf_counter

from fastapi import Request
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.codes import BusinessCode
from app.core.i18n.language import apply_language_headers, locale_for_request
from app.core.logging.context import (
    bind_request_context,
    deactivate_request_context,
    reset_request_context,
)
from app.core.logging.details import HttpLogDetails
from app.core.logging.events import request_log_level, safe_log
from app.core.response import request_id_for

logger = logging.getLogger(__name__)


def _request_log_fields(request: Request, *, status_code: int | None) -> dict[str, object]:
    """
        组装完成与响应后失败事件共用的安全请求字段。
        使用路由模板、已认证身份和已旁观收发的脱敏摘要，不记录原始路径或凭据。

    :param request: 保存请求起点、关联 ID、业务码和可信操作者的请求对象。
    :param status_code: 已知的 HTTP 状态码；未确认已发送时可以为 None。
    :return: 两类请求日志共用的关联、状态及耗时字段。
    """
    # 从服务端状态取可信用户和耗时起点，路由只取模板，不把真实 URL 和查询参数写日志。
    route = request.scope.get("route")
    started_at = getattr(request.state, "request_started_at", None)
    duration_ms = (
        round((perf_counter() - started_at) * 1000, 3)
        if isinstance(started_at, float)
        else None
    )
    fields: dict[str, object] = {
        "request_id": request_id_for(request),
        "http_method": request.method,
        "route": getattr(route, "path", "<unmatched>"),
        "http_status_code": status_code,
        "business_code": getattr(request.state, "business_code", None),
        "duration_ms": duration_ms,
        "user_id": getattr(request.state, "user_id", None),
    }
    # 摘要失败也不能丢掉整条请求记录；基础关联、状态与耗时仍然保留。
    try:
        details = getattr(request.state, "log_details", None)
        if isinstance(details, HttpLogDetails):
            fields.update(details.fields())
    except Exception:
        pass
    return fields


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
    """
        尽力记录一次请求完成事件，包含真实发送状态、耗时与安全异常元信息。
        用请求状态防止重复记录；观察失败不会覆盖响应或应用原始异常。

    :param request: 保存请求起点、关联 ID、业务码与操作者信息的请求对象。
    :param status_code: 已发送或预期返回的 HTTP 状态码，无法确认时为 None。
    :param outcome: 请求结果分类，例如 success、failure 或 error。
    :param response_started: 响应开始消息是否已成功发送。
    :param response_completed: 最后一段响应体是否已成功发送。
    :param client_disconnected: 是否已经收到客户端断开事件。
    :param exception: 可选的故障异常，只记录安全诊断元信息。
    :param failure_phase: 可选的失败阶段标识，区分发送、接收及业务执行故障。
    :return: 无返回值，日志已尝试记录或因重复及日志故障被安全忽略。
    """
    try:
        # 同一请求可能同时经过发送回调与异常处理，只记录一次“请求完成”，避免把一次请求算多次。
        if getattr(request.state, "request_completion_recorded", False):
            return
        request.state.request_completion_recorded = True

        # 公共字段只组装一次；本事件另外记录真实发送结果和失败阶段。
        extra: dict[str, object] = {
            **_request_log_fields(request, status_code=status_code),
            "outcome": outcome,
            # 业务已成功但发送失败时，两者要分开：operation_outcome 是业务结果，outcome 是收发结果。
            "operation_outcome": getattr(request.state, "operation_outcome", None) or outcome,
            "response_started": response_started,
            "response_completed": response_completed,
            "client_disconnected": client_disconnected,
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
        # 日志故障不能改变业务响应，也不能把真正的业务异常覆盖掉。
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
    """
        单独记录响应完成后的任务失败，不改写已经发送给客户端的结果。
        日志故障只在本函数内消化，不替换原应用异常。

    :param request: 提供请求 ID、路由、耗时和业务身份信息的请求对象。
    :param status_code: 已知的 HTTP 响应状态码，无法确认时为 None。
    :param response_started: 响应开始消息是否已成功发送。
    :param response_completed: 最后一段响应体是否已成功发送。
    :param client_disconnected: 是否已观察到客户端断开连接。
    :param exception: 响应完成后发生的异常或取消事件。
    :param failure_phase: 表明响应后失败类型的稳定标识。
    :return: 无返回值，安全尝试记录响应后的失败事件。
    """
    try:
        # 响应已结束后仍可能有后台任务报错；另记事件并沿用 request_id，不伪造第二次请求完成。
        extra: dict[str, object] = {
            **_request_log_fields(request, status_code=status_code),
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


def _request_failure_phase(*, send_failed: bool, receive_failed: bool,
                           client_disconnected: bool, otherwise: str) -> str:
    """
        按实际收发状态指出请求失败阶段，兜底值由取消或异常路径分别给出。

    :param send_failed: 向客户端发送响应时是否失败。
    :param receive_failed: 从客户端读取请求时是否失败。
    :param client_disconnected: 是否已收到客户端断开消息。
    :param otherwise: 没有收发故障时由调用路径选定的阶段名称。
    :return: 用于请求日志的稳定失败阶段标识。
    """
    # 同时观察到多种状态时优先报发送故障，再报接收故障、断开，否则使用调用方的阶段。
    if send_failed:
        return "send"
    if receive_failed:
        return "receive"
    if client_disconnected:
        return "client_disconnect"
    return otherwise


class RequestLoggingMiddleware:
    """
        为请求生成关联 ID，观察实际收发结果，统一记录耗时、失败阶段和响应后的异常。
        中间件只观察并补响应头，不代替登录、权限判断或业务异常处理。
    """

    def __init__(self, app: ASGIApp,
                 log_hmac_key: bytes | None = None
                 ) -> None:
        """
            保存下游 ASGI 应用，用于在真实收发边界观察请求生命周期。

        :param app: 下一个中间件或最终 ASGI 应用。
        :param log_hmac_key: 独立日志密钥的字节值；纯中间件测试不提供时不会计算密码指纹。
        :return: 无返回值，完成中间件初始化。
        """
        self.app = app  # 下游 ASGI 应用；中间件可由多请求共用，单次请求状态必须留在 __call__ 内。
        self.log_hmac_key = log_hmac_key  # 只用于新密码日志指纹，不是登录凭据或数据库密码哈希。

    async def __call__(self, scope: Scope,
                       receive: Receive,
                       send: Send
                       ) -> None:
        """
            为 HTTP 请求生成关联 ID，并观察接收、发送、取消及响应后故障。
            最后一段响应体发送成功才记录完成；异常继续向上传播，finally 恢复
            原日志上下文。非 HTTP 连接直接交给下游，不套用请求日志逻辑。

        :param scope: ASGI 连接上下文与路由状态。
        :param receive: 从服务端接收请求消息的异步回调。
        :param send: 向服务端发送响应消息的异步回调。
        :return: 无返回值，下游应用执行结束且日志上下文已恢复。
        :raises BaseException: 下游异常及取消在记录安全状态后继续传播。
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. 请求 ID 由服务端新建，并为本次请求绑定独立日志上下文，避免并发请求相互串号。
        request = Request(scope, receive=receive)
        details = HttpLogDetails(request, self.log_hmac_key)
        request.state.log_details = details  # 本次请求专用，不与其他请求共用正文缓冲区。
        request.state.request_id = str(uuid.uuid4())
        request.state.locale = locale_for_request(request)  # 本次请求选中的文案语言，不改变业务数据。
        request.state.request_started_at = perf_counter()  # 单调时钟起点，只用来算耗时，不是业务时间戳。
        request.state.request_completion_recorded = False  # 防止正常完成和异常路径重复记一条完成日志。
        context_token = bind_request_context(request.state.request_id, http_details=details)
        context_is_bound = True  # 标记日志上下文尚未释放，避免重复恢复上下文。
        response_status_code: int | None = None  # 只认成功发送的响应状态；未发送时不能假定客户端收到 200。
        response_started = False  # 响应头已交给服务端发送。
        response_completed = False  # 最后一段响应体已交给服务端发送。
        client_disconnected = False  # 是否观察到客户端断开消息。
        send_failed = False  # 发送消息失败，与业务函数自身报错分开定位。
        receive_failed = False  # 接收请求消息失败，与发送故障分开定位。

        def release_request_context() -> None:
            """
                恢复请求进入前的日志上下文，使用绑定状态防止重复释放令牌。

            :return: 无返回值，当前请求上下文绑定已释放。
            """
            # 外层 finally 实际调用时才恢复旧上下文，绑定状态确保至多恢复一次。
            nonlocal context_is_bound
            if context_is_bound:
                reset_request_context(context_token)
                context_is_bound = False

        async def receive_with_logging() -> Message:
            """
                读取原始 ASGI 请求消息，并记录客户端断开或接收失败的状态。
                取消和接收异常保持原样传播给外层中间件处理。

            :return: 服务端返回的原始 ASGI 消息。
            :raises BaseException: 取消和接收错误原样传播，接收错误会先标记失败状态。
            """
            # 下游实际读取时才调用原连接；普通接收错误单独标记，取消保持原样传播。
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
            # 业务读到什么就旁观什么，不为记录日志额外读取或消费请求体。
            try:
                details.observe_request(message)
            except Exception:
                pass
            return message

        async def send_with_logging(message: Message) -> None:
            """
                为响应开始消息补充请求 ID 和语言头，再观察真实发送是否成功。
                仅在最终响应体成功发送后记录完成并停用请求日志 ID；发送失败
                不提前标记成功，原异常继续向上传播。

            :param message: 下游应用准备发送的原始 ASGI 响应消息。
            :return: 无返回值，消息已发送且相应生命周期状态已更新。
            :raises BaseException: 取消和发送错误先标记发送失败，再继续向上传播。
            """
            nonlocal response_completed, response_started, response_status_code
            nonlocal send_failed
            pending_status_code: int | None = None
            # 在真实响应头发送前补关联 ID 和语言头，成功、校验失败、权限拒绝都使用同一规则。
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

            # await send 成功之后才改变发送状态，不能把“准备返回成功”误记成“已返回成功”。
            try:
                details.observe_response(message)
            except Exception:
                pass
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
                # 响应之后运行的后台工作不自动继承“当前请求正在进行”的日志上下文。
                deactivate_request_context()

        # 2. 这里只声明了收发回调；从这一调用开始，下游真实读写才会触发它们。
        try:
            await self.app(scope, receive_with_logging, send_with_logging)
            # 下游正常返回却没有发送完整响应也要记录，避免这类中断在日志里悄悄消失。
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
        # 3. 下游取消或报错时按真实收发状态记录；响应已结束则只记录后续故障，不重写结果。
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
                    failure_phase=_request_failure_phase(
                        send_failed=send_failed,
                        receive_failed=receive_failed,
                        client_disconnected=client_disconnected,
                        otherwise="request_cancelled",
                    ),
                )
            raise
        except Exception as exc:
            # 已发送完整响应时只能记录后续故障，不能把客户端已收到的结果改成新的 500。
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
                    failure_phase=_request_failure_phase(
                        send_failed=send_failed,
                        receive_failed=receive_failed,
                        client_disconnected=client_disconnected,
                        otherwise="response_body" if response_started else "application",
                    ),
                )
            raise
        finally:
            # 清掉临时正文和日志状态，后台任务不能继续持有正文缓冲。
            details.request_body.buffer.clear()
            details.response_body.buffer.clear()
            del request.state.log_details
            release_request_context()
