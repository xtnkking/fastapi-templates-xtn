#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    请求与操作关联上下文；日志和审计共用 ID，并发操作互不串号，结束后上下文失效。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从日志模块拆出请求关联上下文
# 2026/09/30    XTN       V1.001        移除默认项目未使用的后台任务上下文工具
# 2026/10/13    XTN       V1.002        补充并发请求日志绑定、失效和恢复的通俗步骤
# 2026/10/16    XTN       V1.003        说明 HTTP 与命令行入口共用关联上下文及清理规则
# 2026/10/16    XTN       V1.004        审计复用当前请求的有限正文采集，不向业务层传递 Request
# 2026/10/16    XTN       V1.005        通过现有请求上下文记录登录用户，移除路由日志赋值
# --------------------------------------------------------------------------------------------------

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.logging.details import HttpLogDetails


@dataclass(slots=True)
class _RequestLogContext:
    """
        保存本次请求或命令行操作的关联信息；操作结束后，复制出去的上下文也会失效。
    """

    request_id: str  # 服务端入口生成的关联 ID，用于对应同一次操作的日志和审计。
    active: bool = True  # 请求结束时置 False，后台任务不能继续冒用已经结束的请求 ID。
    http_details: "HttpLogDetails | None" = None  # HTTP 审计复用的旁观数据；命令行入口为空。


# ContextVar 为并发协程隔离上下文，不是所有用户共用的全局 request_id。
_REQUEST_CONTEXT: ContextVar[_RequestLogContext | None] = ContextVar(
    "request_log_context", default=None
)


def bind_request_context(request_id: str, *, http_details: "HttpLogDetails | None" = None
                         ) -> Token[_RequestLogContext | None]:
    """
        将入口生成的关联 ID 绑定到当前上下文，供本次操作的日志与审计自动读取。
        HTTP 中间件已经执行此步骤；命令行等入口开始操作时绑定一次，并在 finally 中清理。

    :param request_id: 当前 HTTP 请求 UUID，或非 HTTP 操作入口生成的安全关联 ID。
    :param http_details: 已有 HTTP 日志采集对象；非 HTTP 操作不提供，不额外读取正文。
    :return: 用于在请求结束后恢复原上下文的 ContextVar 令牌。
    """
    # 给当前协程保存独立请求信息，并返回恢复凭据；这个令牌不是用户的登录 Token。
    return _REQUEST_CONTEXT.set(_RequestLogContext(request_id=request_id, http_details=http_details))


def deactivate_request_context() -> None:
    """
        将请求上下文标记为失效，防止复制的上下文继续使用已结束请求的 ID。

    :return: 无返回值，当前上下文存在时更新其有效状态。
    """
    # 在共享上下文对象上标记结束，已经复制到后台任务的上下文也会看到这个失效状态。
    context = _REQUEST_CONTEXT.get()
    if context is not None:
        context.active = False


def reset_request_context(token: Token[_RequestLogContext | None]) -> None:
    """
        使用绑定时保存的令牌恢复日志请求上下文。

    :param token: bind_request_context 返回的上下文恢复令牌。
    :return: 无返回值，恢复绑定之前的上下文值。
    """
    # 用绑定时的恢复凭据还原前一个上下文，避免后续任务继续借用本次请求信息。
    _REQUEST_CONTEXT.reset(token)


def current_request_id() -> str | None:
    """
        取得仍处于有效状态的请求或操作关联 ID，供日志与审计共用。

    :return: 当前有效请求 ID；上下文缺失或请求已结束时返回 None。
    """
    # 仅返回仍在进行中的请求 ID，缺失或结束时不给日志器一个过期关联 ID。
    context = _REQUEST_CONTEXT.get()
    return context.request_id if context is not None and context.active else None


def current_http_details() -> "HttpLogDetails | None":
    """
        读取本次 HTTP 请求已经采集的正文与语言，供提交前构造审计快照。

    :return: 当前有效请求的采集对象；命令行、缺失或已结束的上下文返回 None。
    """
    # 与关联 ID 使用同一份有效期和协程隔离规则，不能借用上一次请求或后台任务的正文。
    context = _REQUEST_CONTEXT.get()
    return context.http_details if context is not None and context.active else None


def set_log_user_id(user_id: str) -> None:
    """
        将已确认的登录用户记到本次请求日志中，业务调用方不用接收 Request。
        只在登录全部成功后调用；这里记录日志身份，不负责验证用户或授予权限。

    :param user_id: 已通过账号、密码检查，并完成 Redis 登录登记的用户 ID。
    :return: 无返回值；没有 HTTP 请求或请求已结束时不做任何操作。
    """
    # 1. 从已有上下文找到本次请求；取不到就跳过，不能为日志创建另一个请求。
    details = current_http_details()
    if details is None:
        return
    # 2. 写入中间件原本就会读取的用户字段，发送失败和响应后异常也能沿用它。
    details.request.state.user_id = user_id
