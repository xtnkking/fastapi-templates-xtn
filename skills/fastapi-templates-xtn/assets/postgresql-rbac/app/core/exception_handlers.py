#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    统一异常响应文件，把业务、参数、限流和依赖异常转换为约定的 JSON 响应。
#    register_exception_handlers 只负责登记对应关系；请求完成日志由中间件负责。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        从启动入口拆出职责，保留现有行为并补充模块导读
# 2026/09/26    XTN       V1.001        限流响应头改从真实 HTTP 辅助模块导入
# 2026/09/26    XTN       V1.002        统一请求日志中间件的职责称呼
# 2026/09/26    XTN       V1.003        使限流依赖日志字段直接表达实际检查
# 2026/09/29    XTN       V1.004        从业务码与异常模块导入清晰职责
# 2026/09/29    XTN       V1.005        统一异常 JSON 组装并保留各错误的独立处理
# 2026/09/30    XTN       V1.006        从专名模块导入安全的参数错误处理
# 2026/10/02    XTN       V1.007        从专名模块导入 PostgreSQL 故障分类
# 2026/10/02    XTN       V1.008        登录失败复用通用 401 处理器，不再反向导入 Service
# 2026/10/02    XTN       V1.009        从统一数据库入口读取 PostgreSQL 故障分类
# 2026/10/02    XTN       V1.010        拉直框架 HTTP 异常的状态校验和通用码选择
# 2026/10/02    XTN       V1.011        外层未捕获异常响应补齐浏览器安全头
# 2026/10/08    XTN       V1.012        限流响应头在 429 处理处直接组装
# 2026/10/09    XTN       V1.013        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/13    XTN       V1.014        补充错误响应组装、故障分类和限流等待时间的步骤说明
# 2026/10/14    XTN       V1.015        业务异常的内部原因码交给统一文件日志记录
# 2026/10/19    XTN       V1.016        精简异常注释，保留错误分类与安全要求
# 2026/10/20    XTN       V1.017        密码计算队列满或等待超时时统一返回双语繁忙响应
# --------------------------------------------------------------------------------------------------

import logging
import math
from collections.abc import Mapping

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.codes import BusinessCode, generic_error_code
from app.core.exceptions import AppError
from app.core.i18n.messages import MessageKey
from app.core.i18n.validation_messages import validation_field, validation_message
from app.core.logging.events import safe_exception_metadata, safe_log
from app.core.middleware.security_headers import apply_security_headers
from app.core.rate_limit.limiter import RateLimitExceeded, RateLimitUnavailable
from app.core.response import (
    ValidationErrorItem,
    ValidationErrorResponse,
    error_content,
    request_id_for,
    request_id_headers,
)
from app.core.security.passwords import PasswordBusyError
from app.db.postgres_db import DatabaseUnavailableError, database_error_category

logger = logging.getLogger(__name__)

# 框架抛出的 HTTP 状态码 →（响应体中的数字业务码，中英文消息键）。
# 业务异常使用自身的业务码；此表只处理通用 HTTP 错误，消息按请求语言翻译。
HTTP_ERROR_CONTRACT: dict[int, tuple[BusinessCode, MessageKey]] = {
    # 400 参数不合法；401 登录凭据无效；403 身份有效但没有访问权限。
    400: (BusinessCode.BAD_REQUEST, MessageKey.ERROR_BAD_REQUEST),
    401: (BusinessCode.INVALID_AUTHENTICATION, MessageKey.ERROR_UNAUTHENTICATED),
    403: (BusinessCode.ACCESS_FORBIDDEN, MessageKey.ERROR_FORBIDDEN),
    # 404 资源不存在；405 请求方法不允许；409 并发版本或业务状态发生冲突。
    404: (BusinessCode.NOT_FOUND, MessageKey.ERROR_NOT_FOUND),
    405: (BusinessCode.METHOD_NOT_ALLOWED, MessageKey.ERROR_METHOD_NOT_ALLOWED),
    409: (BusinessCode.CONFLICT, MessageKey.ERROR_CONFLICT),
    # 413 请求体太大；415 媒体类型不支持；422 字段校验失败；429 调用超过限流额度。
    413: (BusinessCode.PAYLOAD_TOO_LARGE, MessageKey.ERROR_PAYLOAD_TOO_LARGE),
    415: (
        BusinessCode.UNSUPPORTED_MEDIA_TYPE,
        MessageKey.ERROR_UNSUPPORTED_MEDIA_TYPE,
    ),
    422: (BusinessCode.VALIDATION_FAILED, MessageKey.ERROR_VALIDATION_FAILED),
    429: (BusinessCode.RATE_LIMITED, MessageKey.ERROR_RATE_LIMITED),
    # 500 是未预期的程序错误；503 是已识别的依赖暂不可用，不能把所有程序错误都归为 503。
    500: (BusinessCode.INTERNAL_ERROR, MessageKey.ERROR_INTERNAL),
    503: (BusinessCode.SERVICE_UNAVAILABLE, MessageKey.ERROR_SERVICE_UNAVAILABLE),
}


def _json_error_response(request: Request, *, status_code: int, code: int | BusinessCode,
                         message_key: MessageKey, data: object | None = None,
                         headers: Mapping[str, str] | None = None) -> JSONResponse:
    """
        组装统一错误响应，保留处理器指定的状态码和响应头。

    :param request: 提供语言与服务端请求 ID 的当前请求。
    :param status_code: 本次错误实际返回的 HTTP 状态码。
    :param code: 对应的五位数字业务码。
    :param message_key: 需要按请求语言翻译的公开错误文案键。
    :param data: 可安全公开的附加错误数据；没有时为 None。
    :param headers: 由具体处理器决定的额外响应头。
    :return: 包含统一四字段正文、请求 ID、语言和禁止缓存响应头的 JSON 响应。
    """
    # 保留专用响应头，再补禁止缓存、请求 ID 和响应语言。
    response_headers = dict(headers or {})
    response_headers.setdefault("Cache-Control", "no-store")
    return JSONResponse(
        status_code=status_code,
        content=error_content(request, code=code, message_key=message_key, data=data),
        headers=request_id_headers(request, response_headers),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
        登记异常处理器；请求出错时，框架再调用对应函数。

    :param app: 尚未启动、需要注册错误处理规则的 FastAPI 应用。
    :return: 无返回值，应用已登记参数、业务、限流、密码繁忙、数据库和兜底异常处理器。
    """
    # 分别处理参数、业务和限流错误，保留各自状态码。
    app.exception_handler(RequestValidationError)(handle_request_validation_error)
    app.exception_handler(AppError)(handle_access_error)
    app.exception_handler(RateLimitExceeded)(handle_rate_limit_exceeded)
    app.exception_handler(RateLimitUnavailable)(handle_rate_limit_unavailable)
    app.exception_handler(PasswordBusyError)(handle_password_busy)

    # 数据库错误先分类，再登记框架错误和未知错误的兜底处理。
    app.exception_handler(SQLAlchemyError)(handle_database_unavailable)
    app.exception_handler(DatabaseUnavailableError)(handle_database_unavailable)
    app.exception_handler(StarletteHTTPException)(handle_http_error)
    app.exception_handler(Exception)(handle_unexpected_error)


async def handle_request_validation_error(request: Request, exc: RequestValidationError) -> Response:
    """
        参数校验失败时返回 HTTP 422，只公开字段位置和安全提示。

    :param request: 用于选择语言和关联请求 ID 的请求对象。
    :param exc: FastAPI 汇总的请求参数校验异常。
    :return: 含字段错误列表、请求 ID 和禁止缓存响应头的 JSON 响应。
    """
    # 不直接返回完整校验错误，其中可能含密码等原始输入。
    errors = ValidationErrorResponse(
        errors=[
            ValidationErrorItem(
                field=validation_field(error),
                message=validation_message(request, error),
            )
            for error in exc.errors()
        ]
    )
    return _json_error_response(
        request,
        status_code=422,
        code=BusinessCode.VALIDATION_FAILED,
        message_key=MessageKey.ERROR_VALIDATION_FAILED,
        data=errors,
    )


async def handle_access_error(request: Request, exc: AppError) -> JSONResponse:
    """
        按业务异常返回状态码和提示，不公开内部拒绝原因。

    :param request: 用于响应语言与请求 ID 的请求对象。
    :param exc: 包含状态码、业务码与消息键的权限业务异常。
    :return: 使用异常约定状态码且禁止缓存的 JSON 错误响应。
    """
    # 内部原因只供日志使用，公开提示由消息目录提供。
    request.state.reason_code = exc.reason_code
    # 401 告知客户端需要有效 Bearer 登录凭据；403 则表示无操作权限，不混为密码错误。
    headers: dict[str, str] = {}
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return _json_error_response(
        request,
        status_code=exc.status_code,
        code=exc.business_code,
        message_key=exc.message_key,
        headers=headers,
    )


async def handle_rate_limit_exceeded(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
        超出限流额度时返回 HTTP 429，附上额度和等待时间，不公开 Redis key。

    :param request: 用于响应语言与请求 ID 的请求对象。
    :param exc: 包含决定本次拒绝的策略及计数结果的限流异常。
    :return: 包含 Retry-After 等限流响应头的统一 JSON 错误响应。
    """
    # 策略名只记日志，对外用 Retry-After 提示多久后重试。
    safe_log(
        logger,
        logging.WARNING,
        "rate_limit.denied",
        extra={"rate_limit_policy": exc.policy_name},
    )
    # 毫秒换成秒并向上取整，避免客户端提前重试。
    retry_after = max(1, math.ceil(exc.result.retry_after_ms / 1000))
    reset_after = max(1, math.ceil(exc.result.reset_after_ms / 1000))
    return _json_error_response(
        request,
        status_code=429,
        code=BusinessCode.RATE_LIMITED,
        message_key=MessageKey.ERROR_RATE_LIMITED_RETRY,
        headers={
            "RateLimit-Limit": str(exc.result.limit),
            "RateLimit-Remaining": str(exc.result.remaining),
            "RateLimit-Reset": str(reset_after),
            "Retry-After": str(retry_after),
            "Cache-Control": "no-store",
        },
    )


async def handle_rate_limit_unavailable(request: Request, exc: RateLimitUnavailable) -> JSONResponse:
    """
        限流服务不可用时返回 HTTP 503，并记录安全故障日志。

    :param request: 用于响应语言与请求 ID 的请求对象。
    :param exc: 限流策略或 Redis 操作不可用的异常。
    :return: 禁止缓存的统一服务不可用 JSON 响应。
    """
    # 这是限流故障，不是额度用完；返回 503，不能跳过限流放行业务。
    safe_log(
        logger,
        logging.ERROR,
        "dependency.rate_limit.unavailable",
        extra={
            "dependency": "rate_limit_redis",
            "dependency_operation": "rate_limit_check",
            **safe_exception_metadata(exc),
        },
    )
    return _json_error_response(
        request,
        status_code=503,
        code=BusinessCode.SERVICE_UNAVAILABLE,
        message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
    )


async def handle_password_busy(request: Request, exc: PasswordBusyError) -> JSONResponse:
    """
        密码计算排满或等得太久时返回 HTTP 503，请用户稍后重新提交。

    :param request: 用于响应语言、请求 ID 和请求日志的当前请求。
    :param exc: 只含队列满或等待超时原因的密码繁忙异常，不携带密码。
    :return: 业务码 50301、data 为 None 的统一繁忙响应，不要求客户端自动重试。
    """
    # 1. 内部原因只记日志，让维护者分清“队列满了”和“等待超时”，不读取密码或异常正文。
    request.state.reason_code = exc.reason_code
    safe_log(
        logger,
        logging.WARNING,
        "password.busy",
        extra={"reason_code": exc.reason_code},
    )
    # 2. 两种原因对外都提示系统繁忙，复用请求 ID、双语和禁止缓存处理，不添加自动重试响应头。
    return _json_error_response(
        request,
        status_code=503,
        code=BusinessCode.SERVICE_UNAVAILABLE,
        message_key=MessageKey.ERROR_PASSWORD_BUSY,
    )


async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """
        把框架 HTTP 错误转成统一响应，未登记的 4xx、5xx 使用通用业务码。

    :param request: 用于响应语言与请求 ID 的请求对象。
    :param exc: Starlette 或 FastAPI 产生的 HTTP 异常。
    :return: 不包含原异常详情的统一 JSON 错误响应。
    """
    # 非错误状态不是有效的 HTTP 异常，统一按内部错误处理。
    status_code = exc.status_code
    if not 400 <= status_code <= 599:
        status_code = 500

    # 查找对应业务码；未登记时使用“HTTP 状态码 + 01”。
    contract: tuple[int | BusinessCode, MessageKey] | None = HTTP_ERROR_CONTRACT.get(status_code)
    if contract is None:
        contract = (generic_error_code(status_code), MessageKey.ERROR_REQUEST_FAILED)
    code, message_key = contract
    # 保留框架响应头，例如 405 的 Allow；401 补充 Bearer 认证提示。
    headers = dict(exc.headers or {})
    if status_code == 401:
        headers.setdefault("WWW-Authenticate", "Bearer")
    return _json_error_response(
        request,
        status_code=status_code,
        code=code,
        message_key=message_key,
        headers=headers,
    )


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """
        未知错误返回 HTTP 500；故障详情由日志中间件记录，不公开给客户端。

    :param request: 用于响应语言与请求 ID 的请求对象。
    :param exc: 未被更具体处理器处理的异常，不将其文本返回给客户端。
    :return: 禁止缓存且包含请求 ID 的内部错误 JSON 响应。
    """
    # 只返回通用错误，用 request_id 关联日志排查，不泄露异常原文。
    response = _json_error_response(
        request,
        status_code=500,
        code=BusinessCode.INTERNAL_ERROR,
        message_key=MessageKey.ERROR_INTERNAL,
    )
    # 这条响应不会再经过安全头中间件，需要在这里补上。
    apply_security_headers(response.headers, path=request.url.path)
    return response


async def handle_database_unavailable(request: Request,
                                      exc: SQLAlchemyError | DatabaseUnavailableError) -> JSONResponse:
    """
        数据库连接、超时等故障返回 HTTP 503；SQL 写错或约束冲突仍抛回原错误。

    :param request: 用于日志关联、响应语言与请求 ID 的请求对象。
    :param exc: SQLAlchemy 异常或数据库客户端封装的不可用异常。
    :return: 已识别可用性故障对应的统一 HTTP 503 JSON 响应。
    :raises SQLAlchemyError: 无法归类为可用性故障的原数据库异常。
    """
    # 1. 区分连接故障与程序错误，不能把 SQL 写错等问题统称为服务不可用。
    category = database_error_category(exc)
    if category is None:
        # 无法归为连接或超时故障时，保留原错误。
        raise exc
    # 2. 记录故障类别和安全位置，再返回 503，不公开驱动原文或连接信息。
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
            "error_category": category,
            **safe_exception_metadata(exc),
        },
    )
    return _json_error_response(
        request,
        status_code=503,
        code=BusinessCode.SERVICE_UNAVAILABLE,
        message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
    )
