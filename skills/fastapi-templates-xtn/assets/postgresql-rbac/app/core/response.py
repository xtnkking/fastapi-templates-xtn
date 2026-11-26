#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    统一 API 响应结构、请求 ID 和响应组装；业务码定义在 core/codes.py。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释业务码、统一响应字段及分页字段，便于前后端学习对接
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.003        为统一响应、分页和错误响应头补齐中文接口文档说明
# 2026/09/29    XTN       V2.000        删除已关闭 OpenAPI 文档专用的路由和响应声明
# 2026/09/29    XTN       V2.001        泛型响应改用 TypeVar 与 Generic 声明
# 2026/09/29    XTN       V2.002        统一成功与错误响应组装，整理模型和函数说明
# 2026/09/29    XTN       V2.003        业务码移至专名模块，响应文件只保留模型和组装
# 2026/09/30    XTN       V2.004        语言响应头直接引用语言协商模块
# 2026/10/02    XTN       V2.005        修正文件职责说明，业务码由独立模块定义
# 2026/10/09    XTN       V2.006        普通成功响应默认使用 20000，特殊业务码仍显式传入
# 2026/10/09    XTN       V2.007        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V2.008        统一响应模型基类，集中额外字段与字段赋值约束
# 2026/10/13    XTN       V2.009        补充请求 ID 校验、语言响应头和统一响应的通俗步骤
# 2026/10/15    XTN       V2.010        统一记录业务结果，路由不再重复标记成功
# 2026/10/15    XTN       V2.011        成功响应统一通知日志保存新建目标，不在路由重复赋值
# 2026/10/19    XTN       V2.012        冻结字段示例改用实际保留的统一响应字段
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from fastapi import Request
from pydantic import UUID4, BaseModel, ConfigDict, Field
from starlette.datastructures import MutableHeaders

from app.core.codes import BusinessCode
from app.core.i18n.language import apply_language_headers, locale_for_request
from app.core.i18n.messages import MessageKey, translate
from app.core.logging.details import HttpLogDetails

T = TypeVar("T")  # 统一响应和分页结果中的业务数据类型，由实际接口决定。


class ResponseBase(BaseModel):
    """
        接口响应的公共基类，统一拒绝未定义字段，并防止组装后重新给字段赋值。
        例如 response.code = 20000 会报错；字段中的列表仍可修改，不是深层冻结。
        此配置不负责加密或权限检查，响应仍只能声明允许公开的业务字段。
    """

    # extra="forbid"：构造响应时，多传一个未声明的字段就报错，便于发现误塞内部数据的代码。
    # frozen=True：响应组装后不能给字段重新赋值；不限制列表等字段内部内容的修改。
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApiResponse(ResponseBase, Generic[T]):
    """
        成功和失败接口共用的四字段响应结构。
    """

    # 固定四个响应字段；T 是当前接口的数据类型，例如 UserResponse。
    # 稳定业务码，前端按它判断结果，不按可能切换语言的 message 判断。
    code: int = Field(strict=True, ge=10000, le=59999, description="五位数字业务码；HTTP 状态码独立返回。")
    # 给人阅读的中文/英文提示，依据 Accept-Language 选择。
    message: str = Field(min_length=1, description="结果提示，按 Accept-Language 返回中文或英文。")
    # 当前接口的业务结果；没有结果时为 null，不把内部异常或凭据塞进这里。
    data: T | None = Field(description="当前接口的业务数据；没有返回数据时为 null。")
    # 服务端为本次请求生成的 UUID，与 X-Request-ID 和请求日志对应，便于排错。
    request_id: UUID4 = Field(description="服务端生成的 UUIDv4 请求 ID，与 X-Request-ID 响应头一致。")


class PageResponse(ResponseBase, Generic[T]):
    """
        列表接口放在 data 字段中的分页结果。
    """

    # 列表接口的 data 使用此结构，翻页只改变 page/page_size，不改变字段名称。
    items: list[T] = Field(description="当前页记录列表，没有匹配记录时为空数组。")
    page: int = Field(strict=True, ge=1, description="当前页码，从 1 开始。")
    page_size: int = Field(strict=True, ge=1, le=200, description="请求的每页条数，1～200；当前页实际条数可能更少。")
    total: int = Field(strict=True, ge=0, description="当前筛选条件及可见范围内的总记录数，不是本页条数。")


class ValidationErrorItem(ResponseBase):
    """
        单个请求字段的安全校验提示。
    """

    field: str = Field(description="未通过校验的字段路径，不包含用户提交的原值。")
    message: str = Field(description="该字段的中文或英文纠正提示，语言与本次响应一致。")


class ValidationErrorResponse(ResponseBase):
    """
        请求校验失败时返回的字段错误集合。
    """

    errors: list[ValidationErrorItem] = Field(description="字段校验错误列表，前端可将提示显示到对应表单项。")


def request_id_for(request: Request) -> str:
    """
        获取当前请求的 UUIDv4 关联 ID，无有效 ID 时生成并写入请求状态。

    :param request: 保存请求关联信息的 FastAPI 请求对象。
    :return: 标准小写 UUIDv4 字符串。
    """
    # 先核对请求状态中的 ID 确实是标准 UUIDv4，缺失或格式不对时生成并保存新 ID。
    request_id = getattr(request.state, "request_id", None)
    try:
        parsed = uuid.UUID(request_id) if isinstance(request_id, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.version != 4 or str(parsed) != request_id:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
    return request_id


def request_id_headers(request: Request, headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """
        合并请求关联 ID 和语言响应头，不修改调用方传入的映射。

    :param request: 用于读取请求 ID 与语言偏好的请求对象。
    :param headers: 需要保留的额外响应头，可为空。
    :return: 包含 X-Request-ID、Content-Language 与 Vary 的响应头字典。
    """
    # 复制额外响应头后补入同一个请求 ID 和展示语言，避免修改调用方的原字典。
    result = dict(headers or {})
    result["X-Request-ID"] = request_id_for(request)
    localized_headers = MutableHeaders(headers=result)
    apply_language_headers(localized_headers, locale_for_request(request))
    return dict(localized_headers.items())


def api_response(request: Request, *, message_key: MessageKey,
                 data: T | None,
                 code: int | BusinessCode = BusinessCode.OK
                 ) -> ApiResponse[T]:
    """
        构造统一业务响应，并集中记录日志需要的业务码与业务结果。
        普通成功默认使用 20000；创建等特殊响应由调用方显式指定业务码。
        业务码不会设置 HTTP 状态，创建路由仍需声明 HTTP 201。
        已准备成功结果后发生响应发送等故障，保留成功标记，由日志另记请求失败。

    :param request: 用于关联 ID、语言选择及业务码、业务结果记录的请求对象。
    :param message_key: 从中英文目录读取提示文案的消息键。
    :param data: 返回给客户端的业务数据，无数据时为 None。
    :param code: 已分配的五位数字业务码，默认 BusinessCode.OK（20000）。
    :return: 包含业务码、文案、数据和请求 ID 的响应模型。
    """
    # 1. 集中记录业务码；路由正常完成服务调用后，在这里标记已准备成功业务结果。
    request.state.business_code = int(code)
    if 20000 <= int(code) < 30000:
        request.state.operation_outcome = "success"
    elif 40000 <= int(code) < 60000 and getattr(request.state, "operation_outcome", None) != "success":
        # 拒绝和错误响应都不能标成成功；但后续故障不能抹掉已确认的成功结果。
        # 例如密码已修改，随后发送失败：业务仍是 success，请求收发由中间件记为 error。
        request.state.operation_outcome = "failure"
    # 2. 按当前语言和请求 ID 组装公开数据；日志状态不改变响应字段或 HTTP 状态。
    response = ApiResponse(
        code=int(code),
        message=translate(request, message_key),
        data=data,
        request_id=uuid.UUID(request_id_for(request)),
    )
    # 3. 新建对象的 ID 只有业务完成才知道，统一交给日志模块在发送前保存。
    # 日志模块只读所需 ID；任何记录故障都不能影响已构造的业务响应。
    if 20000 <= int(code) < 30000:
        try:
            details = getattr(request.state, "log_details", None)
            if isinstance(details, HttpLogDetails):
                details.record_created_target(response.data)
        except Exception:
            pass
    return response


def error_content(request: Request, *, code: int | BusinessCode, message_key: MessageKey,
                  data: Any = None) -> dict[str, Any]:
    """
        构造可直接交给 JSON 响应的统一错误内容。
        复用普通响应构造流程，再转换为 JSON 兼容字典。

    :param request: 用于关联 ID、语言选择及业务码记录的请求对象。
    :param code: 已分配的数字业务错误码。
    :param message_key: 客户端可见错误文案的消息键。
    :param data: 允许公开的错误附加数据，默认 None。
    :return: 已转为 JSON 兼容值的错误响应字典。
    """
    # 复用成功响应相同的四字段结构，再把模型值转换成可写入 JSON 的字典。
    response = api_response(
        request,
        code=code,
        message_key=message_key,
        data=data,
    )
    return response.model_dump(mode="json")
