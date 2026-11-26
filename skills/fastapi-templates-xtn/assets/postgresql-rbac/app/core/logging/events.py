#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    结构化日志安全处理、异常脱敏和 JSON 格式化；日志故障不能覆盖业务结果。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释基础类字段、枚举用途与日志审计边界常量
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/29    XTN       V1.003        请求上下文和有界后台输出分别交由专名模块
# 2026/09/29    XTN       V1.004        类型别名改用普通赋值形式
# 2026/09/30    XTN       V1.005        移除默认项目未使用的后台任务日志工具
# 2026/10/02    XTN       V1.006        删除仅供 Redis 会话调用的泛化依赖故障分类
# 2026/10/02    XTN       V1.007        按标量、字典和序列拆清日志安全转换阶段
# 2026/10/02    XTN       V1.008        将单次使用的字段名脱敏判断放回日志值转换入口
# 2026/10/13    XTN       V1.009        补充日志脱敏、异常线索和单行 JSON 组装的通俗步骤
# 2026/10/14    XTN       V1.010        删除日志服务和环境字段，阻止附加字段重新写入
# 2026/10/14    XTN       V1.011        统一日志空字段并允许经过格式校验的密码专用指纹
# 2026/10/14    XTN       V1.012        日志时间统一使用带时区的北京时间，与文件日期一致
# --------------------------------------------------------------------------------------------------

import json
import logging
import math
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Final, cast

from app.core.logging.context import current_request_id

JsonValue = (
    bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None
)
LogExcInfo = (
    bool
    | BaseException
    | tuple[type[BaseException], BaseException, TracebackType | None]
    | tuple[None, None, None]
    | None
)

LOG_TIMEZONE: Final = timezone(timedelta(hours=8))  # 日志时间和日期目录统一用北京时间，不依赖机器时区。
_REDACTED: Final = "[REDACTED]"  # 敏感值已遮盖；这只是日志标记，不改动原业务数据。
_MAX_STRING_LENGTH: Final = 2048  # 单个日志字符串最多保留的字符数，超出会标注截断。
_MAX_EVENT_NAME_LENGTH: Final = 128  # 事件标识的字符上限，标识应来自代码而非用户自由输入。
_MAX_FIELD_NAME_LENGTH: Final = 128  # 附加字段名称的字符上限，过长字段会被省略并计数。
_MAX_COLLECTION_ITEMS: Final = 100  # 单个容器保留的元素数量，避免把大型业务对象完整写入日志。
_MAX_NESTING_DEPTH: Final = 5  # 嵌套结构的递归层级上限，超过后只保留说明标记。
# 以下占位符区分非法事件、省略文本、不支持对象、越界数字和循环引用，帮助排查日志为何缺字段。
_INVALID_EVENT: Final = "logging.invalid_event"
_OMITTED: Final = "[OMITTED]"
_UNSUPPORTED: Final = "[UNSUPPORTED]"
_OUT_OF_RANGE: Final = "[OUT_OF_RANGE]"
_CYCLE: Final = "[CYCLE]"
# 数字按有符号 64 位范围输出，减少日志采集后写数据库或跨语言解析的溢出问题。
_SIGNED_BIGINT_MIN: Final = -(2**63)
_SIGNED_BIGINT_MAX: Final = 2**63 - 1
_EVENT_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
# 字段名含这些敏感片段就遮盖；随后还扫描普通文本，防止凭据藏在 message 等字段里。
_SENSITIVE_FIELD_NAMES: Final = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credentials",
        "database_url",
        "email",
        "id_token",
        "jti",
        "jwt",
        "jwt_secret",
        "password",
        "password_hash",
        "private_key",
        "proxy_url",
        "redis_url",
        "secret",
        "set_cookie",
        "token",
        "username",
    }
)
_BEARER_RE: Final = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_URL_CREDENTIAL_RE: Final = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@"
)
_KEY_VALUE_SECRET_RE: Final = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|authorization)\s*([=:])\s*"
    r"([^\s,;]+)"
)
# 标准 logging 的内部字段不能被 extra 覆盖；下面的固定 JSON 字段同样保留给格式器。
_STANDARD_RECORD_FIELDS: Final = frozenset(
    logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__
) | {"asctime", "message"}
_BASE_PAYLOAD_FIELDS: Final = frozenset(
    {
        "timestamp",
        "level",
        "event",
        "logger",
        # 已移除的服务和环境字段也直接忽略，避免业务 extra 又把它们写回日志。
        "service",
        "service_version",
        "environment",
        "target_type",  # 文件日志用明确的目标用户/角色字段，不恢复重复的泛化字段。
        "target_id",
        "request_id",
        "message_template",
        "message_parameters",
        "_oversized_fields_omitted",
    }
)


# 各类文件事件共用这些业务与诊断字段；没有信息时写 null，便于直接按同一列查看。
_EMPTY_LOG_FIELDS: Final = dict.fromkeys((
    "request_id", "http_method", "route", "http_status_code", "business_code", "duration_ms",
    "user_id", "target_user_id", "target_role_id", "action", "operation_outcome", "reason_code",
    "request_data", "response_data", "password_fingerprint", "outcome", "response_started",
    "response_completed", "client_disconnected", "failure_phase", "error_id", "exception_type",
    "exception_module", "exception_location",
))


def request_log_level(status_code: int) -> int:
    """
        按 HTTP 状态选择请求完成日志级别。

    :param status_code: 请求最终的 HTTP 响应状态码。
    :return: 5xx 对应 ERROR，4xx 对应 WARNING，其余对应 INFO 的数值级别。
    """
    # 服务故障记 ERROR，客户端或业务拒绝记 WARNING，正常响应记 INFO。
    if status_code >= 500:
        return logging.ERROR
    if status_code >= 400:
        return logging.WARNING
    return logging.INFO


def _redact_text(value: str, *, limit: int = _MAX_STRING_LENGTH) -> str:
    """
        限制日志文本长度并遮盖 Bearer 凭据、带密码 URL 和常见密钥片段。

    :param value: 待脱敏的普通字符串。
    :param limit: 脱敏前最多保留的字符数。
    :return: 脱敏后的文本，原文超长时追加截断标记。
    """
    # 先截断到允许长度，再遮盖可识别凭据；只修改写入日志的副本，不修改业务数据。
    truncated = len(value) > limit
    bounded = value[:limit]
    bounded = _BEARER_RE.sub("Bearer [REDACTED]", bounded)
    bounded = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", bounded)
    bounded = _KEY_VALUE_SECRET_RE.sub(r"\1\2[REDACTED]", bounded)
    return f"{bounded}...[TRUNCATED]" if truncated else bounded


def _safe_value(value: object, *, field_name: str, depth: int = 0, seen: set[int] | None = None) -> JsonValue:
    """
        将日志附加值转换为有界且脱敏的 JSON 值。
        限制数字、深度和集合长度，检测循环引用，不调用任意对象的字符串方法。

    :param value: 待转换的日志值。
    :param field_name: 用于敏感字段判断的当前字段名。
    :param depth: 当前递归层级，超过上限后返回深度限制标记。
    :param seen: 当前递归路径已访问的容器对象 ID 集合。
    :return: 可安全序列化的值，敏感、不支持或超限部分替换为说明标记。
    """
    # 字段名先统一大小写和连字符；敏感字段整项遮盖，不再读取其值。
    normalized_field = field_name.casefold().replace("-", "_")
    # 专用指纹必须是 32 位十六进制摘要，不能借这个字段写入密码或任意原文。
    if normalized_field == "password_fingerprint":
        if value is None or (type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value)):
            return value
        return _REDACTED
    if any(fragment in normalized_field for fragment in _SENSITIVE_FIELD_NAMES):
        return _REDACTED
    if depth > _MAX_NESTING_DEPTH:
        return "[MAX_DEPTH]"
    # 只接受下方列出的精确类型，避免自定义子类在记录日志时运行自己的转换方法。
    value_type = type(value)
    if value is None:
        return None
    if value_type is bool:
        return cast(bool, value)
    if value_type is int:
        integer = cast(int, value)
        return (
            integer
            if _SIGNED_BIGINT_MIN <= integer <= _SIGNED_BIGINT_MAX
            else _OUT_OF_RANGE
        )
    if value_type is float:
        number = cast(float, value)
        if math.isfinite(number):
            return number
        if math.isnan(number):
            return "NaN"
        return "Infinity" if number > 0 else "-Infinity"
    if value_type is str:
        return _redact_text(cast(str, value))
    if value_type is uuid.UUID or value_type is datetime:
        return str(value)
    # 容器按字段或元素分别处理；同一路径的对象 ID 用于发现真正的循环引用。
    if value_type is dict:
        return _safe_mapping(
            cast(dict[object, object], value),
            depth=depth,
            seen=seen if seen is not None else set(),
        )
    if value_type is list or value_type is tuple:
        return _safe_sequence(
            cast(list[object] | tuple[object, ...], value),
            field_name=field_name,
            depth=depth,
            seen=seen if seen is not None else set(),
        )
    return _UNSUPPORTED


def _safe_mapping(mapping: dict[object, object], *, depth: int, seen: set[int]) -> JsonValue:
    """
        只读取普通字典中合规的字符串字段，并在当前递归路径检测循环。
        不读取非法字段的值，也不调用未知键或值的字符串方法。

    :param mapping: 已确认是普通字典的日志附加值。
    :param depth: 字典在原始附加值中的递归层级。
    :param seen: 当前递归路径上的容器对象 ID，返回前移除本字典。
    :return: 有界且脱敏的字段映射；循环引用返回固定标记。
    """
    # 1. 记录当前路径的字典身份，遇到自己包含自己的结构时用固定标记替代。
    identity = id(mapping)
    if identity in seen:
        return _CYCLE
    seen.add(identity)
    mapping_result: dict[str, JsonValue] = {}
    omitted_keys = 0
    oversized_keys = 0
    try:
        # 2. 最多读有限字段，非法或过长键只计数省略，合法值再逐层脱敏。
        for index, (key, item) in enumerate(mapping.items()):
            if index >= _MAX_COLLECTION_ITEMS:
                mapping_result["_truncated"] = True
                break
            if type(key) is not str:
                omitted_keys += 1
                continue
            if len(key) > _MAX_FIELD_NAME_LENGTH:
                oversized_keys += 1
                continue
            mapping_result[key] = _safe_value(
                item,
                field_name=key,
                depth=depth + 1,
                seen=seen,
            )
        if omitted_keys:
            mapping_result["_non_string_keys_omitted"] = omitted_keys
        if oversized_keys:
            mapping_result["_oversized_keys_omitted"] = oversized_keys
        return mapping_result
    finally:
        # 离开这一层后移除身份，同一字典在其他分支再次出现不应误判为循环。
        seen.remove(identity)


def _safe_sequence(sequence: list[object] | tuple[object, ...], *, field_name: str,
                   depth: int, seen: set[int]) -> JsonValue:
    """
        最多转换一百个普通列表或元组元素，并在当前递归路径检测循环。

    :param sequence: 已确认是普通列表或元组的日志附加值。
    :param field_name: 父字段名，元素沿用它进行敏感值判断。
    :param depth: 序列在原始附加值中的递归层级。
    :param seen: 当前递归路径上的容器对象 ID，返回前移除本序列。
    :return: 有界且脱敏的元素列表；循环引用返回固定标记。
    """
    # 1. 检查当前路径是否已经进入同一列表，真正循环时不再向下展开。
    identity = id(sequence)
    if identity in seen:
        return _CYCLE
    seen.add(identity)
    try:
        # 2. 只转换前一百项并继续脱敏，剩余内容用截断标记说明。
        result = [
            _safe_value(
                item,
                field_name=field_name,
                depth=depth + 1,
                seen=seen,
            )
            for item in sequence[:_MAX_COLLECTION_ITEMS]
        ]
        if len(sequence) > _MAX_COLLECTION_ITEMS:
            result.append("[TRUNCATED]")
        return result
    finally:
        # 返回或转换失败时都清掉这一层身份，供其他分支独立检查。
        seen.remove(identity)


def safe_exception_metadata(exc: BaseException) -> dict[str, object]:
    """
        提取异常类型及白名单应用栈位置，不读取异常消息、局部变量或完整堆栈。

    :param exc: 需要记录诊断元信息的异常对象。
    :return: 错误 ID、异常类型与模块，以及可用时的应用函数和行号。
    """
    # 1. 沿异常堆栈只找 app 内最后一处代码位置，不读取异常正文和函数局部变量。
    exception_type = type(exc)
    traceback = exc.__traceback__
    application_location: dict[str, object] | None = None
    while traceback is not None:
        frame = traceback.tb_frame
        module_name = frame.f_globals.get("__name__")
        function_name = frame.f_code.co_name
        if (
            type(module_name) is str
            and (module_name == "app" or module_name.startswith("app."))
            and type(function_name) is str
        ):
            application_location = {
                "module": module_name[:256],
                "function": function_name[:128],
                "line": traceback.tb_lineno,
            }
        traceback = traceback.tb_next

    # 2. 给本次故障生成关联 ID，再保存类型和位置，方便安全排错。
    metadata: dict[str, object] = {
        "error_id": str(uuid.uuid4()),
        "exception_type": exception_type.__name__[:_MAX_FIELD_NAME_LENGTH],
        "exception_module": exception_type.__module__[:256],
    }
    if application_location is not None:
        metadata["exception_location"] = application_location
    return metadata


def safe_log(logger: logging.Logger, level: int, event: str, extra: Mapping[str, object] | None = None,
             exc_info: LogExcInfo = None) -> bool:
    """
        尽力记录结构化日志，阻止日志系统异常影响原业务流程。
        异常对象仅转换为安全元信息，不把原始异常交给日志输出器。

    :param logger: 接收日志的标准日志器。
    :param level: 标准 logging 数值日志级别。
    :param event: 稳定的结构化事件名称。
    :param extra: 额外字段，仅接受普通字典并排除标准日志保留字段。
    :param exc_info: 可选异常或异常元组，仅提取安全诊断元信息。
    :return: 日志调用未抛出异常时为 True，调用失败时为 False。
    """
    # 1. 整个记录过程都在保护内执行，日志出错只报告 False，不覆盖业务结果。
    try:
        safe_extra: dict[str, object] = {}
        if type(extra) is dict:
            for key, value in extra.items():
                if type(key) is str and key not in _STANDARD_RECORD_FIELDS:
                    safe_extra[key] = value

        # 2. 原始异常只提取安全位置和类型，绝不交给 logging 展开异常消息或堆栈。
        exception: BaseException | None = None
        if isinstance(exc_info, BaseException):
            exception = exc_info
        elif type(exc_info) is tuple and len(exc_info) >= 2:
            candidate = exc_info[1]
            if isinstance(candidate, BaseException):
                exception = candidate
        if exception is not None:
            for key, value in safe_exception_metadata(exception).items():
                safe_extra.setdefault(key, value)

        # 3. 发给日志器的是事件名和附加字段，字段值的脱敏由安全格式器完成。
        safe_event = event if type(event) is str else _INVALID_EVENT
        logger.log(level, safe_event, extra=safe_extra or None, exc_info=None)
    except Exception:
        return False
    return True


def _message_fields(record: logging.LogRecord) -> tuple[str, dict[str, JsonValue]]:
    """
        检查日志消息是否为稳定事件名，并省略任意消息文本和插值参数。

    :param record: 标准 logging 日志记录。
    :return: 安全事件名及消息字段字典；不合法事件使用统一占位标识。
    """
    # 只公开代码定义的事件名称；任意消息正文和插值参数都用省略标记代替。
    message = record.msg
    fields: dict[str, JsonValue] = {}
    if (
        type(message) is str
        and len(message) <= _MAX_EVENT_NAME_LENGTH
        and _EVENT_NAME_RE.fullmatch(message)
    ):
        fields["message_template"] = message
        event = message
    else:
        event = _INVALID_EVENT
        fields["message_template"] = _OMITTED

    args = record.args
    if not (type(args) is tuple and len(args) == 0):
        fields["message_parameters"] = _OMITTED
    return event, fields


class SafeJsonFormatter(logging.Formatter):
    """
        每条日志输出一行 JSON，附加对象只转换允许的数据类型，不随意调用 str() 泄露对象内部信息。
    """

    def __init__(self, *, include_exception_details: bool) -> None:
        """
            初始化单行 JSON 日志格式器，保存是否提取安全异常线索的配置。

        :param include_exception_details: True 时额外提取原异常的类型与代码位置；False 时跳过，两者都不展开异常原文。
        :return: 无返回值，完成格式器初始化。
        """
        # 使用标准格式器初始化，只保存日志确实需要的异常线索配置。
        super().__init__()
        # 只允许异常类型、代码位置等安全线索；打开此项也不输出原始异常字符串、局部变量或请求体。
        self._include_exception_details = include_exception_details

    def format(self, record: logging.LogRecord) -> str:
        """
            将日志记录格式化为单行 JSON，并对附加字段做有界脱敏处理。
            请求 ID 优先读取当前有效上下文，不展开原始异常消息与任意对象。

        :param record: 待格式化的标准日志记录。
        :return: 包含时间、级别、事件及安全附加字段的 JSON 字符串。
        """
        # 1. 按北京时间组装时间、级别和安全事件名，+08:00 明确时区，避免误读成 UTC。
        event, message_fields = _message_fields(record)
        payload: dict[str, JsonValue] = {
            "timestamp": datetime.fromtimestamp(record.created, LOG_TIMEZONE).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "event": event,
            "logger": record.name,
            **message_fields,
            **_EMPTY_LOG_FIELDS,
        }
        request_id = current_request_id() or getattr(record, "request_id", None)
        if isinstance(request_id, str) and request_id:
            payload["request_id"] = _redact_text(request_id, limit=128)

        # 2. 排除格式器保留字段，对额外字段逐项限制大小并脱敏，超长字段只记录数量。
        oversized_fields = 0
        for key, value in record.__dict__.items():
            if not isinstance(key, str):
                continue
            if key in _STANDARD_RECORD_FIELDS or key in _BASE_PAYLOAD_FIELDS:
                continue
            if len(key) > _MAX_FIELD_NAME_LENGTH:
                oversized_fields += 1
                continue
            payload[key] = _safe_value(value, field_name=key)
        if oversized_fields:
            payload["_oversized_fields_omitted"] = oversized_fields

        # 3. 按配置提取原异常的安全线索，最后写成一行 JSON，不输出原始异常或插值文本。
        exc_info = record.exc_info
        if (
            self._include_exception_details
            and type(exc_info) is tuple
            and len(exc_info) >= 2
            and isinstance(exc_info[1], BaseException)
        ):
            for key, value in safe_exception_metadata(exc_info[1]).items():
                if payload.get(key) is None:
                    payload[key] = _safe_value(value, field_name=key)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
