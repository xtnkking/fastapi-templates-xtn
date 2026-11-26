#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    把 Pydantic 参数错误映射为中英文提示和安全的字段位置。
#    不回显用户输入、原始异常文本或深层字典键。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        从多语言模块分离请求参数错误的文案和字段处理
# 2026/10/10    XTN       V1.001        原生密码长度错误返回统一提示，保留列表长度错误的独立文案
# 2026/10/13    XTN       V1.002        补充校验提示映射和安全字段位置提取的通俗步骤
# 2026/10/14    XTN       V1.003        说明密码长度提示自动读取统一上下限
# 2026/10/20    XTN       V1.004        密码长度提示读取当前字段的实际界限，不再统一套用新密码策略
# --------------------------------------------------------------------------------------------------

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from fastapi import Request

from app.core.i18n.messages import MessageKey, translate

# Pydantic 错误类型只映射到预先写好的消息键，不直接返回其可能包含输入值的原始描述。
_VALIDATION_MESSAGE_KEYS: Mapping[str, MessageKey] = MappingProxyType(
    {
        "missing": MessageKey.VALIDATION_REQUIRED,
        "extra_forbidden": MessageKey.VALIDATION_EXTRA_FORBIDDEN,
        "string_type": MessageKey.VALIDATION_STRING_TYPE,
        "string_too_short": MessageKey.VALIDATION_STRING_TOO_SHORT,
        "string_too_long": MessageKey.VALIDATION_STRING_TOO_LONG,
        "string_pattern_mismatch": MessageKey.VALIDATION_STRING_PATTERN,
        "int_type": MessageKey.VALIDATION_INTEGER,
        "int_parsing": MessageKey.VALIDATION_INTEGER,
        "bool_type": MessageKey.VALIDATION_BOOLEAN,
        "bool_parsing": MessageKey.VALIDATION_BOOLEAN,
        "uuid_type": MessageKey.VALIDATION_UUID,
        "uuid_parsing": MessageKey.VALIDATION_UUID,
        "list_type": MessageKey.VALIDATION_LIST,
        "too_short": MessageKey.VALIDATION_LIST_LENGTH,
        "too_long": MessageKey.VALIDATION_LIST_LENGTH,
        "greater_than": MessageKey.VALIDATION_NUMBER_RANGE,
        "greater_than_equal": MessageKey.VALIDATION_NUMBER_RANGE,
        "less_than": MessageKey.VALIDATION_NUMBER_RANGE,
        "less_than_equal": MessageKey.VALIDATION_NUMBER_RANGE,
        "literal_error": MessageKey.VALIDATION_LITERAL,
        "enum": MessageKey.VALIDATION_LITERAL,
        "json_invalid": MessageKey.VALIDATION_JSON_INVALID,
        "username_reserved": MessageKey.VALIDATION_USER_NAME_RESERVED,
        "username_format": MessageKey.VALIDATION_USER_NAME_FORMAT,
        "passwords_must_differ": MessageKey.VALIDATION_PASSWORDS_MUST_DIFFER,
        "role_fields_required": MessageKey.VALIDATION_ROLE_FIELDS_REQUIRED,
        "role_fields_not_null": MessageKey.VALIDATION_ROLE_FIELDS_NOT_NULL,
        "permission_ids_unique": MessageKey.VALIDATION_PERMISSION_IDS_UNIQUE,
        "role_ids_unique": MessageKey.VALIDATION_ROLE_IDS_UNIQUE,
    }
)

# 只允许回显固定的请求位置和简单字段名，不能把恶意键名放进错误响应。
_PUBLIC_FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
_PUBLIC_LOCATION_ROOTS = frozenset({"body", "query", "path", "header", "cookie"})


def validation_message(request: Request, error: Mapping[str, Any]) -> str:
    """
        根据稳定的参数错误类型返回翻译后的提示，未知类型使用通用提示。

    :param request: 当前请求，用于选择中文或英文。
    :param error: Pydantic 错误记录；type 和 loc 区分字段，ctx 提供该字段实际要求的长度。
    :return: 不包含原始输入或异常文本的可见提示。
    """
    # 先按固定错误类型选文案键，未知类型也只返回通用提示，不返回原始异常描述。
    error_type = error.get("type")
    key = _VALIDATION_MESSAGE_KEYS.get(error_type) if isinstance(error_type, str) else None
    # SecretStr 的 Field 长度错误与列表共用 too_short/too_long；按接口字段区分，避免误报“列表数量不符”。
    # 登录和新密码的长度界限不同，使用框架给出的当前字段界限，不按字段名猜业务。
    location = error.get("loc")
    if (error_type in ("too_short", "too_long")
            and isinstance(location, (tuple, list)) and location
            and location[-1] in ("password", "current_password", "new_password")):
        is_short = error_type == "too_short"
        key = MessageKey.VALIDATION_STRING_TOO_SHORT if is_short else MessageKey.VALIDATION_STRING_TOO_LONG
        context = error.get("ctx")
        limit = context.get("min_length" if is_short else "max_length") if isinstance(context, Mapping) else None
        # 只把框架提供的正整数填入固定模板，不能回显密码、输入值或原始异常文本。
        if type(limit) is int and limit > 0:
            key = MessageKey.VALIDATION_PASSWORD_TOO_SHORT if is_short else MessageKey.VALIDATION_PASSWORD_TOO_LONG
            return translate(request, key).format(length=limit)
    return translate(request, key or MessageKey.VALIDATION_INVALID)


def validation_field(error: Mapping[str, Any]) -> str:
    """
        提取受控的请求字段位置，隐藏多层路径和用户任意提供的键名。

    :param error: Pydantic 错误记录，使用 loc 和 type 字段。
    :return: request、请求位置或请求位置加第一层安全字段名。
    """
    # 1. 只接受框架给出的请求位置，缺失或来源不认识时统一显示 request。
    location = error.get("loc")
    if not isinstance(location, (tuple, list)) or not location:
        return "request"
    root = location[0]
    if not isinstance(root, str) or root not in _PUBLIC_LOCATION_ROOTS:
        return "request"
    # 2. 多余字段不回显客户端提供的名称；其余错误最多公开第一层安全字段名。
    if error.get("type") == "extra_forbidden" or len(location) < 2:
        return root
    field = location[1]
    if not isinstance(field, str) or not _PUBLIC_FIELD_PATTERN.fullmatch(field):
        return root
    return f"{root}.{field}"
