#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    授权与账号安全审计的内置动作，以及审计标识校验和敏感字段过滤。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释基础类字段、枚举用途与日志审计边界常量
# 2026/09/29    XTN       V1.002        审计 JSON 类型别名改用普通赋值形式
# 2026/10/09    XTN       V1.003        按授权和账号安全业务集中定义已有审计动作
# 2026/10/13    XTN       V1.004        补充审计敏感内容过滤和大小校验的通俗步骤
# 2026/10/16    XTN       V1.005        审计从当前操作上下文自动读取关联 ID，不再逐层传参
# 2026/10/16    XTN       V1.006        默认账号与权限审计共用业务分类、执行结果和脱敏快照
# --------------------------------------------------------------------------------------------------

import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Final

from app.core.logging.context import current_request_id
from app.core.logging.details import SUMMARY_MAX_BYTES, summarize_log_data

# 审计只能保存这些明确的 JSON 值；不能把 Request、数据库连接或任意对象直接存进去。
AuditJsonValue = (
    bool
    | int
    | float
    | str
    | list["AuditJsonValue"]
    | dict[str, "AuditJsonValue"]
    | None
)


class AuditCategory(str, Enum):  # noqa: UP042
    """
        一张操作审计表内按业务区分账号安全和权限管理，查询时使用此字段筛选。
    """

    ACCOUNT = "account"  # 注册、新增账号、本人改密和管理员重置密码。
    PERMISSION = "permission"  # 用户状态、角色和权限绑定等管理操作。


class AuditOutcome(str, Enum):  # noqa: UP042
    """
        记录操作实际结论；成功记录随业务一起提交，不把仅通过权限检查当成成功。
    """

    SUCCEEDED = "succeeded"  # 业务和此条审计都已成功提交后，记录才对其他事务可见。
    DENIED = "denied"  # 身份、权限或业务条件不允许，业务回滚后尽力独立保存。
    FAILED = "failed"  # 明确失败的业务结果；基础设施异常默认只写文件日志。


# 内置动作按实际业务分组；写入审计时取 .value，保存原有机器标识而不是翻译文案。
# 此目录不限制 api.<路由名> 等动态拒绝事件，也不替项目定义订单等主业务审计动作。
class RbacAuditAction(str, Enum):  # noqa: UP042
    """
        用户、角色和权限管理的内置审计动作，写入统一 operation_audit_events。
        动作只说明做什么；成功或拒绝由同一记录的 outcome 和 reason_code 表达。
    """

    # 用户管理及默认角色绑定。
    CREATE_USER = "user.create"  # 创建用户并绑定最低级 user 角色。
    UPDATE_USER_STATUS = "user.status.update"  # 管理员启用或停用目标用户。
    LOGOUT_USER_SESSIONS = "user.sessions.revoke"  # 管理员强制退出目标用户的全部登录。
    BIND_USER_ROLES = "user.roles.bind"  # 给目标用户绑定角色。
    UNBIND_USER_ROLES = "user.roles.unbind"  # 收回目标用户的角色绑定。
    # 角色资料、生命周期和权限绑定。
    CREATE_ROLE = "role.create"  # 新建普通角色。
    UPDATE_ROLE = "role.update"  # 修改角色名称或说明。
    ENABLE_ROLE = "role.enable"  # 启用普通角色。
    DISABLE_ROLE = "role.disable"  # 停用普通角色。
    DELETE_ROLE = "role.delete"  # 软删除普通角色及其有效关系。
    BIND_ROLE_PERMISSIONS = "role.permissions.bind"  # 给角色绑定权限。
    UNBIND_ROLE_PERMISSIONS = "role.permissions.unbind"  # 收回角色的权限绑定。


class AccountAuditAction(str, Enum):  # noqa: UP042
    """
        注册、新增账号和密码操作的内置审计动作，写入统一 operation_audit_events。
        category=account 与权限管理区分，不包含密码、验证码答案或 Token 原文。
    """

    REGISTER_USER = "account_security.registration.completed"  # 用户自行注册完成。
    ADMIN_CREATE_USER = "account_security.registration.admin_created"  # 管理员新增账号完成。
    CHANGE_PASSWORD = "account_security.password.changed"  # 本人改密；成功与失败使用同一动作。
    ADMIN_RESET_PASSWORD = "account_security.password.admin_reset"  # 管理员重置目标用户密码。
    OPERATOR_RESET_PASSWORD = "account_security.password.operator_reset"  # 受控线下恢复超级管理员密码。


class AuditSource(StrEnum):
    """
        说明操作从哪里发起；这是审计分类，不表示操作者已经通过权限检查。
    """

    # HTTP 接口、内部服务调用、后台任务分别记录来源，方便追查调用链。
    HTTP = "http"
    SERVICE = "service"
    JOB = "job"
    # 受控人工运维和用户自行执行的迁移来源；定义这些值不代表自动生成对应入口。
    OPERATOR = "operator"
    MIGRATION = "migration"


# 固定动作名和原因码只保存程序标识，不把用户输入或可变中文提示当作可统计的动作。
_ACTION_RE: Final = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_REASON_RE: Final = re.compile(r"^[a-z][a-z0-9_]*$")
_REQUEST_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
# 即使字段名看起来安全，也检查正文中常见的 Token、私钥和带账号密码的连接串。
_SENSITIVE_TEXT_RE: Final = re.compile(
    r"(?i)(?:\bbearer\s+\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:password|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+|"
    r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)"
)
# 这是密码重置“权限名称”，不是密码内容；精确放行，避免冒号被当成 secret=value 形式。
_SAFE_AUDIT_IDENTIFIERS: Final = frozenset({"users:password:reset"})
_MAX_DEPTH: Final = 6  # JSON 最多递归到此层级，避免深层对象占用过多处理资源。
_MAX_COLLECTION_ITEMS: Final = 100  # 单个对象字段或数组元素的上限，不是审计总记录数。
_MAX_STATE_BYTES: Final = 16 * 1024  # 单份前/后状态的 UTF-8 大小上限，单位字节。
# 字段名命中这些禁止项或下面的敏感后缀就拒绝保存，不能依赖前端“不上传”来保密。
_SENSITIVE_KEYS: Final = frozenset(
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
_SENSITIVE_SUFFIXES: Final = (
    "_api_key",
    "_cookie",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)


def _require_safe_key(key: str) -> None:
    """
        检查审计状态字段名，拒绝敏感字段及长度不合规的名称。

    :param key: 待写入审计 JSON 对象的字段名。
    :return: 无返回值，校验通过后继续执行。
    :raises ValueError: 字段涉及敏感信息或长度不在 1 至 120 字符之间。
    """
    # 大小写和连字符统一后检查敏感名称，再限制字段长度，不能靠换个拼写藏密码字段。
    normalized = key.casefold().replace("-", "_")
    if normalized in _SENSITIVE_KEYS or normalized.endswith(_SENSITIVE_SUFFIXES):
        raise ValueError(f"audit state contains forbidden sensitive field: {key}")
    if not key or len(key) > 120:
        raise ValueError("audit state keys must contain 1 to 120 characters")


def _audit_json(value: object, *, depth: int) -> AuditJsonValue:
    """
        递归转换审计值为 JSON 兼容数据，并检查敏感内容与集合边界。
        时间必须带时区，统一转换为 UTC；不支持的对象不会被强制转字符串。

    :param value: 需要校验和转换的审计值。
    :param depth: 当前递归层级，用于限制嵌套深度。
    :return: 校验通过的 JSON 兼容值。
    :raises ValueError: 存在敏感信息、超限数据或不支持的值类型。
    """
    # 1. 先限制嵌套深度；简单值直接保留，字符串另查可能泄露的凭据内容。
    if depth > _MAX_DEPTH:
        raise ValueError("audit state exceeds the maximum nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if value not in _SAFE_AUDIT_IDENTIFIERS and _SENSITIVE_TEXT_RE.search(value):
            raise ValueError("audit state contains sensitive text")
        return value
    # 2. 数字必须能正常写成 JSON；ID 转文本，时间必须带时区并统一为 UTC。
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("audit state cannot contain non-finite numbers")
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("audit timestamps must include a timezone")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _audit_json(value.value, depth=depth + 1)
    # 3. 对象和数组逐层检查，每层都限制大小；对象字段还要经过敏感名称检查。
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("audit state contains too many object fields")
        result: dict[str, AuditJsonValue] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("audit state object keys must be strings")
            _require_safe_key(raw_key)
            result[raw_key] = _audit_json(item, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("audit state contains too many array items")
        return [_audit_json(item, depth=depth + 1) for item in value]
    # 连接、请求等未知对象直接拒绝，避免转字符串时意外泄露内部数据。
    raise ValueError(f"unsupported audit state value: {type(value).__name__}")


def sanitize_audit_state(state: Mapping[str, object] | None) -> dict[str, AuditJsonValue] | None:
    """
        校验审计前后状态，并限制序列化结果最多为 16 KiB。

    :param state: 审计状态映射；无状态时传 None。
    :return: 安全的 JSON 对象，输入为 None 时返回 None。
    :raises ValueError: 状态内容、嵌套结构或序列化大小不符合审计约束。
    """
    # 1. None 表示没有这份状态；有内容时先逐层检查敏感字段、值类型和集合上限。
    if state is None:
        return None
    value = _audit_json(state, depth=0)
    if not isinstance(value, dict):
        raise ValueError("audit state must be a JSON object")
    # 2. 按实际 UTF-8 JSON 字节数限制整份状态，字符少不一定代表存储字节少。
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > _MAX_STATE_BYTES:
        raise ValueError("audit state exceeds 16 KiB")
    return value


def sanitize_audit_request(value: Mapping[str, object] | None) -> dict[str, object] | None:
    """
        过滤操作审计的请求快照，只保留 query/body 两部分并沿用日志脱敏规则。

    :param value: 已采集的查询参数和 JSON 正文；非 HTTP 操作为 None。
    :return: 总计不超过 4 KiB 的脱敏副本；超限保留固定省略原因。
    """
    # 1. 不沿用前后状态的敏感字段拒绝规则：请求需要保留 password 字段名，值必须遮盖。
    if value is None:
        return None
    result: dict[str, object] = {
        "query": summarize_log_data(value.get("query", {})),
        "body": summarize_log_data(value.get("body")),
    }
    # 2. 合并后再检查总字节数，不能绕过每份摘要的大小边界。
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > SUMMARY_MAX_BYTES:
        return {"query": {}, "body": {"_omitted": "summary_too_large"}}
    return result


def validate_audit_action(value: str) -> str:
    """
        校验审计动作名的长度和稳定机器标识格式。

    :param value: 3 至 120 字符的审计动作名。
    :return: 校验通过的原动作名。
    :raises ValueError: 动作名长度或格式不合法。
    """
    # 动作必须是短而稳定的机器名称，拒绝把整句用户输入或异常文本当成事件分类。
    if not 3 <= len(value) <= 120 or _ACTION_RE.fullmatch(value) is None:
        raise ValueError("invalid audit action")
    return value


def validate_audit_reason(value: str) -> str:
    """
        校验审计原因码，确保它是可聚合查询的稳定标识。

    :param value: 2 至 80 字符、由小写字母数字及下划线组成的原因码。
    :return: 校验通过的原原因码。
    :raises ValueError: 原因码长度或格式不合法。
    """
    # 用固定字符和长度约束原因码，便于按相同原因统计事件。
    if not 2 <= len(value) <= 80 or _REASON_RE.fullmatch(value) is None:
        raise ValueError("invalid audit reason code")
    return value


def validate_audit_request_id(value: str) -> str:
    """
        校验审计请求关联 ID，限制长度及允许出现的字符。

    :param value: HTTP 请求 ID 或后台任务的关联 ID。
    :return: 校验通过的原关联 ID。
    :raises ValueError: 关联 ID 为空、超过 128 字符或包含非法字符。
    """
    # 关联 ID 只保留允许字符，不能让任意正文混入审计与日志的连接标识。
    if not 1 <= len(value) <= 128 or _REQUEST_ID_RE.fullmatch(value) is None:
        raise ValueError("invalid audit request or correlation ID")
    return value


def get_audit_request_id() -> str:
    """
        读取当前操作已经绑定的关联 ID，让审计与响应、文件日志使用同一个编号。
        HTTP 中间件负责绑定请求 ID；命令行等入口在操作开始时绑定自己的操作 ID。

    :return: 已通过审计字符和长度规则检查的当前关联 ID，不会生成新的编号。
    :raises RuntimeError: 没有绑定操作上下文，或原请求已经结束。
    :raises ValueError: 入口绑定的关联 ID 不符合审计规则。
    """
    # 1. 从当前协程的上下文读取编号；不同并发请求各读自己的值，不共用全局字符串。
    request_id = current_request_id()
    # 2. 没有有效上下文说明入口漏了绑定；不能每条审计另造一个 ID，把同一次操作拆散。
    if request_id is None:
        raise RuntimeError("audit requires an active request or operation context")
    # 3. 保留原有安全校验，再把同一个编号交给审计模型保存。
    return validate_audit_request_id(request_id)
