#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    通用业务审计事件目录与载荷校验；校验事件类型、字段白名单及安全快照。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释基础类字段、枚举用途与日志审计边界常量
# 2026/10/10    XTN       V1.002        业务审计发起者统一使用 operator 命名
# 2026/10/10    XTN       V1.003        平铺操作人、被操作人和非用户来源，明确执行入口与目标对象
# 2026/10/13    XTN       V1.004        补充业务审计目录、身份和隐私检查的通俗步骤
# 2026/10/16    XTN       V1.005        业务事实不再接收由审计构造自动读取的请求关联 ID
# --------------------------------------------------------------------------------------------------


import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from app.core.audit import (
    AuditJsonValue,
    AuditSource,
    sanitize_audit_state,
    validate_audit_reason,
)
from app.core.ids import require_audit_id, require_entity_id

# domain 是业务分类，如 orders；action 使用 orders.order.created 这样的稳定分段名称。
_DOMAIN_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
BUSINESS_AUDIT_ACTION_PATTERN: Final = re.compile(
    r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$"
)
# 操作者/资源 ID 只接受有限字符，邮箱和 IP 识别规则用于拒绝个人信息被混入自由文本。
_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$")
_EMAIL_RE: Final = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)
_IPV4_CANDIDATE_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.])"
)
_IPV6_CANDIDATE_RE: Final = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?=[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:]))"
    r"(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)"
    r"[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:])"
)
# 通用审计不接收整份请求、响应或联系方式；业务只选择确有追查价值的字段留档。
_FORBIDDEN_BUSINESS_KEYS: Final = frozenset(
    {
        "address",
        "bank_account",
        "body",
        "card_number",
        "customer_text",
        "display_name",
        "headers",
        "ip",
        "ip_address",
        "note",
        "phone",
        "postal_address",
        "query",
        "query_string",
        "request_body",
        "response_body",
        "user_agent",
    }
)
_FORBIDDEN_BUSINESS_SUFFIXES: Final = (
    "_address",
    "_bank_account",
    "_card_number",
    "_customer_text",
    "_display_name",
    "_ip",
    "_ip_address",
    "_note",
    "_phone",
    "_user_agent",
)
MAX_BUSINESS_AUDIT_CONTEXT_BYTES: Final = 4 * 1024  # 补充上下文最多 4 KiB，不是整份事件的大小上限。


class BusinessAuditOutcome(StrEnum):
    """
        区分业务已成功、执行中失败和规则明确拒绝，避免把服务故障记成用户越权。
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class BusinessAuditSourceType(StrEnum):
    """
        说明是谁执行本次操作；用户使用 user_id，其他来源按类型使用 source_id。
    """

    USER = "user"  # 已登录用户，操作人记录在 user_id。
    SERVICE = "service"  # 其他服务，source_id 保存可信服务标识。
    SYSTEM = "system"  # 系统自身行为，没有具体操作人或外部来源 ID。
    JOB = "job"  # 后台任务，source_id 保存可追查的任务标识。
    MAINTENANCE = "maintenance"  # 受控维护操作，source_id 保存维护身份标识。


def require_business_machine_name(value: str, *, field: str) -> str:
    """
        校验业务审计领域或资源类型的机器名称。

    :param value: 以小写字母开头、最长 64 字符的名称。
    :param field: 校验失败时用于定位配置项的字段说明。
    :return: 校验通过的原名称。
    :raises ValueError: 名称不符合小写字母、数字及下划线格式。
    """
    # 业务分类和对象类别只接受约定的机器名称，不接收展示文案或自由文本。
    if _DOMAIN_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def require_business_identifier(value: str, *, field: str) -> str:
    """
        校验业务审计的操作者或资源 ID，拒绝任意自由文本。

    :param value: 最长 128 字符的业务标识。
    :param field: 校验失败时使用的字段说明。
    :return: 校验通过的原业务标识。
    :raises ValueError: 标识长度或字符格式不合法。
    """
    # 只检查标识格式；这里不查对象是否存在，也不判断谁有操作权限。
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"invalid business audit {field}")
    return value


def require_business_event_id(value: str) -> str:
    """
        确认业务审计事件使用 BA 开头的 22 位标识。

    :param value: 待校验的事件 ID。
    :return: 校验通过的事件 ID。
    :raises ValueError: ID 格式错误。
    """
    # 复用 BA 审计 ID 的前缀、长度和字符校验，不能把订单或用户 ID 当作事件 ID。
    return require_audit_id(value, "BA")


def _contains_network_identifier(value: str) -> bool:
    """
        检测文本是否为 IP 地址或包含合法的 IPv4、IPv6 地址片段。

    :param value: 需要检查的审计文本。
    :return: 找到合法网络地址时为 True，否则为 False。
    """
    # 1. 先检查整段文本是否就是一个 IP 地址。
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return True

    # 2. 再找嵌在正文里的 IPv4 候选，经过地址解析确认，避免只凭数字和点就误判。
    for match in _IPV4_CANDIDATE_RE.finditer(value):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            continue
        return True

    # 3. 同样检查 IPv6 候选；全部没有合法地址时返回 False。
    for match in _IPV6_CANDIDATE_RE.finditer(value):
        try:
            ipaddress.IPv6Address(match.group())
        except ipaddress.AddressValueError:
            continue
        return True
    return False


def _reject_business_sensitive_data(value: object) -> None:
    """
        递归拒绝业务审计中的个人信息字段、邮箱和网络地址。
        与通用审计校验配合使用，避免自由文本带入不应长期保存的数据。

    :param value: 待检查的映射、序列或标量值。
    :return: 无返回值，未发现禁止内容时继续执行。
    :raises ValueError: 字段名或字符串内容包含禁止记录的信息。
    """
    # 1. 对象逐项检查字段名，再往下检查字段内容；非字符串字段名由通用审计校验拒绝。
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                continue
            normalized = raw_key.casefold().replace("-", "_")
            if normalized in _FORBIDDEN_BUSINESS_KEYS or normalized.endswith(
                _FORBIDDEN_BUSINESS_SUFFIXES
            ):
                raise ValueError("business audit payload contains forbidden data")
            _reject_business_sensitive_data(item)
        return
    # 2. 列表和元组继续逐项检查，个人信息不能藏在更深一层的集合里。
    if isinstance(value, list | tuple):
        for item in value:
            _reject_business_sensitive_data(item)
        return
    # 3. 字段名安全也不够，正文中的邮箱和 IP 地址同样禁止长期留档。
    if isinstance(value, str):
        if _EMAIL_RE.search(value) is not None:
            raise ValueError("business audit payload contains an email address")
        if _contains_network_identifier(value):
            raise ValueError("business audit payload contains a network identifier")


def sanitize_business_payload(state: Mapping[str, object] | None, *,
                              max_bytes: int) -> dict[str, AuditJsonValue] | None:
    """
        执行业务审计专用内容校验，并按指定字节上限检查 JSON 大小。

    :param state: 审计状态或上下文映射，无内容时为 None。
    :param max_bytes: 本类审计内容允许的最大 UTF-8 编码字节数。
    :return: 转换后的安全 JSON 对象，输入为 None 时返回 None。
    :raises ValueError: 内容包含禁止数据、结构不合法或序列化结果超限。
    """
    # 1. 缺内容直接保留 None；有内容先查业务隐私，再查通用凭据、类型和结构限制。
    if state is None:
        return None
    _reject_business_sensitive_data(state)
    sanitized = sanitize_audit_state(state)
    assert sanitized is not None
    # 2. 计算实际 JSON 字节数，再应用这类业务内容自己的上限。
    encoded = json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("business audit payload exceeds its size limit")
    return sanitized


@dataclass(frozen=True, slots=True)
class BusinessAuditActionSpec:
    """
        定义一种业务动作允许怎样记录审计，相当于“事件填写规则”，不是一条实际发生的记录。
    """

    domain: str  # 所属业务分类，例如 orders；不代表数据库表名。
    action: str  # 固定事件名，例如 orders.order.created，必须以 domain 开头。
    target_type: str  # 被操作对象的类别，例如 order；user 专指被操作用户本身。
    allowed_outcomes: frozenset[BusinessAuditOutcome]  # 本动作允许成功、拒绝或失败中的哪些结果。
    reason_codes: frozenset[str]  # 允许填写的固定原因，不能塞入任意异常文本。
    source_types: frozenset[BusinessAuditSourceType]  # 允许由用户、服务等哪些来源执行这个动作。
    before_fields: frozenset[str] = frozenset()  # 允许留档的变更前字段，空集合表示不能记录任何前置字段。
    after_fields: frozenset[str] = frozenset()  # 允许留档的变更后字段，只有成功事件可以有变更后状态。
    context_fields: frozenset[str] = frozenset()  # 允许补充的追查字段，不是任意请求内容的容器。
    schema_version: int = 1  # 审计字段结构版本，便于以后解释历史记录；不是用户或 Token 版本。

    def __post_init__(self) -> None:
        """
            校验业务审计动作目录的领域、结果、原因码及字段白名单。
            目录集合必须不可变，动作须属于声明的领域且版本为正整数。

        :return: 无返回值，完成动作规范的初始化校验。
        :raises TypeError: 集合或枚举类型不符合目录定义。
        :raises ValueError: 动作、版本、必填集合或允许记录的字段不合法。
        """
        # 1. 动作规则创建时先要求集合不可变，避免运行中被悄悄修改允许范围。
        collection_fields = (
            self.allowed_outcomes,
            self.reason_codes,
            self.source_types,
            self.before_fields,
            self.after_fields,
            self.context_fields,
        )
        if any(not isinstance(value, frozenset) for value in collection_fields):
            raise TypeError("business audit catalog collections must be frozenset")
        # 2. 校验动作名属于本业务分类，目标类型也必须使用稳定机器名称。
        require_business_machine_name(self.domain, field="domain")
        if (
            len(self.action) > 120
            or BUSINESS_AUDIT_ACTION_PATTERN.fullmatch(self.action) is None
        ):
            raise ValueError("invalid business audit action")
        if self.action.split(".", 1)[0] != self.domain:
            raise ValueError("business audit action must start with its domain")
        require_business_machine_name(self.target_type, field="target type")
        # 3. 成功/失败、原因和操作来源都必须明确列出，不能使用随意字符串扩大范围。
        if not self.allowed_outcomes:
            raise ValueError("business audit action requires an allowed outcome")
        if any(
            not isinstance(outcome, BusinessAuditOutcome)
            for outcome in self.allowed_outcomes
        ):
            raise TypeError("allowed outcomes must use BusinessAuditOutcome")
        if not self.reason_codes:
            raise ValueError("business audit action requires a reason code")
        if not self.source_types:
            raise ValueError("business audit action requires a source type")
        if any(
            not isinstance(source_type, BusinessAuditSourceType)
            for source_type in self.source_types
        ):
            raise TypeError("source types must use BusinessAuditSourceType")
        for reason_code in self.reason_codes:
            validate_audit_reason(reason_code)
        # 4. 版本必须是正整数，允许留档的每个字段名也要先经过隐私规则。
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version < 1
        ):
            raise ValueError("business audit schema version must be a positive integer")
        for field_name in self.before_fields | self.after_fields | self.context_fields:
            sanitize_business_payload(
                {field_name: None}, max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES
            )


@dataclass(frozen=True, slots=True)
class BusinessAuditFacts:
    """
        描述这一次实际发生的业务事实，之后按动作目录校验，再转为数据库审计记录。
        请求关联 ID 由审计服务从当前执行上下文取得，不属于调用方传入的业务事实。
    """

    event_id: str  # 本次审计记录的 BA 业务 ID，不是订单或用户 ID。
    action: str  # 已注册的事件名，必须能在 BusinessAuditActionSpec 目录找到。
    source_type: BusinessAuditSourceType  # 谁执行操作：用户、服务、系统、任务或维护人员。
    target_id: str  # 本次被操作对象的稳定 ID，例如订单 ID；对象类别来自动作目录。
    reason_code: str  # 本次结果的程序原因码，必须属于该动作允许的原因。
    entrypoint: AuditSource  # 从哪个入口执行，例如 HTTP；与“谁执行”的 source_type 分开。
    user_id: str | None = None  # 操作人；只在 source_type 为 USER 时填写，从登录身份获取。
    source_id: str | None = None  # 非用户来源的稳定 ID；服务、任务和维护操作必须填写。
    target_user_id: str | None = None  # 被操作人；目标是用户时等于 target_id，订单等目标可记录关联用户。
    before_state: Mapping[str, object] | None = None  # 选定的变更前字段；None 表示没有这份状态。
    after_state: Mapping[str, object] | None = None  # 成功后的选定字段；拒绝或失败时必须为 None。
    context: Mapping[str, object] | None = None  # 必要补充线索，仍需遵守字段白名单和 4 KiB 上限。

    def __post_init__(self) -> None:
        """
            先确认谁执行操作，再检查对应身份字段，避免把服务或任务伪装成用户。
            被操作用户单独校验；它与操作人可以相同，也可以不同。

        :return: 无返回值，完成不可变业务事实的身份校验。
        :raises TypeError: 来源类型没有使用规定的枚举。
        :raises ValueError: 身份字段缺失、混用或 ID 格式不符合约定。
        """
        # 1. 构造事实时先核对来源类型；这个检查不等于验证来源的真实身份。
        if not isinstance(self.source_type, BusinessAuditSourceType):
            raise TypeError("business audit source type must use BusinessAuditSourceType")

        # 用户操作只写操作人的 user_id；不再把它装进一个笼统的操作方对象。
        if self.source_type is BusinessAuditSourceType.USER:
            if self.user_id is None or self.source_id is not None:
                raise ValueError("user business audit requires only a user ID")
            require_entity_id(self.user_id, "U")
        # 系统自身动作没有具体身份 ID，既不填写用户，也不虚构一个来源。
        elif self.source_type is BusinessAuditSourceType.SYSTEM:
            if self.user_id is not None or self.source_id is not None:
                raise ValueError("system business audit must not have a user or source ID")
        # 服务、任务和维护操作保留各自的稳定来源 ID，供后续追查。
        else:
            if self.user_id is not None or self.source_id is None:
                raise ValueError("non-user business audit requires only a source ID")
            require_business_identifier(self.source_id, field="source ID")

        # 被操作人不是操作人；没有用户目标的业务允许留空，填写时必须是真正的用户 ID。
        if self.target_user_id is not None:
            require_entity_id(self.target_user_id, "U")
