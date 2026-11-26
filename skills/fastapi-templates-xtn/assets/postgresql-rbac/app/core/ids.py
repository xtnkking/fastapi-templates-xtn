#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    集中生成和校验用户、角色、关系及审计记录的业务 ID。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/04    XTN       V1.000        新建业务 ID 规则
# 2026/10/09    XTN       V1.001        集中长度和格式，供生成、接口校验与模型约束共用
# 2026/10/13    XTN       V1.002        补充业务 ID 生成、时间和失败边界的通俗说明
# 2026/10/16    XTN       V1.003        逐项说明字符表、长度、业务前缀和格式规则的用途及维护方式
# 2026/10/16    XTN       V1.004        默认账号与权限操作审计统一使用 OA 前缀
# 2026/10/19    XTN       V1.005        精简生成和校验说明，保留格式与维护要求
# --------------------------------------------------------------------------------------------------


import re
import secrets
from datetime import datetime, timedelta, timezone

# 生成随机部分时可选的字符：26 个大写英文字母 + 10 个数字，共 36 种。
# 普通业务 ID 和审计 ID 都从这里取随机字符；不含小写字母、空格和符号。
ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# 单个随机字符的校验规则：[A-Z0-9] 表示一位大写字母或数字。
# 各类 ID 再指定重复次数；字符范围须与 ID_ALPHABET 一致。
ID_RANDOM_PATTERN = r"[A-Z0-9]"
# 普通业务 ID 的总字符数，包含前缀：默认 U/R/P + 14 位随机字符，UR/RP + 13 位随机字符。
# 按项目规模调整这个值；接口校验和 ORM 字段/约束引用它，已有数据库仍需使用者自行迁移。
ENTITY_ID_LENGTH = 15
# 审计 ID 中“时间部分”的位数，不包含前缀和随机尾部。
# YYMMDDHHMMSSmm：两位年、月、日、时、分、秒、百分之一秒，共 14 位。
# 最后两位对应 10 毫秒精度，按微秒值截取而非四舍五入，不是三位毫秒或分钟。
# 例如 26092211414155 表示 2026-09-22 11:41:41.55；改变格式时也必须修改 new_audit_id 的时间拼接。
AUDIT_TIME_LENGTH = 14
# 审计 ID 最后的随机字符数，默认 6 位，每位均从 ID_ALPHABET 取值。
# 用于区分同一百分之一秒内生成的记录；仍可能碰撞，最终由数据库主键约束保证唯一。
AUDIT_RANDOM_LENGTH = 6
# 审计 ID 的总字符数，自动计算：2 位业务前缀 + 14 位时间 + 6 位随机字符，默认 22 位。
# 审计模型的字段长度及接口校验引用这个值；调整随机尾部长度时不用单独修改总长度。
AUDIT_ID_LENGTH = 2 + AUDIT_TIME_LENGTH + AUDIT_RANDOM_LENGTH
# 审计 ID 统一用北京时间 UTC+8，不受服务器时区影响。
# 它只控制 ID 内的时间文字；数据库时间字段和日志时间由各自模块处理。
CHINA_TIMEZONE = timezone(timedelta(hours=8))

# 以下规则供请求参数及 ORM 约束共用；^ 和 $ 表示整个 ID 的开头和结尾。
# 随机部分按“总长度减去前缀长度”计算，不同实体的默认总长度都是 15 位。
# 格式正确不代表记录存在或有权访问；数据库唯一约束和业务权限检查仍各自负责。
# 用户 ID：users.user_id，U + 14 位随机字符；JWT 中的 user_id 也使用这一类 ID。
USER_ID_PATTERN = rf"^U{ID_RANDOM_PATTERN}{{{ENTITY_ID_LENGTH - 1}}}$"
# 角色 ID：roles.id，R + 14 位随机字符，用于定位角色本身。
ROLE_ID_PATTERN = rf"^R{ID_RANDOM_PATTERN}{{{ENTITY_ID_LENGTH - 1}}}$"
# 权限 ID：permissions.id，P + 14 位随机字符；不同于 users:read 这样的权限标识。
PERMISSION_ID_PATTERN = rf"^P{ID_RANDOM_PATTERN}{{{ENTITY_ID_LENGTH - 1}}}$"
# 用户角色绑定记录 ID：user_roles.id，UR + 13 位随机字符；用于区分每次绑定，不是用户或角色 ID。
USER_ROLE_ID_PATTERN = rf"^UR{ID_RANDOM_PATTERN}{{{ENTITY_ID_LENGTH - 2}}}$"
# 角色权限绑定记录 ID：role_permissions.id，RP + 13 位随机字符；用于区分每次授权绑定。
ROLE_PERMISSION_ID_PATTERN = rf"^RP{ID_RANDOM_PATTERN}{{{ENTITY_ID_LENGTH - 2}}}$"
# 以下审计规则只检查前缀、长度及字符范围，不检查时间部分是否真的是一个有效日期。
# 默认操作审计 ID：operation_audit_events.id，OA + 14 位时间 + 6 位随机字符，共 22 位。
OPERATION_AUDIT_ID_PATTERN = rf"^OA[0-9]{{{AUDIT_TIME_LENGTH}}}{ID_RANDOM_PATTERN}{{{AUDIT_RANDOM_LENGTH}}}$"
# 业务审计 ID：business_audit_events.id，BA + 时间 + 随机尾部，用于项目自行接入的重要业务事件。
BUSINESS_AUDIT_ID_PATTERN = rf"^BA[0-9]{{{AUDIT_TIME_LENGTH}}}{ID_RANDOM_PATTERN}{{{AUDIT_RANDOM_LENGTH}}}$"

# 普通业务 ID 的前缀和规则，供 new_entity_id、require_entity_id 使用。
# 新增类型时，先在上方定义规则，再登记到这里，并在模型和接口中引用。
ENTITY_ID_PATTERNS = {
    "U": USER_ID_PATTERN,  # 用户。
    "R": ROLE_ID_PATTERN,  # 角色。
    "P": PERMISSION_ID_PATTERN,  # 权限目录。
    "UR": USER_ROLE_ID_PATTERN,  # 用户与角色的一次绑定。
    "RP": ROLE_PERMISSION_ID_PATTERN,  # 角色与权限的一次绑定。
}
# 审计 ID 的前缀和规则，供 new_audit_id、require_audit_id 使用。
# 默认 OA 和可选 BA 都是两位；新增前缀时须与 AUDIT_ID_LENGTH 中的前缀长度保持一致。
AUDIT_ID_PATTERNS = {
    "OA": OPERATION_AUDIT_ID_PATTERN,  # 默认账号安全和权限管理操作。
    "BA": BUSINESS_AUDIT_ID_PATTERN,  # 项目自行定义的业务审计。
}


def new_entity_id(prefix: str) -> str:
    """
        按 ENTITY_ID_LENGTH 生成业务 ID；默认 15 位，不同实体使用各自的固定前缀。

    :param prefix: U、R、P、UR 或 RP。
    :return: 前缀加安全随机大写字母或数字。
    :raises ValueError: 前缀不是支持的实体类型。
    """
    # 检查前缀，再用随机字符补足总长度；数据库唯一约束防止撞号。
    if prefix not in ENTITY_ID_PATTERNS:
        raise ValueError("unknown entity ID prefix")
    random_length = ENTITY_ID_LENGTH - len(prefix)
    return prefix + "".join(secrets.choice(ID_ALPHABET) for _ in range(random_length))


def require_entity_id(value: object, prefix: str) -> str:
    """
        检查业务 ID 的类型、前缀、长度和字符。

    :param value: 来自请求、JWT 或调用方的原始 ID。
    :param prefix: 预期实体的固定前缀。
    :return: 校验通过的原始 ID。
    :raises ValueError: ID 不符合预期格式。
    """
    # 按原文匹配，不修正空格或大小写，也不检查记录是否存在。
    if prefix not in ENTITY_ID_PATTERNS:
        raise ValueError("unknown entity ID prefix")
    if not isinstance(value, str) or re.fullmatch(ENTITY_ID_PATTERNS[prefix], value) is None:
        raise ValueError("invalid entity ID")
    return value


def new_audit_id(prefix: str, *, at: datetime | None = None) -> str:
    """
        生成审计 ID：前缀、YYMMDDHHMMSSmm、随机尾部，默认共 22 位。
        mm 是百分之一秒，不是三位毫秒；审计排序仍以 created_at 为准。

    :param prefix: 默认操作审计使用 OA；BA 用于可选业务审计。
    :param at: 测试时可传入固定时间；实际使用当前中国时间。
    :return: 本次审计事件的业务 ID。
    :raises ValueError: 前缀不支持，或指定时间没有时区。
    """
    # 1. 检查前缀和时区，避免把其他时区的时间误当成北京时间。
    if prefix not in AUDIT_ID_PATTERNS:
        raise ValueError("unknown audit ID prefix")
    if at is not None and at.tzinfo is None:
        raise ValueError("audit ID time must include a timezone")
    # 2. 转成北京时间，保留百分之一秒，再拼上随机尾部以区分同时生成的记录。
    current = (at or datetime.now(CHINA_TIMEZONE)).astimezone(CHINA_TIMEZONE)
    time_part = f"{current:%y%m%d%H%M%S}{current.microsecond // 10000:02d}"
    random_part = "".join(secrets.choice(ID_ALPHABET) for _ in range(AUDIT_RANDOM_LENGTH))
    return f"{prefix}{time_part}{random_part}"


def require_audit_id(value: object, prefix: str) -> str:
    """
        检查审计 ID 的前缀、长度和字符。

    :param value: 待校验的审计事件 ID。
    :param prefix: 预期审计业务前缀。
    :return: 校验通过的原始 ID。
    :raises ValueError: ID 格式错误。
    """
    # 只检查格式，不检查时间部分是否为真实日期。
    if prefix not in AUDIT_ID_PATTERNS:
        raise ValueError("unknown audit ID prefix")
    if not isinstance(value, str) or re.fullmatch(AUDIT_ID_PATTERNS[prefix], value) is None:
        raise ValueError("invalid audit ID")
    return value
