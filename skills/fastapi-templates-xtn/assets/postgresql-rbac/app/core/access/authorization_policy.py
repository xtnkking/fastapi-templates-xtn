#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    提供用户和角色管理共用的纯授权判断与策略结果。
#    具体角色管理和用户管理规则分别位于 role_policy.py、user_policy.py。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        明确授权策略模块名称，保持权限决策行为
# 2026/09/23    XTN       V1.002        解释权限判断与目标范围，区分策略结果和实际数据库操作
# 2026/09/29    XTN       V1.003        将角色和用户专属决策移至对应业务策略模块
# 2026/10/02    XTN       V1.004        说明纯策略结果与业务执行的边界
# 2026/10/10    XTN       V1.005        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.006        补充策略结果构造与权限范围判断的通俗步骤
# 2026/10/26    XTN       V1.007        用户角色权限信息类型统一命名为 UserInfo
# --------------------------------------------------------------------------------------------------


from dataclasses import dataclass

from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SUPER_ADMIN_PERMISSION_KEYS


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """
        表示一次纯授权判断的结果，不执行查库、加锁、HTTP 响应或审计。
        业务层读取结果后，负责实际操作和失败处理。
    """

    allowed: bool  # True 表示当前输入快照通过策略，写入前仍须使用锁后读取的新快照。
    reason_code: str  # 内部稳定原因，供日志/审计排错；不要直接当成客户端提示返回。


def allow() -> PolicyDecision:
    """
        构造权限策略检查通过的统一结果。

    :return: 允许操作且原因代码为 allowed 的策略决定。
    """
    # 只标记此次策略允许继续；实际查库、写入和审计仍由调用方完成。
    return PolicyDecision(allowed=True, reason_code="allowed")


def deny(reason_code: str) -> PolicyDecision:
    """
        构造权限策略拒绝结果，供服务层统一处理响应及审计。

    :param reason_code: 本次拒绝的固定原因代码，不包含用户敏感信息。
    :return: 禁止操作并携带拒绝原因的策略决定。
    """
    # 把拒绝原因带回业务层，不在这个纯判断函数中抛出 HTTP 错误。
    return PolicyDecision(allowed=False, reason_code=reason_code)


def target_within_user_authority(current_user: UserInfo, target: UserInfo) -> bool:
    """
        检查目标用户的全部权限是否同时处于系统管理范围及操作者权限范围内。

    :param current_user: 发起管理操作的用户授权快照。
    :param target: 待管理用户的授权快照。
    :return: 目标权限没有超出任一权限上限时返回 True。
    """
    # 集合的 <= 表示“全部包含于”，不是比较数量；等级低也不能管理自己没有的权限。
    return (
        target.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and target.permissions <= current_user.permissions
    )


def role_within_user_authority(current_user: UserInfo, role: RoleGrant) -> bool:
    """
        检查角色权限是否同时受系统权限目录及操作者已有权限约束。

    :param current_user: 发起角色管理操作的用户授权快照。
    :param role: 待检查的角色及其权限集合。
    :return: 角色权限不超出任一权限上限时返回 True。
    """
    # 角色中的每一项权限都必须既在系统允许的范围内，也由操作者自己持有。
    return (
        role.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and role.permissions <= current_user.permissions
    )


def check_user_permission(current_user: UserInfo, required: PermissionKey) -> PolicyDecision | None:
    """
        先检查操作权限及操作者启用状态，供后续管理边界判断复用。

    :param current_user: 当前操作者的授权快照。
    :param required: 本次操作要求具备的权限标识。
    :return: 缺少权限或账号停用时返回拒绝决定，基础检查通过时返回 None。
    """
    # 必须先有操作权，再判断目标；否则可能通过不同错误猜出自己无权查看的目标。
    if required.value not in current_user.permissions:
        return deny("missing_operation_permission")
    # 持有权限的停用账号也不能继续管理，避免只看角色而忽略账号状态。
    if not current_user.user_is_active:
        return deny("user_inactive")
    return None
