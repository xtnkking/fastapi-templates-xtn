#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    判断管理员能否查看、管理用户及绑定或解绑用户角色。
#    只计算策略结果；目标读取、写入和审计由用户 Service 负责。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从共用授权策略中独立用户管理与用户角色绑定规则
# 2026/09/29    XTN       V1.001        说明角色变更的三阶段检查并拒绝未知操作
# 2026/10/08    XTN       V1.002        角色关系操作改用普通字符串，保留实际校验
# 2026/10/10    XTN       V1.003        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.004        补充用户可见性和管理权限检查的通俗步骤
# 2026/10/20    XTN       V1.005        用户管理统一比较 role_level，角色自身使用 level
# 2026/10/24    XTN       V1.006        用户角色变更检查使用 bind 和 unbind 权限名
# 2026/10/26    XTN       V1.007        用户角色权限信息类型统一命名为 UserInfo
# 2026/11/27    XTN       V1.008        admin 按普通自定义角色检查，取消按名称限制其分配人
# --------------------------------------------------------------------------------------------------


from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.authorization_policy import (
    PolicyDecision,
    allow,
    check_user_permission,
    deny,
    role_within_user_authority,
    target_within_user_authority,
)
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SystemRoleKey


def is_administrative_user_visible(*, current_user: UserInfo, target: UserInfo) -> bool:
    """
        判断管理界面能否查看目标用户，普通管理员只能查看未受保护的严格下级。

    :param current_user: 执行查看操作的用户授权快照。
    :param target: 被查看用户的授权快照。
    :return: 超级管理员或满足严格下级可见边界时返回 True，不代替接口权限检查。
    """
    # 超级管理员可见全部用户；普通管理员只能看本人以外、未保护且等级严格更低的用户。
    if current_user.is_super_admin:
        return True
    return (
        current_user.user_id != target.user_id
        and not target.is_protected
        and target.role_level < current_user.role_level
    )


def decide_role_change(*, operation: str,
                       current_user: UserInfo,
                       target_before: UserInfo,
                       target_after: UserInfo,
                       changed_roles: tuple[RoleGrant, ...]) -> PolicyDecision:
    """
        检查用户绑定或解绑角色的权限，并同时约束变更前后的目标等级和权限。

        禁止管理本人、在线授予超级管理员或解绑默认 user 角色。
        自定义角色按等级和权限检查，不因名称叫 admin 就获得特殊待遇。

    :param operation: 角色关系操作，bind 表示绑定，unbind 表示解绑。
    :param current_user: 当前操作者的授权快照。
    :param target_before: 目标用户在变更前的授权快照。
    :param target_after: 根据待执行变更计算的目标用户预测快照。
    :param changed_roles: 本次绑定或解绑涉及的全部角色。
    :return: 允许操作或首个边界检查失败的策略决定。
    :raises ValueError: 操作不是 bind 或 unbind，不能误按解绑操作处理。
    """
    # 1. 先确认操作是绑定还是解绑，未知操作不能按另一项权限继续处理。
    if operation not in ("bind", "unbind"):
        raise ValueError("unsupported user role operation")
    # 2. 核对具体操作权限及目标状态；停用用户不能新增角色，受保护用户和本人不能管理。
    required = (
        PermissionKey.ROLES_BIND
        if operation == "bind"
        else PermissionKey.ROLES_UNBIND
    )
    basic = check_user_permission(current_user, required)
    if basic is not None:
        return basic
    if current_user.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if operation == "bind" and not target_before.user_is_active:
        return deny("target_inactive")
    if target_before.is_protected:
        return deny("protected_subject")

    # 3. 逐个检查待变更角色：超级管理员只允许线下处理，默认 user 角色不可解绑。
    for role in changed_roles:
        if role.key == SystemRoleKey.SUPER_ADMIN.value or role.is_protected:
            return deny("super_admin_assignment_offline_only")
        if operation == "unbind" and role.key == SystemRoleKey.USER.value:
            return deny("default_user_role_required")
        if not role_within_user_authority(current_user, role):
            return deny("permission_ceiling_exceeded")
        if current_user.role_level <= role.level:
            return deny("role_not_strictly_lower")

    # 4. 用户可能持有多个角色，变更前后都比较整体等级和权限，避免只看本次角色而越权。
    if current_user.role_level <= target_before.role_level:
        return deny("target_not_strictly_lower")
    if current_user.role_level <= target_after.role_level:
        return deny("target_not_strictly_lower")
    if not target_within_user_authority(current_user, target_before):
        return deny("permission_ceiling_exceeded")
    if not target_within_user_authority(current_user, target_after):
        return deny("permission_ceiling_exceeded")
    return allow()


def _decide_user_administration(*, current_user: UserInfo, target_before: UserInfo,
                                required_permission: PermissionKey) -> PolicyDecision:
    """
        检查用户管理的共同边界，仅允许具备相应权限的操作者管理未保护的严格下级。

    :param current_user: 执行用户管理操作的授权快照。
    :param target_before: 目标用户在操作前的授权快照。
    :param required_permission: 本次用户管理操作要求的权限标识。
    :return: 允许管理或包含权限、本人、保护状态、等级等拒绝原因的决定。
    """
    # 1. 操作者先要有本次管理权限且账号可用，不能只凭管理员称号继续。
    basic = check_user_permission(current_user, required_permission)
    if basic is not None:
        return basic
    # 2. 排除本人及受保护用户，再要求目标严格低级且权限完全在操作者范围内。
    if current_user.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if target_before.is_protected:
        return deny("protected_subject")
    if current_user.role_level <= target_before.role_level:
        return deny("target_not_strictly_lower")
    if not target_within_user_authority(current_user, target_before):
        return deny("permission_ceiling_exceeded")
    return allow()


def decide_user_status_change(*, current_user: UserInfo, target_before: UserInfo) -> PolicyDecision:
    """
        检查启用或停用用户的权限，沿用禁止管理本人及同级、上级的共同边界。

    :param current_user: 准备修改用户状态的操作者快照。
    :param target_before: 待修改状态用户的当前授权快照。
    :return: 允许修改状态或包含拒绝原因的策略决定。
    """
    # 用修改状态权限执行共同边界检查；这里不实际启用或停用账号。
    return _decide_user_administration(
        current_user=current_user,
        target_before=target_before,
        required_permission=PermissionKey.USERS_STATUS_UPDATE,
    )


def decide_user_password_reset(*, current_user: UserInfo, target_before: UserInfo) -> PolicyDecision:
    """
        检查管理员重置密码权限，只允许为未受保护的严格下级重置密码。

    :param current_user: 准备重置密码的操作者授权快照。
    :param target_before: 待重置密码用户的当前授权快照。
    :return: 允许重置密码或包含拒绝原因的策略决定。
    """
    # 用重置密码权限执行共同边界检查；密码哈希和写入由业务服务处理。
    return _decide_user_administration(
        current_user=current_user,
        target_before=target_before,
        required_permission=PermissionKey.USERS_PASSWORD_RESET,
    )


def decide_user_sessions_revoke(*, current_user: UserInfo, target_before: UserInfo) -> PolicyDecision:
    """
        检查管理员撤销用户全部登录的权限，禁止普通用户借此退出自己的全部登录。

    :param current_user: 准备撤销登录的操作者授权快照。
    :param target_before: 待撤销全部登录用户的当前授权快照。
    :return: 允许撤销严格下级的全部登录或包含拒绝原因的策略决定。
    """
    # 用撤销全部登录权限执行共同边界检查；这里不删除 Redis 中的登录记录。
    return _decide_user_administration(
        current_user=current_user,
        target_before=target_before,
        required_permission=PermissionKey.USERS_SESSIONS_REVOKE,
    )
