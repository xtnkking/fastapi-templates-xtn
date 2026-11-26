#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    判断角色的可见性、创建、资料管理和权限绑定边界。
#    只计算策略结果；锁内重读、写入和审计由角色 Service 负责。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从共用授权策略中独立角色管理规则，保持原有拒绝语义
# 2026/09/29    XTN       V1.001        共用角色变更边界检查，明确未知权限操作不能按解绑处理
# 2026/10/08    XTN       V1.002        操作名称改用普通字符串，允许值与权限在实际映射处说明
# 2026/10/10    XTN       V1.003        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.004        补充角色可见范围和多阶段管理边界的通俗说明
# 2026/10/20    XTN       V1.005        等级比较区分角色 level 与用户 role_level
# 2026/10/26    XTN       V1.006        用户角色权限信息类型统一命名为 UserInfo
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
from app.core.access.roles import SUPER_ADMIN_PERMISSION_KEYS


def is_administrative_role_visible(*, current_user: UserInfo, role: RoleGrant) -> bool:
    """
        判断管理界面能否查看角色，普通管理员不能查看同级、高级及受保护角色。

    :param current_user: 执行查看操作的用户授权快照。
    :param role: 被查看的角色授权。
    :return: 超级管理员或角色满足严格下级可见边界时返回 True。
    """
    # 超级管理员可见全部角色；其余人还要同时满足未保护、非超级管理员和严格低级。
    if current_user.is_super_admin:
        return True
    return (
        not role.is_protected
        and not role.is_super_admin
        and role.level < current_user.role_level
    )


def _affected_subjects_are_manageable(*, current_user: UserInfo,
                                      affected: tuple[UserInfo, ...]) -> PolicyDecision:
    """
        检查角色变动影响的每个用户，防止借修改共享角色间接修改本人或上级。

    :param current_user: 发起角色变更的用户授权快照。
    :param affected: 本次变更会影响的用户授权快照集合。
    :return: 首个不满足保护、等级或权限上限的拒绝决定，全部通过则允许。
    """
    # 一个角色可能被许多人持有，改它会一起影响这些人，不能借此间接给本人或上级改权限。
    for subject in affected:
        if subject.is_protected or current_user.user_id == subject.user_id:
            return deny("affected_subject_not_manageable")
        if current_user.role_level <= subject.role_level:
            return deny("affected_subject_not_strictly_lower")
        if not target_within_user_authority(current_user, subject):
            return deny("permission_ceiling_exceeded")
    return allow()


def decide_role_create(*, current_user: UserInfo, level: int) -> PolicyDecision:
    """
        检查创建角色权限，并要求新自定义角色等级有效且严格低于操作者。

    :param current_user: 创建角色的用户授权快照。
    :param level: 新角色的等级，允许范围为 1～999，还必须低于当前用户的 role_level。
    :return: 允许创建或包含具体拒绝原因的策略决定。
    """
    # 1. 先确认账号可用并持有创建权限，角色等级检查不能替代操作权限。
    basic = check_user_permission(current_user, PermissionKey.ROLES_CREATE)
    if basic is not None:
        return basic
    # 2. 新角色必须使用普通角色的等级，且低于操作者，不能造出平级或上级角色。
    if level < 1 or level >= 1000:
        return deny("custom_role_tier_out_of_range")
    if current_user.role_level <= level:
        return deny("role_not_strictly_lower")
    return allow()


def _check_mutable_role(*, current_user: UserInfo, changed_role: RoleGrant,
                        current_user_holds_role: bool) -> PolicyDecision | None:
    """
        检查两类角色变更共用的目标边界，避免资料变更与权限变更的规则逐渐分叉。
        调用方必须先检查当前操作要求的具体权限。

    :param current_user: 当前操作者的完整权限快照。
    :param changed_role: 变更前的目标角色及其已有权限。
    :param current_user_holds_role: 操作者是否持有该角色，持有时不能间接修改本人。
    :return: 首个拒绝决定；角色可继续处理时返回 None。
    """
    # 1. 系统角色禁止在线修改；自己持有的角色也不能改，避免间接改变本人权限。
    if changed_role.is_system:
        return deny("system_role_immutable")
    if current_user_holds_role:
        return deny("indirect_self_change_forbidden")
    # 2. 目标角色既要严格低级，也不能含有操作者没有的权限。
    if current_user.role_level <= changed_role.level:
        return deny("role_not_strictly_lower")
    if not role_within_user_authority(current_user, changed_role):
        return deny("permission_ceiling_exceeded")
    return None


def decide_role_administration(*, operation: str, current_user: UserInfo,
                               changed_role: RoleGrant, current_user_holds_role: bool,
                               affected: tuple[UserInfo, ...]) -> PolicyDecision:
    """
        检查角色资料、状态和删除操作，禁止修改系统角色或操作者持有的角色。

        除角色自身严格低于操作者外，其影响的所有用户也必须满足管理边界。

    :param operation: 更新、启用、禁用或删除角色的具体操作名称。
    :param current_user: 当前操作者的授权快照。
    :param changed_role: 准备变更的角色及权限。
    :param current_user_holds_role: 操作者是否持有该角色，用于禁止间接修改自身。
    :param affected: 该角色变更会影响的全部用户快照。
    :return: 允许变更或包含首个拒绝原因的策略决定。
    :raises ValueError: 操作不是更新、启用、禁用或删除角色。
    """
    # 1. 按 update、enable/disable、delete 选择所需权限；这里只判断，不执行资料或状态变更。
    permissions_by_operation = {
        "update": PermissionKey.ROLES_UPDATE,
        "enable": PermissionKey.ROLES_STATUS_UPDATE,
        "disable": PermissionKey.ROLES_STATUS_UPDATE,
        "delete": PermissionKey.ROLES_DELETE,
    }
    if operation not in permissions_by_operation:
        raise ValueError("unsupported role administration operation")
    required = permissions_by_operation[operation]
    basic = check_user_permission(current_user, required)
    if basic is not None:
        return basic
    # 2. 检查角色本身是否允许修改，系统角色、本人持有角色或权限越界会被拒绝。
    role_boundary = _check_mutable_role(
        current_user=current_user,
        changed_role=changed_role,
        current_user_holds_role=current_user_holds_role,
    )
    if role_boundary is not None:
        return role_boundary
    # 3. 一个角色会影响所有持有者，再逐个检查这些用户，避免借共享角色间接越权。
    return _affected_subjects_are_manageable(current_user=current_user, affected=affected)


def decide_role_permissions_change(*, operation: str, current_user: UserInfo,
                                   changed_role_before: RoleGrant, permission_keys_after: frozenset[str],
                                   current_user_holds_role: bool,
                                   affected_after: tuple[UserInfo, ...]) -> PolicyDecision:
    """
        检查角色权限绑定或解绑，限制权限上限并检查所有受影响用户。

        系统角色不可在线修改，也不能通过修改自己持有的角色改变本人权限。

    :param operation: bind 表示绑定权限，unbind 表示解绑权限。
    :param current_user: 当前操作者的授权快照。
    :param changed_role_before: 变更前的目标角色及权限集合。
    :param permission_keys_after: 执行变更后该角色预计拥有的完整权限集合。
    :param current_user_holds_role: 操作者当前是否持有目标角色。
    :param affected_after: 变更后所有受影响用户的预测授权快照。
    :return: 允许变更或包含首个拒绝原因的策略决定。
    :raises ValueError: 操作不是 bind 或 unbind，不能误用另一项权限继续执行。
    """
    # 1. 只接受绑定或解绑，先核对该操作权限，避免未知字符串被当成解绑继续处理。
    if operation not in ("bind", "unbind"):
        raise ValueError("unsupported role permission operation")
    required = (
        PermissionKey.ROLES_PERMISSIONS_BIND
        if operation == "bind"
        else PermissionKey.ROLES_PERMISSIONS_UNBIND
    )
    basic = check_user_permission(current_user, required)
    if basic is not None:
        return basic
    # 2. 再检查变更前角色，防止通过清空权限等方式绕开系统角色和本人保护。
    role_boundary = _check_mutable_role(
        current_user=current_user,
        changed_role=changed_role_before,
        current_user_holds_role=current_user_holds_role,
    )
    if role_boundary is not None:
        return role_boundary
    # 3. 新权限集合也不能越界，随后检查角色变更后每位持有者的预测权限。
    if not permission_keys_after <= SUPER_ADMIN_PERMISSION_KEYS:
        return deny("permission_outside_control_plane")
    if not permission_keys_after <= current_user.permissions:
        return deny("permission_ceiling_exceeded")
    return _affected_subjects_are_manageable(
        current_user=current_user,
        affected=affected_after,
    )
