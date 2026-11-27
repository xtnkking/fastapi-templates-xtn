#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证系统角色和管理员向下可见的业务规则。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        对齐权限策略模块名称，保留最小交付的权限边界验证
# 2026/09/26    XTN       V1.002        使用 authorization 业务名称，保持管理员层级隔离验证
# 2026/09/29    XTN       V1.003        从用户策略模块检查管理员层级隔离
# 2026/10/02    XTN       V1.004        展开角色快照并分别验证本人和另一名同级管理员
# 2026/10/15    XTN       V1.005        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/15    XTN       V1.006        对齐当前用户参数名，保留管理员层级可见性检查
# 2026/10/26    XTN       V1.007        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V1.008        验证普通用户仅有基础权限且管理员同样具有本人能力
# 2026/11/27    XTN       V1.009        只预置超级管理员和普通用户，管理者改由自定义角色提供权限
# --------------------------------------------------------------------------------------------------


from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SYSTEM_ROLE_SPECS, SystemRoleKey
from app.core.access.user_policy import is_administrative_user_visible
from app.core.ids import new_entity_id


def test_administrator_cannot_see_peer_or_higher_authority() -> None:
    """
        普通管理员可查看更低用户，不能查看本人、另一名同级管理员或超级管理员。

    :return: 无返回值；层级隔离失效时断言失败。
    """
    # 系统只预置超级管理员和普通用户，管理员角色由项目按业务自行配置。
    assert set(SYSTEM_ROLE_SPECS) == {SystemRoleKey.SUPER_ADMIN, SystemRoleKey.USER}
    snapshots: dict[SystemRoleKey, UserInfo] = {}
    for key, spec in SYSTEM_ROLE_SPECS.items():
        role = RoleGrant(
            role_id=new_entity_id("R"),
            key=key.value,
            level=spec.level,
            permissions=spec.permissions,
            is_system=True,
            is_protected=spec.is_protected,
            is_super_admin=spec.is_super_admin,
        )
        snapshots[key] = UserInfo.build(
            user_id=new_entity_id("U"),
            user_is_active=True,
            user_is_protected=False,
            roles=(role,),
        )

    # 测试显式配置一个 500 级自定义管理角色；不是默认系统角色，也不自动获得权限。
    regular_user = snapshots[SystemRoleKey.USER]
    manager_role = RoleGrant(
        role_id=new_entity_id("R"), key="admin", level=500,
        permissions=frozenset({PermissionKey.USERS_READ.value}),
        is_system=False, is_protected=False, is_super_admin=False,
    )
    current_user = UserInfo.build(
        user_id=new_entity_id("U"), user_is_active=True, user_is_protected=False,
        roles=(*regular_user.roles, manager_role),
    )
    peer_admin = UserInfo.build(
        user_id=new_entity_id("U"),
        user_is_active=True,
        user_is_protected=False,
        roles=current_user.roles,
    )
    super_admin = snapshots[SystemRoleKey.SUPER_ADMIN]
    assert is_administrative_user_visible(current_user=current_user, target=regular_user)
    assert not is_administrative_user_visible(current_user=current_user, target=current_user)
    assert not is_administrative_user_visible(current_user=current_user, target=peer_admin)
    assert not is_administrative_user_visible(current_user=current_user, target=super_admin)

    # 基础 user 只有查看本人和本人改密权限，不授予后台管理能力。
    basic_permissions = frozenset({PermissionKey.ACCOUNT_READ.value, PermissionKey.ACCOUNT_CHANGE_PASSWORD.value})
    assert SYSTEM_ROLE_SPECS[SystemRoleKey.USER].permissions == basic_permissions
    assert basic_permissions <= SYSTEM_ROLE_SPECS[SystemRoleKey.SUPER_ADMIN].permissions
    assert current_user.permissions == basic_permissions | {PermissionKey.USERS_READ.value}
    assert not manager_role.is_system and not manager_role.is_super_admin
