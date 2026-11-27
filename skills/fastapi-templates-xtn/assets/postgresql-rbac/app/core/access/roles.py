#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    定义超级管理员和普通用户两个系统角色、初始权限及用户角色数量上限。
#    这些角色元数据不替代具体权限校验、目标等级比较和在线管理保护。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从授权快照模块独立系统角色定义，保持角色值及权限白名单不变
# 2026/09/29    XTN       V1.001        去除未使用的英文展示字段，角色显示名称以数据库记录为准
# 2026/10/20    XTN       V1.002        系统角色等级字段统一使用 level
# 2026/10/24    XTN       V1.003        初始权限白名单对齐用户角色绑定和解绑名称
# 2026/10/26    XTN       V1.004        三个系统角色明确包含本人账号基础权限
# 2026/10/26    XTN       V1.005        为三个角色的每项初始权限补充通俗说明
# 2026/11/27    XTN       V1.006        取消固定 admin 角色，管理员改由自定义角色和权限组成
# --------------------------------------------------------------------------------------------------


from dataclasses import dataclass
from enum import StrEnum

from app.core.access.permissions import PermissionKey


class SystemRoleKey(StrEnum):
    """
        定义不可删除的两个系统角色标识，不允许自定义角色占用这些名称。
    """

    SUPER_ADMIN = "super_admin"  # 唯一超级管理员；首位绑定与更换由开发人员线下操作数据库。
    USER = "user"  # 所有正常注册或管理员新增账号必备的最低级角色，不能解绑。


@dataclass(frozen=True, slots=True)
class SystemRoleSpec:
    """
        描述一个系统角色的固定等级、保护标志及显式权限集合。
        展示名称与说明属于数据库角色数据，不由此安全配置决定。
    """

    key: SystemRoleKey  # 稳定角色编码，只识别 super_admin 和 user；不是展示名称。
    level: int  # 固定等级：超级管理员 1000、普通用户 0；自定义角色在别处按 1～999 创建。
    is_protected: bool  # True 表示角色受在线管理保护，不等同于角色是否为系统内置。
    is_super_admin: bool  # True 仅对应唯一超级管理员角色，不靠名称模糊匹配识别。
    permissions: frozenset[str]  # 明确列出的初始权限；新增权限不会自动进入这个集合。


# 系统角色使用显式权限白名单：新增权限不会自动授予管理员，必须逐项确认后加入。
# 具备权限仍需通过目标等级和保护状态检查，不能单凭集合中的权限管理平级或上级。
SUPER_ADMIN_PERMISSION_KEYS = frozenset(
    {
        # 本人账号。
        PermissionKey.ACCOUNT_READ.value,  # 查看本人的账号信息和有效权限。
        PermissionKey.ACCOUNT_CHANGE_PASSWORD.value,  # 修改本人密码，仍需旧密码和验证码。
        # 权限目录。
        PermissionKey.PERMISSIONS_READ.value,  # 查看权限目录列表和详情。
        # 角色管理。
        PermissionKey.ROLES_READ.value,  # 查看角色列表、详情和已绑定权限。
        PermissionKey.ROLES_CREATE.value,  # 新建普通角色。
        PermissionKey.ROLES_UPDATE.value,  # 修改可管理角色的名称和说明。
        PermissionKey.ROLES_STATUS_UPDATE.value,  # 启用或禁用普通角色。
        PermissionKey.ROLES_DELETE.value,  # 软删除普通角色，系统角色不能删除。
        # 给用户绑定或解绑角色。
        PermissionKey.ROLES_BIND.value,  # 给可管理用户绑定已有角色。
        PermissionKey.ROLES_UNBIND.value,  # 解绑用户的指定角色，必备 user 角色不能解绑。
        # 给角色绑定或解绑权限。
        PermissionKey.ROLES_PERMISSIONS_BIND.value,  # 给可管理角色增加权限。
        PermissionKey.ROLES_PERMISSIONS_UNBIND.value,  # 从可管理角色解绑指定权限。
        # 用户管理。
        PermissionKey.USERS_READ.value,  # 查看用户列表、详情及其角色和权限。
        PermissionKey.USERS_CREATE.value,  # 新建用户，初始只绑定最低级 user 角色。
        PermissionKey.USERS_STATUS_UPDATE.value,  # 启用或禁用可管理用户。
        PermissionKey.USERS_PASSWORD_RESET.value,  # 管理员重置他人密码，仍需目标检查和验证码。
        PermissionKey.USERS_SESSIONS_REVOKE.value,  # 强制结束可管理用户的全部登录。
        PermissionKey.PROJECTS_READ.value,  # 仅维护示例：查询项目，默认项目不导出。
        PermissionKey.PROJECTS_UPDATE.value,  # 仅维护示例：修改项目，默认项目不导出。
    }
)
# 最低级 user 角色只提供本人账号基础权限，不包含用户、角色或权限管理能力。
USER_PERMISSION_KEYS = frozenset(
    {
        PermissionKey.ACCOUNT_READ.value,  # 查看本人的账号信息和有效权限。
        PermissionKey.ACCOUNT_CHANGE_PASSWORD.value,  # 修改本人密码，仍需旧密码和验证码。
    }
)

# 只预置超级管理员 1000 和普通用户 0；管理员需要另建普通角色，配置 1～999 的等级及权限。
# is_protected 控制在线管理保护，不等同于系统角色不可删除；后者由系统角色标识和业务规则控制。
SYSTEM_ROLE_SPECS: dict[SystemRoleKey, SystemRoleSpec] = {
    SystemRoleKey.SUPER_ADMIN: SystemRoleSpec(
        key=SystemRoleKey.SUPER_ADMIN,
        level=1000,
        is_protected=True,
        is_super_admin=True,
        permissions=SUPER_ADMIN_PERMISSION_KEYS,
    ),
    SystemRoleKey.USER: SystemRoleSpec(
        key=SystemRoleKey.USER,
        level=0,
        is_protected=False,
        is_super_admin=False,
        permissions=USER_PERMISSION_KEYS,
    ),
}
# 系统角色标识保留给固定角色；自定义角色校验复用同一集合，避免出现重名的“伪系统角色”。
SYSTEM_ROLE_KEYS = frozenset(item.value for item in SystemRoleKey)
# 自定义角色创建时使用的保留名称集合；与系统编码共用，避免维护两份名单。
RESERVED_ROLE_KEYS = SYSTEM_ROLE_KEYS
# 每个用户最多同时拥有 10 个有效角色，包含必备 user 角色；调整时需同步模型交接约束和测试。
MAX_ROLES_PER_USER = 10
