#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    集中定义权限标识、名称、分组和说明，展示文字从中英文目录读取。
#    只读取内存中的消息目录；未知业务权限沿用调用方提供的数据库说明。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        独立权限定义并按业务分组，支持中英文说明与业务文本回退
# 2026/09/30    XTN       V1.001        默认语言常量从语言协商模块导入
# 2026/10/13    XTN       V1.002        说明内置权限翻译与自定义权限回退的执行步骤
# 2026/10/24    XTN       V1.003        用户角色权限统一使用 bind 和 unbind，与接口动作对应
# 2026/10/26    XTN       V1.004        增加查看本人信息和修改本人密码的基础权限
# 2026/11/28    XTN       V1.005        权限目录统一维护名称和分组，保留说明及未知权限回退
# --------------------------------------------------------------------------------------------------


from dataclasses import dataclass
from enum import StrEnum

from app.core.i18n.language import DEFAULT_LOCALE
from app.core.i18n.messages import MessageKey, translate_for_locale


class PermissionKey(StrEnum):
    """
        统一定义可绑定到角色的权限标识，供接口校验和权限目录使用。
        值是稳定的资源与操作编码，不随展示语言变化；持有权限后仍须检查目标可见性和管理条件。
    """

    # 本人账号；不允许查看或修改其他用户。
    ACCOUNT_READ = "account:read"  # 查看当前登录用户自己的信息和有效权限。
    ACCOUNT_CHANGE_PASSWORD = "account:change_password"  # 验证旧密码后修改自己的密码。

    # 权限目录。
    PERMISSIONS_READ = "permissions:read"  # 查看权限目录列表和单项详情，不代表可以授予权限。

    # 角色管理。
    ROLES_READ = "roles:read"  # 查看可见角色的列表、详情及其已绑定权限。
    ROLES_CREATE = "roles:create"  # 创建普通自定义角色，不能创建或冒用固定系统角色。
    ROLES_UPDATE = "roles:update"  # 修改可管理角色的名称、说明，不改变角色等级或系统身份。
    ROLES_STATUS_UPDATE = "roles:status:update"  # 启用、禁用可管理的普通角色。
    ROLES_DELETE = "roles:delete"  # 软删除可管理的普通角色；固定系统角色不允许删除。
    ROLES_PERMISSIONS_BIND = "roles:permissions:bind"  # 给可管理角色增加权限，还须检查是否可授予该权限。
    ROLES_PERMISSIONS_UNBIND = "roles:permissions:unbind"  # 从可管理角色中解绑指定权限。

    # 用户角色绑定。
    ROLES_BIND = "roles:bind"  # 给可管理用户绑定已有角色，不是给角色绑定权限。
    ROLES_UNBIND = "roles:unbind"  # 解绑可管理用户的角色；不能移除必备的 user 角色。

    # 用户管理。
    USERS_READ = "users:read"  # 查看可见用户的身份、角色及有效权限。
    USERS_CREATE = "users:create"  # 管理员新增用户，新账号仍只获得最低级 user 角色。
    USERS_STATUS_UPDATE = "users:status:update"  # 启用、停用可管理用户；不能绕过目标等级保护。
    USERS_PASSWORD_RESET = "users:password:reset"  # 重置严格低于自身且可管理用户的密码。
    USERS_SESSIONS_REVOKE = "users:sessions:revoke"  # 管理员强制结束可管理用户的全部登录。

    # 仅维护示例：精简项目导出时移除，不自动引入项目业务模块。
    PROJECTS_READ = "projects:read"  # 完整参考资产中的项目查询权限。
    PROJECTS_UPDATE = "projects:update"  # 完整参考资产中的项目修改权限。


class PermissionGroup(StrEnum):
    """
        权限页面的业务分组；分组只用于展示，不授予任何权限。
    """

    ACCOUNT = "account"  # 查看本人信息和修改本人密码。
    USERS = "users"  # 查询和管理其他用户。
    ROLES = "roles"  # 管理角色定义以及角色的权限。
    USER_ROLES = "user_roles"  # 给用户分配或移除角色。
    PERMISSIONS = "permissions"  # 查看权限目录。
    PROJECTS = "projects"  # 仅维护示例的展示分组，不授予权限。
    OTHER = "other"  # 数据库存在但代码目录尚未登记的业务权限。


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    """
        一项权限的展示定义；名称和说明保存翻译键，实际文案由请求语言决定。
    """

    name: MessageKey  # 简短权限名称，例如“查询用户”。
    group_key: PermissionGroup  # 明确所属业务分组，不根据权限前缀猜测。
    description: MessageKey  # 详细说明这项权限允许做什么。


# 分组标识固定，分组名称跟随响应语言；新增分组在这里补齐展示名称。
PERMISSION_GROUP_NAMES: dict[PermissionGroup, MessageKey] = {
    PermissionGroup.ACCOUNT: MessageKey.PERMISSION_GROUP_ACCOUNT,
    PermissionGroup.USERS: MessageKey.PERMISSION_GROUP_USERS,
    PermissionGroup.ROLES: MessageKey.PERMISSION_GROUP_ROLES,
    PermissionGroup.USER_ROLES: MessageKey.PERMISSION_GROUP_USER_ROLES,
    PermissionGroup.PERMISSIONS: MessageKey.PERMISSION_GROUP_PERMISSIONS,
    PermissionGroup.PROJECTS: MessageKey.PERMISSION_GROUP_PROJECTS,
    PermissionGroup.OTHER: MessageKey.PERMISSION_GROUP_OTHER,
}

# 每项权限的展示信息只在这份目录登记；数据库中的权限记录和角色授权仍由项目所有者准备。
PERMISSION_CATALOG: dict[PermissionKey, PermissionSpec] = {
    # 本人账号。
    PermissionKey.ACCOUNT_READ: PermissionSpec(
        name=MessageKey.PERMISSION_ACCOUNT_READ_NAME,
        group_key=PermissionGroup.ACCOUNT,
        description=MessageKey.PERMISSION_ACCOUNT_READ,
    ),
    PermissionKey.ACCOUNT_CHANGE_PASSWORD: PermissionSpec(
        name=MessageKey.PERMISSION_ACCOUNT_CHANGE_PASSWORD_NAME,
        group_key=PermissionGroup.ACCOUNT,
        description=MessageKey.PERMISSION_ACCOUNT_CHANGE_PASSWORD,
    ),
    # 权限目录。
    PermissionKey.PERMISSIONS_READ: PermissionSpec(
        name=MessageKey.PERMISSION_PERMISSIONS_READ_NAME,
        group_key=PermissionGroup.PERMISSIONS,
        description=MessageKey.PERMISSION_PERMISSIONS_READ,
    ),
    # 角色管理。
    PermissionKey.ROLES_READ: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_READ_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_READ,
    ),
    PermissionKey.ROLES_CREATE: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_CREATE_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_CREATE,
    ),
    PermissionKey.ROLES_UPDATE: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_UPDATE_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_UPDATE,
    ),
    PermissionKey.ROLES_STATUS_UPDATE: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_STATUS_UPDATE_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_STATUS_UPDATE,
    ),
    PermissionKey.ROLES_DELETE: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_DELETE_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_DELETE,
    ),
    PermissionKey.ROLES_PERMISSIONS_BIND: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_PERMISSIONS_BIND_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_PERMISSIONS_BIND,
    ),
    PermissionKey.ROLES_PERMISSIONS_UNBIND: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_PERMISSIONS_UNBIND_NAME,
        group_key=PermissionGroup.ROLES,
        description=MessageKey.PERMISSION_ROLES_PERMISSIONS_UNBIND,
    ),
    # 用户角色绑定。
    PermissionKey.ROLES_BIND: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_BIND_NAME,
        group_key=PermissionGroup.USER_ROLES,
        description=MessageKey.PERMISSION_ROLES_BIND,
    ),
    PermissionKey.ROLES_UNBIND: PermissionSpec(
        name=MessageKey.PERMISSION_ROLES_UNBIND_NAME,
        group_key=PermissionGroup.USER_ROLES,
        description=MessageKey.PERMISSION_ROLES_UNBIND,
    ),
    # 用户管理。
    PermissionKey.USERS_READ: PermissionSpec(
        name=MessageKey.PERMISSION_USERS_READ_NAME,
        group_key=PermissionGroup.USERS,
        description=MessageKey.PERMISSION_USERS_READ,
    ),
    PermissionKey.USERS_CREATE: PermissionSpec(
        name=MessageKey.PERMISSION_USERS_CREATE_NAME,
        group_key=PermissionGroup.USERS,
        description=MessageKey.PERMISSION_USERS_CREATE,
    ),
    PermissionKey.USERS_STATUS_UPDATE: PermissionSpec(
        name=MessageKey.PERMISSION_USERS_STATUS_UPDATE_NAME,
        group_key=PermissionGroup.USERS,
        description=MessageKey.PERMISSION_USERS_STATUS_UPDATE,
    ),
    PermissionKey.USERS_PASSWORD_RESET: PermissionSpec(
        name=MessageKey.PERMISSION_USERS_PASSWORD_RESET_NAME,
        group_key=PermissionGroup.USERS,
        description=MessageKey.PERMISSION_USERS_PASSWORD_RESET,
    ),
    PermissionKey.USERS_SESSIONS_REVOKE: PermissionSpec(
        name=MessageKey.PERMISSION_USERS_SESSIONS_REVOKE_NAME,
        group_key=PermissionGroup.USERS,
        description=MessageKey.PERMISSION_USERS_SESSIONS_REVOKE,
    ),
    # 仅维护示例。
    PermissionKey.PROJECTS_READ: PermissionSpec(
        name=MessageKey.PERMISSION_PROJECTS_READ_NAME,
        group_key=PermissionGroup.PROJECTS,
        description=MessageKey.PERMISSION_PROJECTS_READ,
    ),
    PermissionKey.PROJECTS_UPDATE: PermissionSpec(
        name=MessageKey.PERMISSION_PROJECTS_UPDATE_NAME,
        group_key=PermissionGroup.PROJECTS,
        description=MessageKey.PERMISSION_PROJECTS_UPDATE,
    ),
}


def get_permission_description(permission_key: str, *,
                               stored_description: str = "",
                               locale: str = DEFAULT_LOCALE
                               ) -> str:
    """
        将稳定权限值解析为指定语言的展示说明，不读取数据库或执行其他 I/O。
        已知权限使用内存消息目录；未知业务权限原样保留调用方提供的数据库说明。

    :param permission_key: 用于授权和存储的稳定权限值，例如 permissions:read，不随语言变化。
    :param stored_description: 数据库已保存的业务说明，仅在权限值不属于内置目录时作为回退文本。
    :param locale: 展示语言，使用 zh-CN 或 en；默认中文，不支持的语言通过共享翻译逻辑回退为中文。
    :return: 已知权限的本地化说明；未知业务权限返回原有说明，包括空字符串。
    """
    # 先识别内置权限；项目自行新增的权限没有翻译目录时，原样保留数据库里的说明。
    try:
        key = PermissionKey(permission_key)
    except ValueError:
        return stored_description
    # 内置权限按展示语言取消息，不支持的语言由翻译函数回退到中文。
    return translate_for_locale(locale, PERMISSION_CATALOG[key].description)
