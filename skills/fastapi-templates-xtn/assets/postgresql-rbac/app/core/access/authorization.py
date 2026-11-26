#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    定义只读的登录信息、用户角色权限信息和请求授权上下文。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        逐项说明权限能力、系统角色和授权快照字段
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.003        准确说明权限变更版本号的用途和一致性边界
# 2026/09/29    XTN       V1.004        将权限目录与系统角色迁至独立业务模块，保留身份与授权快照
# 2026/10/04    XTN       V1.005        对齐 JTI 与 JWT 声明使用的 UUID 类型
# 2026/10/13    XTN       V1.006        补充角色预测快照和权限读取的通俗步骤说明
# 2026/10/15    XTN       V1.007        权限快照移除用户权限版本，保留实时角色和登录版本
# 2026/10/16    XTN       V1.008        请求 ID 由审计自动读取，授权上下文只保存身份权限及来源
# 2026/10/16    XTN       V1.009        授权上下文移除不参与权限判断的全局版本标记
# 2026/10/20    XTN       V1.010        角色等级使用 level，用户最高角色等级使用 role_level
# 2026/10/20    XTN       V1.011        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/24    XTN       V1.012        当前用户账号及角色权限信息统一使用 user_info 字段
# 2026/10/26    XTN       V1.013        用户角色权限信息类型统一命名为 UserInfo
# --------------------------------------------------------------------------------------------------


import uuid
from dataclasses import dataclass

from app.core.audit import AuditSource


@dataclass(frozen=True, slots=True)
class LoginInfo:
    """
        保存本次已经验证的登录信息；Token 和 Redis 登录有效，不代表数据库账号已检查。
        这里只记录用户 ID、Token 编号、登录版本和有效期，不包含角色权限。
    """

    user_id: str  # 当前登录用户 ID，对应 JWT 的 user_id，不是操作者输入的目标用户 ID。
    token_version: int  # Redis 登录记录绑定的用户登录版本；与数据库不一致则该登录失效。
    token_id: uuid.UUID  # 本次登录的 JTI，须命中 Redis 活跃记录；不能记录到日志或公开返回。
    issued_at: int  # JWT 签发时间，UTC Unix 整数秒。
    expires_at: int  # JWT 到期时间，UTC Unix 整数秒。


@dataclass(frozen=True, slots=True)
class RoleGrant:
    """
        保存一个有效角色对用户提供的等级、权限与保护状态。
    """

    role_id: str  # 提供此次授权的角色 ID，对应 roles.id，不是绑定关系 ID。
    key: str  # 稳定角色编码，例如 admin；识别系统身份时与固定标志共同校验。
    level: int  # 当前角色的等级；用户绑定多个有效角色时，取最高值作为用户的 role_level。
    permissions: frozenset[str]  # 当前角色有效权限键集合，不含软删除的权限或已解绑关系。
    is_system: bool  # True 表示固定系统角色，不能按普通自定义角色停用或删除。
    is_protected: bool  # True 表示角色受在线管理保护，并影响绑定用户的整体保护状态。
    is_super_admin: bool  # True 表示这一角色提供唯一超级管理员身份。


@dataclass(frozen=True, slots=True)
class UserInfo:
    """
        保存用户状态、角色、最高角色等级、权限和保护信息，构建后不能修改。
        按传入角色计算：鉴权使用启用角色，管理保护判断还会包含停用角色。
        不包含密码哈希，不是数据库用户对象，也不是直接返回客户端的响应模型。
    """

    user_id: str  # 这份信息所属用户 ID，可代表当前操作者或待比较的目标用户。
    user_is_active: bool  # 用户账号本身是否启用；False 时不能正常使用业务接口。
    user_is_protected: bool  # 用户账号自身的在线管理保护标志，尚未合并角色保护。
    token_version: int  # 数据库中的登录撤销版本，用于核对登录是否仍有效，不表示权限等级。
    roles: tuple[RoleGrant, ...]  # 本次参与计算的角色；鉴权只含启用角色，管理保护判断可含停用角色。
    permissions: frozenset[str]  # 上述角色权限的并集；包含停用角色的结果不能用于授予接口权限。
    role_level: int  # 上述角色中的最高等级；没有角色时为 0。
    is_protected: bool  # 账号本身或上述任一角色受保护时为 True。
    is_super_admin: bool  # 上述任一角色提供超级管理员身份时为 True，仍须通过身份有效性校验。

    @classmethod
    def build(cls, *, user_id: str,
              user_is_active: bool,
              user_is_protected: bool,
              token_version: int = 0,
              roles: tuple[RoleGrant, ...]
              ) -> "UserInfo":
        """
            合并传入角色的权限并计算最高等级，得到一份只读用户信息。

        :param user_id: 这份信息所属用户的唯一 ID。
        :param user_is_active: 用户当前是否允许使用业务功能。
        :param user_is_protected: 用户自身是否受保护、禁止在线管理。
        :param token_version: 用户当前的令牌版本，用于识别已撤销的登录。
        :param roles: 已读取的角色；鉴权传启用角色，管理保护判断可同时传入停用角色。
        :return: 包含用户状态、角色、权限并集、最高等级及保护状态的只读信息。
        """
        # 1. 把传入角色的权限合在一起并去重，一个低等级角色也可能提供独有权限。
        permissions = frozenset(
            permission for role in roles for permission in role.permissions
        )
        # 2. 固定角色顺序，并汇总最高等级、任一保护标志和超级管理员身份；不写数据库。
        return cls(
            user_id=user_id,
            user_is_active=user_is_active,
            user_is_protected=user_is_protected,
            token_version=token_version,
            roles=tuple(sorted(roles, key=lambda role: str(role.role_id))),
            permissions=permissions,
            role_level=max((role.level for role in roles), default=0),
            is_protected=(
                user_is_protected or any(role.is_protected for role in roles)
            ),
            is_super_admin=any(role.is_super_admin for role in roles),
        )

    def with_role(self, role: RoleGrant) -> "UserInfo":
        """
            生成绑定角色后的预测快照，同 ID 的角色授权会被新值替换。

        :param role: 要新增或替换的角色授权。
        :return: 重新汇总权限后的新快照，不写数据库且不修改当前对象。
        """
        # 按角色 ID 替换或加入授权，再重算整体权限；这是预演结果，不是真正绑定角色。
        roles = {item.role_id: item for item in self.roles}
        roles[role.role_id] = role
        return self._replace_roles(tuple(roles.values()))

    def without_role(self, role_id: str) -> "UserInfo":
        """
            生成解绑指定角色后的预测快照，不存在该角色时保留其余授权。

        :param role_id: 要从当前快照中移除的角色 ID。
        :return: 不含该角色、已重新汇总权限的新快照。
        """
        # 过滤掉目标角色再重算整体权限，角色原本不存在时结果中的授权不变。
        return self._replace_roles(
            tuple(role for role in self.roles if role.role_id != role_id)
        )

    def _replace_roles(self, roles: tuple[RoleGrant, ...]) -> "UserInfo":
        """
            保留用户状态及登录撤销版本，仅根据新的角色集合重新计算授权属性。

        :param roles: 替换原集合后的全部角色授权。
        :return: 用户身份不变、角色及派生权限已更新的新快照。
        """
        # 用户启用状态和登录撤销版本沿用原值，只让新角色集合重新决定权限、等级和保护状态。
        return self.build(
            user_id=self.user_id,
            user_is_active=self.user_is_active,
            user_is_protected=self.user_is_protected,
            token_version=self.token_version,
            roles=roles,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """
        保存本次登录信息、数据库中的当前用户信息和审计来源。
    """

    login_info: LoginInfo  # 本次已验证的 Token 登录信息。
    user_info: UserInfo  # 数据库中当前用户的账号状态、有效角色、角色等级及权限。
    audit_source: AuditSource = AuditSource.SERVICE  # 事件入口；服务调用默认 service，HTTP 入口显式指定 http。

    @property
    def permissions(self) -> frozenset[str]:
        """
            读取本次查到的当前用户权限。

        :return: 当前快照的不可变权限标识集合，不进行额外数据库查询。
        """
        # 直接读取本次已保存的权限集合；这里不会向数据库确认是否刚发生了权限变更。
        return self.user_info.permissions
