#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户管理请求、身份与角色权限响应；复用身份字段校验，不查询数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        增加 JSON 目标标识，清理无调用的旧权限替换请求
# 2026/09/23    XTN       V1.002        合并 access 与 authentication 中属于管理员用户业务的数据格式
# 2026/09/23    XTN       V1.003        说明用户输入、可见角色与有效权限字段
# 2026/09/23    XTN       V1.004        为用户管理与当前权限的接口文档补齐中文字段说明
# 2026/09/26    XTN       V1.005        统一用户请求与权限结果命名并归入用户创建结果
# 2026/09/30    XTN       V1.006        管理员新增账号直接接收可登录密码
# 2026/10/02    XTN       V1.007        管理员请求字段先列目标用户再列本次提交内容
# 2026/10/09    XTN       V1.008        共用校验从所属模块导入，管理员会话结果归用户模型
# 2026/10/09    XTN       V1.009        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.010        用户请求与响应统一继承公共基类，删除重复公共配置
# 2026/10/10    XTN       V1.011        统一用户 ID 与当前用户命名
# 2026/10/10    XTN       V1.012        管理员新增与重置共用统一 Password 字段类型
# 2026/10/13    XTN       V1.013        补齐字段校验函数的通俗说明和逻辑步骤
# 2026/10/15    XTN       V1.014        用户响应移除权限版本字段，保留实际权限和全局变更记录
# 2026/10/15    XTN       V1.015        已绑定角色字段统一为 bound_role_ids，与绑定记录用词一致
# 2026/10/16    XTN       V1.016        本人权限响应只保留身份、管理等级及实时权限
# 2026/10/19    XTN       V1.017        业务 ID 校验类型统一从公共模型导入
# 2026/10/19    XTN       V1.018        用户角色操作只返回最终信息，不返回内部变更标记
# 2026/10/20    XTN       V1.019        管理员创建和重置密码按 NewPassword 检查当前策略长度
# 2026/10/20    XTN       V1.020        用户详情与本人权限统一返回 role_level
# 2026/10/24    XTN       V1.021        用户角色操作响应简化命名为 UserRoleResponse
# --------------------------------------------------------------------------------------------------


from pydantic import Field, field_validator
from pydantic_core import PydanticCustomError

from app.core.access.roles import MAX_ROLES_PER_USER
from app.core.response import ResponseBase
from app.schemas.captcha import CaptchaAnswer
from app.schemas.common import NewPassword, RequestBase, RoleId, UserId, UsernameRequest


class UserCreateRequest(UsernameRequest, CaptchaAnswer):
    """
        管理员创建用户的请求，包含用户名、初始密码和新增用户业务验证码。
    """

    # 管理员设置可直接登录的初始密码；私下交付用户，不在响应中回显。
    # 用户名来自 UsernameRequest，新增业务验证码来自 CaptchaAnswer；不能提交初始管理员角色。
    password: NewPassword


class UserPasswordResetRequest(CaptchaAnswer):
    """
        管理员重置密码的 HTTP 请求体，合并目标用户 ID、新密码和验证码。
    """

    user_id: UserId = Field(description="被重置密码的用户 ID，不是当前操作者 ID。")
    new_password: NewPassword  # 管理员设置的新密码；成功后用户可直接使用它登录。


class UserRoleIdsRequest(RequestBase):
    """
        用户角色绑定或解绑的 HTTP 请求体，不从 URL 获取目标用户。
    """

    user_id: UserId = Field(description="接受角色变更的用户 ID，仍须满足当前操作者的可管理范围。")
    # 本次要绑定或解绑的角色 ID；用户最终最多 10 个有效绑定还由业务层校验，不只看本次列表。
    role_ids: list[RoleId] = Field(
        min_length=1,
        max_length=MAX_ROLES_PER_USER,
        description="本次绑定或解绑的角色 ID，1～10 项且不能重复；用户最终最多保留 10 个有效角色绑定。",
    )

    @field_validator("role_ids")
    @classmethod
    def unique_role_ids(cls, value: list[str]) -> list[str]:
        """
            拒绝角色 ID 列表中的重复项，避免同一请求重复描述一条绑定关系。

        :param value: 已完成角色 ID 格式及数量检查的角色 ID 列表。
        :return: 不含重复项的原角色 ID 列表。
        :raises PydanticCustomError: 列表中存在重复角色 ID。
        """
        # set 会合并重复 ID；合并后数量变少，说明请求把同一个角色写了多次，直接拒绝。
        if len(value) != len(set(value)):
            raise PydanticCustomError("role_ids_unique", "role_ids_unique")
        return value


class UserTargetRequest(RequestBase):
    """
        用户启停和强制退出登录的 HTTP 请求体，仅接收目标用户 ID。
    """

    user_id: UserId = Field(description="被管理员操作的用户 ID；具体操作由接口决定，仍须满足可管理范围。")


class UserCreatedResponse(ResponseBase):
    """
        用户创建成功后的用户 ID，不包含密码或自动提升的角色信息。
    """

    user_id: UserId = Field(description="本次创建成功的用户 ID；管理员新增用户时，此值不是操作者 ID。")


class ActiveSessionsResponse(ResponseBase):
    """
        当前有效登录会话数量及各次登录时间，不表示物理设备数量。
    """

    active_count: int = Field(
        ge=0,
        description="当前有效登录会话数；0 表示没有有效会话，不是累计登录次数或物理设备数。",
    )
    login_times: tuple[str, ...] = Field(
        description="当前各有效会话的 UTC ISO 8601 登录时间；不包含已到期或已撤销的历史登录。",
    )


class UserResponse(ResponseBase):
    """
        按操作者可见范围返回的用户身份、角色绑定和当前有效权限。
    """

    user_id: UserId = Field(description="目标用户的业务 ID。")
    user_name: str = Field(description="登录用户名，大小写按项目的用户名规则处理。")
    is_active: bool = Field(description="账号是否启用；false 表示停用，不表示账号已删除。")
    # 可见且尚未解绑的角色 ID，包含已停用角色，方便管理员看清已有绑定。
    bound_role_ids: tuple[RoleId, ...] = Field(
        description="当前操作者可见且尚未解绑的角色 ID，包含可见的已停用角色。",
    )
    # 上述绑定中仍启用、实际贡献权限的可见角色 ID，可能比 bound_role_ids 少。
    effective_role_ids: tuple[RoleId, ...] = Field(
        description="已有绑定中仍启用并提供当前权限的可见角色 ID；可能少于 bound_role_ids。",
    )
    # 用户有效角色中的最高等级；没有有效角色时是 0。
    role_level: int = Field(
        description="当前用户所有有效角色中的最高等级；数字越大等级越高，没有有效角色时为 0。",
    )
    # 只合并有效角色的权限键，停用角色不会继续提供权限。
    effective_permissions: tuple[str, ...] = Field(description="有效角色提供的权限键并集；已停用角色不提供有效权限。")


class UserRoleResponse(ResponseBase):
    """
        绑定或解绑角色后的用户信息。
    """

    user: UserResponse = Field(description="操作后的用户信息，包含当前操作者有权查看的角色和权限。")


class UserAccessResponse(ResponseBase):
    """
        当前用户的 ID、角色等级和有效权限。
    """

    user_id: UserId = Field(description="当前已登录用户的 ID。")
    role_level: int = Field(
        description="当前用户所有有效角色中的最高等级；数字越大等级越高，没有有效角色时为 0。",
    )
    permissions: list[str] = Field(
        description="有效角色提供的权限键并集；前端可用于显示按钮，服务端仍独立检查每次请求。",
    )
