#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    接口公共定义：请求基类、业务 ID、用户名和密码字段类型，不查询数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/09    XTN       V1.001        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.002        解释请求基类的实际约束，通用操作响应统一继承响应基类
# 2026/10/10    XTN       V1.003        新旧密码字段类型集中定义，便于对照查找校验规则
# 2026/10/10    XTN       V1.004        密码统一使用 SecretStr 与 Field 长度约束，删除专用长度回调
# 2026/10/13    XTN       V1.005        补齐字段校验函数的通俗说明和逻辑步骤
# 2026/10/14    XTN       V1.006        密码字段说明直接读取共享长度常量，默认 8～32 位
# 2026/10/19    XTN       V1.007        合并用户、角色及权限 ID 校验类型，减少公共模型文件
# 2026/10/19    XTN       V1.008        删除仅返回 changed 的操作响应，空结果统一使用 data null
# 2026/10/20    XTN       V1.009        用户名校验不再重复传入字段名
# 2026/10/20    XTN       V1.010        登录和旧密码使用独立输入边界，新密码按当前策略检查长度
# 2026/11/26    XTN       V1.011        用户名字段引用统一规则和说明
# 2026/11/26    XTN       V1.012        用户名字段校验及共用入口统一用 validate 命名
# 2026/11/26    XTN       V1.013        密码字段直接引用统一规则及四类字符要求说明
# --------------------------------------------------------------------------------------------------


from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints, field_validator
from pydantic_core import PydanticCustomError

from app.core.ids import PERMISSION_ID_PATTERN, ROLE_ID_PATTERN, USER_ID_PATTERN
from app.core.security.password_rules import (
    MAX_PASSWORD_CHARACTERS,
    MAX_PASSWORD_INPUT_CHARACTERS,
    MIN_PASSWORD_CHARACTERS,
    NEW_PASSWORD_DESCRIPTION_ZH,
    PASSWORD_INPUT_DESCRIPTION_ZH,
)
from app.core.security.user_name import (
    MAX_USER_NAME_LENGTH,
    MIN_USER_NAME_LENGTH,
    USER_NAME_CHARACTERS_ZH,
    USER_NAME_PATTERN,
    validate_user_name,
)

# POST 请求、GET 查询和响应共用这些类型；长度和字符规则统一读取 core/ids.py。
# 这里只检查 ID 格式，不查询记录是否存在，也不判断当前用户有没有访问权限。
UserId = Annotated[str, StringConstraints(pattern=USER_ID_PATTERN)]  # 用户 ID，必须使用 U 前缀。
RoleId = Annotated[str, StringConstraints(pattern=ROLE_ID_PATTERN)]  # 角色 ID，必须使用 R 前缀。
PermissionId = Annotated[str, StringConstraints(pattern=PERMISSION_ID_PATTERN)]  # 权限 ID，必须使用 P 前缀。

# 登录和验证旧密码只检查输入非空及传输长度，不受以后调整的新密码策略影响。
# SecretStr 只隐藏默认展示，不等于可放心记录整个请求；日志仍禁止读取密码原文。
Password = Annotated[
    SecretStr,
    Field(
        min_length=1,
        max_length=MAX_PASSWORD_INPUT_CHARACTERS,
        description=PASSWORD_INPUT_DESCRIPTION_ZH,
    ),
]

# 注册、管理员创建、本人改密和管理员重置使用此类型；字符、弱密码及组合规则由业务层继续检查。
NewPassword = Annotated[
    SecretStr,
    Field(
        min_length=MIN_PASSWORD_CHARACTERS,
        max_length=MAX_PASSWORD_CHARACTERS,
        description=NEW_PASSWORD_DESCRIPTION_ZH,
    ),
]


class RequestBase(BaseModel):
    """
        接口请求的公共基类，拒绝未定义字段，并防止解析后重新给字段赋值。
        例如 body.user_name = "Bob" 会报错；字段中的列表仍可修改，不是深层冻结。
        此配置不负责加密或权限检查，敏感字段和具体业务仍需各自的安全校验。
    """

    # extra="forbid"：客户端多传一个未声明的字段就拒绝，避免拼错参数却被悄悄忽略。
    # frozen=True：解析完成后不能给字段重新赋值；不限制列表等字段内部内容的修改。
    model_config = ConfigDict(extra="forbid", frozen=True)


class UsernameRequest(RequestBase):
    """
        携带用户名的身份请求，统一应用空白清理、字符规则和保留名称检查。
    """

    # 用户名的长度、字符和保留名称统一在 core/security/user_name.py 维护。
    # 普通用户名是否区分大小写由生成项目时确认的身份规则决定，不能在此擅自全转小写。
    user_name: str = Field(
        min_length=MIN_USER_NAME_LENGTH,
        max_length=MAX_USER_NAME_LENGTH,
        pattern=USER_NAME_PATTERN,
        description=(
            f"先去掉首尾空白，再检查是否为 {MIN_USER_NAME_LENGTH}～{MAX_USER_NAME_LENGTH} 位{USER_NAME_CHARACTERS_ZH}；"
            "保留名称不区分大小写禁止使用，普通用户名是否区分大小写由项目的用户名规则决定。"
        ),
    )

    @field_validator("user_name", mode="before")
    @classmethod
    def validate_user_name(cls, value: object) -> object:
        """
            先去掉首尾空白再校验用户名，并为格式和保留名称错误提供稳定的可翻译类型。

        :param value: 请求提交的原始用户名，可能包含待清理的首尾空白。
        :return: 校验通过的规范化用户名；非字符串原样交给字段类型检查。
        :raises PydanticCustomError: 用户名格式不合法或命中禁止使用的保留名称。
        """
        # 1. 非文字值交给字段类型检查，不把数字等值偷偷转成用户名。
        if not isinstance(value, str):
            return value
        # 2. 按共用规则清理首尾空白并检查格式、保留名称，再返回规范化结果。
        try:
            return validate_user_name(value)
        except ValueError as exc:
            # 3. 把不同错误换成固定错误类型，统一异常处理器可以据此返回中文或英文提示。
            if str(exc) == "reserved_user_name":
                raise PydanticCustomError(
                    "username_reserved", "username_reserved"
                ) from exc
            raise PydanticCustomError("username_format", "username_format") from exc
