#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    注册、登录和本人改密的请求及令牌响应；共用校验和验证码模型分别由所属文件提供。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        管理员重置密码通过 JSON 请求体接收目标用户 ID
# 2026/09/23    XTN       V1.002        管理员用户请求归入 user 模块，保留身份与验证码的共用校验
# 2026/09/23    XTN       V1.003        补充密码类型、验证码业务和登录响应的逐字段说明
# 2026/09/23    XTN       V1.004        为身份、验证码和登录结果补齐接口文档可见的中文字段说明
# 2026/09/26    XTN       V1.005        统一临时密码请求和通用操作结果的业务命名
# 2026/09/29    XTN       V1.006        说明新密码仅允许可见 ASCII 字符
# 2026/09/30    XTN       V1.007        删除临时密码完成请求和登录改密标记
# 2026/10/02    XTN       V1.008        区分运行时校验、离线接口结构和令牌有效期说明
# 2026/10/04    XTN       V1.009        验证码申请只保留业务场景输入
# 2026/10/09    XTN       V1.010        验证码用途改用公共枚举，统一允许值来源
# 2026/10/09    XTN       V1.011        共用校验、验证码和管理员会话模型归回所属文件
# 2026/10/09    XTN       V1.012        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.013        登录响应继承统一响应基类，删除重复公共配置
# 2026/10/10    XTN       V1.014        新旧密码字段类型统一从 common 导入，不再分散定义
# 2026/10/10    XTN       V1.015        所有密码字段统一使用 Password 和 8～60 位长度边界
# 2026/10/13    XTN       V1.016        补齐字段校验函数的通俗说明和逻辑步骤
# 2026/10/14    XTN       V1.017        登录密码注释引用统一长度规则，避免重复固定数字
# 2026/10/20    XTN       V1.018        登录和当前密码不套用新密码策略，设置新密码使用 NewPassword
# --------------------------------------------------------------------------------------------------


from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from app.core.response import ResponseBase
from app.schemas.captcha import CaptchaAnswer
from app.schemas.common import NewPassword, Password, UsernameRequest


class RegisterRequest(UsernameRequest, CaptchaAnswer):
    """
        公开注册请求，要求用户名、密码及注册业务的一次性图形验证码。
    """

    # 自行注册设置的新密码；成功后只授予最低级 user 角色。
    password: NewPassword


class LoginRequest(UsernameRequest, CaptchaAnswer):
    """
        用户名密码登录请求，必须同时提交登录业务的一次性图形验证码。
    """

    # 只检查非空及传输长度；即使以后收紧新密码策略，原有密码仍按保存的哈希验证。
    password: Password


class PasswordChangeRequest(CaptchaAnswer):
    """
        本人修改密码请求，要求旧密码、新密码和本人改密业务的图形验证码。
    """

    # 本人当前密码，证明不是只有登录 Token 的他人在改密；按原文核对密码哈希。
    current_password: Password
    # 本人准备设置的新密码，不能与旧密码完全相同；业务层继续检查字符、弱密码及组合要求。
    new_password: NewPassword

    @model_validator(mode="after")
    def require_changed_password(self) -> Self:
        """
            拒绝将新密码设为与旧密码完全相同的值，不改变或裁剪密码内容。

        :return: 新旧密码不同的当前改密请求。
        :raises PydanticCustomError: 新密码与旧密码完全相同。
        """
        # 对比用户输入的密码原文；两次完全相同就不是改密，直接拒绝，不去改动密码内容。
        if (
            self.current_password.get_secret_value()
            == self.new_password.get_secret_value()
        ):
            raise PydanticCustomError("passwords_must_differ", "passwords_must_differ")
        return self


class AccessTokenResponse(ResponseBase):
    """
        正常登录成功的访问令牌、Bearer 类型及签发时设定的有效期，不含用户密码。
    """

    # Bearer 访问令牌只交给客户端保存，禁止写入日志。
    access_token: str = Field(
        min_length=1,
        repr=False,
        description="访问令牌；后续请求通过 Authorization: Bearer <token> 携带。",
    )
    token_type: Literal["bearer"] = Field(default="bearer", description="令牌类型，固定为 bearer。")
    # 默认期限由 JWT_ACCESS_TOKEN_TTL_SECONDS 配置；返回签发时的期限，不是实时倒计时。
    expires_in: int = Field(
        strict=True,
        ge=1,
        description="访问令牌签发时设定的有效期，单位秒；实际剩余时间会随时间减少。",
    )
