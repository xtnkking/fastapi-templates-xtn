#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    图形验证码申请、答案和图片响应模型，共用统一用途枚举和请求基类。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/09    XTN       V1.001        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.002        验证码响应继承统一响应基类，删除重复公共配置
# --------------------------------------------------------------------------------------------------


import uuid
from typing import Literal

from pydantic import Field

from app.core.captcha import CaptchaScene
from app.core.response import ResponseBase
from app.schemas.common import RequestBase


class CaptchaAnswer(RequestBase):
    """
        图形验证码答案，验证码所属业务及用户绑定由后续业务校验确认。
    """

    captcha_id: uuid.UUID = Field(description="申请当前业务验证码时返回的标识，与 captcha_answer 一起提交。")
    # 答案仅供本次校验使用，不得写入日志或审计；校验成功或失败都会消耗该验证码。
    captcha_answer: str = Field(
        min_length=1,
        max_length=16,
        description="根据图片输入的验证码答案；每张验证码只能尝试一次。",
    )


class CaptchaCreateRequest(RequestBase):
    """
        按固定业务申请一张新的图形验证码。
    """

    # 允许值由 core/captcha.py 的枚举统一定义；Pydantic 会拒绝未登记的用途。
    # 登录要求也在该文件维护；公开验证码不绑定 IP，IP 仅用于获取频率限制。
    scene: CaptchaScene = Field(
        description="验证码使用用途；允许值由 CaptchaScene 定义，不同用途不能混用，登录后用途还绑定当前用户。",
    )


class CaptchaResponse(ResponseBase):
    """
        返回图形验证码标识、Base64 图片和 300 秒有效期，不包含答案。
    """

    captcha_id: uuid.UUID = Field(description="本张验证码的标识；提交答案时原样带回。")
    image_base64: str = Field(description="验证码图片的 Base64 编码，供页面展示，不是答案文本。")
    expires_in: Literal[300] = Field(
        default=300,
        description="有效期，单位为秒；固定为 300 秒，即 5 分钟，一次尝试后即消耗。",
    )
