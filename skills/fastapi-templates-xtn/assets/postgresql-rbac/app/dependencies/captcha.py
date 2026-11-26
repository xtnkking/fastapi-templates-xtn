#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    图形验证码校验依赖；只读取验证码参数和已验证的当前用户，再调用验证码服务。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        补充 JSON 请求体预检与正式参数校验之间的边界
# 2026/09/26    XTN       V2.000        合并验证码请求适配，避免两个近义依赖文件
# 2026/09/26    XTN       V2.001        统一 HTTP 限流辅助及应用配置依赖名称
# 2026/09/27    XTN       V3.000        分离验证码与限流职责并明确一次性校验命名
# 2026/09/29    XTN       V3.001        将登录后验证码参数预检并入专用认证依赖
# 2026/10/04    XTN       V3.002        说明验证码拒绝额度的实际触发位置
# 2026/10/04    XTN       V3.003        签发入口不再传递上一张验证码标识
# 2026/10/09    XTN       V3.004        请求枚举以原有字符串值传入验证码服务
# 2026/10/09    XTN       V3.005        验证码请求和响应从所属模型模块导入
# 2026/10/09    XTN       V3.006        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V3.007        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/09    XTN       V3.008        调用共享验证码服务并明确一次性删除与答案比较的职责
# 2026/10/10    XTN       V3.009        删除验证码响应转发，签发归 Service、完整响应归路由
# 2026/10/12    XTN       V3.010        五种敏感操作统一通过显式依赖校验验证码
# 2026/10/12    XTN       V3.011        移除业务限流权限调度及完整请求重复校验
# 2026/10/12    XTN       V3.012        直接提取验证码字段并统一使用 user_id
# 2026/10/13    XTN       V3.013        通俗说明字段读取及验证码依赖创建和调用时机
# 2026/10/14    XTN       V3.014        将路由固定用途枚举直接传给验证码 Service
# 2026/10/16    XTN       V3.015        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/19    XTN       V3.016        精简验证码依赖注释，保留身份和一次性校验步骤
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Awaitable, Callable
from json import JSONDecodeError

from fastapi import Request

from app.core.captcha import CaptchaScene
from app.core.exceptions import invalid_request_400, unauthenticated_401
from app.db.redis_db import get_redis
from app.dependencies.auth import AppSettings
from app.services.captcha_service import captcha_service


def read_body_field(body: dict[str, object], field_name: str) -> str:
    """
        从请求体读取一个必填文字字段，保留用户输入的原文。

    :param body: 当前请求的 JSON 字典，只读取验证码需要的字段。
    :param field_name: 要读取的字段名，例如 captcha_id 或 captcha_answer。
    :return: 字段原文；缺失、不是文字或只有空白时报参数错误。
    """
    # 拒绝空内容和非文字，不自动转换或裁剪输入。
    value = body.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise invalid_request_400("captcha_parameter_missing_or_invalid")
    return value


def require_captcha(scene: CaptchaScene) -> Callable[..., Awaitable[None]]:
    """
        为指定业务创建验证码检查依赖。
        路由需先声明限流或身份权限依赖，这里只校验验证码。

    :param scene: 路由写定的验证码用途，不能由客户端更换。
    :return: 验证码校验依赖；验证失败时阻止执行路由中的业务代码。
    """
    # 路由加载时只创建检查函数，请求到来后才校验验证码。
    async def check_captcha(request: Request, settings: AppSettings) -> None:
        """
            校验提交的验证码是否符合本接口的用途和当前用户。

        :param request: 当前请求，用来读取验证码字段和 Redis 客户端。
        :param settings: 当前应用的验证码校验配置。
        :return: 通过时返回 None；身份、参数或验证码不符时阻止业务执行。
        """
        # 1. 需要登录的用途，只认前面认证依赖确认的用户 ID，不认请求体里的用户 ID。
        user_id = None
        if scene.requires_login:
            user_id = getattr(request.state, "user_id", None)
            if not isinstance(user_id, str) or not user_id:
                raise unauthenticated_401("missing_captcha_user")

        # 2. 只读取验证码 ID 和答案；其他字段交给路由模型校验。
        try:
            body = await request.json()
        except JSONDecodeError as exc:
            raise invalid_request_400("invalid_json_body") from exc
        if not isinstance(body, dict):
            raise invalid_request_400("invalid_json_body")

        captcha_id_text = read_body_field(body, "captcha_id")
        captcha_answer = read_body_field(body, "captcha_answer")
        try:
            captcha_id = uuid.UUID(captcha_id_text)
        except ValueError as exc:
            raise invalid_request_400("invalid_captcha_id") from exc
        # 与请求模型一致：验证码答案最多 16 个字符，超长输入不访问 Redis。
        if len(captcha_answer) > 16:
            raise invalid_request_400("invalid_captcha_answer")

        # 3. Service 先取出并删除验证码，再校验用途、用户和答案；答对答错都只能用一次。
        # 登录、注册不绑定用户或 IP，所以 user_id 为 None。
        await captcha_service.verify_captcha(
            redis=get_redis(request),
            settings=settings,
            captcha_id=captcha_id,
            answer=captcha_answer,
            scene=scene,
            user_id=user_id,
        )

    # 交给 Depends，排在路由的限流或认证依赖之后执行。
    return check_captcha
