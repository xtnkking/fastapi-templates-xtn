#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    登录注册、公开验证码及当前登录退出接口。
# History:
# Date          Author    Version       Modification
# 2026/10/19    XTN       V4.022        直接导入共享业务服务，删除仅返回实例的依赖入口
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        归并匿名验证码、临时密码完成和当前登录退出，统一认证业务分组
# 2026/09/23    XTN       V1.002        明确业务服务入口，版本前缀交由总路由装配
# 2026/09/23    XTN       V1.003        明确匿名、超级管理员及当前登录的访问条件和验证码顺序
# 2026/09/23    XTN       V1.004        逐项对齐接口参数和业务调用，便于阅读实际执行顺序
# 2026/09/26    XTN       V2.000        统一 auth 命名并展开限流、验证码和认证的执行顺序
# 2026/09/26    XTN       V2.001        统一请求结果名称并保持各接口限流文档准确
# 2026/09/26    XTN       V2.002        使公开操作 ID 与简洁的路由函数名保持一致
# 2026/09/27    XTN       V2.003        分行说明访问权限并解释路由装饰器参数
# 2026/09/27    XTN       V2.004        接入必执行限流服务、路由额度声明和验证码消费职责
# 2026/09/29    XTN       V3.000        简化路由装饰器并由认证权限依赖自动选择限流额度
# 2026/09/29    XTN       V3.001        直接使用 JWT 身份类型及 Redis 会话签发、撤销模块
# 2026/09/29    XTN       V3.002        删除路由级缓存响应头与无用响应参数
# 2026/09/30    XTN       V3.003        移除公开注册开关接口，保留自行注册
# 2026/09/30    XTN       V3.004        删除临时密码完成接口与登录改密分支
# 2026/10/02    XTN       V3.005        解释公开验证码预检依赖在请求处理前执行的原因
# 2026/10/02    XTN       V3.006        修正过时的第一版说明并展开登录响应字段
# 2026/10/02    XTN       V3.007        将登录响应说明对齐签发时配置的有效期
# 2026/10/04    XTN       V3.008        公开验证码限流由一个依赖统一完成，路由只处理签发
# 2026/10/04    XTN       V3.009        公开验证码申请只需提交业务场景
# 2026/10/08    XTN       V3.010        注册接口调用名称统一为 check_register
# 2026/10/08    XTN       V3.011        可信 IP 从限流请求依赖读取
# 2026/10/08    XTN       V4.000        注册登录和公开验证码在路由显式注入限流
# 2026/10/09    XTN       V4.001        验证码接口和业务校验共同引用统一用途枚举
# 2026/10/09    XTN       V4.002        认证、验证码和共用结果从各自模型文件导入
# 2026/10/09    XTN       V4.003        退出路由通过专用身份依赖统一完成认证与限流
# 2026/10/09    XTN       V4.004        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V4.005        注册成功响应引用统一的 register 文案成员名称
# 2026/10/09    XTN       V4.006        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V4.007        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/10    XTN       V4.008        验证码直接调用 Service，完整响应在路由组装
# 2026/10/12    XTN       V4.009        登录注册显式注入验证码校验依赖
# 2026/10/12    XTN       V4.010        验证码签发统一使用 user_id 参数
# 2026/10/13    XTN       V4.011        补齐接口业务执行与成功响应的通俗步骤
# 2026/10/13    XTN       V4.012        当前登录撤销不再传入服务与环境配置
# 2026/10/14    XTN       V4.013        公开验证码直接向 Service 传递用途枚举
# 2026/10/14    XTN       V4.014        为文件请求日志记录认证动作、完成结果与新建用户目标
# 2026/10/15    XTN       V4.015        移除路由重复的日志动作和结果赋值，保留操作人与目标信息
# 2026/10/15    XTN       V4.016        注册目标由统一日志入口提取，删除路由重复赋值
# 2026/10/16    XTN       V4.017        注册只传业务参数，请求 ID 由审计自动获取
# 2026/10/16    XTN       V4.018        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V4.019        登录路由调用统一的 login 业务方法
# 2026/10/16    XTN       V4.020        完整登录交给认证服务，路由只传参并组装成功响应
# 2026/10/16    XTN       V4.021        登录用户日志由请求上下文统一记录，删除路由赋值
# 2026/10/19    XTN       V4.023        按验证码、注册、登录、退出登录排列接口
# 2026/10/19    XTN       V4.024        退出登录只返回成功提示，data 为 null
# 2026/10/20    XTN       V4.025        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/20    XTN       V4.026        退出登录的 Token 内容统一使用 token_info 名称
# 2026/10/20    XTN       V4.027        退出登录调用直观的登录记录删除入口
# 2026/10/22    XTN       V4.028        退出直接验证登录后撤销当前会话，不执行专用限流
# 2026/10/22    XTN       V4.029        退出直接使用 check_token 验证当前登录凭证
# 2026/10/23    XTN       V4.030        退出登录通过 Redis 登录仓储删除记录
# --------------------------------------------------------------------------------------------------


from fastapi import APIRouter, Depends, Request, status

from app.core.access.authorization import LoginInfo
from app.core.captcha import PUBLIC_CAPTCHA_SCENES, CaptchaScene
from app.core.codes import BusinessCode
from app.core.exceptions import invalid_request_400
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, api_response
from app.core.security.jwt_tokens import AccessTokenInfo
from app.db.redis_db import get_redis
from app.dependencies.auth import AppSettings, check_token
from app.dependencies.captcha import require_captcha
from app.dependencies.rate_limit import (
    rate_limit_login,
    rate_limit_public_captcha,
    rate_limit_register,
)
from app.repositories.redis.login_session_repository import login_session_repository
from app.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
    RegisterRequest,
)
from app.schemas.captcha import CaptchaCreateRequest, CaptchaResponse
from app.schemas.user import UserCreatedResponse
from app.services.auth_service import auth_service
from app.services.captcha_service import captcha_service

# prefix 统一当前业务路径；response_model 会在运行时校验返回结构，因此关闭文档后仍保留。
router = APIRouter(prefix="/auth")


# 依赖先按场景或错误请求扣次；路由只判断公开入口能否使用该场景并签发图片。
@router.post("/captcha", response_model=ApiResponse[CaptchaResponse])
async def create_public_captcha(body: CaptchaCreateRequest,
                                request: Request,
                                settings: AppSettings,
                                rate_limited: None = Depends(rate_limit_public_captcha)
                                ) -> ApiResponse[CaptchaResponse]:
    """
        签发登录或注册使用的图形验证码，返回内容禁止缓存。
        访问条件：允许未登录访问。
        所需权限：无管理权限要求。
        其他要求：只接受 login、register 两种场景；验证码按用途隔离，不绑定来源 IP。
        来源 IP 只用于申请频率限制，避免网络切换导致验证码失效。
        每张验证码只能提交校验一次，无论答案正确与否都不能再次尝试。

    :param body: 登录或注册的验证码业务场景。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param settings: 当前应用已验证的认证、验证码及限流配置。
    :param rate_limited: 申请验证码按场景和可信 IP 限流通过后为 None。
    :return: 一次性验证码标识与图片的统一响应。
    """
    # 拒绝把匿名入口用来申请管理员操作验证码；这些场景必须先登录，再从本人验证码入口申请。
    if body.scene not in PUBLIC_CAPTCHA_SCENES:
        raise invalid_request_400("captcha_scene_requires_authentication")
    # 限流依赖已按 IP 和场景扣次；Service 生成新图，公开验证码不绑定用户或 IP。
    data = await captcha_service.create_captcha(
        redis=get_redis(request),
        settings=settings,
        scene=body.scene,
        user_id=None,
    )
    # 路由负责成功文案、请求 ID 和统一响应外层；Service 只提供验证码数据。
    return api_response(request, message_key=MessageKey.AUTH_CAPTCHA_CREATED, data=data)


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=ApiResponse[UserCreatedResponse])
async def register(body: RegisterRequest,
                   request: Request,
                   rate_limited: None = Depends(rate_limit_register),
                   captcha_checked: None = Depends(require_captcha(CaptchaScene.REGISTER))
                   ) -> ApiResponse[UserCreatedResponse]:
    """
        通过注册限流和验证码后创建账号，初始仅分配基础用户角色。
        访问条件：允许未登录访问；自行注册没有后台开关。
        所需权限：无管理权限要求。
        其他要求：必须提交 register 场景的一次性图形验证码；创建成功不会直接登录，也不能选择管理员角色。

    :param body: 用户名、密码及本次注册验证码。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param rate_limited: 注册业务按可信 IP 限流通过后为 None；超额时不进入路由。
    :param captcha_checked: 前面的限流通过后校验 register 验证码；答错也会作废验证码。
    :return: 新用户 ID 的统一响应，不自动签发登录 Token。
    """
    # 前置保护全部通过后才计算密码哈希并进入数据库注册事务。
    user_id = await auth_service.register(
        user_name=body.user_name,
        password=body.password.get_secret_value(),
    )
    # 2. 返回新用户 ID 和创建成功提示，不在注册接口自动签发登录 Token。
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.AUTH_REGISTER_SUCCEEDED,
        data=UserCreatedResponse(user_id=user_id),
    )


@router.post("/login", response_model=ApiResponse[AccessTokenResponse])
async def login(body: LoginRequest,
                request: Request,
                settings: AppSettings,
                rate_limited: None = Depends(rate_limit_login),
                captcha_checked: None = Depends(require_captcha(CaptchaScene.LOGIN))
                ) -> ApiResponse[AccessTokenResponse]:
    """
        通过登录限流、验证码和密码检查后登记活跃登录，再返回 Access Token。
        访问条件：允许未登录访问。
        所需权限：无管理权限要求。
        其他要求：必须提交正确用户名、密码及 login 场景验证码；停用或已删除账号不能登录。

    :param body: 用户名、密码及本次登录验证码。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param settings: 应用已校验的 Token 签名、有效期及同时登录数量等配置。
    :param rate_limited: 登录业务按可信 IP 限流通过后为 None；超额时不进入路由。
    :param captcha_checked: 前面的限流通过后校验 login 验证码；答错也会作废验证码。
    :return: Token、类型和签发时设定的有效期秒数。
    """
    # 1. 限流和验证码依赖通过后，让 Service 完成登录；失败会直接抛出异常。
    result = await auth_service.login(
        user_name=body.user_name,
        password=body.password.get_secret_value(),
        redis=get_redis(request),
        settings=settings,
    )
    # 2. 把 Service 返回的 Token 和有效期包装成统一响应。
    return api_response(
        request,
        message_key=MessageKey.AUTH_LOGIN_SUCCEEDED,
        data=AccessTokenResponse(access_token=result.access_token, expires_in=result.expires_in),
    )


@router.post("/logout", response_model=ApiResponse[None])
async def logout(request: Request,
                 login_info: LoginInfo = Depends(check_token)
                 ) -> ApiResponse[None]:
    """
        验证当前登录后，撤销这张 Token 对应的活跃登录。
        访问条件：持有通过签名和活跃登录校验的 Access Token。
        所需权限：无管理权限要求。
        目标限制：只退出这一次登录，不退出同账号的其他登录；本接口不依赖数据库权限查询。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param login_info: 已通过 Token 和 Redis 活跃登录校验的当前身份。
    :return: 退出成功的统一响应，data 为 null。
    """
    # 1. 登录校验通过后，只撤销这张 Token 对应的登录，不查询数据库或检查业务权限。
    token_info = AccessTokenInfo(
        user_id=login_info.user_id,
        token_id=login_info.token_id,
        issued_at=login_info.issued_at,
        expires_at=login_info.expires_at,
    )
    await login_session_repository.delete_login_session(
        get_redis(request),
        token_info=token_info,
        user_token_version=login_info.token_version,
    )
    # 2. Redis 撤销成功后返回成功提示，不删除账号或其他登录。
    return api_response(
        request,
        message_key=MessageKey.AUTH_LOGOUT_SUCCEEDED,
        data=None,
    )
