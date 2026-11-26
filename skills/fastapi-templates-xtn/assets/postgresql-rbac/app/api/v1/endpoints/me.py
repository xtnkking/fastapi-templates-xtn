#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    第一版当前用户信息、修改密码和验证码接口。
# History:
# Date          Author    Version       Modification
# 2026/10/19    XTN       V2.021        直接导入共享业务服务，删除仅返回实例的依赖入口
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        归并本人权限、登录会话、改密及验证码，统一个人中心业务分组
# 2026/09/23    XTN       V1.002        明确业务服务入口，版本前缀交由总路由装配
# 2026/09/23    XTN       V1.003        明确本人接口仅需登录及验证码与敏感操作的权限边界
# 2026/09/23    XTN       V1.004        逐项对齐接口参数、响应字段和业务调用
# 2026/09/26    XTN       V1.005        处理函数按访问详情和会话列表用途命名
# 2026/09/27    XTN       V1.006        分行说明访问权限并解释路由装饰器参数
# 2026/09/27    XTN       V1.007        统一路由额度声明、验证码限流与验证消费入口
# 2026/09/29    XTN       V2.000        简化路由装饰器并由认证依赖自动选择本人业务额度
# 2026/09/29    XTN       V2.001        在线登录列表直接调用 Redis 会话模块
# 2026/09/29    XTN       V2.002        删除路由级缓存响应头与无用响应参数
# 2026/09/30    XTN       V2.003        会话列表改由用户管理接口提供
# 2026/10/04    XTN       V2.004        登录后验证码限流归认证依赖，路由只处理场景和签发
# 2026/10/04    XTN       V2.005        登录后验证码申请只需提交业务场景
# 2026/10/09    XTN       V2.006        本人改密和验证码入口引用统一用途定义
# 2026/10/09    XTN       V2.007        改密、验证码和共用结果按模型职责直接导入
# 2026/10/09    XTN       V2.008        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V2.009        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V2.010        验证码直接调用 Service，完整响应在路由组装
# 2026/10/12    XTN       V2.011        本人改密通过显式依赖校验验证码
# 2026/10/12    XTN       V2.012        私有验证码签发统一使用 user_id 参数
# 2026/10/13    XTN       V2.013        补齐接口业务执行与成功响应的通俗步骤
# 2026/10/14    XTN       V2.014        已登录验证码直接向 Service 传递用途枚举
# 2026/10/14    XTN       V2.015        为文件请求日志记录本人业务动作及改密目标
# 2026/10/15    XTN       V2.016        移除路由重复的日志动作和结果赋值，保留本人改密目标
# 2026/10/15    XTN       V2.017        本人改密目标由日志读取已认证用户，不在路由重复登记
# 2026/10/15    XTN       V2.018        本人权限响应删除用户权限版本，保留实时权限
# 2026/10/16    XTN       V2.019        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V2.020        本人权限接口不再读取或返回全局授权版本
# 2026/10/19    XTN       V2.022        本人改密返回成功及重新登录提示，data 为 null
# 2026/10/20    XTN       V2.023        本人权限响应的最高角色等级改为 role_level
# 2026/10/20    XTN       V2.024        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/20    XTN       V2.025        本人接口显式使用用户上下文依赖，避免误认为返回 User 对象
# 2026/10/22    XTN       V2.026        本人接口统一使用 get_current_user 检查当前用户
# 2026/10/23    XTN       V2.027        当前用户信息路径改为 user_info，处理函数改为 get_user_info
# 2026/10/24    XTN       V2.028        当前用户信息从 context.user_info 读取并统一局部变量名
# 2026/10/24    XTN       V2.029        本人改密验证码场景统一命名 user_change_password
# 2026/10/26    XTN       V2.030        本人信息和改密接口检查默认 user 角色的基础权限
# --------------------------------------------------------------------------------------------------


from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.captcha import PRIVATE_CAPTCHA_SCENES, CaptchaScene
from app.core.exceptions import invalid_request_400
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, api_response
from app.db.redis_db import get_redis
from app.dependencies.auth import AppSettings, get_captcha_user
from app.dependencies.captcha import require_captcha
from app.dependencies.permission import require_permission
from app.schemas.auth import PasswordChangeRequest
from app.schemas.captcha import CaptchaCreateRequest, CaptchaResponse
from app.schemas.user import UserAccessResponse
from app.services.auth_service import auth_service
from app.services.captcha_service import captcha_service

# prefix 统一当前业务路径；response_model 会在运行时校验返回结构，因此关闭文档后仍保留。
router = APIRouter(prefix="/me")


@router.get("/user_info", response_model=ApiResponse[UserAccessResponse])
async def get_user_info(request: Request,
                        context: Annotated[
                            AuthorizationContext,
                            Depends(require_permission(PermissionKey.ACCOUNT_READ)),
                        ]
                        ) -> ApiResponse[UserAccessResponse]:
    """
        返回当前登录用户的 ID、角色等级和有效权限。
        访问条件：已登录且账号可用，普通 user 也可调用。
        所需权限：account:read，查看本人信息；默认 user 角色已包含。
        目标限制：只能查看本人，不接受目标用户 ID；查询其他用户须使用有管理权限的用户接口。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 当前用户 ID、角色等级和有效权限的统一响应。
    """
    # 1. 权限依赖已查好当前用户信息，取出后直接整理成响应。
    user_info = context.user_info
    data = UserAccessResponse(
        user_id=user_info.user_id,
        role_level=user_info.role_level,
        permissions=sorted(user_info.permissions),
    )
    # 2. 返回本人权限信息；这里不修改角色或授予新权限。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.post("/password/change", response_model=ApiResponse[None])
async def change_my_password(body: PasswordChangeRequest,
                             request: Request,
                             context: Annotated[
                                 AuthorizationContext,
                                 Depends(require_permission(PermissionKey.ACCOUNT_CHANGE_PASSWORD)),
                             ],
                             captcha_checked: None = Depends(
                                 require_captcha(CaptchaScene.USER_CHANGE_PASSWORD))
                             ) -> ApiResponse[None]:
    """
        验证本人改密验证码及旧密码后修改密码，撤销旧登录。
        访问条件：已登录且账号可用。
        所需权限：account:change_password，修改本人密码；默认 user 角色已包含。
        目标限制：只能修改本人密码，不接受其他用户 ID。
        其他要求：必须提交正确旧密码及 user_change_password 场景、绑定本人的一次性验证码；成功后需重新登录。

    :param body: 旧密码、新密码以及本人改密验证码。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 已验证登录、账号状态及本人改密权限的用户上下文。
    :param captcha_checked: 前面的身份依赖通过后，校验绑定本人的 user_change_password 验证码。
    :return: 改密成功及需要重新登录的提示，data 为 null。
    """
    # 1. 基础权限和一次性验证码均已通过，服务再核对旧密码并保存新密码。
    await auth_service.change_password(
        context=context,
        current_password=body.current_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
    )
    # 2. 服务完成改密后返回结果，并提示用户旧登录已失效，需要重新登录。
    return api_response(
        request,
        message_key=MessageKey.AUTH_PASSWORD_CHANGED_RELOGIN,
        data=None,
    )


@router.post("/captcha", response_model=ApiResponse[CaptchaResponse])
async def create_authenticated_captcha(body: CaptchaCreateRequest,
                                       request: Request,
                                       settings: AppSettings,
                                       context: AuthorizationContext = Depends(
                                           get_captcha_user)
                                       ) -> ApiResponse[CaptchaResponse]:
    """
        为新增用户、重置密码或本人改密签发绑定当前用户的验证码。
        访问条件：已登录且账号可用。
        所需权限：无管理权限要求。
        其他要求：申请验证码图片本身不授予后续操作权限；user_change_password 用于本人改密，
        admin_create_user、admin_reset_user_password 用于管理员新增用户、重置他人密码，
        三个操作接口仍分别检查 users:create、users:password:reset、account:change_password；
        拿到图片不代表已经获得操作权限。

    :param body: 已登录操作的验证码业务场景。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param settings: 当前应用已验证的认证、验证码及限流配置。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 一次性验证码标识与图片的统一响应。
    """
    # 允许的已登录用途从公共枚举自动生成；图片绑定当前用户，不能给另一用户使用。
    if body.scene not in PRIVATE_CAPTCHA_SCENES:
        raise invalid_request_400("captcha_scene_is_public")
    # 认证依赖已校验身份并按用户和场景扣次；Service 将新图绑定当前用户。
    data = await captcha_service.create_captcha(
        redis=get_redis(request),
        settings=settings,
        scene=body.scene,
        user_id=context.login_info.user_id,
    )
    # 与公开入口一样，由当前路由组装完整 API 响应。
    return api_response(request, message_key=MessageKey.AUTH_CAPTCHA_CREATED, data=data)
