#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    API v1 启动路由校验规则
#    声明认证规则，校验通过后为当前应用保存权限关联接口目录
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从总路由分离启动认证规则，保持业务路由装配清晰
# 2026/09/30    XTN       V1.001        移除临时密码匿名路由白名单
# 2026/10/09    XTN       V1.002        退出路由必须同时接入有效身份与业务限流
# 2026/10/13    XTN       V1.003        通俗说明启动时实际路由规则检查
# 2026/10/20    XTN       V1.004        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/20    XTN       V1.005        路由校验同步本人及内部管理上下文依赖名称
# 2026/10/22    XTN       V1.006        退出只要求有效登录，不再要求退出限流依赖
# 2026/10/22    XTN       V1.007        对齐 Token 和用户入口，直接识别权限依赖
# 2026/11/28    XTN       V1.008        启动校验通过后保存本应用的权限关联接口，不在请求中重复扫描
# --------------------------------------------------------------------------------------------------


from collections.abc import Callable

from fastapi import FastAPI

from app.core.access.permissions import PermissionKey
from app.core.route_validation import validate_api_routes
from app.dependencies.auth import (
    check_token,
    get_captcha_user,
    get_current_user,
)
from app.dependencies.permission import require_permission

# 只有这些固定认证入口允许匿名；新增业务路由默认必须具备已登录依赖。
# 匿名不代表免验证：注册和登录仍执行各自的限流与验证码校验。
_PUBLIC_ROUTES = frozenset({
    ("POST", "/api/v1/auth/captcha"),
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/login"),
})
# 普通业务走身份和权限上下文；这些依赖会选择相应的业务限流。
# 权限项只提供一个已创建的检查函数供识别；每个路由实际要求的权限仍在路由中声明。
_AUTHENTICATED_DEPENDENCIES: tuple[Callable[..., object], ...] = (
    get_current_user,
    require_permission(PermissionKey.USERS_READ),
)
# 退出当前登录只校验有效登录；本人验证码仍走场景专用认证和限流依赖。
_SPECIAL_ROUTES: dict[tuple[str, str], tuple[Callable[..., object], str]] = {
    ("POST", "/api/v1/auth/logout"): (
        check_token,
        "current-session logout must validate the active Token",
    ),
    ("POST", "/api/v1/me/captcha"): (
        get_captcha_user,
        "authenticated CAPTCHA must use its scene-specific authorization dependency",
    ),
}


def validate_v1_api_routes(app: FastAPI) -> None:
    """
        用本版 API 的公开入口和认证依赖规则，检查应用实际装配的业务路由。
        路由方法、参数位置及重复名称仍由通用校验器检查，不连接外部服务。
        全部通过后，把权限关联接口保存在当前应用内存，供权限列表和详情直接使用。

    :param app: 已装配业务路由、尚未开始接收请求的 FastAPI 应用。
    :return: 无返回值；成功后更新 app.state.permission_api_routes，失败时不写入部分目录。
    :raises ValueError: 业务路由不满足公开入口、认证依赖或输入约定。
    """
    # 1. 将本版规则交给统一检查器，一次遍历完成校验和接口目录整理；漏保护就阻止启动。
    permission_api_routes = validate_api_routes(
        app,
        public_routes=_PUBLIC_ROUTES,
        authenticated_dependencies=_AUTHENTICATED_DEPENDENCIES,
        special_routes=_SPECIAL_ROUTES,
    )
    # 2. 只在全部通过后保存；每个 FastAPI 应用各有一份，不与其他应用共用可变全局目录。
    app.state.permission_api_routes = permission_api_routes
