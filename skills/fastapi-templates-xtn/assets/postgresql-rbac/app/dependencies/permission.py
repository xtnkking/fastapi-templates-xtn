#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    接口权限依赖；验证 Token 后依次限流、检查账号和指定权限。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        独立管理权限检查，复用授权事务服务的拒绝审计
# 2026/10/02    XTN       V1.001        每个接口只要求一个明确权限，移除未使用的组合模式
# 2026/10/02    XTN       V1.002        展开拒绝审计动作选择，明确路由名缺失时的回退值
# 2026/10/13    XTN       V1.003        通俗说明权限依赖创建、执行及拒绝审计步骤
# 2026/10/16    XTN       V1.004        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.005        权限拒绝统一交给操作审计服务保存脱敏请求和错误快照
# 2026/10/16    XTN       V1.006        拒绝审计使用统一入口，直接沿用当前用户上下文
# 2026/10/19    XTN       V1.007        精简权限依赖注释，说明检查时机和拒绝审计
# 2026/10/20    XTN       V1.008        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/20    XTN       V1.009        使用内部管理上下文入口，区分身份准备与具体权限检查
# 2026/10/22    XTN       V1.010        直接完成管理限流和账号检查，删除中间准备依赖
# 2026/10/22    XTN       V1.011        默认使用普通额度，管理业务由路由显式选择
# 2026/11/28    XTN       V1.012        权限检查函数附带固定权限键，供启动时自动整理关联接口
# --------------------------------------------------------------------------------------------------

from collections.abc import Awaitable, Callable

from fastapi import Depends, Request

from app.core.access.authorization import AuthorizationContext, LoginInfo
from app.core.access.permissions import PermissionKey
from app.core.config import Settings, get_settings
from app.core.exceptions import forbidden_403
from app.db.postgres_db import SessionFactory
from app.dependencies import auth
from app.dependencies.rate_limit import rate_limit_user
from app.services.audit_service import AuditService


def require_permission(required: PermissionKey, *, management: bool = False
                       ) -> Callable[..., Awaitable[AuthorizationContext]]:
    """
        为接口创建指定权限的检查依赖。
        这里只检查操作权限，具体目标能否查看或修改由 Service 判断。
        默认使用普通接口额度；管理业务可单独选择管理额度，不按用户角色判断。

    :param required: 接口要求的权限，例如 roles:read。
    :param management: 是否使用管理业务额度；默认 False 使用普通额度，True 使用管理额度，不改变权限要求。
    :return: 请求到来时执行的权限检查函数；附带的 permission_key 只供启动时整理接口目录。
    """
    # 路由加载时记住所需权限和所选额度，请求到来后才检查。
    required_key = required.value

    async def dependency(request: Request,
                         login_info: LoginInfo = Depends(auth.check_token),
                         settings: Settings = Depends(get_settings)
                         ) -> AuthorizationContext:
        """
            Token 通过后，依次检查本接口次数、账号状态和所需权限。
            POST 无权限时记录拒绝审计，记录失败仍返回 403。

        :param request: 当前请求，用来判断请求方法和路由名称。
        :param login_info: check_token 已验证的登录信息，提供可信用户 ID 和登录版本。
        :param settings: 普通及管理业务的查询、修改限流配置。
        :return: 检查通过后的原用户上下文。
        :raises AppError: 登录、账号或限流不允许继续，或缺少本接口要求的权限。
        """
        # 1. Token 已通过；按路由选择的额度计数，超限就停止，不再查询账号。
        await rate_limit_user(request, login_info, settings, management=management)
        # 2. 复用账号检查，确认账号可用、登录版本一致，并读取当前权限。
        context = await auth._load_current_user(request, login_info)
        # 3. 检查接口明确要求的权限；目标能否操作仍由 Service 判断。
        if required_key not in context.permissions:
            error = forbidden_403("missing_required_permission")
            if request.method == "POST":
                route = request.scope.get("route")
                route_name = getattr(route, "name", None)
                if isinstance(route_name, str) and route_name:
                    action = f"api.{route_name}"
                else:
                    # 路由名缺失时使用固定动作名，不使用请求方传入的路径或参数。
                    action = "api.protected_write"
                # POST 无权限时记录拒绝审计，失败仍保留原来的 403。
                await AuditService(SessionFactory).audit_denied(
                    error=error,
                    action=action,
                    context=context,
                    target_user_id=None,
                    target_role_id=None,
                )
            raise error
        # 4. 通过后交回用户信息，路由无需再声明一次登录检查。
        return context

    # 把路由已声明的权限记在检查函数上；启动时直接读取，不另维护一份“权限对应哪些接口”。
    # 这个标记不代替上面的权限检查，也不会在整理接口目录时执行检查函数。
    setattr(dependency, "permission_key", required_key)  # noqa: B010 - 给函数附加目录标记，保留原有调用类型。
    # 交给 Depends 在请求到来时执行。
    return dependency
