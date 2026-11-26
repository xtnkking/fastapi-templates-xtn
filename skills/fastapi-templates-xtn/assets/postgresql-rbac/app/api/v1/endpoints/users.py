#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户管理接口，包含查询、新增、角色、状态、密码与会话管理。
# History:
# Date          Author    Version       Modification
# 2026/10/19    XTN       V2.024        直接导入共享业务服务，删除仅返回实例的依赖入口
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        归并用户新增与密码重置，查询使用列表详情路径，操作目标进入 JSON
# 2026/09/23    XTN       V1.002        明确业务服务入口，版本前缀交由总路由装配
# 2026/09/23    XTN       V1.003        补齐用户接口权限、验证码用途及管理目标边界
# 2026/09/23    XTN       V1.004        对齐接口参数与业务调用，补充文档页查询参数中文说明
# 2026/09/26    XTN       V1.005        统一详情函数和用户请求结果模型命名
# 2026/09/27    XTN       V1.006        分行说明访问权限并解释路由装饰器参数
# 2026/09/27    XTN       V1.007        统一管理员敏感操作的验证码验证消费入口
# 2026/09/27    XTN       V1.008        为全部用户管理业务显式声明限流档位
# 2026/09/29    XTN       V2.000        简化路由装饰器并由权限依赖自动执行管理限流
# 2026/09/29    XTN       V2.001        删除路由级缓存响应头与无用响应参数
# 2026/09/30    XTN       V2.002        管理员新增及重置统一使用正式密码
# 2026/09/30    XTN       V2.003        会话列表移入用户管理并明确强制全部退出路径
# 2026/09/30    XTN       V2.004        查询接口显式注入 PostgreSQL 会话
# 2026/10/02    XTN       V2.005        每个接口使用单个明确权限的依赖
# 2026/10/02    XTN       V2.006        修正新增用户路由对缓存响应责任的说明
# 2026/10/02    XTN       V2.007        会话统计交给用户服务并修正过时的文件说明
# 2026/10/02    XTN       V2.008        解释查询参数校验顺序并整理用户管理路由排版
# 2026/10/02    XTN       V2.009        修正用户名校验说明和接口参数文档顺序
# 2026/10/09    XTN       V2.010        管理员操作的验证码用途统一引用公共枚举
# 2026/10/09    XTN       V2.011        用户查询复用请求 ID 类型，不单独维护格式
# 2026/10/09    XTN       V2.012        共用结果及用户会话模型按职责直接导入
# 2026/10/09    XTN       V2.013        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V2.014        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V2.015        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/12    XTN       V2.016        管理员新增及重置密码显式注入验证码依赖
# 2026/10/13    XTN       V2.017        补齐接口业务执行与成功响应的通俗步骤
# 2026/10/15    XTN       V2.018        管理员新增直接调用 UserService 的简洁业务入口
# 2026/10/13    XTN       V2.018        会话查询不再注入只用于旧 Redis 键的配置
# 2026/10/14    XTN       V2.019        为文件请求日志记录用户管理动作、被操作人和完成结果
# 2026/10/15    XTN       V2.020        移除路由重复的日志动作和结果赋值，保留被操作用户信息
# 2026/10/15    XTN       V2.021        被操作用户由日志统一提取，删除逐接口的目标赋值
# 2026/10/15    XTN       V2.022        角色变更响应移除用户权限版本，保留实际角色与权限
# 2026/10/19    XTN       V2.023        用户查询 ID 校验统一从公共模型导入
# 2026/10/19    XTN       V2.024        强制退出与重置密码不再返回内部变更标记
# 2026/10/22    XTN       V2.025        用户管理业务显式选择管理额度，与权限要求分开
# 2026/10/20    XTN       V2.025        用户名查询校验不再重复传入字段名
# 2026/10/24    XTN       V2.026        从 context.user_info 读取当前用户信息
# 2026/10/24    XTN       V2.027        新增及重置密码验证码场景补全操作对象
# 2026/10/24    XTN       V2.028        用户列表增加用户 ID、启停和软删除筛选
# 2026/10/24    XTN       V2.029        用户角色接口权限名与绑定和解绑动作一致
# 2026/10/24    XTN       V2.030        用户角色绑定和解绑响应改用简洁的模型名
# 2026/11/26    XTN       V2.031        用户名查询参数引用统一规则和说明
# 2026/11/26    XTN       V2.032        用户名查询校验入口统一用 validate 命名
# --------------------------------------------------------------------------------------------------


from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BeforeValidator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.captcha import CaptchaScene
from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, PageResponse, api_response
from app.core.security.user_name import (
    MAX_USER_NAME_LENGTH,
    MIN_USER_NAME_LENGTH,
    USER_NAME_CHARACTERS_ZH,
    USER_NAME_PATTERN,
    validate_user_name,
)
from app.db.postgres_db import get_postgres_session
from app.db.redis_db import get_redis
from app.dependencies.captcha import require_captcha
from app.dependencies.permission import require_permission
from app.schemas.common import UserId
from app.schemas.user import (
    ActiveSessionsResponse,
    UserCreatedResponse,
    UserCreateRequest,
    UserPasswordResetRequest,
    UserResponse,
    UserRoleIdsRequest,
    UserRoleResponse,
    UserTargetRequest,
)
from app.services.user_service import user_service

# prefix 统一当前业务路径；response_model 会在运行时校验返回结构，因此关闭文档后仍保留。
router = APIRouter(prefix="/users")
# 本模块是用户管理业务，显式选择管理额度；有接口权限不代表用户具有管理员角色。


def _validate_user_name_query(value: object) -> str | None:
    """
        清理用户名首尾空白并执行统一格式与保留名校验，保留项目确定的大小写规则。

    :param value: 外部传入的用户名查询值。
    :return: 规范化后的用户名；未提供时返回 None。
    :raises ValueError: 输入不是字符串，或用户名不符合项目规则。
    """
    # 没传查询条件就不筛选；传了则只接受文字，交给统一用户名规则清理和校验。
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("user_name must be a string")
    return validate_user_name(value)


# BeforeValidator 调用统一规则：先去首尾空白，再检查长度、字符和保留名；Query 还声明接口约束。
# 保留这一步顺序，直接在路由里处理会使带首尾空白的合法用户名提前得到 422。
UserNameQuery = Annotated[
    str | None,
    BeforeValidator(_validate_user_name_query),
    Query(
        min_length=MIN_USER_NAME_LENGTH,
        max_length=MAX_USER_NAME_LENGTH,
        pattern=USER_NAME_PATTERN,
        description=(
            f"可选的用户名精确匹配条件；仅支持 {MIN_USER_NAME_LENGTH} 至 {MAX_USER_NAME_LENGTH} 位"
            f"{USER_NAME_CHARACTERS_ZH}，"
            "不传则不按用户名筛选。"
        ),
    ),
]

# users:read 允许进入后台用户查询，不等于可以查看同级和上级；具体可见范围由服务限制。
UserReadContext = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.USERS_READ, management=True)),
]
# users:status:update 只覆盖启停账号；改密码、绑定角色和退出全部登录有各自独立的权限。
UserStatusContext = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.USERS_STATUS_UPDATE, management=True)),
]


@router.get("/list", response_model=ApiResponse[PageResponse[UserResponse]])
async def list_users(request: Request,
                     context: UserReadContext,
                     db: Annotated[AsyncSession, Depends(get_postgres_session)],
                     page: Annotated[int, Query(ge=1, description="页码，从 1 开始；默认第 1 页。")] = 1,
                     page_size: Annotated[int, Query(ge=1, le=200, description="每页条数，默认 20 条。")] = 20,
                     user_id: Annotated[UserId | None, Query(description="按用户 ID 精确筛选；不传则不限。")] = None,
                     user_name: UserNameQuery = None,
                     is_active: Annotated[bool | None, Query(
                         description="启用状态：true 只查启用，false 只查禁用；不传包含两种状态。",
                     )] = None,
                     is_deleted: Annotated[bool, Query(
                         description="软删除状态：默认 false 只查未删除；true 只查已软删除用户。",
                     )] = False
                     ) -> ApiResponse[PageResponse[UserResponse]]:
    """
        按可见范围分页查询用户，可按 ID、用户名、启停和软删除状态筛选。
        访问条件：已登录且账号可用。
        所需权限：users:read（查询后台用户）。
        目标限制：普通管理员只能查看未受保护的下级用户，不能通过此接口查看本人、同级或上级；
        默认只查未删除用户；is_deleted=true 只查已软删除用户，同样受可见范围限制。
        超级管理员可查看所选删除状态下的全部用户，本人权限可通过个人中心接口查询。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :param page: 从 1 开始的页码。
    :param page_size: 每页条数，HTTP 接口限制在 1 至 200。
    :param user_id: 用户 ID 精确匹配条件；None 表示不按 ID 筛选。
    :param user_name: 规范化后的用户名精确匹配条件；None 表示不按用户名筛选。
    :param is_active: True 只查启用，False 只查禁用，None 不限制启用状态。
    :param is_deleted: False 只查未删除用户，True 只查已软删除用户。
    :return: 包含可见用户列表及相同筛选范围总数的统一响应。
    """
    # 1. 先限定能看谁，再同时匹配已传的筛选条件；搜索不能绕过等级和保护限制。
    data = await user_service.list_users(
        db,
        current_user=context.user_info,
        page=page,
        page_size=page_size,
        user_id=user_id,
        user_name=user_name,
        is_active=is_active,
        is_deleted=is_deleted,
    )
    # 2. 将可见用户的分页结果包装成统一响应。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.get("/detail", response_model=ApiResponse[UserResponse])
async def get_user_detail(request: Request,
                          user_id: Annotated[UserId, Query(description="用户 ID；只能查询操作者可见用户。")],
                          context: UserReadContext,
                          db: Annotated[AsyncSession, Depends(get_postgres_session)]
                          ) -> ApiResponse[UserResponse]:
    """
        查询当前操作者可见的用户详情，不泄露不可见账号是否存在。
        访问条件：已登录且账号可用。
        所需权限：users:read（查看后台用户详情）。
        目标限制：普通管理员只能查看未受保护的下级；超级管理员可查看全部未删除用户。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param user_id: 查询参数中的目标用户业务 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :return: 目标用户及其可见角色、权限信息的统一响应。
    """
    # 对不可见和不存在的用户给出相同错误；知道某个 user_id 并不等于拥有查看权限。
    data = await user_service.get_user_detail(
        db,
        current_user=context.user_info,
        user_id=user_id,
    )
    # 2. 返回该用户的可见资料、角色和权限，不在路由直接查询更多字段。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.post("/roles/bind", response_model=ApiResponse[UserRoleResponse])
async def bind_user_roles(
    request: Request,
    body: UserRoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permission(PermissionKey.ROLES_BIND, management=True)),
    ],
) -> ApiResponse[UserRoleResponse]:
    """
        为可管理用户批量绑定角色，业务服务检查最终角色数量和完整权限。
        访问条件：已登录且账号可用。
        所需权限：roles:bind（给用户绑定角色）。
        目标限制：目标必须是可管理的下级，不能给本人授权；一个用户最多 10 个角色，包含基础 user。
        admin 角色只能由超级管理员分配；super_admin 绑定必须由开发人员直接维护数据库。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标用户 ID、需要绑定的角色 ID 列表。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含绑定后用户角色及有效权限快照的统一响应。
    """
    # 服务同时检查变更前后权限，避免“当前是下级，绑定之后变成同级或上级”的间接提权。
    result = await user_service.change_user_roles(
        target_user_id=body.user_id,
        role_ids=body.role_ids,
        operation="bind",
        context=context,
    )
    # 2. 返回绑定后的角色和权限结果，业务事务已由服务处理。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/roles/unbind", response_model=ApiResponse[UserRoleResponse])
async def unbind_user_roles(
    request: Request,
    body: UserRoleIdsRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permission(PermissionKey.ROLES_UNBIND, management=True)),
    ],
) -> ApiResponse[UserRoleResponse]:
    """
        解除可管理用户的指定角色，保留必需的基础角色和解绑历史。
        访问条件：已登录且账号可用。
        所需权限：roles:unbind（解绑用户角色）。
        目标限制：只能操作可管理的下级，不能管理本人；必备 user 角色不可解绑，admin 只能由超级管理员撤销。
        super_admin 绑定不允许通过此接口解除。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标用户 ID、需要解除绑定的角色 ID 列表。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含解绑后用户角色及有效权限快照的统一响应。
    """
    # 解除的是用户与角色的关系，角色定义继续保留；服务会拒绝解绑基础 user 角色。
    result = await user_service.change_user_roles(
        target_user_id=body.user_id,
        role_ids=body.role_ids,
        operation="unbind",
        context=context,
    )
    # 2. 返回解绑后的角色和权限结果，保留基础角色及历史的规则由服务执行。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/disable", response_model=ApiResponse[UserResponse])
async def disable_user(request: Request,
                       body: UserTargetRequest,
                       context: UserStatusContext
                       ) -> ApiResponse[UserResponse]:
    """
        停用可管理用户，由业务服务完成状态与授权变更。
        访问条件：已登录且账号可用。
        所需权限：users:status:update（启用或禁用用户）。
        目标限制：只允许操作等级更低、未受保护且权限未超出操作者范围的用户，不能停用本人。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 包含待执行管理操作的目标用户 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 用户停用后的不可变信息快照响应。
    """
    # 停用保留账号和历史记录，服务同时使旧登录版本失效，避免只改状态而遗漏会话控制。
    result = await user_service.update_user_status(
        target_user_id=body.user_id,
        is_active=False,
        context=context,
    )
    # 2. 返回停用后的账号信息，不把账号记录物理删除。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/enable", response_model=ApiResponse[UserResponse])
async def enable_user(request: Request,
                      body: UserTargetRequest,
                      context: UserStatusContext
                      ) -> ApiResponse[UserResponse]:
    """
        启用可管理用户，重新检查其恢复后的完整权限范围。
        访问条件：已登录且账号可用。
        所需权限：users:status:update（启用或禁用用户）。
        目标限制：只允许恢复可管理的下级；不能借启用操作让目标恢复到同级、上级或超出操作者的权限范围。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 包含待执行管理操作的目标用户 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 用户启用后的不可变信息快照响应。
    """
    # 启用沿用用户原有角色，因此服务先检查恢复后的权限，而不只是把 is_active 设为 True。
    result = await user_service.update_user_status(
        target_user_id=body.user_id,
        is_active=True,
        context=context,
    )
    # 2. 返回启用后的账号信息，不恢复已经作废的旧登录。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.get("/sessions/list", response_model=ApiResponse[ActiveSessionsResponse])
async def list_user_sessions(request: Request,
                             user_id: Annotated[UserId, Query(description="要查询有效登录的可见用户 ID。")],
                             context: UserReadContext
                             ) -> ApiResponse[ActiveSessionsResponse]:
    """
        查看可管理用户当前有效的登录次数和登录时间，不推断物理设备。
        访问条件：已登录且账号可用。
        所需权限：users:read（查看后台用户及其有效登录）。
        目标限制：普通管理员只能查看未受保护的下级；本人、同级、上级与不存在的目标统一不可见。

    :param request: 当前 HTTP 请求，用于读取 Redis 客户端并关联响应请求 ID。
    :param user_id: 查询参数中的目标用户 ID。
    :param context: 已验证的当前身份和 users:read 权限上下文。
    :return: 目标用户当前在线登录数量和登录时间列表的统一响应。
    """
    # 服务先核对目标，再读取其 Redis 会话；数据库会话不会在 Redis 请求期间占用连接。
    data = await user_service.list_user_sessions(
        current_user=context.user_info,
        user_id=user_id,
        redis=get_redis(request),
    )
    # 2. 返回在线登录数量和时间，不把登录会话当成物理设备。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.post("/sessions/logout-all", response_model=ApiResponse[None])
async def revoke_user_sessions(
    request: Request,
    body: UserTargetRequest,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permission(PermissionKey.USERS_SESSIONS_REVOKE, management=True)),
    ],
) -> ApiResponse[None]:
    """
        撤销目标用户的全部现有登录，仅允许具备对应管理权限的操作者调用。
        访问条件：已登录且账号可用。
        所需权限：users:sessions:revoke（强制下级用户全部退出登录）。
        目标限制：目标必须是可管理的下级，不能操作本人；普通用户只能使用退出当前登录的接口。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 包含待执行管理操作的目标用户 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 全部登录已失效的统一响应，data 为 null。
    """
    # 撤销影响的是目标账号的所有现有登录，操作成功不等于禁止其以后重新登录。
    await user_service.revoke_user_sessions(
        context=context,
        target_user_id=body.user_id,
    )
    # 2. 服务完成全部登录失效后再返回成功，不禁止目标账号以后重新登录。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=None,
    )


@router.post("/create", status_code=status.HTTP_201_CREATED, response_model=ApiResponse[UserCreatedResponse])
async def create_user(
    body: UserCreateRequest,
    request: Request,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permission(PermissionKey.USERS_CREATE, management=True)),
    ],
    captcha_checked: None = Depends(require_captcha(CaptchaScene.ADMIN_CREATE_USER)),
) -> ApiResponse[UserCreatedResponse]:
    """
        验证管理员权限及验证码后，以初始密码创建只有基础角色的新用户。
        访问条件：已登录且账号可用。
        所需权限：users:create（管理员新增用户）。
        其他要求：必须提交 admin_create_user 场景、绑定当前操作者的一次性验证码，无须输入操作者密码。
        新用户只有基础 user 角色，管理员私下交付初始密码后即可登录。

    :param body: 新用户名、初始密码和新增用户业务验证码。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param captcha_checked: 前面的新增权限依赖通过后，校验绑定当前管理员的 admin_create_user 验证码。
    :return: 新用户 ID 和创建成功提示。
    """
    # 权限和一次性验证码依赖均通过后，服务才进入创建账号的事务。
    user_id = await user_service.admin_create_user(
        context=context,
        user_name=body.user_name,
        password=body.password.get_secret_value(),
    )
    # 2. 返回新用户 ID 和创建成功提示，不返回密码明文。
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.AUTH_USER_CREATED,
        data=UserCreatedResponse(user_id=user_id),
    )


@router.post("/password/reset", response_model=ApiResponse[None])
async def reset_user_password(
    body: UserPasswordResetRequest,
    request: Request,
    context: Annotated[
        AuthorizationContext,
        Depends(require_permission(PermissionKey.USERS_PASSWORD_RESET, management=True)),
    ],
    captcha_checked: None = Depends(require_captcha(CaptchaScene.ADMIN_RESET_USER_PASSWORD)),
) -> ApiResponse[None]:
    """
        将可管理用户的密码重置为管理员指定的新密码。
        访问条件：已登录且账号可用。
        所需权限：users:password:reset（重置下级用户密码）。
        目标限制：不能重置本人、同级、上级或受保护用户；成功后目标用户的旧登录失效。
        其他要求：必须提交 admin_reset_user_password 场景、绑定当前操作者的一次性验证码，无须输入操作者密码。

    :param body: 目标用户 ID、管理员设置的新密码及重置业务验证码。
    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param captcha_checked: 前面的重置权限依赖通过后，校验绑定当前管理员的 admin_reset_user_password 验证码。
    :return: 密码重置成功的统一响应，data 为 null，不返回密码本身。
    """
    # 验证码依赖已按重置业务一次性校验，服务继续检查目标范围并保存新密码。
    await user_service.reset_user_password(
        context=context,
        target_user_id=body.user_id,
        new_password=body.new_password.get_secret_value(),
    )
    # 2. 返回重置结果，不在响应中返回新密码。
    return api_response(
        request,
        message_key=MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED,
        data=None,
    )
