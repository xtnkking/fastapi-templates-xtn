#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    角色管理接口；入口校验权限，业务规则由角色服务处理。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        统一查询动作路由，目标 ID 改用 JSON 并整理紧凑排版
# 2026/09/23    XTN       V1.002        角色更新直接传入完整请求，移除目标和版本的重复传参
# 2026/09/23    XTN       V1.003        逐接口说明权限、管理范围和并发版本含义
# 2026/09/23    XTN       V1.004        对齐接口参数与业务调用，补充文档页查询参数中文说明
# 2026/09/26    XTN       V1.005        统一详情函数和角色请求模型命名
# 2026/09/27    XTN       V1.006        分行说明访问权限并解释路由装饰器参数
# 2026/09/27    XTN       V1.007        为全部角色业务显式声明用户限流档位
# 2026/09/29    XTN       V2.000        简化路由装饰器并由权限依赖自动执行管理限流
# 2026/09/30    XTN       V2.001        查询接口显式注入 PostgreSQL 会话
# 2026/10/02    XTN       V2.002        每个接口使用单个明确权限的依赖
# 2026/10/02    XTN       V2.003        修正文件职责说明，避免把当前接口误称第一版
# 2026/10/02    XTN       V2.004        按函数签名顺序整理角色查询参数说明
# 2026/10/09    XTN       V2.005        角色查询复用请求 ID 类型，不单独维护格式
# 2026/10/09    XTN       V2.006        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V2.007        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V2.008        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V2.009        补齐接口业务执行与成功响应的通俗步骤
# 2026/10/14    XTN       V2.010        为文件请求日志记录角色管理动作、目标角色和完成结果
# 2026/10/15    XTN       V2.011        移除路由重复的日志动作和结果赋值，保留目标角色信息
# 2026/10/15    XTN       V2.012        目标角色由日志统一提取，删除逐接口的目标赋值
# 2026/10/19    XTN       V2.013        角色查询 ID 校验统一从公共模型导入
# 2026/10/19    XTN       V2.014        直接导入共享业务服务，删除仅返回实例的依赖入口
# 2026/10/22    XTN       V2.015        角色管理业务显式选择管理额度，与权限要求分开
# 2026/10/24    XTN       V2.016        从 context.user_info 读取当前用户信息
# 2026/10/24    XTN       V2.017        角色 Service 请求参数使用 body，删除直接调用 delete_role
# 2026/10/26    XTN       V2.018        角色列表增加 ID、编码、名称、启停、系统及软删除筛选
# 2026/11/27    XTN       V2.019        删除角色说明对齐两个系统角色及按权限配置的管理员
# --------------------------------------------------------------------------------------------------


from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, PageResponse, api_response
from app.db.postgres_db import get_postgres_session
from app.dependencies.permission import require_permission
from app.schemas.common import RoleId
from app.schemas.role import (
    RoleCreateRequest,
    RoleMutationResponse,
    RolePermissionIdsRequest,
    RoleResponse,
    RoleUpdateRequest,
    RoleVersionRequest,
)
from app.services.role_service import role_service

# prefix 统一当前业务路径；response_model 会在运行时校验返回结构，因此关闭文档后仍保留。
router = APIRouter(prefix="/roles")
# 本模块是角色管理业务，显式选择管理额度；该选择不改变接口权限或用户角色。
# roles:read 只允许查询，仍由 Service 限制可见等级；不会因有查询权限就能看上级角色。
RoleReadContext = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_READ, management=True)),
]
# 启用和禁用共用 roles:status:update；拥有它也不能修改系统角色或本人持有的角色。
RoleStatusContext = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_STATUS_UPDATE, management=True)),
]


@router.get("/list", response_model=ApiResponse[PageResponse[RoleResponse]])
async def list_roles(request: Request,
                     context: RoleReadContext,
                     db: Annotated[AsyncSession, Depends(get_postgres_session)],
                     page: Annotated[int, Query(ge=1, description="页码，从 1 开始；默认第 1 页。")] = 1,
                     page_size: Annotated[int, Query(ge=1, le=200, description="每页条数，默认 20 条。")] = 20,
                     role_id: Annotated[RoleId | None, Query(description="角色 ID 精确匹配；不传则不限。")] = None,
                     key: Annotated[str | None, Query(
                         min_length=1, max_length=80, description="角色编码精确匹配，例如 user；不传则不限。",
                     )] = None,
                     name: Annotated[str | None, Query(
                         min_length=1, max_length=160,
                         description="角色名称包含匹配；% 和 _ 按普通字符查询，不传则不限。",
                     )] = None,
                     is_active: Annotated[bool | None, Query(
                         description="true 只查启用，false 只查禁用；不传包含两种状态。",
                     )] = None,
                     is_system: Annotated[bool | None, Query(
                         description="true 只查系统角色，false 只查自定义角色；不传包含两种类型。",
                     )] = None,
                     is_deleted: Annotated[bool, Query(
                         description="默认 false 只查未删除角色；true 只查已软删除角色。",
                     )] = False
                     ) -> ApiResponse[PageResponse[RoleResponse]]:
    """
        按 ID、编码、名称和状态分页查询可见角色；多个条件同时满足才返回。
        访问条件：已登录且账号可用。
        所需权限：roles:read（查看角色及其权限）。
        目标限制：普通管理员只能查看等级低于自己且未受保护的角色；超级管理员可查看所选删除状态下的全部角色。
        默认只查未删除角色；is_deleted=true 只查已软删除记录，这些记录的权限列表为空。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :param page: 从 1 开始的页码。
    :param page_size: 每页条数，HTTP 接口限制在 1 至 200。
    :param role_id: 角色 ID 精确匹配条件；None 不筛选。
    :param key: 角色编码精确匹配条件；None 不筛选。
    :param name: 角色名称包含的文字；None 不筛选。
    :param is_active: True 只查启用，False 只查禁用，None 不限制启用状态。
    :param is_system: True 只查系统角色，False 只查自定义角色，None 不限制类型。
    :param is_deleted: False 只查未删除角色，True 只查已软删除角色。
    :return: 包含可见角色列表及相同可见范围总数的统一响应。
    """
    # 1. 传入当前用户和所有筛选条件；列表与总数使用相同的筛选及查看范围。
    data = await role_service.list_roles(
        db,
        current_user=context.user_info,
        page=page,
        page_size=page_size,
        role_id=role_id,
        key=key,
        name=name,
        is_active=is_active,
        is_system=is_system,
        is_deleted=is_deleted,
    )
    # 2. 返回可见角色的分页数据，不泄露其他角色的列表或总数。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.get("/detail", response_model=ApiResponse[RoleResponse])
async def get_role_detail(request: Request,
                          role_id: Annotated[RoleId, Query(description="角色 ID；只能查询操作者可见角色。")],
                          context: RoleReadContext,
                          db: Annotated[AsyncSession, Depends(get_postgres_session)]
                          ) -> ApiResponse[RoleResponse]:
    """
        读取当前操作者可见的角色详情，不存在与不可见使用相同错误。
        访问条件：已登录且账号可用。
        所需权限：roles:read（查看角色及其权限）。
        目标限制：普通管理员不能查询同级、上级或受保护角色；超级管理员可查看全部未删除角色。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param role_id: 查询参数中的目标角色业务 ID。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :return: 包含角色信息及其权限的统一响应。
    """
    # 查询参数中的 ID 只是目标定位，真正能否查看仍按操作者等级和角色保护状态判断。
    data = await role_service.get_role_detail(
        db,
        current_user=context.user_info,
        role_id=role_id,
    )
    # 2. 返回已通过可见范围检查的角色详情。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.post("/create", response_model=ApiResponse[RoleMutationResponse], status_code=status.HTTP_201_CREATED)
async def create_role(
    request: Request,
    body: RoleCreateRequest,
    context: Annotated[AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_CREATE, management=True))],
) -> ApiResponse[RoleMutationResponse]:
    """
        创建自定义角色，由业务服务校验授予范围并原子记录审计。
        访问条件：已登录且账号可用。
        所需权限：roles:create（新增角色）。
        目标限制：新角色等级必须低于操作者，不能占用系统角色名称；创建后尚未绑定任何权限。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 角色键、名称、等级和描述；新角色不包含初始权限。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含新角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # 入口权限通过后，服务仍会在写事务内重新核对授权，创建角色并一起保存审计。
    result = await role_service.create_role(context=context, body=body)
    # 2. 服务创建完成后返回新角色及版本；HTTP 状态明确使用 201。
    return api_response(
        request,
        code=BusinessCode.CREATED,
        message_key=MessageKey.COMMON_CREATED,
        data=result,
    )


@router.post("/update", response_model=ApiResponse[RoleMutationResponse])
async def update_role(
    request: Request,
    body: RoleUpdateRequest,
    context: Annotated[AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_UPDATE, management=True))],
) -> ApiResponse[RoleMutationResponse]:
    """
        按预期版本修改可管理角色的信息，拒绝过期写入。
        访问条件：已登录且账号可用。
        所需权限：roles:update（修改角色资料）。
        目标限制：只允许修改可管理的下级自定义角色；不能改系统角色、本人持有的角色或借此影响上级。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、期望版本和需要修改的角色信息。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含更新后角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # expected_version 应使用查询结果中的 role.version；过期时重新读取，避免覆盖别人刚改的资料。
    result = await role_service.update_role(context=context, body=body)
    # 2. 返回修改后的角色和最新版本，供下一次修改时使用。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/disable", response_model=ApiResponse[RoleMutationResponse])
async def disable_role(request: Request,
                       body: RoleVersionRequest,
                       context: RoleStatusContext
                       ) -> ApiResponse[RoleMutationResponse]:
    """
        停用可管理角色，使其不再贡献生效权限。
        访问条件：已登录且账号可用。
        所需权限：roles:status:update（启用或禁用角色）。
        目标限制：只允许操作可管理的下级自定义角色；系统角色、本人持有的角色以及影响上级的操作会被拒绝。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、用于防止覆盖其他操作的期望角色版本。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含停用后角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # 启停复用同一业务流程；is_active=False 表示暂停角色授权，不是删除角色或解绑历史。
    result = await role_service.set_role_active(
        role_id=body.role_id,
        is_active=False,
        expected_version=body.expected_version,
        context=context,
    )
    # 2. 返回停用后的角色状态及版本，角色历史仍保留。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/enable", response_model=ApiResponse[RoleMutationResponse])
async def enable_role(request: Request,
                      body: RoleVersionRequest,
                      context: RoleStatusContext
                      ) -> ApiResponse[RoleMutationResponse]:
    """
        启用可管理角色，业务服务重新检查受影响用户的权限边界。
        访问条件：已登录且账号可用。
        所需权限：roles:status:update（启用或禁用角色）。
        目标限制：只允许操作可管理的下级自定义角色；恢复权限后不能让受影响用户越过操作者的管理范围。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、用于防止覆盖其他操作的期望角色版本。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含启用后角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # 启用会让已有角色绑定重新贡献权限，因此服务要检查恢复后的用户权限，不能只翻转状态。
    result = await role_service.set_role_active(
        role_id=body.role_id,
        is_active=True,
        expected_version=body.expected_version,
        context=context,
    )
    # 2. 返回启用后的角色状态及版本，不在路由额外修改权限。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/delete", response_model=ApiResponse[RoleMutationResponse])
async def delete_role(
    request: Request,
    body: RoleVersionRequest,
    context: Annotated[AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_DELETE, management=True))],
) -> ApiResponse[RoleMutationResponse]:
    """
        软删除可管理的自定义角色，并在同一事务中解除其存续关系。
        访问条件：已登录且账号可用。
        所需权限：roles:delete（软删除角色），由角色权限配置决定。
        目标限制：super_admin 和 user 不能删除；自定义角色仍须低于操作者且不得影响本人或不可管理用户。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、本次删除要求匹配的角色版本。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含删除结果、角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # 只提交删除意图；角色和关联关系的软删除、权限版本更新、审计由服务在同一事务内完成。
    result = await role_service.delete_role(
        context=context,
        role_id=body.role_id,
        expected_version=body.expected_version,
    )
    # 2. 返回服务提供的软删除结果，不把记录从数据库物理删除。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/permissions/bind", response_model=ApiResponse[RoleMutationResponse])
async def bind_role_permissions(
    request: Request,
    body: RolePermissionIdsRequest,
    context: Annotated[
        AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_PERMISSIONS_BIND, management=True)),
    ],
) -> ApiResponse[RoleMutationResponse]:
    """
        为可管理角色绑定指定权限，整批通过授权校验后一起生效。
        访问条件：已登录且账号可用。
        所需权限：roles:permissions:bind（给角色增加权限）。
        目标限制：只能管理下级自定义角色，且不能授予本人没有的权限；系统角色和本人持有的角色禁止在线修改。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、待绑定权限 ID 列表及期望角色版本。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含绑定后角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # permission_ids 是要增加的权限，不是替换后的完整列表；整批校验通过才执行写入。
    result = await role_service.change_role_permissions(
        role_id=body.role_id,
        permission_ids=body.permission_ids,
        operation="bind",
        context=context,
        expected_version=body.expected_version,
    )
    # 2. 返回增加指定权限后的角色结果和最新版本。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )


@router.post("/permissions/unbind", response_model=ApiResponse[RoleMutationResponse])
async def unbind_role_permissions(
    request: Request,
    body: RolePermissionIdsRequest,
    context: Annotated[
        AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_PERMISSIONS_UNBIND, management=True)),
    ],
) -> ApiResponse[RoleMutationResponse]:
    """
        解除可管理角色的指定权限，业务服务保留软删除历史。
        访问条件：已登录且账号可用。
        所需权限：roles:permissions:unbind（撤销角色的指定权限）。
        目标限制：只能管理下级自定义角色；系统角色、本人持有的角色和影响不可管理用户的变更都会被拒绝。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param body: 目标角色 ID、待解绑权限 ID 列表及期望角色版本。
    :param context: 依赖已验证的当前身份与完整权限上下文。
    :return: 包含解绑后角色快照及角色并发修改版本 role.version 的统一响应。
    """
    # 与绑定共用校验和事务流程，operation="unbind" 只解除本次指定的权限关系。
    result = await role_service.change_role_permissions(
        role_id=body.role_id,
        permission_ids=body.permission_ids,
        operation="unbind",
        context=context,
        expected_version=body.expected_version,
    )
    # 2. 返回解除指定权限后的角色结果和最新版本。
    return api_response(
        request,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data=result,
    )
