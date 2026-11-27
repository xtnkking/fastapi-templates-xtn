#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    第一版权限目录查询接口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        统一权限列表详情路径，详情 ID 使用查询参数
# 2026/09/23    XTN       V1.002        权限分页和详情业务统一交给 PermissionService
# 2026/09/23    XTN       V1.003        明确权限查询的访问条件和权限标识，补充接口阶段说明
# 2026/09/23    XTN       V1.004        对齐接口参数与业务调用，补充文档页查询参数中文说明
# 2026/09/26    XTN       V1.005        详情处理函数统一使用 detail 命名
# 2026/09/27    XTN       V1.006        统一访问权限说明并解释路由装饰器参数
# 2026/09/27    XTN       V1.007        为权限查询显式声明管理读取限流档位
# 2026/09/29    XTN       V2.000        简化路由装饰器并由权限依赖自动执行管理限流
# 2026/09/29    XTN       V2.001        使用独立权限定义并按请求语言返回内置权限说明
# 2026/09/30    XTN       V2.002        请求语言选择直接使用语言协商模块
# 2026/09/30    XTN       V2.003        查询接口显式注入 PostgreSQL 会话
# 2026/10/02    XTN       V2.004        每个接口使用单个明确权限的依赖
# 2026/10/09    XTN       V2.005        权限查询复用请求 ID 类型，不单独维护格式
# 2026/10/09    XTN       V2.006        普通成功响应使用统一默认业务码
# 2026/10/09    XTN       V2.007        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/13    XTN       V2.008        补齐接口业务执行与成功响应的通俗步骤
# 2026/10/14    XTN       V2.009        为文件请求日志记录权限查询动作和完成结果
# 2026/10/15    XTN       V2.010        移除路由重复的日志动作和结果赋值，保留权限查询流程
# 2026/10/19    XTN       V2.011        权限查询 ID 校验统一从公共模型导入
# 2026/10/22    XTN       V2.012        权限目录业务显式选择管理额度，与权限要求分开
# 2026/11/28    XTN       V2.013        列表和详情返回业务分组、名称及启动时收集的关联接口
# --------------------------------------------------------------------------------------------------


from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.i18n.language import locale_for_request
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, PageResponse, api_response
from app.db.postgres_db import get_postgres_session
from app.dependencies.permission import require_permission
from app.schemas.common import PermissionId
from app.schemas.permission import PermissionResponse
from app.services.permission_service import permission_service

# prefix 统一当前业务路径；response_model 会在运行时校验返回结构，因此关闭文档后仍保留。
router = APIRouter(prefix="/permissions")
# 权限目录属于管理业务，显式选择管理额度；其他带权限的普通业务无需设置此参数。

# 权限目录查询统一要求 permissions:read；它允许查看权限定义，不代表可以给角色授权。
# 依赖先验证登录及账号状态，再检查这一权限；别名只简化签名，不保存任何请求状态。
PermissionReadContext = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.PERMISSIONS_READ, management=True)),
]


@router.get("/list", response_model=ApiResponse[PageResponse[PermissionResponse]])
async def list_permissions(request: Request,
                           _context: PermissionReadContext,
                           db: Annotated[AsyncSession, Depends(get_postgres_session)],
                           page: Annotated[int, Query(ge=1, description="页码，从 1 开始；默认第 1 页。")] = 1,
                           page_size: Annotated[int, Query(ge=1, le=200, description="每页条数，默认 20 条。")] = 20
                           ) -> ApiResponse[PageResponse[PermissionResponse]]:
    """
        分页读取未删除权限，返回名称、分组、说明及实际关联接口。
        访问条件：已登录且账号可用。
        所需权限：permissions:read（查看系统权限目录）；普通 user 角色默认没有此权限。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param _context: 用于完成该接口准确权限检查的上下文，函数体不重复使用。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :param page: 从 1 开始的页码。
    :param page_size: 每页条数，HTTP 接口限制在 1 至 200。
    :return: 包含权限条目、页码、每页条数和总数的统一响应。
    """
    # 权限已通过；把本应用启动时收集的接口目录交给服务，不在请求期间扫描路由。
    data = await permission_service.list_permissions(
        db,
        page=page,
        page_size=page_size,
        permission_api_routes=request.app.state.permission_api_routes,
        locale=locale_for_request(request),
    )
    # 2. 将权限分页结果和查询成功提示包装成统一响应。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )


@router.get("/detail", response_model=ApiResponse[PermissionResponse])
async def get_permission_detail(request: Request,
                                permission_id: Annotated[PermissionId, Query(description="权限 ID；可从列表读取。")],
                                _context: PermissionReadContext,
                                db: Annotated[AsyncSession, Depends(get_postgres_session)]
                                ) -> ApiResponse[PermissionResponse]:
    """
        查询权限详情及其名称、分组、说明和关联接口；不存在或已删除时返回 404。
        访问条件：已登录且账号可用。
        所需权限：permissions:read（查看单个权限定义）。
        目标限制：这里只查询权限目录定义，不会读取某个用户的完整权限。

    :param request: 当前 HTTP 请求，用于读取服务资源和关联响应请求 ID。
    :param permission_id: 目标权限的业务 ID。
    :param _context: 用于完成该接口准确权限检查的上下文，函数体不重复使用。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭，不在接口提交事务。
    :return: 目标权限详情的统一响应。
    """
    # 只把经过参数校验的目标 ID 交给服务；未找到记录的错误也由服务统一处理。
    data = await permission_service.get_permission_detail(
        db,
        permission_id=permission_id,
        permission_api_routes=request.app.state.permission_api_routes,
        locale=locale_for_request(request),
    )
    # 2. 返回该权限的详情和查询成功提示，不改变权限分配。
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data=data,
    )
