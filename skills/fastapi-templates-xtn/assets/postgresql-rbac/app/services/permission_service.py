#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    查询权限列表和详情；接口依赖负责检查查询权限。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        新建权限目录业务入口，统一分页及详情结果
# 2026/09/23    XTN       V1.001        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.003        逐项展示权限与分页响应字段
# 2026/09/29    XTN       V1.004        权限说明按请求语言从独立权限目录翻译
# 2026/09/30    XTN       V1.005        默认语言改从语言协商模块读取
# 2026/10/02    XTN       V1.006        展开权限列表的公开字段与双语说明映射
# 2026/10/09    XTN       V1.007        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/13    XTN       V1.008        分步说明权限详情的未删除查询与公开字段转换
# 2026/10/16    XTN       V1.009        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/19    XTN       V1.010        精简权限查询注释，保留查询条件和权限要求
# 2026/10/24    XTN       V1.011        共用权限响应转换，简化列表变量及查询步骤说明
# --------------------------------------------------------------------------------------------------


from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.permissions import get_permission_description
from app.core.exceptions import not_found_404
from app.core.i18n.language import DEFAULT_LOCALE
from app.core.response import PageResponse
from app.models.postgres.permission import Permission
from app.repositories.postgres.permission_repository import permission_repository
from app.schemas.permission import PermissionResponse


class PermissionService:
    """
        查询权限目录，不创建或修改权限。
    """

    @staticmethod
    def _build_permission_response(permission: Permission, *, locale: str) -> PermissionResponse:
        """
            把已查到的权限整理成响应，不再查数据库。

        :param permission: 已查询到的权限记录。
        :param locale: 接口已协商的响应语言。
        :return: 权限 ID、权限标识和对应语言的说明。
        """
        # 内置权限翻译成请求语言，自定义权限保留数据库里的说明。
        return PermissionResponse(
            id=permission.id,
            key=permission.key,
            description=get_permission_description(
                permission.key,
                stored_description=permission.description,
                locale=locale,
            ),
        )

    async def list_permissions(self, session: AsyncSession, *,
                               page: int,
                               page_size: int,
                               locale: str = DEFAULT_LOCALE
                               ) -> PageResponse[PermissionResponse]:
        """
            分页查询权限列表和总数。
            需要 permissions:read；能查看权限目录不代表拥有目录中的权限。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param page: 从 1 开始的页码，已通过接口范围校验。
        :param page_size: 每页条数，已通过接口上限校验。
        :param locale: 接口已协商的响应语言；直接调用时默认中文。
        :return: 当前页权限列表、页码、每页条数和未删除权限总数。
        """
        # 1. 查未删除权限的总数和当前页，例如第 3 页、每页 20 条，先跳过 40 条。
        offset = (page - 1) * page_size
        total_permissions = await permission_repository.count_live_permissions(session)
        permissions = await permission_repository.list_live_permissions(
            session,
            offset=offset,
            limit=page_size,
        )
        # 2. 每条权限按相同规则整理字段和语言。
        permission_responses = [
            self._build_permission_response(permission, locale=locale)
            for permission in permissions
        ]
        # 3. 带上分页信息返回，当前页没有权限时列表为空。
        return PageResponse(
            items=permission_responses,
            page=page,
            page_size=page_size,
            total=total_permissions,
        )

    async def get_permission_detail(self, session: AsyncSession, *,
                                    permission_id: str,
                                    locale: str = DEFAULT_LOCALE
                                    ) -> PermissionResponse:
        """
            查询权限详情；不存在或已删除都返回 404。
            需要 permissions:read，此处只查询，不授予权限。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param permission_id: 要查询的权限业务 ID。
        :param locale: 接口已协商的响应语言；直接调用时默认中文。
        :return: 权限 ID、权限标识和说明。
        :raises AppError: 权限不存在或已经软删除。
        """
        # 1. 按 ID 查询未删除的权限。
        permission = await permission_repository.get_live_permission(session, permission_id=permission_id)
        # 2. 没查到时返回 404，不区分不存在和已删除。
        if permission is None:
            raise not_found_404("permission_not_found")
        # 3. 复用列表的字段和语言规则返回详情。
        return self._build_permission_response(permission, locale=locale)


# 共用服务对象，数据库会话由每次调用传入。
permission_service = PermissionService()
