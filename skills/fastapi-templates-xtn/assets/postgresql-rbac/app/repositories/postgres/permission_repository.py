#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    权限目录的数据访问；统一排除软删除权限。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        分离权限列表与计数查询，共用存续范围并展开查询步骤
# 2026/09/23    XTN       V1.002        解释查询范围、授权边界及初学者易混淆的数据语义
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/10/02    XTN       V1.004        展开列表排序、计数范围及批量查询条件
# 2026/10/13    XTN       V1.005        补齐查询构造步骤并明确目录模型与事务边界
# 2026/10/19    XTN       V1.006        精简权限目录查询说明
# --------------------------------------------------------------------------------------------------


from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.models.postgres.permission import Permission


class PermissionRepository:
    """
        查询未删除权限的列表、详情和 ID，不自行提交事务。
        登录和 permissions:read 权限由接口依赖检查。
    """

    @staticmethod
    def _select_live_permissions() -> Select[tuple[Permission]]:
        """
            为列表、总数和详情统一加上“未删除”条件。

        :return: 尚未执行的权限查询，未加分页条件。
        """
        # deleted_at 为空表示未删除；这里只拼 SQL，尚未查数据库。
        return select(Permission).where(Permission.deleted_at.is_(None))

    async def list_live_permissions(self, session: AsyncSession, *,
                                    offset: int,
                                    limit: int
                                    ) -> tuple[Permission, ...]:
        """
            按权限标识和 ID 稳定排序，读取指定范围的未软删除权限。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param offset: 跳过的记录数，由业务层根据页码计算。
        :param limit: 最多读取的记录数，由接口校验分页上限。
        :return: 当前页的权限对象元组；没有匹配记录时为空。
        """
        # 先固定排序再分页，避免相邻页的顺序不稳定。
        statement = (
            self._select_live_permissions()
            .order_by(Permission.key, Permission.id)
            .offset(offset)
            .limit(limit)
        )
        # 读出当前页，会话关闭和事务结束由调用方负责。
        result = await session.scalars(statement)
        return tuple(result.all())

    async def count_live_permissions(self, session: AsyncSession) -> int:
        """
            统计与权限列表相同范围的未软删除权限数量。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :return: 权限目录中未软删除的记录总数。
        """
        # 总数沿用列表的未删除条件，避免两个结果范围不同。
        live_permissions = self._select_live_permissions().subquery()
        statement = select(func.count()).select_from(live_permissions)
        total = await session.scalar(statement)
        return int(total or 0)

    async def get_live_permission(self, session: AsyncSession, *,
                                  permission_id: str
                                  ) -> Permission | None:
        """
            按业务 ID 查询未删除权限，调用方负责检查查询权限。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param permission_id: 目标权限的业务 ID。
        :return: 权限对象；不存在或已软删除时返回 None。
        """
        # 将软删除记录视为不存在，调用方不需要再次判断删除状态。
        statement = self._select_live_permissions().where(Permission.id == permission_id)
        result = await session.execute(statement)
        return result.scalar_one_or_none()

    async def load_permission_ids(self, session: AsyncSession,
                                  permission_keys: frozenset[str]
                                  ) -> dict[str, str]:
        """
            按精确权限标识查询未软删除的权限 ID。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param permission_keys: 待查询的精确权限标识集合。
        :return: 找到的权限标识到 ID 的映射；缺失项不在结果中。
        """
        # 没有目标就不查数据库。
        if not permission_keys:
            return {}
        # 一次查出全部“权限标识 → ID”，供后续绑定使用。
        statement = select(Permission.key, Permission.id).where(
            Permission.key.in_(permission_keys),
            Permission.deleted_at.is_(None),
        )
        result = await session.execute(statement)
        rows = result.all()
        return {row.key: row.id for row in rows}

    async def load_permission_keys(self, session: AsyncSession,
                                   permission_ids: frozenset[str]
                                   ) -> dict[str, str]:
        """
            按业务 ID 查询未软删除的权限标识。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param permission_ids: 待查询的权限业务 ID 集合。
        :return: 找到的权限 ID 到标识的映射；缺失项不在结果中。
        """
        # 没有目标就不查数据库。
        if not permission_ids:
            return {}
        # 只返回未删除权限，缺少的 ID 交给业务层处理。
        statement = select(Permission.id, Permission.key).where(
            Permission.id.in_(permission_ids),
            Permission.deleted_at.is_(None),
        )
        result = await session.execute(statement)
        rows = result.all()
        return {row.id: row.key for row in rows}


# 共享仓储不保存用户或会话，每次查询由调用方传入会话。
permission_repository = PermissionRepository()
