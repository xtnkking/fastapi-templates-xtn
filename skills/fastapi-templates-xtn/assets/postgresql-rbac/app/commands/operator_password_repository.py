#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    仅供线下超级管理员密码恢复命令使用的 PostgreSQL 查询。
#    不进入新项目默认生成结果，也不提供 HTTP 接口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        从默认用户角色 Repository 移出维护命令专用查询
# 2026/10/13    XTN       V1.001        通俗说明唯一超级管理员持有人查询步骤
# --------------------------------------------------------------------------------------------------

"""查询线下密码恢复命令需要的超级管理员持有人。"""


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.roles import SystemRoleKey
from app.models.postgres.role import Role
from app.models.postgres.user import UserRole


class OperatorPasswordRepository:
    """提供线下恢复命令专用的 PostgreSQL 查询，不提交事务。"""

    async def load_live_super_admin_holder_ids(self, session: AsyncSession) -> frozenset[str]:
        """
            读取未解绑的超级管理员持有人，确认密码只能重置给唯一持有人。
            调用方必须先持有全局授权写锁；停用账号也算已有持有人。

        :param session: 调用方持有写锁并管理事务的 PostgreSQL 异步会话。
        :return: 超级管理员绑定中的用户 ID 不可变集合。
        """
        # 1. 查未删除的超级管理员角色和未解绑用户；账号停用也仍算持有人，不能误判成空缺。
        statement = (
            select(UserRole.user_id)
            .join(Role, (Role.id == UserRole.role_id) & Role.deleted_at.is_(None))
            .where(Role.key == SystemRoleKey.SUPER_ADMIN.value, UserRole.deleted_at.is_(None))
            .order_by(UserRole.user_id)
        )
        # 2. 执行查询并返回去重后的用户 ID；这里只查询，不自行提交或修改绑定。
        holder_ids = await session.scalars(statement)
        return frozenset(holder_ids.all())


operator_password_repository = OperatorPasswordRepository()
