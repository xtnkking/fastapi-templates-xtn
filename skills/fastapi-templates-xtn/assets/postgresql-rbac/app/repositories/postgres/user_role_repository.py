#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户角色绑定的批量查询和软删除；不执行权限决策或提交事务。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        明确用户角色查询和软解绑步骤，保留批量范围与锁定语义
# 2026/09/23    XTN       V1.002        解释查询范围、授权边界及初学者易混淆的数据语义
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/10/02    XTN       V1.004        移出仅供线下密码恢复使用的持有人查询
# 2026/10/10    XTN       V1.005        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.006        明确绑定查询去重、未删除范围及软解绑事务边界
# 2026/10/19    XTN       V1.007        精简绑定查询和解绑说明，纠正过时的版本更新描述
# 2026/10/24    XTN       V1.008        绑定和解绑的 Service 权限说明对齐当前名称
# 2026/10/24    XTN       V1.009        简化绑定查询、计数和解绑名称，明确查询范围与执行步骤
# --------------------------------------------------------------------------------------------------


from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.postgres.user import User, UserRole


class UserRoleRepository:
    """
        查询用户角色绑定，解绑时保留记录并写入删除标记。
        Service 负责 roles:bind/roles:unbind 权限检查和加锁。
    """

    async def get_role_ids(self, session: AsyncSession, *,
                           user_ids: set[str],
                           role_ids: frozenset[str] | None = None
                           ) -> set[str]:
        """
            查询这些用户已绑定的角色 ID，包含停用角色，排除已解绑记录。

        :param session: 当前事务的数据库会话。
        :param user_ids: 要读取绑定的用户集合；空集合不查询数据库。
        :param role_ids: 可选角色 ID 范围；None 查询全部，空集合返回空集。
        :return: 所有匹配角色 ID 的去重集合，不按用户分组。
        """
        # 1. 没有目标就直接返回；role_ids=None 表示查全部，空集合表示一个也不查。
        if not user_ids or role_ids == frozenset():
            return set()
        # 2. 从绑定表查角色 ID；停用角色仍需参与加锁，所以这里不筛选角色状态。
        role_ids_query = select(UserRole.role_id).where(
            UserRole.user_id.in_(user_ids),
            UserRole.deleted_at.is_(None),
        )
        if role_ids is not None:
            role_ids_query = role_ids_query.where(UserRole.role_id.in_(role_ids))
        # 3. 同一角色可能绑定给多个用户，返回时合并去重。
        role_ids_result = await session.scalars(role_ids_query)
        return set(role_ids_result.all())

    async def get_user_ids(self, session: AsyncSession, *,
                           role_id: str
                           ) -> set[str]:
        """
            查询绑定了这个角色的用户 ID，排除已删除用户和已解绑记录。

        :param session: 当前事务的数据库会话。
        :param role_id: 将要发生权限或状态变更的角色 ID。
        :return: 受角色变更影响、需要参与后续加锁的用户 ID 集合。
        """
        # 1. 用角色 ID 查绑定，同时排除已删除用户；停用用户也会受角色变更影响，仍需保留。
        user_ids_query = (
            select(UserRole.user_id)
            .join(User, (User.user_id == UserRole.user_id) & User.deleted_at.is_(None))
            .where(UserRole.role_id == role_id, UserRole.deleted_at.is_(None))
        )
        # 2. 返回用户 ID 集合，供 Service 找齐受影响的人并加锁。
        user_ids_result = await session.scalars(user_ids_query)
        return set(user_ids_result.all())

    async def unbind_roles(self, session: AsyncSession, *,
                           role_ids: frozenset[str],
                           deleted_at: datetime,
                           deleted_by_user_id: str,
                           user_id: str | None = None
                           ) -> None:
        """
            解绑指定角色，只写删除标记，保留历史记录。
            传 user_id 只解绑该用户；省略则解绑这些角色的所有用户。

        :param session: 当前事务的数据库会话。
        :param role_ids: 已通过业务校验并持锁的目标角色集合；空集合不写数据库。
        :param deleted_at: 外层事务统一采用的软删除时间。
        :param deleted_by_user_id: 已通过授权校验的操作者用户 ID。
        :param user_id: 可选目标用户 ID；None 表示指定角色的所有用户绑定。
        :return: 无返回值；记录变更由调用方统一提交或回滚。
        """
        # 1. 没有目标角色就直接返回，不能把空集合当成解绑全部角色。
        if not role_ids:
            return
        # 2. 只处理尚未解绑的关系，保留以前的解绑时间和操作人。
        binding_update = update(UserRole).where(UserRole.role_id.in_(role_ids), UserRole.deleted_at.is_(None))
        if user_id is not None:
            # 传了 user_id 就只解绑这一名用户。
            binding_update = binding_update.where(UserRole.user_id == user_id)
        # 3. 记下解绑时间和操作人；由 Service 连同审计一起提交，失败时一起回滚。
        binding_update = binding_update.values(deleted_at=deleted_at, deleted_by_user_id=deleted_by_user_id)
        await session.execute(binding_update)

    async def count_roles(self, session: AsyncSession, *,
                          user_id: str
                          ) -> int:
        """
            统计用户已绑定的角色数量，用于检查最多十个角色的限制。

        :param session: 当前事务的数据库会话。
        :param user_id: 目标用户的业务 ID。
        :return: 未软删除绑定的条数，包括停用角色的绑定。
        """
        # 1. 只排除已解绑记录；停用角色仍占名额，不能靠停用绕过数量上限。
        role_count_query = select(func.count(UserRole.id)).where(
            UserRole.user_id == user_id, UserRole.deleted_at.is_(None),
        )
        # 2. 读取数量，没有绑定时返回 0。
        total_roles = await session.scalar(role_count_query)
        return int(total_roles or 0)


# 无状态共享实例；角色数量、授权范围和事务提交均由业务层管理。
user_role_repository = UserRoleRepository()
