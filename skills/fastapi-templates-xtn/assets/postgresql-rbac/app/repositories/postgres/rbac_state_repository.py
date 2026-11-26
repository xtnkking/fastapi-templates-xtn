#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    修改角色权限前锁住全局记录，让并发授权写入排队。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        集中注册开关和授权状态读取，明确查询与加锁步骤
# 2026/09/23    XTN       V1.002        解释查询范围、授权边界及初学者易混淆的数据语义
# 2026/09/30    XTN       V1.003        移除不再使用的注册开关读取
# 2026/10/13    XTN       V1.004        补齐状态读取步骤及缺失状态的失败契约
# 2026/10/16    XTN       V1.005        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.006        删除普通状态读取，只保留授权写事务的统一加锁入口
# 2026/10/19    XTN       V1.007        用简短说明解释全局记录和写锁
# --------------------------------------------------------------------------------------------------


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import unavailable_503
from app.models.postgres.rbac_state import RbacState


class RbacStateRepository:
    """
        读取并锁住唯一的 global 记录，用来协调授权写入。
    """

    async def lock_rbac_state(self, session: AsyncSession) -> RbacState:
        """
            先锁住 global 记录，让其他授权写事务等待。
            取得锁后，调用方仍需重查权限；提交或回滚后才释放锁。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :return: 已加锁的 global 记录。
        :raises AppError: 全局授权状态未初始化，不能继续授权写入。
        """
        # 授权写入都先锁这同一条记录，再锁用户和角色，保持取锁顺序一致。
        statement = (
            select(RbacState)
            .where(RbacState.scope == "global")
            .with_for_update()
        )
        state = await session.scalar(statement)
        # 缺少记录说明初始化未完成，需由使用者处理，不能在请求中临时补建。
        if state is None:
            raise unavailable_503("rbac_state_missing")
        return state


# 共享仓储不保存会话或锁，锁属于调用方的事务。
rbac_state_repository = RbacStateRepository()
