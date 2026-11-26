#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 授权协调模型，只为权限写事务提供统一行锁入口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        从 access 模块按业务拆分，保留原模型字段和约束
# 2026/09/23    XTN       V1.002        区分统一授权锁、权限版本与公开注册开关
# 2026/09/30    XTN       V1.003        移除公开注册开关字段，保留授权协调状态
# 2026/10/16    XTN       V1.004        删除全局权限计数，只保留固定授权锁记录
# --------------------------------------------------------------------------------------------------


from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.postgres.base import Base


class RbacState(Base):
    """
        当前项目唯一的权限状态行，变更时用作统一加锁入口。
        只有 scope 标识这条固定记录；该记录长期保留，不提供删除操作。
    """

    # 当前单项目共用一行权限状态，不保存租户、用户登录或 Token 数据。
    __tablename__ = "rbac_state"
    # scope 只能是 global，主键使其最多存在一行；初始行仍由项目维护者准备。
    __table_args__ = (
        CheckConstraint("scope = 'global'", name="scope_global"),
    )

    # 固定主键 global，所有授权写操作先锁这一行以统一并发顺序；不是全站限流额度。
    scope: Mapped[str] = mapped_column(String(16), primary_key=True)
