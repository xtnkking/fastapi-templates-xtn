#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 权限目录模型，声明稳定权限键和软删除字段。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        从 access 模块按业务拆分，保留原模型字段和约束
# 2026/09/23    XTN       V1.002        说明权限 ID、能力键和软删除字段的不同用途
# 2026/10/09    XTN       V1.003        主键、外键长度及格式约束引用核心 ID 规则
# 2026/10/10    XTN       V1.004        统一用户身份命名，区分用户 ID、当前用户及目标用户
# --------------------------------------------------------------------------------------------------


from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import ENTITY_ID_LENGTH, PERMISSION_ID_PATTERN, new_entity_id
from app.models.postgres.base import Base


class Permission(Base):
    """
        权限目录中的单个稳定权限键，采用软删除，删除后不重复使用原权限键。
    """

    # 权限目录表；定义能力并不等于已经授予某个角色，授权关系在 role_permissions。
    __tablename__ = "permissions"
    # 有删除操作者时必须同时有删除时间；删除时间索引用于排除历史记录。
    __table_args__ = (
        CheckConstraint(f"id ~ '{PERMISSION_ID_PATTERN}'", name="id_format"),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_permission_deleting_user_requires_timestamp",
        ),
        Index("ix_permissions_deleted_at", "deleted_at"),
    )

    # 权限条目的随机 ID，用于绑定和查询；不是接口权限校验使用的 key。
    id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        primary_key=True,
        default=lambda: new_entity_id("P"),
    )
    # 稳定能力键，例如 roles:read；必须精确匹配，软删除后也不允许复用同一个键。
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    # 告诉维护者这项权限允许做什么；说明文字不参与权限计算。
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # 软删除时间，带时区；None 表示权限仍在有效目录中。
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 删除此权限的操作者用户 ID；None 表示未记录操作者，不等于未删除。
    deleted_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey(
            "users.user_id",
            name="fk_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
