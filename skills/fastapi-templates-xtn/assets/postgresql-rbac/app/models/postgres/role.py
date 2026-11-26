#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 角色及角色权限绑定模型，声明等级、系统角色和授权关系约束。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        从 access 模块按业务拆分，保留原模型字段和约束
# 2026/09/23    XTN       V1.002        补充角色等级、保护标志、编辑版本和授权关系说明
# 2026/10/02    XTN       V1.003        整理等级和版本说明，区分角色唯一与持有人唯一
# 2026/10/02    XTN       V1.004        系统角色标志只允许用于三个固定角色键
# 2026/10/09    XTN       V1.005        主键、外键长度及格式约束引用核心 ID 规则
# 2026/10/10    XTN       V1.006        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/15    XTN       V1.007        用户权限版本移除后更新角色编辑版本的用途说明
# 2026/10/15    XTN       V1.008        权限关系统一使用绑定操作人和绑定时间字段
# 2026/10/20    XTN       V1.009        角色等级字段及对应列约束统一使用 level
# --------------------------------------------------------------------------------------------------


from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import ENTITY_ID_LENGTH, ROLE_ID_PATTERN, ROLE_PERMISSION_ID_PATTERN, new_entity_id
from app.models.postgres.base import Base


class Role(Base):
    """
        角色及其等级，记录系统身份、启停状态和并发修改版本。
        普通角色采用软删除；固定系统角色必须保持有效，不能停用或删除。
    """

    # 角色定义表；一个用户可绑定多个角色，具体能力来自 RolePermission 中的有效绑定。
    __tablename__ = "roles"
    # 角色键终身唯一；检查约束固定三个系统角色的等级与标志，软删除必须同时停用。
    # 唯一索引只能保证一条超级管理员角色定义，不能保证只有一名用户绑定该角色。
    # 超级管理员用户绑定的最终唯一性仍需使用者在数据库自行落实保护。
    __table_args__ = (
        CheckConstraint(f"id ~ '{ROLE_ID_PATTERN}'", name="id_format"),
        UniqueConstraint("key", name="uq_roles_key"),
        CheckConstraint(
            "level >= 0 AND level <= 1000",
            name="level_range",
        ),
        CheckConstraint(
            "level < 1000 OR is_super_admin",
            name="super_admin_tier_reserved",
        ),
        CheckConstraint(
            "is_system OR (level >= 1 AND level <= 999)",
            name="custom_role_tier_range",
        ),
        CheckConstraint(
            "NOT is_system OR key IN ('super_admin', 'admin', 'user')",
            name="system_role_key_fixed",
        ),
        CheckConstraint("version >= 0", name="version_nonnegative"),
        CheckConstraint(
            "NOT is_protected OR is_system",
            name="protected_role_is_system",
        ),
        CheckConstraint(
            "NOT is_system OR (is_active AND deleted_at IS NULL)",
            name="system_role_always_available",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR NOT is_active",
            name="deleted_role_inactive",
        ),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_role_deleting_user_requires_timestamp",
        ),
        CheckConstraint(
            "NOT is_super_admin OR (is_system AND is_protected AND is_active "
            "AND level = 1000 AND key = 'super_admin' "
            "AND deleted_at IS NULL)",
            name="super_admin_flag_shape",
        ),
        CheckConstraint(
            "key <> 'super_admin' OR (is_system AND is_protected AND is_super_admin "
            "AND is_active AND level = 1000 AND deleted_at IS NULL)",
            name="super_admin_role_shape",
        ),
        CheckConstraint(
            "key <> 'admin' OR (is_system AND NOT is_protected AND NOT is_super_admin "
            "AND is_active AND level = 500 AND deleted_at IS NULL)",
            name="admin_role_shape",
        ),
        CheckConstraint(
            "key <> 'user' OR (is_system AND NOT is_protected AND NOT is_super_admin "
            "AND is_active AND level = 0 AND deleted_at IS NULL)",
            name="user_role_shape",
        ),
        Index("ix_roles_active", "is_active"),
        Index("ix_roles_deleted_at", "deleted_at"),
        Index(
            "uq_roles_single_super_admin",
            "is_super_admin",
            unique=True,
            postgresql_where=text("is_super_admin"),
        ),
    )

    # 角色业务 ID，随机生成；API 的 role_id 与用户角色绑定都引用它。
    id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        primary_key=True,
        default=lambda: new_entity_id("R"),
    )
    # 稳定角色编码；super_admin、admin、user 为保留值，软删除后也不能复用编码。
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    # 后台展示名称，可管理的普通角色可以通过更新接口修改，不参与等级比较。
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    # 角色用途说明；空字符串表示暂未填写，不等于角色没有权限。
    description: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    # 角色等级不是权限数量；数字越大等级越高。自定义角色为 1～999，
    # 固定 user/admin/super_admin 为 0/500/1000，1000 只供超级管理员使用。
    level: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    # True 角色启用，False 不再提供有效权限；停用不删除用户与角色的历史绑定。
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # True 表示在线管理保护；也会使绑定用户的整体授权进入受保护状态。
    is_protected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # True 表示固定系统角色，必须保持启用且不能软删除；不等于拥有所有权限。
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # True 仅用于唯一超级管理员角色，与固定 key、等级和保护标志一起受约束。
    is_super_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # 角色编辑版本：前端提交读取到的 expected_version；版本已变化时拒绝覆盖别人修改。
    # 它与用户的 token_version（撤销旧登录）用途不同，不决定用户是否有权限。
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    # 角色创建的带时区时间，由数据库生成。
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # 软删除时间；None 表示未删除。普通角色删除后保留历史记录，且必须已停用。
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 执行角色软删除的用户 ID；None 表示未记录操作者，不能代替 deleted_at 判断状态。
    deleted_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey(
            "users.user_id",
            name="fk_roles_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class RolePermission(Base):
    """
        角色与权限的绑定关系，记录授权人及授权时间。
        解绑使用软删除；唯一索引只约束有效关系，历史关系继续保留。
    """

    # 角色获得某项权限的一次绑定记录，与用户获得角色的 user_roles 分开保存。
    __tablename__ = "role_permissions"
    # 每个角色与权限最多有一条有效绑定；软删除的旧关系继续保留作历史。
    __table_args__ = (
        CheckConstraint(f"id ~ '{ROLE_PERMISSION_ID_PATTERN}'", name="id_format"),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_role_permission_deleting_user_requires_timestamp",
        ),
        Index(
            "uq_role_permissions_live",
            "role_id",
            "permission_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_role_permissions_permission_role", "permission_id", "role_id"),
        Index("ix_role_permissions_deleted_at", "deleted_at"),
    )

    # 本次角色权限绑定记录 ID，不是角色 ID 或权限 ID。
    id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        primary_key=True,
        default=lambda: new_entity_id("RP"),
    )
    # 接受这项权限的角色 ID，关联 roles.id。
    role_id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # 授予角色的权限目录 ID，关联 permissions.id；实际能力键由目录记录给出。
    permission_id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("permissions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # 绑定操作人：是谁给这个角色绑定了权限。
    # None 表示线下初始化，没有在线操作人；不是接受权限的角色 ID。
    bound_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=True,
    )
    # 绑定时间：这个角色从什么时候开始拥有该权限，保存带时区时间。
    # 解绑后保留原时间；以后重新绑定时创建新的关系记录。
    bound_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # 解绑时间；None 表示关系未解绑，实际生效仍要求角色和权限本身有效。
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 执行本次权限解绑的用户 ID；None 表示未记录具体操作者。
    deleted_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey(
            "users.user_id",
            name="fk_role_permissions_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
