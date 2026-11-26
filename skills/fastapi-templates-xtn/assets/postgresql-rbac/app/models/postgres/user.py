#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 用户及用户角色绑定模型，声明账号状态、密码哈希和关系约束。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        从 access 模块按业务拆分，保留原模型字段和约束
# 2026/09/23    XTN       V1.002        补充用户字段、登录版本与角色绑定的阅读说明
# 2026/09/30    XTN       V1.003        删除临时密码状态字段并简化密码状态约束
# 2026/10/02    XTN       V1.004        整理版本字段说明并准确解释自行注册的角色分配人
# 2026/10/09    XTN       V1.005        主键、外键长度及格式约束引用核心 ID 规则
# 2026/10/10    XTN       V1.006        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/15    XTN       V1.007        移除用户权限版本字段与约束，保留登录撤销版本
# 2026/10/15    XTN       V1.008        角色关系使用绑定操作人和绑定时间字段，补齐直白说明
# 2026/11/26    XTN       V1.009        用户名列长度及检查约束引用统一规则
# --------------------------------------------------------------------------------------------------


from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import ENTITY_ID_LENGTH, USER_ID_PATTERN, USER_ROLE_ID_PATTERN, new_entity_id
from app.core.security.user_name import MAX_USER_NAME_LENGTH, USER_NAME_PATTERN
from app.models.postgres.base import Base


class User(Base):
    """
        本地用户名密码用户，密码仅保存哈希，并记录登录撤销版本。
        账号采用软删除；删除时必须停用并清除密码哈希，用户名仍保持唯一占用。
    """

    # 账号实体所在表；角色归属保存在下方 UserRole，不通过此表新增管理员标志。
    __tablename__ = "users"
    # 用户名唯一约束覆盖软删除账号，删除后仍不能被别人重新注册使用。
    # 其余检查保证密码状态相互匹配、已删除用户停用，声明约束不会自行建表。
    __table_args__ = (
        CheckConstraint(f"user_id ~ '{USER_ID_PATTERN}'", name="user_id_format"),
        UniqueConstraint("user_name", name="uq_users_user_name"),
        CheckConstraint(
            f"user_name ~ '{USER_NAME_PATTERN}'",
            name="user_name_format",
        ),
        CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        CheckConstraint(
            "password_hash IS NULL OR password_hash ~ "
            "'^\\$argon2id\\$v=19\\$m=[1-9][0-9]*,t=[1-9][0-9]*,"
            "p=[1-9][0-9]*\\$[A-Za-z0-9+/]{16,}\\$"
            "[A-Za-z0-9+/]{16,}$'",
            name="password_hash_shape",
        ),
        CheckConstraint(
            "(password_hash IS NULL AND password_changed_at IS NULL) OR "
            "(password_hash IS NOT NULL AND password_changed_at IS NOT NULL)",
            name="password_state_coherent",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR password_hash IS NULL",
            name="deleted_user_no_password",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR NOT is_active",
            name="deleted_user_inactive",
        ),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_deleting_user_requires_timestamp",
        ),
        Index("ix_users_deleted_at", "deleted_at"),
    )

    # 用户业务 ID：U 加 14 位安全随机字符；JWT user_id 和角色绑定均使用它。
    user_id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        primary_key=True,
        default=lambda: new_entity_id("U"),
    )
    # 登录用户名；列长度和上面的格式约束都读取统一规则，首尾空白由应用层清理。
    user_name: Mapped[str] = mapped_column(String(MAX_USER_NAME_LENGTH), nullable=False)
    # 只存 Argon2id 哈希，不存明文；None 表示没有可用本地密码，删除账号时也会清空。
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # 当前密码最近设置时间，带时区；None 与没有密码哈希配套，不是“从未登录”。
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # True 允许账号使用，False 表示停用；账号启用并不代表已获得任何管理权限。
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # True 表示账号自身受在线管理保护；角色带来的保护还需汇入完整授权快照。
    is_protected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # 登录撤销版本：改密、封号或强制退出时递增；Redis 记录版本不匹配就拒绝旧登录。
    # 此值不写入 JWT 声明，由服务端保存并核对。
    token_version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    # 账号创建时间，使用数据库生成的带时区时间，不是秒数或毫秒数。
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # 软删除时间；None 表示未删除，有时间即从正常账号查询和登录范围中排除。
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 执行软删除的用户 ID；None 表示没有记录删除操作者，不能单独据此判断是否已删除。
    deleted_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey(
            "users.user_id",
            name="fk_users_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )


class UserRole(Base):
    """
        用户与角色的绑定关系，记录分配人及分配时间。
        撤销角色使用软删除；同一用户和角色只允许存在一条有效绑定关系。
    """

    # 每行是一条授权关系；用户和角色本身仍分别保存在 users、roles。
    __tablename__ = "user_roles"
    # 唯一索引只覆盖未软删除的绑定：可以保留历史，但不能重复授予同一个有效角色。
    __table_args__ = (
        CheckConstraint(f"id ~ '{USER_ROLE_ID_PATTERN}'", name="id_format"),
        CheckConstraint(
            "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
            name="deleted_user_role_deleting_user_requires_timestamp",
        ),
        Index(
            "uq_user_roles_live",
            "user_id",
            "role_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_user_roles_role_user", "role_id", "user_id"),
        Index("ix_user_roles_deleted_at", "deleted_at"),
    )

    # 这一次用户角色绑定的记录 ID，区别于下面的用户 ID 和角色 ID。
    id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        primary_key=True,
        default=lambda: new_entity_id("UR"),
    )
    # 接受角色授权的用户 ID，关联 users.user_id；不是执行授权的管理员 ID。
    user_id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    # 授予的角色 ID，关联 roles.id；默认注册和新增用户都必须绑定 user 角色。
    role_id: Mapped[str] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # 绑定操作人：是谁给这个用户绑定了角色。
    # None 表示自行注册或线下初始化，没有在线操作人。
    bound_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=True,
    )
    # 绑定时间：这个用户从什么时候开始拥有该角色，保存带时区时间。
    # 解绑后保留原时间；以后重新绑定时创建新的关系记录。
    bound_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # 解绑时间；None 表示关系仍存在，是否实际提供权限还要检查账号和角色启停状态。
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 执行本次角色解绑的用户 ID；None 表示未记录具体操作者。
    deleted_by_user_id: Mapped[str | None] = mapped_column(
        String(ENTITY_ID_LENGTH, collation="C"),
        ForeignKey(
            "users.user_id",
            name="fk_user_roles_deleted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
