#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL ORM 公共基类及约束命名；提供 metadata，不执行建表。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释约束命名模板和模型元数据职责
# --------------------------------------------------------------------------------------------------

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# 统一生成数据库约束名称，便于定位错误及用户自行生成迁移；占位符由 SQLAlchemy 替换。
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",  # 普通索引：表名 + 相关列名。
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",  # 唯一约束：防止指定列组合出现重复值。
    "ck": "ck_%(table_name)s_%(constraint_name)s",  # 检查约束：保留业务提供的规则名称。
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",  # 外键：标明本表列与被引用表。
    "pk": "pk_%(table_name)s",  # 主键：一张表内唯一定位一条记录。
}


class Base(DeclarativeBase):
    """
        PostgreSQL 模型统一基类，为索引、唯一约束和外键提供稳定名称。
    """

    # 保存所有模型的表结构描述并复用统一命名；声明 metadata 不会连接数据库或执行建表。
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
