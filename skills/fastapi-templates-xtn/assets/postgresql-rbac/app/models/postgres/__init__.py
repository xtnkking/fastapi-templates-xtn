#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    集中登记 PostgreSQL 模型元数据，供使用者生成迁移；导入不连接数据库或执行建表。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        按用户、角色、权限、状态和审计业务登记模型
# 2026/09/23    XTN       V1.002        说明模型导出清单与导入副作用边界
# 2026/09/26    XTN       V1.003        账号审计模型改用更简洁的模块路径
# 2026/10/16    XTN       V1.004        默认仅登记统一操作审计，业务审计改为按需导入
# --------------------------------------------------------------------------------------------------


from app.models.postgres.base import Base
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.permission import Permission
from app.models.postgres.rbac_state import RbacState
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole

# 本包公开的模型名；上面的导入把各表登记到 Base.metadata，不执行建表或准备初始化数据。
__all__ = [
    "Base",
    "OperationAuditEvent",
    "Permission",
    "RbacState",
    "Role",
    "RolePermission",
    "User",
    "UserRole",
]
