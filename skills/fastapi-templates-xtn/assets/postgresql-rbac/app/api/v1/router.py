#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    API v1 总路由文件
#    只按业务装配接口，并统一声明 /api/v1 版本前缀
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        按认证、本人、用户、角色和权限五类业务集中装配接口
# 2026/09/23    XTN       V1.002        集中声明 API 版本前缀，业务路由只维护业务路径
# 2026/09/29    XTN       V1.003        公开入口和特殊认证规则归属 API 装配层，不再散落在 core
# 2026/09/29    XTN       V1.004        总路由只保留业务挂载，启动认证规则移至独立模块
# --------------------------------------------------------------------------------------------------


from fastapi import APIRouter

from app.api.v1.endpoints import auth, me, permissions, roles, users

# 版本前缀只在此声明；各业务模块只维护自己的业务路径。
router = APIRouter(prefix="/api/v1")

# 公开认证与当前登录会话。
router.include_router(auth.router)

# 当前用户自己的资料、密码和登录会话。
router.include_router(me.router)

# 后台用户管理。
router.include_router(users.router)

# 后台角色管理。
router.include_router(roles.router)

# 权限目录查询。
router.include_router(permissions.router)
