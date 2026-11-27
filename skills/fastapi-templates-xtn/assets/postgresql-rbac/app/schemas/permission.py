#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    权限目录的公开字段，不执行数据库查询或权限判断。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        增加 JSON 目标标识，清理无调用的旧权限替换请求
# 2026/09/23    XTN       V1.002        从 access 模块按权限业务独立公开字段
# 2026/09/23    XTN       V1.003        为权限公开字段补充面向调用方的中文说明
# 2026/09/23    XTN       V1.004        在接口文档中显示权限 ID、能力键与说明的中文含义
# 2026/09/29    XTN       V1.005        明确内置权限说明随响应语言切换，权限码保持固定
# 2026/10/10    XTN       V1.006        权限目录条目继承统一响应基类
# 2026/10/19    XTN       V1.007        权限 ID 校验类型统一从公共模型导入
# 2026/11/28    XTN       V1.008        权限目录返回名称、业务分组和实际关联接口
# --------------------------------------------------------------------------------------------------


from pydantic import Field

from app.core.response import ResponseBase
from app.schemas.common import PermissionId


class PermissionApiRouteResponse(ResponseBase):
    """
        入口明确要求某项权限的接口，只展示请求方法和完整路径。
    """

    method: str = Field(description="接口的 HTTP 请求方法，例如 GET 或 POST。")
    path: str = Field(description="实际注册的完整接口路径，包含 /api/v1 等路由前缀。")


class PermissionResponse(ResponseBase):
    """
        权限目录条目，包含名称、分组、用途说明和明确检查此权限的接口。
    """

    id: PermissionId = Field(description="权限目录条目 ID，绑定或解绑角色权限时提交此值。")
    key: str = Field(description="精确权限键，例如 roles:read；表示允许执行的具体操作。")
    name: str = Field(description="简短权限名称，随 Accept-Language 返回中文或英文。")
    group_key: str = Field(description="稳定的业务分组标识，例如 users；只用于分组，不参与授权。")
    group_name: str = Field(description="业务分组的展示名称，例如用户管理；跟随响应语言。")
    description: str = Field(description="权限用途说明；内置权限随 Accept-Language 返回中文或英文。")
    api_routes: tuple[PermissionApiRouteResponse, ...] = Field(
        description="入口明确要求这项权限的接口；启动时自动收集，没有 HTTP 入口时为空数组。",
    )
