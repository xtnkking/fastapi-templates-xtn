#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    角色管理的请求与响应格式，负责版本、修改字段和权限列表的纯参数校验。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        增加 JSON 目标标识，清理无调用的旧权限替换请求
# 2026/09/23    XTN       V1.002        从 access 模块归入角色业务，合并仅用于补充目标 ID 的请求层次
# 2026/09/23    XTN       V1.003        解释角色字段、并发版本和省略值的业务含义
# 2026/09/23    XTN       V1.004        为接口文档补齐角色字段中文说明，保留修改字段的省略与非空约束
# 2026/09/26    XTN       V1.005        请求模型统一使用 Request 后缀
# 2026/10/02    XTN       V1.006        请求字段按目标、版本、修改内容排列并说明文档校正边界
# 2026/10/02    XTN       V1.007        明确 JSON Schema 钩子不代表公开文档路由
# 2026/10/09    XTN       V1.008        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.009        角色请求与响应统一继承公共基类，保留修改请求的专用结构配置
# 2026/10/13    XTN       V1.010        补齐字段校验函数的通俗说明和逻辑步骤
# 2026/10/19    XTN       V1.011        业务 ID 校验类型统一从公共模型导入
# 2026/10/19    XTN       V1.012        角色操作只返回最终角色信息，不返回内部变更标记
# 2026/10/20    XTN       V1.013        角色创建请求和响应的等级统一使用 level
# 2026/10/26    XTN       V1.014        说明软删除角色的列表结果返回空权限
# --------------------------------------------------------------------------------------------------


from datetime import datetime
from typing import Any, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from app.core.response import ResponseBase
from app.schemas.common import PermissionId, RequestBase, RoleId


def _role_update_json_schema(schema: dict[str, Any]) -> None:
    """
        补充角色修改请求的离线 JSON Schema 约束，表达字段可省略但不能显式传入 null。
        名称与说明至少提交一项，规则与运行时请求校验保持一致。
        默认不开放文档 URL；此函数只校正离线生成的接口结构，不执行请求校验。

    :param schema: Pydantic 生成、允许原位调整的 JSON Schema 字典。
    :return: 无返回值，在字段结构有效时直接更新传入的字典。
    """
    # 1. 先找到字段结构；没有字段字典就不改，避免破坏框架生成的其他结构。
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    # 2. 在离线结构中标明名称和说明的文字长度，以及“可以不传，但不能传 null”。
    properties["name"] = {
        "type": "string",
        "minLength": 1,
        "maxLength": 160,
        "title": "Name",
        "description": "新的角色展示名称；省略表示不修改，不允许显式传 null。",
    }
    properties["description"] = {
        "type": "string",
        "maxLength": 1000,
        "title": "Description",
        "description": "新的角色用途说明；省略表示不修改，空字符串表示清空，不允许显式传 null。",
    }
    # 3. anyOf 表示至少满足其中一项：传名称或传说明；实际请求仍由模型校验器检查。
    schema["anyOf"] = [{"required": ["name"]}, {"required": ["description"]}]


class RoleCreateRequest(RequestBase):
    """
        创建普通角色的请求，包含稳定角色键、名称、说明和角色等级。
    """

    # 稳定角色编码；是否占用及保留名称由业务层检查。
    key: str = Field(
        pattern=r"^[a-z][a-z0-9_-]{1,79}$",
        description="角色编码，以小写字母开头，共 2～80 位小写字母、数字、下划线或连字符。",
    )
    name: str = Field(min_length=1, max_length=160, description="角色展示名称，1～160 个字符。")
    description: str = Field(
        default="",
        max_length=1000,
        description="角色用途说明，最多 1000 个字符；省略时为空字符串。",
    )
    # 等级只是管理边界，不能代替具体权限检查。
    level: int = Field(
        ge=1,
        le=999,
        description="自定义角色等级，1～999，数字越大等级越高；必须低于当前用户的角色等级。",
    )


class RoleUpdateRequest(RequestBase):
    """
        角色信息修改的 HTTP 请求体，把目标角色 ID 与修改内容一起提交。
    """

    # 运行时校验在下方 model_validator；此钩子只让离线接口结构表达同一规则，不开放文档路由。
    model_config = ConfigDict(json_schema_extra=_role_update_json_schema)

    role_id: RoleId = Field(description="要修改的角色 ID，在 POST JSON 请求体中提交。")
    # 原样提交最近读取的角色 version；过期时应先刷新角色再重试。
    expected_version: int = Field(
        strict=True,
        ge=0,
        description="最近读取的角色 version，只接受非负整数；版本过期时拒绝修改。",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        description="新的角色展示名称；省略表示不修改，不允许显式传 null。",
    )
    description: str | None = Field(
        default=None,
        max_length=1000,
        description="新的角色用途说明；省略表示不修改，空字符串表示清空，不允许显式传 null。",
    )

    @model_validator(mode="after")
    def require_at_least_one_field(self) -> Self:
        """
            要求角色修改至少提供名称或说明，并拒绝把已提供的字段显式设为 null。

        :return: 符合字段更新约定的当前请求对象。
        :raises PydanticCustomError: 没有提供可修改字段，或已提供字段的值为 None。
        """
        # 1. 找出请求确实传了哪些可修改字段；只有 ID 和版本、没有修改内容时拒绝。
        mutable_fields = self.model_fields_set & {"name", "description"}
        if not mutable_fields:
            raise PydanticCustomError("role_fields_required", "role_fields_required")
        # 2. 没传字段表示保持原值；明确传 null 不表示清空，按接口约定拒绝。
        if any(getattr(self, field_name) is None for field_name in mutable_fields):
            raise PydanticCustomError("role_fields_not_null", "role_fields_not_null")
        return self


class RoleVersionRequest(RequestBase):
    """
        角色启停或软删除的 HTTP 请求体，包含目标角色 ID 及预期版本。
    """

    role_id: RoleId = Field(description="被启用、禁用或软删除的角色 ID；具体操作由所调用的接口决定。")
    expected_version: int = Field(
        strict=True,
        ge=0,
        description="最近读取的角色 version，只接受非负整数；版本过期时拒绝操作。",
    )


class RolePermissionIdsRequest(RequestBase):
    """
        角色权限绑定或解绑的 HTTP 请求体，包含目标角色、权限列表及版本。
    """

    # 绑定与解绑共用参数格式，具体行为与权限由所调用接口决定。
    role_id: RoleId = Field(description="接受权限变更的角色 ID，仍须满足当前操作者的可管理范围。")
    expected_version: int = Field(
        strict=True,
        ge=0,
        description="最近读取的角色 version，只接受非负整数；防止覆盖他人的权限修改。",
    )
    permission_ids: list[PermissionId] = Field(
        min_length=1,
        max_length=100,
        description="本次绑定或解绑的权限 ID，1～100 项且不能重复；不是权限键，也不是全量替换。",
    )

    @field_validator("permission_ids")
    @classmethod
    def unique_permission_ids(cls, value: list[str]) -> list[str]:
        """
            拒绝权限 ID 列表中的重复项，让请求中的每项权限含义明确。

        :param value: 已完成权限 ID 格式及列表长度检查的权限 ID 列表。
        :return: 不含重复项的原权限 ID 列表。
        :raises PydanticCustomError: 列表中存在重复权限 ID。
        """
        # set 会合并重复项；数量变少说明同一个权限 ID 重复出现，拒绝而不是悄悄去重。
        if len(value) != len(set(value)):
            raise PydanticCustomError("permission_ids_unique", "permission_ids_unique")
        return value


class RoleResponse(ResponseBase):
    """
        操作者可查看的角色信息，包含已配置权限、管理等级、版本和软删除状态。
        停用角色仍展示已有权限配置，但这些配置不向绑定该角色的用户提供有效权限。
        已软删除角色只供查看基本信息，权限列表为空。
    """

    id: RoleId = Field(description="角色业务 ID，后续角色管理请求使用此值。")
    key: str = Field(description="稳定角色编码，不是页面展示名称。")
    name: str = Field(description="后台展示的角色名称。")
    description: str = Field(description="角色用途说明，空字符串表示未填写。")
    level: int = Field(description="角色等级，数字越大等级越高；不代表自动获得低等级角色的全部权限。")
    is_active: bool = Field(description="是否启用；false 表示停用，保留已有绑定但不提供有效权限。")
    is_system: bool = Field(description="是否为固定系统角色；系统角色不能停用或删除。")
    is_protected: bool = Field(description="是否受在线管理保护；与是否为系统角色分别表达。")
    permissions: tuple[str, ...] = Field(
        description="已绑定且未软删除的权限键；停用角色展示配置但不提供有效权限，已删除角色返回空列表。",
    )
    version: int = Field(description="当前角色编辑版本；下次修改时作为 expected_version 原样提交。")
    deleted_at: datetime | None = Field(description="软删除时间，包含时区；null 表示尚未删除。")


class RoleMutationResponse(ResponseBase):
    """
        角色管理操作结果，返回操作后的角色信息。
    """

    role: RoleResponse = Field(description="操作后的角色信息，包含供下一次修改使用的最新版本。")
