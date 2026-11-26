#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证角色与用户管理的公开请求参数边界及不可变响应快照，不连接数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        请求结构拆分后直接验证 HTTP Body 的目标 ID 与原有字段规则
# 2026/10/09    XTN       V1.001        角色变更响应模型统一使用 Response 后缀
# 2026/10/10    XTN       V1.002        验证管理请求与响应的公共字段边界及角色修改结构约束
# --------------------------------------------------------------------------------------------------

"""管理请求字段校验和响应不可变行为。"""


from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from app.core.ids import new_entity_id
from app.core.response import PageResponse
from app.schemas.role import (
    RoleCreateRequest,
    RoleMutationResponse,
    RolePermissionIdsRequest,
    RoleResponse,
    RoleUpdateRequest,
    RoleVersionRequest,
)
from app.schemas.user import UserCreatedResponse, UserRoleIdsRequest, UserTargetRequest


def test_role_create_separates_creation_from_permission_grants() -> None:
    """
        创建角色只接受基本信息和普通角色等级，不允许顺带授予权限。

    :return: 无返回值；成功时确认创建请求拒绝权限字段和保留等级。
    """
    request = RoleCreateRequest(
        key="project_manager",
        name="Project manager",
        description="Manages project work",
        level=200,
    )

    assert request.description == "Manages project work"
    with pytest.raises(ValidationError):
        RoleCreateRequest.model_validate(
            {
                "key": "project_manager",
                "name": "Project manager",
                "level": 200,
                "permissions": ["projects:read"],
            }
        )

    with pytest.raises(ValidationError):
        RoleCreateRequest(
            key="tier_zero",
            name="Tier zero",
            level=0,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"expected_version": 0},
        {"expected_version": 0, "name": None},
        {"expected_version": 0, "description": None},
    ],
)
def test_role_update_requires_a_non_null_mutable_field(payload: dict[str, object]) -> None:
    """
        已给出目标角色时，修改内容仍必须存在且不能显式传入 null。

    :param payload: 缺少版本、缺少修改内容或含空修改字段的请求样本。
    :return: 无返回值；成功时所有无效样本均被拒绝。
    """
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate({"role_id": new_entity_id("R"), **payload})


def test_role_update_rejects_authority_fields() -> None:
    """
        修改角色名称或说明不能通过额外字段修改管理等级。

    :return: 无返回值；成功时越过信息修改范围的字段被拒绝。
    """
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate(
            {
                "role_id": new_entity_id("R"),
                "expected_version": 0,
                "name": "Renamed",
                "level": 999,
            }
        )


def test_role_version_inputs_require_a_nonnegative_integer() -> None:
    """
        角色版本允许零和正整数，但不接受负数。

    :return: 无返回值；成功时版本边界与原请求约定一致。
    """
    role_id = new_entity_id("R")
    assert RoleVersionRequest(role_id=role_id, expected_version=0).expected_version == 0
    assert RoleUpdateRequest(role_id=role_id, expected_version=3, name="Renamed").expected_version == 3

    with pytest.raises(ValidationError):
        RoleVersionRequest(role_id=role_id, expected_version=-1)


def test_role_update_schema_preserves_omission_and_non_null_rules() -> None:
    """
        公共请求规则不能覆盖角色修改的结构钩子，说明可省略但不能显式为空。

    :return: 无返回值；合法修改仍可解析，离线结构仍表达至少修改一个非空字段。
    """
    request = RoleUpdateRequest(role_id=new_entity_id("R"), expected_version=0, description="")
    assert request.description == ""
    assert "name" not in request.model_fields_set

    schema = RoleUpdateRequest.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["anyOf"] == [{"required": ["name"]}, {"required": ["description"]}]
    assert schema["properties"]["name"]["type"] == "string"
    assert schema["properties"]["description"]["type"] == "string"


@pytest.mark.parametrize(
    ("model", "payload", "field_name", "replacement"),
    [
        (RoleCreateRequest, {"key": "project_reader", "name": "Reader", "level": 10}, "name", "Changed"),
        (
            RoleUpdateRequest,
            {"role_id": new_entity_id("R"), "expected_version": 0, "name": "Reader"},
            "expected_version",
            1,
        ),
        (UserTargetRequest, {"user_id": new_entity_id("U")}, "user_id", new_entity_id("U")),
    ],
    ids=["role-create", "role-update", "user-target"],
)
def test_management_requests_preserve_validated_input(model: type[BaseModel], payload: dict[str, Any],
                                                      field_name: str, replacement: object
                                                      ) -> None:
    """
        管理请求解析后不能改写角色资料、并发版本或操作目标，防止后续代码误改输入。

    :param model: 管理接口实际接收的请求模型。
    :param payload: 可通过原有业务字段校验的输入。
    :param field_name: 后续代码尝试重新赋值的字段。
    :param replacement: 类型合法但不应允许覆盖原输入的新值。
    :return: 无返回值；重新赋值被拒绝且原输入保持不变。
    """
    request = model.model_validate(payload)
    with pytest.raises(ValidationError) as error:
        setattr(request, field_name, replacement)

    assert error.value.errors()[0]["type"] == "frozen_instance"
    assert getattr(request, field_name) == payload[field_name]


@pytest.mark.parametrize(
    ("model", "payload", "field_name", "replacement"),
    [
        (UserCreatedResponse, {"user_id": "U5N9B2LK7QR4X6D"}, "user_id", "U1N2B3LK7QR4X6D"),
        (
            PageResponse[UserCreatedResponse],
            {"items": [{"user_id": "U5N9B2LK7QR4X6D"}], "page": 1, "page_size": 10, "total": 1},
            "total",
            2,
        ),
    ],
    ids=["user-created", "page"],
)
def test_responses_reject_extra_fields_and_reassignment(model: type[BaseModel], payload: dict[str, Any],
                                                        field_name: str, replacement: object
                                                        ) -> None:
    """
        业务结果和分页外层均拒绝夹带字段，组装完成后不能重新赋值。

    :param model: 实际返回给客户端的响应模型，包括泛型分页结果。
    :param payload: 可序列化的合法业务结果。
    :param field_name: 尝试在响应构造后改写的字段。
    :param replacement: 不应允许覆盖原响应的新值。
    :return: 无返回值；多余字段与重新赋值分别被明确拒绝。
    """
    with pytest.raises(ValidationError) as extra_error:
        model.model_validate({**payload, "unexpected": "not part of the response"})
    assert extra_error.value.errors()[0]["type"] == "extra_forbidden"

    response = model.model_validate(payload)
    with pytest.raises(ValidationError) as frozen_error:
        setattr(response, field_name, replacement)
    assert frozen_error.value.errors()[0]["type"] == "frozen_instance"
    assert getattr(response, field_name) == payload[field_name]


def test_page_response_rejects_extra_fields_inside_business_items() -> None:
    """
        分页外层合法也不能绕过每条业务结果的字段约束，避免静默丢弃多余字段。

    :return: 无返回值；错误位置明确指向分页第一条记录的多余字段。
    """
    with pytest.raises(ValidationError) as error:
        PageResponse[UserCreatedResponse].model_validate(
            {"items": [{"user_id": "U5N9B2LK7QR4X6D", "unexpected": "extra"}],
             "page": 1, "page_size": 10, "total": 1}
        )
    assert error.value.errors()[0]["type"] == "extra_forbidden"
    assert error.value.errors()[0]["loc"] == ("items", 0, "unexpected")


@pytest.mark.parametrize("value", ["1", 1.0, True])
def test_role_version_inputs_reject_coercion(value: object) -> None:
    """
        角色修改、状态和权限绑定请求均拒绝把字符串、小数或布尔值转换成版本。

    :param value: 看似整数但类型不符合严格版本约定的输入。
    :return: 无返回值；成功时三种公开请求均拒绝该值。
    """
    role_id = new_entity_id("R")
    payloads = (
        (RoleVersionRequest, {"role_id": role_id, "expected_version": value}),
        (RoleUpdateRequest, {"role_id": role_id, "expected_version": value, "name": "Renamed"}),
        (
            RolePermissionIdsRequest,
            {"role_id": role_id, "expected_version": value, "permission_ids": [new_entity_id("P")]},
        ),
    )

    for model, payload in payloads:
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_permission_batches_require_one_to_one_hundred_unique_ids() -> None:
    """
        角色权限绑定请求只接受一至一百个互不重复的权限 ID。

    :return: 无返回值；成功时空列表、重复项和超量被拒绝，最大允许数量可通过。
    """
    first = new_entity_id("P")
    role_id = new_entity_id("R")

    with pytest.raises(ValidationError):
        RolePermissionIdsRequest(role_id=role_id, expected_version=0, permission_ids=[])
    with pytest.raises(ValidationError):
        RolePermissionIdsRequest(role_id=role_id, expected_version=0, permission_ids=[first, first])
    with pytest.raises(ValidationError):
        RolePermissionIdsRequest(
            role_id=role_id,
            expected_version=0,
            permission_ids=[new_entity_id("P") for _ in range(101)],
        )

    request = RolePermissionIdsRequest(
        role_id=role_id,
        expected_version=0,
        permission_ids=[new_entity_id("P") for _ in range(100)],
    )
    assert len(request.permission_ids) == 100


def test_role_batches_require_one_to_ten_unique_ids() -> None:
    """
        用户角色请求只接受一至十个互不重复的角色 ID。

    :return: 无返回值；成功时数量和唯一性校验在合并请求层次后仍然生效。
    """
    first = new_entity_id("R")
    user_id = new_entity_id("U")

    with pytest.raises(ValidationError):
        UserRoleIdsRequest(user_id=user_id, role_ids=[])
    with pytest.raises(ValidationError):
        UserRoleIdsRequest(user_id=user_id, role_ids=[first, first])
    with pytest.raises(ValidationError):
        UserRoleIdsRequest(user_id=user_id, role_ids=[new_entity_id("R") for _ in range(11)])

    request = UserRoleIdsRequest(user_id=user_id, role_ids=[new_entity_id("R") for _ in range(10)])
    assert len(request.role_ids) == 10


def test_role_mutation_snapshot_is_immutable() -> None:
    """
        角色修改结果与内部角色快照都保持不可变，防止提交后改写授权结果。

    :return: 无返回值；成功时字段赋值均触发验证错误。
    """
    role = RoleResponse(
        id=new_entity_id("R"),
        key="reader",
        name="Reader",
        description="Read access",
        level=10,
        is_active=True,
        is_system=False,
        is_protected=False,
        permissions=("projects:read",),
        version=3,
        deleted_at=None,
    )
    result = RoleMutationResponse(role=role)

    assert set(result.model_dump()) == {"role"}
    assert result.role.permissions == ("projects:read",)
    with pytest.raises(ValidationError):
        role.version = 4
    with pytest.raises(ValidationError):
        result.role = role.model_copy(update={"version": 4})
