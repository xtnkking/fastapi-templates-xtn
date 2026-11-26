#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查默认项目业务 ID、审计 ID、模型和 JWT 主体契约。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/04    XTN       V1.000        新建前缀 ID 契约测试
# 2026/10/09    XTN       V1.001        检查完整格式约束、引用列长度及非法 ID 边界
# 2026/10/10    XTN       V1.002        统一用户 ID 与当前用户命名
# --------------------------------------------------------------------------------------------------

import re
import uuid
from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import ValidationError
from sqlalchemy import String, Table

from app.core.config import get_settings
from app.core.ids import new_audit_id, new_entity_id, require_audit_id, require_entity_id
from app.core.security.jwt_tokens import decode_access_token, encode_access_token
from app.models.postgres.base import Base
from app.models.postgres.business_audit import BusinessAuditEvent
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.permission import Permission
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole
from app.schemas.role import RolePermissionIdsRequest, RoleVersionRequest
from app.schemas.user import UserTargetRequest


@pytest.mark.parametrize("prefix", ["U", "R", "P", "UR", "RP"])
def test_entity_id_exact_contract(prefix: str) -> None:
    """
        检查普通实体 ID 的前缀、总长度和安全随机字符范围。

    :param prefix: 当前实体的业务前缀。
    :return: 无返回值，规则错误时由断言报告。
    """
    value = new_entity_id(prefix)
    assert len(value) == 15
    assert re.fullmatch(rf"{prefix}[A-Z0-9]{{{15 - len(prefix)}}}", value)
    assert require_entity_id(value, prefix) == value
    with pytest.raises(ValueError):
        require_entity_id(value.lower(), prefix)
    # 长度、字符或尾部换行有误时必须拒绝，不能接受只是开头匹配的输入。
    for invalid in (value[:-1], value + "A", value[:-1] + "_", value + "\n"):
        with pytest.raises(ValueError):
            require_entity_id(invalid, prefix)


@pytest.mark.parametrize("prefix", ["OA", "BA"])
def test_audit_id_china_time_and_hundredths(monkeypatch: pytest.MonkeyPatch, prefix: str) -> None:
    """
        固定时间和随机源，确认审计 ID 的末两位时间是百分之一秒。

    :param monkeypatch: 临时固定随机字符，不改变正式生成器。
    :param prefix: 当前审计表的两位业务前缀。
    :return: 无返回值，格式错误时由断言报告。
    """
    monkeypatch.setattr("app.core.ids.secrets.choice", lambda _alphabet: "A")
    at = datetime(2026, 9, 22, 3, 41, 41, 559999, tzinfo=UTC)
    value = new_audit_id(prefix, at=at)
    assert value == f"{prefix}26092211414155AAAAAA"
    assert len(value) == 22
    assert require_audit_id(value, prefix) == value
    with pytest.raises(ValueError):
        require_audit_id(value.lower(), prefix)
    for invalid in (value[:-1], value + "A", value[:-1] + "_", value + "\n"):
        with pytest.raises(ValueError):
            require_audit_id(invalid, prefix)


@pytest.mark.parametrize(
    ("model", "length", "prefix"),
    [
        (User, 15, "U"), (Role, 15, "R"), (Permission, 15, "P"),
        (UserRole, 15, "UR"), (RolePermission, 15, "RP"),
        (OperationAuditEvent, 22, "OA"),
        (BusinessAuditEvent, 22, "BA"),
    ],
)
def test_model_primary_key_shape(model: type[Base], length: int, prefix: str) -> None:
    """
        检查默认模型与可选业务审计的主键长度及对应数据库格式约束。

    :param model: 当前待检查的 PostgreSQL ORM 模型。
    :param length: 主键应占用的总字符长度。
    :param prefix: 模型对应的固定业务前缀。
    :return: 无返回值，字段或约束不一致时由断言报告。
    """
    table = cast(Table, model.__table__)
    primary_key_name = "user_id" if model is User else "id"
    key_type = table.c[primary_key_name].type
    assert isinstance(key_type, String)
    assert key_type.length == length
    expected_pattern = (rf"^{prefix}[A-Z0-9]{{{length - len(prefix)}}}$" if length == 15
                        else rf"^{prefix}[0-9]{{14}}[A-Z0-9]{{6}}$")
    assert any(str(item.sqltext) == f"{primary_key_name} ~ '{expected_pattern}'"
               for item in table.constraints if hasattr(item, "sqltext"))
    # 外键引用用户、角色或权限时，字段长度必须与目标主键一致。
    for foreign_key in table.foreign_keys:
        source_type = foreign_key.parent.type
        target_type = foreign_key.column.type
        assert isinstance(source_type, String)
        assert isinstance(target_type, String)
        assert source_type.length == target_type.length


@pytest.mark.parametrize("invalid_id", ["U" + "A" * 13, "U" + "A" * 15, "u" + "A" * 14,
                                        "U" + "A" * 13 + "_", "U" + "A" * 14 + "\n"])
def test_request_rejects_malformed_user_id(invalid_id: str) -> None:
    """
        用户请求拒绝长度、大小写、字符范围或结尾不符合契约的 ID。

    :param invalid_id: 不应被接受的用户 ID。
    :return: 无返回值；请求校验必须报告错误。
    """
    with pytest.raises(ValidationError):
        UserTargetRequest(user_id=invalid_id)


def test_jwt_subject_is_user_id_and_jti_stays_uuid4() -> None:
    """
        确认 JWT user_id 使用用户业务 ID，JTI 仍使用规范 UUIDv4。

    :return: 无返回值，编码或解析不一致时由断言报告。
    """
    user_id = new_entity_id("U")
    token_id = uuid.uuid4()
    token, token_info = encode_access_token(user_id=user_id, token_id=token_id, settings=get_settings())
    decoded = decode_access_token(token, get_settings())
    assert token_info.user_id == decoded.user_id == user_id
    assert decoded.token_id == token_id
    with pytest.raises(ValueError):
        encode_access_token(user_id=new_entity_id("R"), token_id=token_id, settings=get_settings())


def test_request_models_reject_wrong_prefix() -> None:
    """
        拒绝把用户 ID 当角色 ID，或把角色 ID 当权限 ID 提交。

    :return: 无返回值，错误前缀被接受时由断言报告。
    """
    with pytest.raises(ValidationError):
        UserTargetRequest(user_id=new_entity_id("R"))
    with pytest.raises(ValidationError):
        RoleVersionRequest(role_id=new_entity_id("U"), expected_version=0)
    with pytest.raises(ValidationError):
        RolePermissionIdsRequest(
            role_id=new_entity_id("R"), expected_version=0,
            permission_ids=[new_entity_id("U")],
        )
