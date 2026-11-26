#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证用户名规则和用户创建时的用户名冲突提示。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        补充测试说明并验证预检查直接返回明确的用户名占用提示
# 2026/10/15    XTN       V1.001        用户创建测试调用合并后的 UserService.create_user
# 2026/10/15    XTN       V1.002        用户创建入口传入预先计算的初始密码哈希
# 2026/10/16    XTN       V1.003        直接服务测试显式绑定审计请求上下文
# 2026/10/20    XTN       V1.004        用户名校验测试移除重复字段名及已删除的字段选择分支
# 2026/11/26    XTN       V1.005        验证新增保留名及其大小写、空白和完整匹配边界
# 2026/11/26    XTN       V1.006        验证保留名两侧数字下划线变体和普通用户名边界
# 2026/11/26    XTN       V1.007        用户名规则测试调用 validate_user_name
# --------------------------------------------------------------------------------------------------

from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.codes import BusinessCode
from app.core.exceptions import AppError
from app.core.i18n.messages import MessageKey
from app.core.security.user_name import validate_user_name
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.user_service import user_service


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("  Mixed_Name  ", "Mixed_Name"),
        ("abc", "abc"),
        ("A" * 32, "A" * 32),
        ("my_admin", "my_admin"),
        ("admin_bob", "admin_bob"),
        ("admin01x", "admin01x"),
        ("ad1min", "ad1min"),
        ("123", "123"),
        ("___", "___"),
        ("_member42_", "_member42_"),
    ],
)
def test_user_name_trims_but_preserves_case(value: str, expected: str) -> None:
    """
        用户名移除首尾空格，但不擅自改变大小写。

    :param value: 用户提交的原始用户名。
    :param expected: 保存前应得到的用户名。
    :return: 无返回值；断言规范化结果与预期一致。
    """
    assert validate_user_name(value) == expected


@pytest.mark.parametrize(
    "value", [None, "  ", "ab", "a" * 33, "has space", "name@example", "\u4e2d\u6587"]
)
def test_user_name_rejects_non_ascii_or_out_of_bounds(value: str | None) -> None:
    """
        拒绝长度或字符不符合账号规则的用户名。

    :param value: 待检查的用户名或空值。
    :return: 无返回值；断言非法输入被拒绝。
    """
    with pytest.raises(ValueError):
        validate_user_name(value)


@pytest.mark.parametrize(
    "value",
    [
        "admin",
        "administrator",
        "root",
        "superadmin",
        "super_admin",
        "sysadmin",
        "system",
        "support",
        "user",
        "test",
        "guest",
        "ceshi",
        "ADMIN",
        "CESHI",
        "admins",
        "kefu",
        "data",
        "python",
        "mysql",
        "php",
        "java",
        "superuser",
        "sys_admin",
        "system_admin",
        "webmaster",
        "security",
        "official",
        "service",
        "anonymous",
        "fastapi",
        "docker",
        "gitlab",
    ],
)
def test_reserved_user_names_and_number_underscore_variants_are_rejected(value: str) -> None:
    """
        保留名及其两侧附加数字或下划线的写法都拒绝，不拦截带其他字母的普通名字。

    :param value: 预留的敏感用户名。
    :return: 无返回值；断言保留名及变体被拒绝，带额外字母的名称可使用。
    """
    for submitted in (value, value.upper(), f"  {value}  ", f"{value}123", f"{value.upper()}_001",
                      f"01{value}", f"_{value}_", f"  01_{value.upper()}_23  "):
        with pytest.raises(ValueError, match="reserved_user_name"):
            validate_user_name(submitted)

    assert validate_user_name(f"{value}_bob") == f"{value}_bob"
    assert validate_user_name(f"my_{value}") == f"my_{value}"


@pytest.mark.usefixtures("audit_request_context")
async def test_existing_user_name_uses_specific_conflict_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        用户名预检查直接返回明确提示，注册和管理员新增无需再次转换同一错误。

    :param monkeypatch: 替换数据库查询，避免测试访问真实 PostgreSQL。
    :return: 无返回值；断言错误码和中英文消息键属于用户名占用。
    """
    session = Mock(spec=AsyncSession)
    session.in_transaction.return_value = True
    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock(return_value=object()))
    monkeypatch.setattr(user_repository, "user_name_exists", AsyncMock(return_value=True))

    with pytest.raises(AppError) as caught:
        await user_service.create_user(
            cast(AsyncSession, session),
            user_name="Existing_User",
            password_hash="$argon2id$prepared-test-hash",
        )

    assert caught.value.business_code == BusinessCode.USER_CREATE_CONFLICT
    assert caught.value.message_key == MessageKey.ERROR_USER_NAME_TAKEN
    assert caught.value.reason_code == "user_already_exists"
