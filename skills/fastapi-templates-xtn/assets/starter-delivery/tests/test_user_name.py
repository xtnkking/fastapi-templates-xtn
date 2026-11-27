#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证用户名及新密码的关键边界，不连接基础设施。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/26    XTN       V1.001        使用 user_name 业务名称，保持用户名和密码输入边界验证
# 2026/10/02    XTN       V1.002        展开入门测试请求字段并明确新旧密码的不同校验阶段
# 2026/10/15    XTN       V1.003        对齐密码共享长度边界及业务层新密码策略检查
# 2026/10/20    XTN       V1.004        入门测试按简化后的用户名校验参数调用
# 2026/10/20    XTN       V1.005        登录保留旧密码输入，新密码长度和强度单独验证
# 2026/11/26    XTN       V1.006        入门测试覆盖客服、数据和开发技术保留名
# 2026/11/26    XTN       V1.007        入门测试覆盖保留名数字及下划线变体
# 2026/11/26    XTN       V1.008        入门测试使用直观的用户名校验入口名称
# 2026/11/26    XTN       V1.009        新密码统一使用密码规则模块并拒绝缺失字符种类
# --------------------------------------------------------------------------------------------------


import uuid

import pytest
from pydantic import ValidationError

from app.core.security.password_rules import (
    MAX_PASSWORD_CHARACTERS,
    MAX_PASSWORD_INPUT_CHARACTERS,
    PasswordPolicyError,
    validate_new_password,
)
from app.core.security.user_name import validate_user_name
from app.schemas.auth import LoginRequest, RegisterRequest


def test_username_trim_and_reserved_names() -> None:
    """
        用户名先去空白，保留名不区分大小写，非法字符不能进入业务。

    :return: 无返回值；关键用户名约束不成立时断言失败。
    """
    normalized = validate_user_name("  member_42  ")
    assert normalized == "member_42"
    assert validate_user_name("my_admin") == "my_admin"
    assert validate_user_name("admin_bob") == "admin_bob"
    for invalid in (
        "ADMIN", "user", "test", "guest", "ceshi",  # 预留名，大小写都不可使用。
        "admins", "kefu", "data", "Python", "MySQL", "PHP", "Java",
        "admin01", "ADMIN_001", "_admin_", "01admin", "python123", "01_KEFU_23",
        "ab", "a-b", "中文名字",  # 长度不足或包含不允许的字符。
    ):
        with pytest.raises(ValueError):
            validate_user_name(invalid)


def test_password_requests_separate_existing_input_and_new_password_policy() -> None:
    """
        登录允许不符合新策略的原密码，注册按新密码长度和业务规则检查。

    :return: 无返回值；原密码被新策略误拦截或新密码规则失效时断言失败。
    """
    payload = {
        "user_name": "member_42",
        "password": "short",
        "captcha_id": str(uuid.uuid4()),
        "captcha_answer": "ABCD",
    }
    # 这些旧密码仍可提交登录，但不能再用于设置新密码。
    for invalid_password in ("short", "A" * (MAX_PASSWORD_CHARACTERS + 1)):
        payload["password"] = invalid_password
        assert LoginRequest.model_validate(payload).password.get_secret_value() == invalid_password
        with pytest.raises(ValidationError):
            RegisterRequest.model_validate(payload)

    # 登录仍拒绝空输入和超大输入，避免不必要的密码计算开销。
    for invalid_password in ("", "A" * (MAX_PASSWORD_INPUT_CHARACTERS + 1)):
        payload["password"] = invalid_password
        with pytest.raises(ValidationError):
            LoginRequest.model_validate(payload)

    # 长度合格不等于可以设置为新密码：登录保留原文，业务层另外拒绝新密码中的空格。
    payload["password"] = "space 42"
    login = LoginRequest.model_validate(payload)
    registration = RegisterRequest.model_validate(payload)
    assert login.password.get_secret_value() == "space 42"
    with pytest.raises(PasswordPolicyError):
        validate_new_password(registration.password.get_secret_value(), user_name=payload["user_name"])

    # 换成合规的新密码后通过业务策略，模型的调试字符串仍不能泄露密码。
    payload["password"] = "Secret-42"
    registration = RegisterRequest.model_validate(payload)
    assert validate_new_password(
        registration.password.get_secret_value(), user_name=payload["user_name"],
    ) == "Secret-42"
    assert "Secret-42" not in repr(registration)


@pytest.mark.parametrize("password", [
    "no-uppercase7!", "NO-LOWERCASE7!", "No-digit-here!", "NoSpecialHere7",
])
def test_new_password_requires_uppercase_lowercase_digit_and_symbol(password: str) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        validate_new_password(password)

    assert caught.value.reason_code == "password_missing_character_types"
