#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    密码规则统一在这里维护：新密码的长度、字符和强度，以及登录密码的输入上限。
#    注册、创建用户、改密和重置密码共用这些规则；本文件不计算哈希，也不读写数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/11/26    XTN       V1.000        新建
# --------------------------------------------------------------------------------------------------

import re
from typing import Final

# 新密码长度，单位为字符；请求字段和提示直接引用，修改后重启服务生效。
MIN_PASSWORD_CHARACTERS: Final = 8
MAX_PASSWORD_CHARACTERS: Final = 32
# 登录和旧密码只受这个传输上限约束，不跟着新密码规则收紧；新密码上限不得超过它。
MAX_PASSWORD_INPUT_CHARACTERS: Final = 1_024

# 每一行是一类必须出现的字符：中文说明、英文说明、匹配规则；每类至少一个。
# 特殊符号规则只在确认全是 ASCII 33～126 后使用，因此 !、@、#、_ 都算，空格和中文不算。
PASSWORD_REQUIRED_CHARACTERS: Final = (
    ("大写字母", "uppercase letter", re.compile(r"[A-Z]")),
    ("小写字母", "lowercase letter", re.compile(r"[a-z]")),
    ("数字", "digit", re.compile(r"[0-9]")),
    ("英文特殊符号", "ASCII punctuation character", re.compile(r"[^A-Za-z0-9]")),
)
# 接口说明和双语错误提示从同一组规则取名称，避免改规则后忘记改文案。
PASSWORD_REQUIRED_CHARACTERS_ZH: Final = "、".join(item[0] for item in PASSWORD_REQUIRED_CHARACTERS)
PASSWORD_REQUIRED_CHARACTERS_EN: Final = ", ".join(item[1] for item in PASSWORD_REQUIRED_CHARACTERS)
NEW_PASSWORD_DESCRIPTION_ZH: Final = (
    f"新密码为 {MIN_PASSWORD_CHARACTERS}～{MAX_PASSWORD_CHARACTERS} 位，"
    f"必须包含{PASSWORD_REQUIRED_CHARACTERS_ZH}，每类至少一个。"
    "只允许可见的英文字母、数字和英文标点，不允许空格、中文、emoji 或不可见字符；"
    "还会检查简单弱密码和与用户名相同的情况。保留原文，不裁剪空白或转换大小写。"
)
PASSWORD_INPUT_DESCRIPTION_ZH: Final = (
    f"原有密码按原文验证，不裁剪空白或转换大小写；不能为空，最多传输 {MAX_PASSWORD_INPUT_CHARACTERS} 个字符。"
    "此上限用于拦截异常大输入，不会用当前新密码的长度、字符或强度规则拒绝原有密码。"
)


class PasswordPolicyError(ValueError):
    """
        记下密码没有通过哪条规则，交给上层返回提示；异常中不保存密码原文。
    """

    def __init__(self, reason_code: str) -> None:
        """
            保存固定原因码，供接口选择对应的中英文提示。

        :param reason_code: 固定错误原因，不得包含用户输入的密码。
        :return: 无返回值，初始化密码规则异常。
        """
        # 只保存原因，不把密码拼进异常或日志。
        self.reason_code = reason_code
        super().__init__(reason_code)


def validate_login_password_input(password: str) -> str:
    """
        检查登录或旧密码是否为空、过长、无法编码，不检查新密码强度。

    :param password: 用户提交的原始密码，不删空格，不改大小写。
    :return: 通过输入检查的原密码。
    :raises PasswordPolicyError: 类型、编码或长度不符合输入要求。
    """
    # 1. 拦住非字符串、空密码和异常大输入，避免无意义的密码计算。
    if not isinstance(password, str):
        raise PasswordPolicyError("password_invalid_type")
    if not password:
        raise PasswordPolicyError("password_empty")
    if len(password) > MAX_PASSWORD_INPUT_CHARACTERS:
        raise PasswordPolicyError("password_too_long")
    # 2. 确认能按 UTF-8 交给哈希器；不使用新规则拒绝以前设置的密码。
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise PasswordPolicyError("password_invalid_unicode") from None
    return password


def validate_new_password(password: str, *, user_name: str | None = None) -> str:
    """
        设置新密码时统一检查长度、可用字符、简单弱密码及四类字符是否齐全。
        注册、创建用户、改密和重置都用它；登录和验证旧密码不用它。

    :param password: 准备用作新密码的原字符串，不裁剪或改写。
    :param user_name: 提供时还会拒绝与完整用户名相同的密码，比较忽略大小写。
    :return: 通过全部规则的原密码。
    :raises PasswordPolicyError: 密码长度、字符或强度不合要求，或与用户名相同。
    :raises TypeError: user_name 不是字符串或 None。
    """
    # 1. 先检查基本输入，再检查新密码长度；这些数字只在本文件定义。
    validate_login_password_input(password)
    if len(password) < MIN_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_short")
    if len(password) > MAX_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_long")
    # 2. 只接收 ASCII 33～126：英文、数字、英文标点；空格、中文和不可见字符都拒绝。
    if any(not 33 <= ord(character) <= 126 for character in password):
        raise PasswordPolicyError("password_invalid_character")

    # 3. 拒绝整段重复字符，以及整段纯字母或纯数字的连续升降序，例如 abcdefgh。
    # 转小写只用于比较，后续保存哈希时仍使用原密码。
    lowercase_password = password.lower()
    if len(set(lowercase_password)) == 1:
        raise PasswordPolicyError("password_common_or_weak")
    if lowercase_password.isdigit() or lowercase_password.isalpha():
        steps = [
            ord(right) - ord(left)
            for left, right in zip(lowercase_password, lowercase_password[1:], strict=False)
        ]
        if len(set(steps)) == 1 and steps[0] in (-1, 1):
            raise PasswordPolicyError("password_common_or_weak")

    # 4. 有用户名时再比较完整值；密码只包含用户名的一部分，不会被这条规则拒绝。
    if user_name is not None and not isinstance(user_name, str):
        raise TypeError("user_name must be a string or None")
    if user_name is not None and lowercase_password == user_name.lower():
        raise PasswordPolicyError("password_same_as_user_name")

    # 5. 逐类检查大写、小写、数字和英文特殊符号，缺任何一类都不能设置。
    # 在计算 Argon2 之前就拒绝，不为不合规则的新密码消耗哈希资源。
    if any(pattern.search(password) is None for _, _, pattern in PASSWORD_REQUIRED_CHARACTERS):
        raise PasswordPolicyError("password_missing_character_types")
    return password
