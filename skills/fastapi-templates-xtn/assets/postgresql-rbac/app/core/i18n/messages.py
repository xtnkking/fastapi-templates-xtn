#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    定义客户端文案键，读取中英文目录并提供翻译查询。
#    请求语言和参数错误分别由 language.py、validation_messages.py 负责。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        移除已清理的无调用权限替换请求专属文案映射
# 2026/09/23    XTN       V1.002        解释基础类字段、枚举用途与日志审计边界常量
# 2026/09/29    XTN       V1.003        删除默认健康检查专属文案键
# 2026/09/29    XTN       V1.004        权限说明接入双语目录，提供不依赖 HTTP 请求的翻译入口
# 2026/09/30    XTN       V1.005        分离语言协商与参数错误，只保留文案目录职责
# 2026/09/30    XTN       V1.006        删除临时密码流程专属文案键
# 2026/10/09    XTN       V1.007        注册成功成员统一用 register 命名，保留双语目录键值
# 2026/10/10    XTN       V1.008        密码长度提示统一用于所有密码输入
# 2026/10/13    XTN       V1.009        补充语言目录加载、完整性校验和翻译回退步骤
# 2026/10/14    XTN       V1.010        密码长度双语提示从共享密码常量填写，不再写死数字
# 2026/10/20    XTN       V1.011        区分实际密码字段长度提示与设置新密码的策略范围提示
# 2026/10/20    XTN       V1.012        增加密码计算队列繁忙的统一公开提示
# 2026/10/24    XTN       V1.013        用户角色权限说明键对齐 bind 和 unbind
# 2026/10/26    XTN       V1.014        补充本人账号基础权限的双语说明键
# 2026/11/26    XTN       V1.015        用户名格式提示读取统一长度及字符说明
# 2026/11/26    XTN       V1.016        密码组合提示按统一规则动态填写中英文字符类型
# 2026/11/27    XTN       V1.017        增加登录失败的统一指引，与 Token 认证失败提示分开
# 2026/11/28    XTN       V1.018        权限目录增加简短名称和业务分组的中英文文案键
# --------------------------------------------------------------------------------------------------

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from importlib.resources import files
from types import MappingProxyType

from fastapi import Request

from app.core.i18n.language import DEFAULT_LOCALE, SUPPORTED_LOCALES, locale_for_request
from app.core.security import password_rules as password_policy
from app.core.security import user_name as user_name_policy


class MessageKey(StrEnum):
    """
        程序选择哪条文案的固定钥匙；实际中英文在 app/assets/locales 中，不靠此值推断权限或错误码。
    """

    # 通用查询、创建和命令成功文案。
    COMMON_SUCCESS = "common.success"
    COMMON_QUERY_SUCCESS = "common.query_success"
    COMMON_CREATED = "common.created"
    COMMON_OPERATION_SUCCESS = "common.operation_success"

    # 登录、注册、验证码和密码操作的结果提示；同一 key 在两份语言目录都有对应文字。
    AUTH_CAPTCHA_CREATED = "auth.captcha_created"
    AUTH_REGISTER_SUCCEEDED = "auth.registration_succeeded"
    AUTH_LOGIN_SUCCEEDED = "auth.login_succeeded"
    AUTH_LOGIN_FAILED = "auth.login_failed"  # 所有账号登录失败共用，不说明账号是否存在或停用。
    AUTH_LOGOUT_SUCCEEDED = "auth.logout_succeeded"
    AUTH_PASSWORD_CHANGED_RELOGIN = "auth.password_changed_relogin"
    AUTH_PASSWORD_RESET_SUCCEEDED = "auth.password_reset_succeeded"
    AUTH_USER_CREATED = "auth.user_created"

    # 本人账号基础权限。
    PERMISSION_ACCOUNT_READ = "permission.account.read"
    PERMISSION_ACCOUNT_CHANGE_PASSWORD = "permission.account.change_password"
    # 权限目录用途说明；permissions:read 等权限码始终不变。
    PERMISSION_PERMISSIONS_READ = "permission.permissions.read"
    # 角色管理业务的能力说明，目标等级限制仍由角色 Service 执行。
    PERMISSION_ROLES_READ = "permission.roles.read"
    PERMISSION_ROLES_CREATE = "permission.roles.create"
    PERMISSION_ROLES_UPDATE = "permission.roles.update"
    PERMISSION_ROLES_STATUS_UPDATE = "permission.roles.status_update"
    PERMISSION_ROLES_DELETE = "permission.roles.delete"
    PERMISSION_ROLES_PERMISSIONS_BIND = "permission.roles.permissions_bind"
    PERMISSION_ROLES_PERMISSIONS_UNBIND = "permission.roles.permissions_unbind"
    # 用户角色绑定业务，不与给角色绑定权限混淆。
    PERMISSION_ROLES_BIND = "permission.roles.bind"
    PERMISSION_ROLES_UNBIND = "permission.roles.unbind"
    # 用户管理业务的能力说明，翻译不能改变授权结果。
    PERMISSION_USERS_READ = "permission.users.read"
    PERMISSION_USERS_CREATE = "permission.users.create"
    PERMISSION_USERS_STATUS_UPDATE = "permission.users.status_update"
    PERMISSION_USERS_PASSWORD_RESET = "permission.users.password_reset"
    PERMISSION_USERS_SESSIONS_REVOKE = "permission.users.sessions_revoke"
    # 维护资产示例；示例权限不会进入默认生成项目的权限目录。
    PERMISSION_PROJECTS_READ = "permission.projects.read"
    PERMISSION_PROJECTS_UPDATE = "permission.projects.update"

    # 权限简短名称；原有 PERMISSION_* 键继续提供详细用途说明。
    PERMISSION_ACCOUNT_READ_NAME = "permission.account.read.name"
    PERMISSION_ACCOUNT_CHANGE_PASSWORD_NAME = "permission.account.change_password.name"
    PERMISSION_PERMISSIONS_READ_NAME = "permission.permissions.read.name"
    PERMISSION_ROLES_READ_NAME = "permission.roles.read.name"
    PERMISSION_ROLES_CREATE_NAME = "permission.roles.create.name"
    PERMISSION_ROLES_UPDATE_NAME = "permission.roles.update.name"
    PERMISSION_ROLES_STATUS_UPDATE_NAME = "permission.roles.status_update.name"
    PERMISSION_ROLES_DELETE_NAME = "permission.roles.delete.name"
    PERMISSION_ROLES_PERMISSIONS_BIND_NAME = "permission.roles.permissions_bind.name"
    PERMISSION_ROLES_PERMISSIONS_UNBIND_NAME = "permission.roles.permissions_unbind.name"
    PERMISSION_ROLES_BIND_NAME = "permission.roles.bind.name"
    PERMISSION_ROLES_UNBIND_NAME = "permission.roles.unbind.name"
    PERMISSION_USERS_READ_NAME = "permission.users.read.name"
    PERMISSION_USERS_CREATE_NAME = "permission.users.create.name"
    PERMISSION_USERS_STATUS_UPDATE_NAME = "permission.users.status_update.name"
    PERMISSION_USERS_PASSWORD_RESET_NAME = "permission.users.password_reset.name"
    PERMISSION_USERS_SESSIONS_REVOKE_NAME = "permission.users.sessions_revoke.name"
    PERMISSION_PROJECTS_READ_NAME = "permission.projects.read.name"
    PERMISSION_PROJECTS_UPDATE_NAME = "permission.projects.update.name"

    # 权限分组的展示名称；account、users 等分组标识本身不翻译。
    PERMISSION_GROUP_ACCOUNT = "permission.group.account"
    PERMISSION_GROUP_USERS = "permission.group.users"
    PERMISSION_GROUP_ROLES = "permission.group.roles"
    PERMISSION_GROUP_USER_ROLES = "permission.group.user_roles"
    PERMISSION_GROUP_PERMISSIONS = "permission.group.permissions"
    PERMISSION_GROUP_PROJECTS = "permission.group.projects"
    PERMISSION_GROUP_OTHER = "permission.group.other"

    # 对外错误提示；内部 reason_code 不直接翻译或展示，以免泄露详细拒绝原因。
    ERROR_BAD_REQUEST = "error.bad_request"
    ERROR_UNAUTHENTICATED = "error.unauthenticated"
    ERROR_FORBIDDEN = "error.forbidden"
    ERROR_NOT_FOUND = "error.not_found"
    ERROR_METHOD_NOT_ALLOWED = "error.method_not_allowed"
    ERROR_CONFLICT = "error.conflict"
    ERROR_STALE_RESOURCE_VERSION = "error.stale_resource_version"
    ERROR_PAYLOAD_TOO_LARGE = "error.payload_too_large"
    ERROR_UNSUPPORTED_MEDIA_TYPE = "error.unsupported_media_type"
    ERROR_VALIDATION_FAILED = "error.validation_failed"
    ERROR_RATE_LIMITED = "error.rate_limited"
    ERROR_RATE_LIMITED_RETRY = "error.rate_limited_retry"
    ERROR_INTERNAL = "error.internal"
    ERROR_SERVICE_UNAVAILABLE = "error.service_unavailable"
    ERROR_PASSWORD_BUSY = "error.password_busy"
    ERROR_REQUEST_FAILED = "error.request_failed"
    ERROR_PASSWORD_SAME_AS_USER_NAME = "error.password_same_as_user_name"
    ERROR_PASSWORD_COMMON_OR_WEAK = "error.password_common_or_weak"
    ERROR_PASSWORD_LENGTH = "error.password_length"
    ERROR_PASSWORD_CHARACTERS = "error.password_characters"
    ERROR_PASSWORD_COMPOSITION = "error.password_composition"
    ERROR_USER_NAME_TAKEN = "error.user_name_taken"
    ERROR_CAPTCHA_INVALID = "error.captcha_invalid"

    # 请求字段校验提示，只描述字段规则，不回显用户提交的密码或 Token。
    VALIDATION_INVALID = "validation.invalid"
    VALIDATION_REQUIRED = "validation.required"
    VALIDATION_EXTRA_FORBIDDEN = "validation.extra_forbidden"
    VALIDATION_STRING_TYPE = "validation.string_type"
    VALIDATION_STRING_TOO_SHORT = "validation.string_too_short"
    VALIDATION_STRING_TOO_LONG = "validation.string_too_long"
    VALIDATION_STRING_PATTERN = "validation.string_pattern"
    VALIDATION_INTEGER = "validation.integer"
    VALIDATION_BOOLEAN = "validation.boolean"
    VALIDATION_UUID = "validation.uuid"
    VALIDATION_LIST = "validation.list"
    VALIDATION_LIST_LENGTH = "validation.list_length"
    VALIDATION_NUMBER_RANGE = "validation.number_range"
    VALIDATION_LITERAL = "validation.literal"
    VALIDATION_JSON_INVALID = "validation.json_invalid"
    VALIDATION_USER_NAME_RESERVED = "validation.user_name_reserved"
    VALIDATION_USER_NAME_FORMAT = "validation.user_name_format"
    VALIDATION_PASSWORDS_MUST_DIFFER = "validation.passwords_must_differ"
    VALIDATION_PASSWORD_TOO_SHORT = "validation.password_too_short"
    VALIDATION_PASSWORD_TOO_LONG = "validation.password_too_long"
    VALIDATION_ROLE_FIELDS_REQUIRED = "validation.role_fields_required"
    VALIDATION_ROLE_FIELDS_NOT_NULL = "validation.role_fields_not_null"
    VALIDATION_PERMISSION_IDS_UNIQUE = "validation.permission_ids_unique"
    VALIDATION_ROLE_IDS_UNIQUE = "validation.role_ids_unique"


def _load_catalog(locale: str) -> Mapping[str, str]:
    """
        从包资源加载语言目录，并验证所有消息键完整且文案非空。
        返回只读映射，避免运行时意外修改全局翻译内容。

    :param locale: 用于校验报错说明的语言标识。
    :return: 消息键到翻译文案的只读映射。
    :raises RuntimeError: 文件读取失败、JSON 无效或消息键缺失及多余。
    """
    # 1. locale 只来自固定支持列表；从包内读取该语言 JSON，不使用请求头构造文件路径。
    catalog_path = files("app.assets.locales").joinpath(f"{locale}.json")
    try:
        raw_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to load i18n catalog for {locale}") from exc
    # 2. 目录必须是非空文本组成的映射，不能把错误类型或空提示留到请求时才发现。
    if not isinstance(raw_catalog, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) or not value.strip()
        for key, value in raw_catalog.items()
    ):
        raise RuntimeError(f"invalid i18n catalog for {locale}")

    # 3. 与全部消息键精确核对，既不缺失也不多余，最后提供不可修改的映射。
    expected_keys = {key.value for key in MessageKey}
    actual_keys = set(raw_catalog)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise RuntimeError(
            f"i18n catalog key mismatch for {locale}; missing={missing}, extra={extra}"
        )
    return MappingProxyType(dict(raw_catalog))


# 导入时校验每种受支持语言的目录，缺少翻译立即报错，不等到用户请求时才发现。
CATALOGS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {locale: _load_catalog(locale) for locale in SUPPORTED_LOCALES}
)


def translate_for_locale(locale: str, key: MessageKey) -> str:
    """
        从已校验的双语目录取得文案，供不依赖 HTTP 对象的业务数据组装使用。
        不支持的语言回退到中文；用户名和密码规则提示读取各自的统一配置。
        只查内存目录和代码常量，不访问数据库或外部翻译服务。

    :param locale: 已协商的 zh-CN 或 en；其他值使用默认中文。
    :param key: 集中定义且两份语言目录都包含的文案键。
    :return: 对应语言的人类可读说明。
    """
    # 1. 按语言和稳定消息键取文案；不支持的语言改用中文。
    message = CATALOGS.get(locale, CATALOGS[DEFAULT_LOCALE])[key.value]
    # 2. 密码长度文案预留两个数字位置，填写服务端常量，调整规则后不必手改语言目录。
    # 这里只使用代码中的上下限，不把请求内容或密码原文放进提示。
    if key == MessageKey.ERROR_PASSWORD_LENGTH:
        return message.format(
            min_length=password_policy.MIN_PASSWORD_CHARACTERS,
            max_length=password_policy.MAX_PASSWORD_CHARACTERS,
        )
    # 3. 组合提示也读取同一组规则名称，缺类时不回显用户输入的密码。
    if key == MessageKey.ERROR_PASSWORD_COMPOSITION:
        return message.format(
            required_types=(password_policy.PASSWORD_REQUIRED_CHARACTERS_EN if locale == "en"
                            else password_policy.PASSWORD_REQUIRED_CHARACTERS_ZH),
        )
    # 4. 用户名提示同样读取规则文件；改长度或字符说明后，不必再修改两份翻译。
    if key == MessageKey.VALIDATION_USER_NAME_FORMAT:
        return message.format(
            min_length=user_name_policy.MIN_USER_NAME_LENGTH,
            max_length=user_name_policy.MAX_USER_NAME_LENGTH,
            characters=(user_name_policy.USER_NAME_CHARACTERS_EN if locale == "en"
                        else user_name_policy.USER_NAME_CHARACTERS_ZH),
        )
    return message


def translate(request: Request, key: MessageKey) -> str:
    """
        按本次请求的语言从已校验的目录取得统一接口文案。

    :param request: 用于确定响应语言的请求对象。
    :param key: 集中定义的消息键枚举值。
    :return: 对应语言的提示文本。
    """
    # 使用本次请求已经选定的语言，确保同一次响应里的所有提示使用相同语言。
    return translate_for_locale(locale_for_request(request), key)
