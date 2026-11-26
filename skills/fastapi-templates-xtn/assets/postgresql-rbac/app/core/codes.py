#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    统一业务码文件；前三位对应 HTTP 状态，后两位区分客户端可见结果。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        集中五位业务码及未登记 HTTP 错误的通用码规则
# 2026/09/29    XTN       V1.001        后两位按业务分段，区分认证、用户、角色和验证码结果
# 2026/09/30    XTN       V1.002        删除临时密码专属业务码
# 2026/10/13    XTN       V1.003        说明通用 HTTP 错误业务码的计算步骤
# --------------------------------------------------------------------------------------------------

from enum import IntEnum


class BusinessCode(IntEnum):
    """
        集中定义成功和失败时使用的五位数字业务码。
    """

    # 前三位对应 HTTP 状态；后两位按业务分段，同一号码不能复用为另一种结果。
    # 00 是通用成功，01-09 是通用错误；10-19 认证，20-29 用户，30-39 角色。
    # 40-49 留给权限特有结果，50-59 留给验证码；跨业务的错误继续用通用码。
    OK = 20000  # 查询或操作成功。
    CREATED = 20100  # 新资源创建成功。
    BAD_REQUEST = 40001  # 请求不符合通用业务约束，且无需更具体的处理。
    ACCESS_FORBIDDEN = 40301  # 当前身份没有执行此操作的权限。
    NOT_FOUND = 40401  # 资源不存在或对当前用户不可见，两者使用相同提示。
    METHOD_NOT_ALLOWED = 40501  # 此路径不支持请求使用的 HTTP 方法。
    CONFLICT = 40901  # 无需更具体客户端处理的通用状态冲突。
    PAYLOAD_TOO_LARGE = 41301  # 请求内容过大。
    UNSUPPORTED_MEDIA_TYPE = 41501  # 请求体格式不受支持。
    VALIDATION_FAILED = 42201  # 字段缺失、类型错误或不满足输入限制。
    RATE_LIMITED = 42901  # 当前业务与当前主体的请求次数超限。
    INTERNAL_ERROR = 50000  # 未预期的内部错误；不向客户端公开异常细节。
    SERVICE_UNAVAILABLE = 50301  # 必需数据库或 Redis 等暂时不可用。

    PASSWORD_POLICY_INVALID = 40010  # 新密码未满足已选定的密码规则。
    INVALID_AUTHENTICATION = 40110  # 未登录，或当前登录凭据已经失效。

    USER_ROLE_SELECTION_INVALID = 40020  # 用户角色绑定请求没有提供角色。
    USER_CREATE_CONFLICT = 40920  # 用户名或新用户标识已被占用。
    USER_ROLE_LIMIT_EXCEEDED = 40921  # 用户已达到最多 10 个角色的限制。

    ROLE_KEY_CONFLICT = 40930  # 角色标识已占用或属于保留标识。
    ROLE_VERSION_STALE = 40931  # 提交的角色版本已过期，应重新读取。

    PERMISSION_SELECTION_INVALID = 40040  # 待绑定权限为空、不存在或不属于可管理目录。
    CAPTCHA_INVALID = 40050  # 验证码错误、失效或与当前业务不匹配。


def generic_error_code(status_code: int) -> int:
    """
        为未登记的 HTTP 错误状态生成同前缀的五位通用业务码。

    :param status_code: 400 至 599 范围内的 HTTP 错误状态码。
    :return: 对应的五位业务码；500 使用统一内部错误码。
    :raises ValueError: 状态码不是 HTTP 客户端或服务端错误。
    """
    # 仅接受错误状态；500 复用固定码，其他状态在末尾补 01 表示通用错误。
    if not 400 <= status_code <= 599:
        raise ValueError("generic error codes require an HTTP 4xx or 5xx status")
    if status_code == 500:
        return int(BusinessCode.INTERNAL_ERROR)
    return status_code * 100 + 1
