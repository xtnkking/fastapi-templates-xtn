#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    统一业务异常及错误构造；保存可翻译的消息标识和稳定业务码。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        区分公开业务错误与内部原因，说明异常交给统一处理器
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/29    XTN       V1.003        密码规则错误在统一错误模块转换为双语业务提示
# 2026/09/29    XTN       V1.004        以异常职责命名模块，业务码从专名模块导入
# 2026/09/29    XTN       V1.005        映射新密码的可见 ASCII 字符限制
# 2026/09/29    XTN       V1.006        按业务分段返回密码与角色的专用响应码
# 2026/09/30    XTN       V1.007        删除临时密码强制改密异常构造器
# 2026/10/02    XTN       V1.008        登录凭据错误复用统一业务异常与 401 响应
# 2026/10/10    XTN       V1.009        密码长度规则使用统一的中英文消息键
# 2026/10/13    XTN       V1.010        补充错误对象构造和密码提示回退的通俗步骤
# 2026/10/16    XTN       V1.011        异常构造器名称统一标明固定 HTTP 状态
# 2026/11/26    XTN       V1.012        缺少密码字符类型时返回统一的双语组合提示
# 2026/11/27    XTN       V1.013        登录失败改用统一的操作指引，不公开账号状态
# 2026/11/27    XTN       V1.014        登录失败的求助说明统一指向平台
# --------------------------------------------------------------------------------------------------

from fastapi import status

from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey
from app.core.security.password_rules import PasswordPolicyError


class AppError(Exception):
    """
        用于中断当前业务并交给统一异常处理器；创建异常对象不等于已经抛出或写日志。
        HTTP 状态、业务码和文案供响应使用，内部原因只用于安全日志/审计。
    """

    def __init__(self, *, status_code: int,
                 business_code: BusinessCode,
                 message_key: MessageKey,
                 reason_code: str
                 ) -> None:
        """
            保存业务错误的 HTTP 状态、业务码、文案键和内部原因码。
            客户端提示由消息键翻译，内部原因码用于定位与审计。

        :param status_code: 返回给客户端的 HTTP 错误状态码。
        :param business_code: 统一响应中的数字业务码。
        :param message_key: 客户端可见提示对应的中英文消息键。
        :param reason_code: 不含敏感数据的内部错误原因标识。
        :return: 无返回值，完成业务异常初始化。
        """
        # 保存响应所需分类和内部排错原因；创建对象本身不会发送响应或写入日志。
        super().__init__(reason_code)
        self.status_code = status_code  # HTTP 层结果，例如 403，不替代 JSON 中的业务码。
        self.business_code = business_code  # 五位数字 code，前端按它识别错误类别。
        self.message_key = message_key  # 指向中英文语言文件的消息键，不是直接显示的文字。
        self.reason_code = reason_code  # 内部拒绝原因，例如权限不足，不泄露给客户端。


class InvalidLoginCredentialsError(AppError):
    """统一表示无效登录凭据，不向客户端区分账号不存在、停用或密码错误。"""

    def __init__(self) -> None:
        """
            固定登录失败的状态、业务码和双语文案，不保存用户名或密码。

        :return: 无返回值；异常可由通用业务错误处理器返回相同的 401 响应。
        """
        # 所有账号失败都提示检查输入、联系平台，不公开具体原因；Token 失效仍用通用认证提示。
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            business_code=BusinessCode.INVALID_AUTHENTICATION,
            message_key=MessageKey.AUTH_LOGIN_FAILED,
            reason_code="invalid_login_credentials",
        )


def unauthenticated_401(reason_code: str) -> AppError:
    """
        构造 HTTP 401 身份认证失败异常，不在此处抛出。

    :param reason_code: 未登录或登录凭据无效的内部原因码。
    :return: 包含统一认证错误码和文案键的业务异常。
    """
    # 选择统一的未登录提示，具体内部原因只留给异常处理器记录。
    return AppError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        business_code=BusinessCode.INVALID_AUTHENTICATION,
        message_key=MessageKey.ERROR_UNAUTHENTICATED,
        reason_code=reason_code,
    )


def not_found_404(reason_code: str) -> AppError:
    """
        构造 HTTP 404 资源不存在异常，不在此处抛出。

    :param reason_code: 资源不可见或不存在的内部原因码。
    :return: 包含统一资源缺失错误码和文案键的业务异常。
    """
    # 不存在和无权查看都可使用同一资源缺失提示，实际选择由调用方决定。
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        business_code=BusinessCode.NOT_FOUND,
        message_key=MessageKey.ERROR_NOT_FOUND,
        reason_code=reason_code,
    )


def forbidden_403(reason_code: str) -> AppError:
    """
        构造 HTTP 403 权限不足异常，不在此处抛出。

    :param reason_code: 权限校验拒绝操作的内部原因码。
    :return: 包含统一禁止访问错误码和文案键的业务异常。
    """
    # 把权限拒绝归入固定的 403 分类，公开提示不直接包含内部原因码。
    return AppError(
        status_code=status.HTTP_403_FORBIDDEN,
        business_code=BusinessCode.ACCESS_FORBIDDEN,
        message_key=MessageKey.ERROR_FORBIDDEN,
        reason_code=reason_code,
    )


def password_policy_response_400(exc: PasswordPolicyError) -> AppError:
    """
        将设置新密码的策略错误转换为可行动的统一业务提示，不回显密码或内部异常。

    :param exc: 密码长度、强度或用户名比较产生的策略异常。
    :return: 带内部原因码及可翻译消息键的请求错误。
    """
    # 用固定原因选择可理解的密码纠正提示；不把密码原文或异常全文交给客户端。
    message_keys = {
        "password_same_as_user_name": MessageKey.ERROR_PASSWORD_SAME_AS_USER_NAME,
        "password_common_or_weak": MessageKey.ERROR_PASSWORD_COMMON_OR_WEAK,
        "password_missing_character_types": MessageKey.ERROR_PASSWORD_COMPOSITION,
        "password_empty": MessageKey.ERROR_PASSWORD_LENGTH,
        "password_too_short": MessageKey.ERROR_PASSWORD_LENGTH,
        "password_too_long": MessageKey.ERROR_PASSWORD_LENGTH,
        "password_invalid_character": MessageKey.ERROR_PASSWORD_CHARACTERS,
        "password_invalid_unicode": MessageKey.ERROR_PASSWORD_CHARACTERS,
    }
    message_key = message_keys.get(exc.reason_code)
    # 新增但尚未配置的密码原因回退到通用请求错误，避免暴露未知内部错误。
    if message_key is None:
        return invalid_request_400(exc.reason_code)
    return AppError(
        status_code=status.HTTP_400_BAD_REQUEST,
        business_code=BusinessCode.PASSWORD_POLICY_INVALID,
        message_key=message_key,
        reason_code=exc.reason_code,
    )


def conflict_409(reason_code: str, *, business_code: BusinessCode = BusinessCode.CONFLICT) -> AppError:
    """
        构造 HTTP 409 业务状态冲突异常，不在此处抛出。

    :param reason_code: 当前操作与资源状态冲突的内部原因码。
    :param business_code: 需要客户端区分时使用所属业务的冲突码；默认通用冲突码。
    :return: 包含统一冲突错误码和文案键的业务异常。
    """
    # 资源状态冲突统一使用 409，具体业务仍可通过专用业务码区分。
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=business_code,
        message_key=MessageKey.ERROR_CONFLICT,
        reason_code=reason_code,
    )


def stale_resource_version_409(reason_code: str) -> AppError:
    """
        构造 HTTP 409 资源版本过期异常，提示客户端重新获取最新状态。

    :param reason_code: 版本校验未通过的内部原因码。
    :return: 带专用版本冲突业务码的异常，不在此处抛出。
    """
    # 使用独立版本冲突码，让客户端知道需要先重新读取资源再尝试修改。
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=BusinessCode.ROLE_VERSION_STALE,
        message_key=MessageKey.ERROR_STALE_RESOURCE_VERSION,
        reason_code=reason_code,
    )


def unavailable_503(reason_code: str) -> AppError:
    """
        构造 HTTP 503 依赖服务暂不可用异常，不在此处抛出。

    :param reason_code: 数据库、Redis 等必需依赖不可用的内部原因码。
    :return: 包含统一服务不可用错误码和文案键的业务异常。
    """
    # 必需依赖故障归入可重试的服务不可用分类，响应中不公开连接和驱动错误。
    return AppError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
        message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
        reason_code=reason_code,
    )


def invalid_request_400(reason_code: str, *, business_code: BusinessCode = BusinessCode.BAD_REQUEST) -> AppError:
    """
        构造 HTTP 400 请求无效异常，不在此处抛出。

    :param reason_code: 请求不符合业务约束的内部原因码。
    :param business_code: 需要客户端区分时使用所属业务的请求错误码；默认通用请求错误码。
    :return: 包含统一请求错误码和文案键的业务异常。
    """
    # 请求不满足业务规则时选用 400，并允许调用方提供所属业务的专用错误码。
    return AppError(
        status_code=status.HTTP_400_BAD_REQUEST,
        business_code=business_code,
        message_key=MessageKey.ERROR_BAD_REQUEST,
        reason_code=reason_code,
    )
