from fastapi import status

from app.core.api_contract import BusinessCode
from app.core.i18n import MessageKey


class RbacError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        business_code: BusinessCode,
        message_key: MessageKey,
        reason_code: str,
    ) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.business_code = business_code
        self.message_key = message_key
        self.reason_code = reason_code


def unauthenticated(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        business_code=BusinessCode.INVALID_AUTHENTICATION,
        message_key=MessageKey.ERROR_UNAUTHENTICATED,
        reason_code=reason_code,
    )


def not_found(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_404_NOT_FOUND,
        business_code=BusinessCode.NOT_FOUND,
        message_key=MessageKey.ERROR_NOT_FOUND,
        reason_code=reason_code,
    )


def forbidden(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_403_FORBIDDEN,
        business_code=BusinessCode.ACCESS_FORBIDDEN,
        message_key=MessageKey.ERROR_FORBIDDEN,
        reason_code=reason_code,
    )


def password_change_required(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_403_FORBIDDEN,
        business_code=BusinessCode.PASSWORD_CHANGE_REQUIRED,
        message_key=MessageKey.ERROR_PASSWORD_CHANGE_REQUIRED,
        reason_code=reason_code,
    )


def conflict(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=BusinessCode.CONFLICT,
        message_key=MessageKey.ERROR_CONFLICT,
        reason_code=reason_code,
    )


def stale_resource_version(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=BusinessCode.STALE_RESOURCE_VERSION,
        message_key=MessageKey.ERROR_STALE_RESOURCE_VERSION,
        reason_code=reason_code,
    )


def unavailable(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
        message_key=MessageKey.ERROR_SERVICE_UNAVAILABLE,
        reason_code=reason_code,
    )


def invalid_request(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_400_BAD_REQUEST,
        business_code=BusinessCode.BAD_REQUEST,
        message_key=MessageKey.ERROR_BAD_REQUEST,
        reason_code=reason_code,
    )
