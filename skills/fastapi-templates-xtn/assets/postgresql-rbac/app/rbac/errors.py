from fastapi import status

from app.api_contract import BusinessCode


class RbacError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        business_code: BusinessCode,
        public_message: str,
        reason_code: str,
    ) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.business_code = business_code
        self.public_message = public_message
        self.reason_code = reason_code


def unauthenticated(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        business_code=BusinessCode.INVALID_AUTHENTICATION,
        public_message="身份验证失败",
        reason_code=reason_code,
    )


def not_found(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_404_NOT_FOUND,
        business_code=BusinessCode.NOT_FOUND,
        public_message="资源不存在",
        reason_code=reason_code,
    )


def forbidden(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_403_FORBIDDEN,
        business_code=BusinessCode.ACCESS_FORBIDDEN,
        public_message="无权执行该操作",
        reason_code=reason_code,
    )


def password_change_required(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_403_FORBIDDEN,
        business_code=BusinessCode.PASSWORD_CHANGE_REQUIRED,
        public_message="必须先修改密码",
        reason_code=reason_code,
    )


def conflict(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=BusinessCode.CONFLICT,
        public_message="当前资源状态存在冲突",
        reason_code=reason_code,
    )


def stale_resource_version(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_409_CONFLICT,
        business_code=BusinessCode.STALE_RESOURCE_VERSION,
        public_message="资源已被其他操作更新，请刷新后重试",
        reason_code=reason_code,
    )


def unavailable(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        business_code=BusinessCode.SERVICE_UNAVAILABLE,
        public_message="服务暂时不可用",
        reason_code=reason_code,
    )


def invalid_request(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_400_BAD_REQUEST,
        business_code=BusinessCode.BAD_REQUEST,
        public_message="请求内容不合法",
        reason_code=reason_code,
    )
