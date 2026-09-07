from fastapi import HTTPException, status

_HTTP_UNPROCESSABLE_CONTENT = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


class RbacError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        public_code: str,
        reason_code: str,
    ) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.public_code = public_code
        self.reason_code = reason_code

    def to_http_exception(self) -> HTTPException:
        headers = (
            {"WWW-Authenticate": "Bearer"}
            if self.status_code == status.HTTP_401_UNAUTHORIZED
            else None
        )
        return HTTPException(
            status_code=self.status_code,
            detail={"code": self.public_code},
            headers=headers,
        )


def unauthenticated(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        public_code="invalid_authentication",
        reason_code=reason_code,
    )


def not_found(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_404_NOT_FOUND,
        public_code="not_found",
        reason_code=reason_code,
    )


def forbidden(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_403_FORBIDDEN,
        public_code="access_forbidden",
        reason_code=reason_code,
    )


def conflict(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_409_CONFLICT,
        public_code="authorization_conflict",
        reason_code=reason_code,
    )


def unavailable(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        public_code="authorization_unavailable",
        reason_code=reason_code,
    )


def invalid_request(reason_code: str) -> RbacError:
    return RbacError(
        status_code=_HTTP_UNPROCESSABLE_CONTENT,
        public_code="invalid_request",
        reason_code=reason_code,
    )


def precondition_required(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_428_PRECONDITION_REQUIRED,
        public_code="precondition_required",
        reason_code=reason_code,
    )


def precondition_failed(reason_code: str) -> RbacError:
    return RbacError(
        status_code=status.HTTP_412_PRECONDITION_FAILED,
        public_code="precondition_failed",
        reason_code=reason_code,
    )
