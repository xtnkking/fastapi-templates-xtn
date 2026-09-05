import uuid
from datetime import UTC, datetime
from typing import Any

import jwt

from app.rbac.domain import Principal
from app.rbac.errors import unauthenticated
from app.settings import Settings


def decode_access_token(token: str, settings: Settings) -> Principal:
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": [
                    "sub",
                    "tid",
                    "ver",
                    "jti",
                    "token_type",
                    "iat",
                    "nbf",
                    "exp",
                ]
            },
        )
        if payload["token_type"] != "access":
            raise ValueError("wrong token type")
        issued_at = datetime.fromtimestamp(int(payload["iat"]), tz=UTC)
        if issued_at > datetime.now(UTC):
            raise ValueError("token issued in the future")
        return Principal(
            user_id=uuid.UUID(str(payload["sub"])),
            token_tenant_id=uuid.UUID(str(payload["tid"])),
            token_version=int(payload["ver"]),
            token_id=str(payload["jti"]),
        )
    except (jwt.PyJWTError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise unauthenticated("invalid_access_token") from exc
