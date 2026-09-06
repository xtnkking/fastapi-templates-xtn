import uuid
from datetime import UTC, datetime
from typing import Any

import jwt

from app.rbac.domain import Principal
from app.rbac.errors import unauthenticated
from app.settings import Settings


def _uuid4(value: object) -> uuid.UUID:
    parsed = uuid.UUID(str(value))
    if parsed.version != 4 or str(parsed) != str(value):
        raise ValueError("claim must be a canonical UUIDv4 string")
    return parsed


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
        token_version = int(payload["ver"])
        if token_version < 0:
            raise ValueError("negative token version")
        return Principal(
            user_id=_uuid4(payload["sub"]),
            token_version=token_version,
            token_id=_uuid4(payload["jti"]),
        )
    except (jwt.PyJWTError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise unauthenticated("invalid_access_token") from exc
