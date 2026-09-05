import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest

from app.rbac.errors import RbacError
from app.rbac.security import decode_access_token
from app.settings import get_settings


def valid_payload() -> dict[str, Any]:
    settings = get_settings()
    now = datetime.now(UTC)
    return {
        "sub": str(uuid.uuid4()),
        "tid": str(uuid.uuid4()),
        "ver": 3,
        "jti": str(uuid.uuid4()),
        "token_type": "access",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }


def encode(payload: dict[str, Any], *, algorithm: str = "HS256") -> str:
    settings = get_settings()
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=algorithm,
    )


def test_valid_access_token_resolves_identity_only() -> None:
    payload = valid_payload()

    principal = decode_access_token(encode(payload), get_settings())

    assert principal.user_id == uuid.UUID(payload["sub"])
    assert principal.token_tenant_id == uuid.UUID(payload["tid"])
    assert principal.token_version == 3


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(iss="https://wrong-issuer.example"),
        lambda payload: payload.update(aud="wrong-audience"),
        lambda payload: payload.update(token_type="refresh"),
        lambda payload: payload.update(exp=datetime.now(UTC) - timedelta(seconds=1)),
        lambda payload: payload.update(nbf=datetime.now(UTC) + timedelta(minutes=5)),
        lambda payload: payload.update(sub="not-a-uuid"),
        lambda payload: payload.pop("jti"),
    ],
)
def test_invalid_access_token_claims_fail_closed(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = valid_payload()
    mutate(payload)

    with pytest.raises(RbacError) as caught:
        decode_access_token(encode(payload), get_settings())

    assert caught.value.status_code == 401
    assert caught.value.public_code == "invalid_authentication"


def test_wrong_jwt_algorithm_fails_closed() -> None:
    with pytest.raises(RbacError):
        decode_access_token(encode(valid_payload(), algorithm="HS384"), get_settings())
