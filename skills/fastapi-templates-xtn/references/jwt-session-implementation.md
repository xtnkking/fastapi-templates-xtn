# JWT Session Implementation Shapes

Read this reference only when concrete token, PostgreSQL session, or Redis
registry code is required. First apply the fixed claims, failure semantics, and
cross-store protocol in [JWT session security](jwt-session-security.md). Adapt
names and exception envelopes to the repository; preserve the invariants.

## Minimal Claims And Decoder

Map `InvalidCredential` to generic `401` with `WWW-Authenticate: Bearer`. Resolve
an asymmetric key from a validated, allowlisted `kid` before this decoder; never
let the token header select the accepted algorithm.

```python
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

ACCESS_TTL_SECONDS = 600
CLOCK_LEEWAY_SECONDS = 30
REQUIRED_ACCESS_CLAIMS = (
    "iss", "aud", "sub", "tid", "jti", "iat", "exp", "token_type"
)


class InvalidCredential(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    jti: uuid.UUID
    issued_at: int
    expires_at: int


def _uuid4(value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise InvalidCredential
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise InvalidCredential from exc
    if parsed.version != 4 or str(parsed) != value:
        raise InvalidCredential
    return parsed


def decode_access_token(token: str, settings: Settings) -> AccessClaims:
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_verification_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            leeway=CLOCK_LEEWAY_SECONDS,
            options={
                "require": list(REQUIRED_ACCESS_CLAIMS),
                "strict_aud": True,
            },
        )
        if payload["token_type"] != "access":
            raise InvalidCredential
        iat, exp = payload["iat"], payload["exp"]
        nbf = payload.get("nbf")
        if (
            isinstance(iat, bool)
            or isinstance(exp, bool)
            or not isinstance(iat, int)
            or not isinstance(exp, int)
            or (
                nbf is not None
                and (isinstance(nbf, bool) or not isinstance(nbf, int))
            )
            or exp <= iat
            or exp - iat > ACCESS_TTL_SECONDS
        ):
            raise InvalidCredential
        return AccessClaims(
            user_id=_uuid4(payload["sub"]),
            tenant_id=_uuid4(payload["tid"]),
            jti=_uuid4(payload["jti"]),
            issued_at=iat,
            expires_at=exp,
        )
    except (jwt.PyJWTError, KeyError, TypeError, InvalidCredential) as exc:
        raise InvalidCredential from exc
```

If `nbf` is present, PyJWT validates it with the configured leeway. Reject an
`iat` unreasonably far in the future. The trusted issuer creates the JTI; never
accept it from a login request.

```python
def issue_access_token(
    *, user_id: uuid.UUID, tenant_id: uuid.UUID, settings: Settings
) -> tuple[str, AccessClaims]:
    now = datetime.now(UTC).replace(microsecond=0)
    claims = AccessClaims(
        user_id=user_id,
        tenant_id=tenant_id,
        jti=uuid.uuid4(),
        issued_at=int(now.timestamp()),
        expires_at=int((now + timedelta(seconds=ACCESS_TTL_SECONDS)).timestamp()),
    )
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(claims.user_id),
        "tid": str(claims.tenant_id),
        "jti": str(claims.jti),
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "token_type": "access",
    }
    token = jwt.encode(
        payload,
        settings.jwt_signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_signing_key_id},
    )
    return token, claims
```

## PostgreSQL Session Model

The access session ID equals `jti`. Keep the user's current token version in the
row, not the JWT, so account-wide revocation stays server-authoritative.

```python
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


class AuthenticationSession(Base):
    __tablename__ = "authentication_sessions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'active', 'revoked')",
            name="authentication_sessions_valid_status",
        ),
        CheckConstraint(
            "expires_at > issued_at",
            name="authentication_sessions_valid_lifetime",
        ),
        CheckConstraint(
            "user_token_version >= 0",
            name="authentication_sessions_nonnegative_user_version",
        ),
        CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)",
            name="authentication_sessions_revocation_shape",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["memberships.tenant_id", "memberships.user_id"],
            name="fk_authentication_sessions_membership_tenant_user",
            ondelete="RESTRICT",
        ),
        Index("ix_authentication_sessions_user_status", "user_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    user_token_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
```

The Alembic revision also creates the named foreign keys/checks/index. The
composite membership foreign key depends on the baseline's unique
`memberships(tenant_id, user_id)` constraint. The issuer supplies the same UUIDv4
for row ID and JTI. At authentication, select the row by all of `id`, `user_id`,
and `tenant_id`; require `active`, require database time before `expires_at`, load
an active user, and compare the row's version with `users.token_version`.

## Redis Registry

Use `decode_responses=True` for this exact-string example. `DuplicateJTI` is an
internal issuance conflict; retry once with a fresh UUIDv4 or fail the issuance.
`AuthenticationUnavailable` maps to `503`, while `InvalidCredential` maps to
generic `401`.

```python
import hashlib
import json

from redis.asyncio import Redis
from redis.exceptions import RedisError


class AuthenticationUnavailable(Exception):
    pass


class DuplicateJTI(Exception):
    pass


def _registry_key(*, environment: str, issuer: str, jti: uuid.UUID) -> str:
    digest = hashlib.sha256(f"{issuer}\0{jti}".encode()).hexdigest()
    return f"auth:access:v1:{environment}:{digest}"


def _registry_value(claims: AccessClaims) -> str:
    return json.dumps(
        {
            "sub": str(claims.user_id),
            "tid": str(claims.tenant_id),
            "typ": "access",
            "exp": claims.expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


async def activate_jti(
    redis: Redis,
    *,
    environment: str,
    issuer: str,
    claims: AccessClaims,
) -> None:
    try:
        created = await redis.set(
            _registry_key(environment=environment, issuer=issuer, jti=claims.jti),
            _registry_value(claims),
            nx=True,
            exat=claims.expires_at,
        )
    except RedisError as exc:
        raise AuthenticationUnavailable from exc
    if created is not True:
        raise DuplicateJTI


async def require_active_jti(
    redis: Redis,
    *,
    environment: str,
    issuer: str,
    claims: AccessClaims,
) -> None:
    try:
        value = await redis.get(
            _registry_key(environment=environment, issuer=issuer, jti=claims.jti)
        )
    except RedisError as exc:
        raise AuthenticationUnavailable from exc
    if value != _registry_value(claims):
        raise InvalidCredential
```

Create the Redis client in FastAPI lifespan with `decode_responses=True`, a
500-millisecond connect timeout, a 500-millisecond socket timeout, and timeout
retry disabled as the starting service default; keep both timeouts inside the
request deadline and tune only from measured deployment latency. Close it in
lifespan cleanup and inject it into the authentication dependency. Do not create
one client per request or add a local positive cache. Reject bearer values over
4096 bytes before JWT parsing unless a documented upstream protocol requires a
smaller limit.

## Asset Integration Checklist

The included asset's current adapter is not an active-JTI implementation. A
complete adaptation changes these boundaries together:

1. Add Redis settings/dependency and a migration plus SQLAlchemy model for
   `authentication_sessions`; keep every identifier UUIDv4.
2. Change `Principal` to carry `user_id`, `tenant_id`, and UUID `jti`; remove the
   token-provided version.
3. Update `security.py` to the minimal claim contract and fixed algorithm/key
   resolver.
4. In `get_current_principal`, decode first, require the exact Redis record, then
   load the matching active PostgreSQL session and current active user. Do not
   execute tenant or RBAC queries on either failure.
5. Integrate the pending-to-active issuance protocol at the trusted issuer or
   token-exchange boundary. Never activate a Redis miss from a bearer request.
6. Revoke PostgreSQL session state and write the outbox/audit atomically; process
   Redis deletion after commit. Recheck session state under the canonical locks
   for privileged writes.
7. Add the full verification matrix from
   [JWT session security](jwt-session-security.md) before claiming revocation is
   complete.
