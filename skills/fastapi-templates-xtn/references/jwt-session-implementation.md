# JWT Active-JTI Implementation Shapes

Read this reference only when concrete Access Token or Redis registry code is
required. First apply the consent-gated claims, failure semantics, and issuance order in
[JWT access-token security](jwt-session-security.md). Adapt names and exception
envelopes to the repository; preserve the invariants.

## Minimal Claims And Decoder

Map `InvalidCredential` to generic `401` with `WWW-Authenticate: Bearer`. Resolve
an asymmetric key from a validated, allowlisted `kid` before this decoder; never
let the Token header select the accepted algorithm.

The concrete block below matches the bundled asset's valid UUIDv4 user-ID
profile. UUID is not mandatory. In a project that selected prefixed business
IDs, change `AccessClaims.user_id` and `build_access_token.user_id` to the
project's user-ID type, and replace only `_uuid4(payload["sub"])` with the exact
prefix/alphabet/length parser from [identifier policy](identifier-policy.md).
Keep `_uuid4(payload["jti"])`: JTI is a protocol identifier and remains UUIDv4.
Never replace subject validation with an unconstrained `str`.

```python
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

DEFAULT_ACCESS_TTL_SECONDS = 86_400
CLOCK_LEEWAY_SECONDS = 30
REQUIRED_ACCESS_CLAIMS = frozenset({"sub", "jti", "iat", "exp", "token_type"})
OPTIONAL_ACCESS_SCOPE_CLAIMS = frozenset({"iss", "aud"})


class InvalidCredential(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
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


def _expected_access_claims(settings: Settings) -> frozenset[str]:
    if (settings.jwt_issuer is None) != (settings.jwt_audience is None):
        raise RuntimeError("JWT issuer and audience must be configured together")
    if settings.jwt_issuer is None:
        return REQUIRED_ACCESS_CLAIMS
    return REQUIRED_ACCESS_CLAIMS | OPTIONAL_ACCESS_SCOPE_CLAIMS


def decode_access_token(token: str, settings: Settings) -> AccessClaims:
    try:
        expected_claims = _expected_access_claims(settings)
        decode_kwargs: dict[str, Any] = {}
        if settings.jwt_issuer is not None and settings.jwt_audience is not None:
            decode_kwargs = {
                "issuer": settings.jwt_issuer,
                "audience": settings.jwt_audience,
            }
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_verification_key,
            algorithms=[settings.jwt_algorithm],
            leeway=CLOCK_LEEWAY_SECONDS,
            options={
                "require": sorted(expected_claims),
                "strict_aud": True,
            },
            **decode_kwargs,
        )
        if set(payload) != expected_claims:
            raise InvalidCredential
        if payload["token_type"] != "access":
            raise InvalidCredential
        iat, exp = payload["iat"], payload["exp"]
        if (
            isinstance(iat, bool)
            or isinstance(exp, bool)
            or not isinstance(iat, int)
            or not isinstance(exp, int)
            or exp <= iat
            or exp - iat > settings.jwt_access_token_ttl_seconds
        ):
            raise InvalidCredential
        return AccessClaims(
            user_id=_uuid4(payload["sub"]),
            jti=_uuid4(payload["jti"]),
            issued_at=iat,
            expires_at=exp,
        )
    except (jwt.PyJWTError, KeyError, TypeError, InvalidCredential) as exc:
        raise InvalidCredential from exc
```

Define `jwt_access_token_ttl_seconds` as positive typed configuration with a default
of `DEFAULT_ACCESS_TTL_SECONDS`. Explicitly tell the user to adjust it for the
product's risk and expected login experience. Reject extra claims and an `iat`
unreasonably far in the future. Define `jwt_issuer` and `jwt_audience` as optional
strings that must be both absent or both nonblank. Do not set them for a new
project until the user has explicitly consented after the policy's plain-language
explanation. Preserve an already configured pair in an existing project unless a
migration is requested. The trusted signer creates the JTI; never accept it from
a login request.

```python
def build_access_token(
    *, user_id: uuid.UUID, settings: Settings
) -> tuple[str, AccessClaims]:
    now = datetime.now(UTC).replace(microsecond=0)
    claims = AccessClaims(
        user_id=user_id,
        jti=uuid.uuid4(),
        issued_at=int(now.timestamp()),
        expires_at=int(
            (now + timedelta(seconds=settings.jwt_access_token_ttl_seconds)).timestamp()
        ),
    )
    payload: dict[str, object] = {
        "sub": str(claims.user_id),
        "jti": str(claims.jti),
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "token_type": "access",
    }
    if settings.jwt_issuer is not None and settings.jwt_audience is not None:
        payload.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
    token = jwt.encode(
        payload,
        settings.jwt_signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_signing_key_id},
    )
    return token, claims
```

## Redis Registry

Use `decode_responses=True` for this string example. The record binds the Token
claims to the server-side user version observed during login. The version does
not enter JWT. `DuplicateJTI` is an internal issuance conflict;
`AuthenticationUnavailable` maps to `503`, while `InvalidCredential` maps to a
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


@dataclass(frozen=True, slots=True)
class ActiveJTIRecord:
    user_version: int


def _registry_key(*, environment: str, service_name: str, jti: uuid.UUID) -> str:
    digest = hashlib.sha256(f"{service_name}\0{jti}".encode()).hexdigest()
    return f"auth:access:v1:{environment}:{digest}"


def _registry_value(claims: AccessClaims, *, user_version: int) -> str:
    return json.dumps(
        {
            "sub": str(claims.user_id),
            "typ": "access",
            "iat": claims.issued_at,
            "exp": claims.expires_at,
            "token_version": user_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _parse_registry_value(value: str | None, claims: AccessClaims) -> ActiveJTIRecord:
    if value is None:
        raise InvalidCredential
    try:
        data = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidCredential from exc
    if not isinstance(data, dict) or set(data) != {
        "sub", "typ", "iat", "exp", "token_version"
    }:
        raise InvalidCredential
    user_version = data["token_version"]
    issued_at = data["iat"]
    expires_at = data["exp"]
    if (
        data["sub"] != str(claims.user_id)
        or data["typ"] != "access"
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at != claims.issued_at
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at != claims.expires_at
        or isinstance(user_version, bool)
        or not isinstance(user_version, int)
        or user_version < 0
    ):
        raise InvalidCredential
    if value != _registry_value(claims, user_version=user_version):
        raise InvalidCredential
    return ActiveJTIRecord(user_version=user_version)


ACTIVATE_JTI = """
redis.replicate_commands()
local redis_time = redis.call('TIME')
local expires_at = tonumber(ARGV[2])
if not expires_at or expires_at ~= math.floor(expires_at) then
    return -1
end
local ttl_seconds = expires_at - tonumber(redis_time[1])
if ttl_seconds <= 0 then
    return -1
end
if not redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ttl_seconds) then
    return 0
end
if redis.call('PEXPIREAT', KEYS[1], expires_at * 1000) ~= 1 then
    redis.call('DEL', KEYS[1])
    return -1
end
return 1
"""


async def activate_jti(
    redis: Redis,
    *,
    environment: str,
    service_name: str,
    claims: AccessClaims,
    user_version: int,
) -> None:
    try:
        created = await redis.eval(
            ACTIVATE_JTI,
            1,
            _registry_key(
                environment=environment,
                service_name=service_name,
                jti=claims.jti,
            ),
            _registry_value(claims, user_version=user_version),
            claims.expires_at,
        )
    except RedisError as exc:
        raise AuthenticationUnavailable from exc
    if type(created) is int and created == 1:
        return
    if type(created) is int and created == 0:
        raise DuplicateJTI
    raise AuthenticationUnavailable


async def require_active_jti(
    redis: Redis,
    *,
    environment: str,
    service_name: str,
    claims: AccessClaims,
) -> ActiveJTIRecord:
    try:
        value = await redis.get(
            _registry_key(
                environment=environment,
                service_name=service_name,
                jti=claims.jti,
            )
        )
    except RedisError as exc:
        raise AuthenticationUnavailable from exc
    return _parse_registry_value(value, claims)
```

The login path must register before returning the Token:

The activation script requires Redis 5.0 or newer. Its single-key operation
uses Redis server time, `SET NX EX` to avoid an unbounded key even if an
unexpected expiry command fails, and `PEXPIREAT` to give the record precisely
the JWT's absolute expiry rather than extending it by a partial second. Its
result is `1` for creation, `0` for a duplicate key, and `-1` for a past deadline
or failed expiry. Treat any other result as unavailable, never as success.

```python
async def issue_registered_access_token(
    redis: Redis,
    *,
    user: User,
    settings: Settings,
) -> str:
    for attempt in range(2):
        token, claims = build_access_token(user_id=user.id, settings=settings)
        try:
            await activate_jti(
                redis,
                environment=settings.environment,
                service_name=settings.service_name,
                claims=claims,
                user_version=user.token_version,
            )
        except DuplicateJTI:
            if attempt == 0:
                continue
            raise
        return token
    raise AssertionError("unreachable")
```

Authenticate credentials and load the active user immediately before calling
this function. A Redis error aborts issuance through
`AuthenticationUnavailable`; no Token is returned.

After decoding and `require_active_jti`, load the existing PostgreSQL user and
current RBAC authority. Require the user to be active and require
`user.token_version == record.user_version`. This reuses the normal identity and
authorization query; do not create or query an individual Token table.

## Confirmed Logout

Use an atomic compare-and-delete so the route only reports success for the exact
record that authentication validated:

```python
COMPARE_AND_DELETE = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""


async def revoke_jti(
    redis: Redis,
    *,
    environment: str,
    service_name: str,
    claims: AccessClaims,
    record: ActiveJTIRecord,
) -> None:
    key = _registry_key(
        environment=environment,
        service_name=service_name,
        jti=claims.jti,
    )
    expected = _registry_value(claims, user_version=record.user_version)
    try:
        deleted = await redis.eval(COMPARE_AND_DELETE, 1, key, expected)
    except RedisError as exc:
        raise AuthenticationUnavailable from exc
    if deleted != 1:
        raise InvalidCredential
```

Return logout success only after `revoke_jti` returns. A Redis error, including a
timeout with an unknown delete outcome, maps to `503`; do not claim success. The
client may retry logout idempotently. A missing or changed key maps to the same
generic `401` as another inactive Token.

The current-Token logout route deliberately stops after this Redis operation and
does not load PostgreSQL user or RBAC state. Deleting the exact presented record
can only reduce authority, and this lets disabled or account-wide-revoked users
discard a still-present JTI without adding a database query. No other protected
route may use this exception.

Confirmed deletion prevents later gate checks; it cannot cancel a request that
already passed the Redis check. Redis failover may restore an older snapshot and
revive a recently deleted key. Choose Redis durability and consistency settings
to match the product risk, and do not claim PostgreSQL-grade linearizable
revocation from this lighter design.

Account-wide revocation increments `users.token_version` in PostgreSQL. Existing
Redis entries expire naturally but fail the version comparison on every later
request. There is no correctness dependency on scanning keys or deleting Token
rows.

Use the same lock order as other identity and authorization writers. The
included asset does not expose `/api/v1/auth/logout-all` to ordinary users.
`POST /api/v1/auth/logout` compares and deletes only the presented active JTI.
Only a separately authorized administrator may force a strictly lower target
out: first lock `rbac_state`, reload and compare complete actor/target authority,
then increment the target's `users.token_version` and write the security audit
in the same PostgreSQL transaction. Do not perform Redis I/O while holding
those locks, and do not allow a caller to target itself, a peer, or a higher user.
The per-user Redis index stores JTI registration times and a bound user version;
stale-version entries do not count towards the project-chosen active-login cap.

## Redis Lifecycle

Create the Redis client in FastAPI lifespan with `decode_responses=True`, a
500-millisecond connect timeout, a 500-millisecond socket timeout, and timeout
retry disabled as the starting service default; keep both timeouts inside the
request deadline and tune only from measured deployment latency. Close it in
lifespan cleanup and inject it into authentication. Do not create one client per
request or add a local positive cache. Reject bearer values over 4096 bytes before
JWT parsing unless a documented upstream protocol requires a smaller limit.

## Bundled Asset And Product Checklist

The bundled asset implements the adapter described here using its established
UUIDv4 entity-ID profile and wires it into the local username/password login
path:
the default exact five-claim profile, the optional consented `iss`/`aud` pair,
the configurable 86,400-second default, Redis lifespan ownership,
atomic Redis 5.0+ `SET NX EX` / `PEXPIREAT` registration before return,
Redis-first request validation,
PostgreSQL user-version comparison, and logout. It adds no individual PostgreSQL
Token table or migration. It also validates the HS256 secret at startup, bounds
input and output Tokens to 4096 bytes, and provides current-Token logout plus
authorized lower-target administrative session revocation.

Before adapting or shipping the asset:

1. Preserve the existing order of trusted credential verification followed by
   `issue_access_token`. If another identity provider replaces local passwords,
   connect it at that same boundary. Never activate a Redis miss from a bearer
   request.
2. Explicitly tell the user that the 24-hour default must be shortened when the
   product's risk, especially an administrative surface, requires a shorter
   replay window, or adjusted when login experience requires a different lifetime.
3. Leave `iss` and `aud` absent by default. Before adding the pair, explain its
   cross-service Token-scoping benefit and coordination cost in plain language,
   then wait for the user's explicit consent. No reply is not consent. Preserve
   an existing configured pair unless the user requests a migration.
4. Configure Redis TLS, ACLs, capacity, persistence, replication, failover, and
   namespace generation for the deployment's revocation requirements.
5. Preserve JWT, Redis, existing PostgreSQL user/RBAC order and exact
   `sub`/type/`iat`/`exp`/user-version binding when adapting code.
6. Run the full verification matrix from
   [JWT access-token security](jwt-session-security.md), including confirmed
   current logout, administrator revocation, weak-secret and Token-size rejection, in-flight
   request, failover, and signing-key compromise cases.

Do not call a deployment production-ready until its required Redis and
PostgreSQL checks pass in the target environment.
