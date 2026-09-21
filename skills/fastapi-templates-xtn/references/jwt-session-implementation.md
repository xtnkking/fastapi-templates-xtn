# JWT Active-JTI Implementation

Read this only for concrete Token or Redis registry work. First apply
[JWT security](jwt-session-security.md), which owns the claims, consent,
authentication order, and failure contract. Use the runnable
[Token implementation](../assets/postgresql-rbac/app/core/security/tokens.py)
as the single source for Python and Lua; do not maintain a second partial
registry algorithm in generated projects.

## Token Contract And Integration

The asset uses canonical UUIDv4 user IDs and JTIs. UUID user IDs are not mandatory:
for a project using prefixed business IDs, adapt subject parsing under
[Identifier policy](identifier-policy.md), including the canonical user-ID input
to the registry digest. Keep random UUIDv4 JTIs.

`decode_access_token` verifies the pinned HS256 algorithm, required integer times,
canonical IDs, literal `token_type=access`, maximum configured lifetime, and the
exact claim set. Default claims are only `sub`, `jti`, `iat`, `exp`, and
`token_type`; the optional `iss`/`aud` pair requires explicit owner consent.
The default lifetime is 86,400 seconds. Tell users where to adjust it for their
business risk and login experience. Neither the user version nor RBAC data
enters JWT. Startup rejects weak secrets; input and output are bounded to
4096 bytes.

After verifying the current credentials and loading the live user, call the
existing issuer:

```python
from app.core.security.tokens import (
    decode_access_token,
    issue_access_token,
    require_active_jti,
    revoke_active_jti,
)

token = await issue_access_token(
    redis,
    user_id=user.id,
    user_token_version=user.token_version,
    settings=settings,
)
```

The issuer signs a fresh Token, atomically registers its session, and returns
only after confirmed registration. It retries a confirmed JTI collision once
with a new UUIDv4. An expired/invalid script input, unexpected reply, or Redis
failure returns safe `503` without a Token; a superseded user version returns
generic `401`. Never replay an ambiguous Redis write or activate a missing
record from a presented JWT.

Protected authentication then performs:

```python
claims = decode_access_token(presented_token, settings)
bound_version = await require_active_jti(redis, claims=claims, settings=settings)
# Now load the live PostgreSQL user and current authority through the existing
# authentication dependency. Reject if user.token_version != bound_version.
```

Do not stop after Redis for an ordinary business operation. The existing
PostgreSQL user/status/version and current RBAC checks remain authoritative;
no individual PostgreSQL Token/session table is introduced.

## Shared Redis 7 Registry

Standalone, Sentinel, and Cluster use the same three-key Lua implementation.
Construct the user's prefix as:

```text
user_digest = SHA256(service_name + NUL + canonical_user_id)
prefix      = auth:sessions:v2:<environment>:{<user_digest>}
jti_field   = SHA256(service_name + NUL + canonical_jti)
```

The braces are a Redis Cluster hash tag. One user's keys share a slot; other
users can use other slots. Environment and service namespaces stay separate.
The optional issuer and audience never determine this namespace.

| Key | Type | Stored data |
| --- | --- | --- |
| `<prefix>:records` | Hash | `jti_field → exact JSON record`, plus reserved `_version` |
| `<prefix>:order` | Sorted set | JTI fields ordered by registration time from Redis `TIME`, with a monotonic tie/clock fallback |
| `<prefix>:expires` | Sorted set | JTI fields scored by their integer `exp` |

An exact record contains only:

```json
{"exp":1800003600,"iat":1800000000,"sub":"8a0d04ef-bc75-4e14-90c3-f5f48e702e82","token_version":3,"typ":"access"}
```

No raw JWT, username, password, role, or permission data is stored. Authentication
validates exact fields, canonical serialization, and the Token's
`sub`/`iat`/`exp`; it also requires both index membership and agreement with
`records._version`.

Every Lua invocation explicitly passes all three keys as `KEYS`. The scripts
only access those keys; members are hash fields, never dynamically discovered
Redis key names. Do not pin all users to one constant hash tag or implement
separate near-identical algorithms per Redis mode.

## Atomic Issuance, Limits, And Expiry

The activation script runs these steps as one Redis operation:

1. Read server `TIME`; validate the deadline, positive configured login maximum,
   and nonnegative user version.
2. Reject an incoming version lower than `records._version` before registering
   anything. Prune sessions whose `exp <= now`; reject an existing JTI field.
3. Retain the larger of the existing `records` absolute expiry
   (`PEXPIRETIME`) and the incoming session's `exp * 1000`.
4. When the version increases, clear old-version records and indexes. Register
   the new canonical record with `HSETNX`, write the version, and add both indexes.
5. Remove the oldest registered session until the selected simultaneous-login
   maximum is satisfied, then `PEXPIREAT` all surviving containers at the retained
   deadline.

An atomic success is `1`, a confirmed duplicate is `0`, stale version is `-2`,
and invalid/expired input is `-1`. Unknown results fail closed. A failed
registration never returns a Token. A lost successful response can still consume
a login slot or evict the previous oldest session, so the client must not silently
replay it as if nothing happened.

The registry does not require newer Redis hash-field expiry commands, so it also
works on Redis 7.0. Each session becomes unusable at its own `exp`:
read/list/activation use Redis server time to reject
and remove expired entries. Inactive fields may physically remain until that
cleanup or container expiry. Reading sessions never extends the deadline.

Containers may outlive a shorter session. Their deadline covers the maximum
previously retained issuance deadline so a short new login cannot prematurely
erase a longer login. Keep `records._version` through this same deadline even
after replacing sessions or logging out the last session. This prevents delayed
old-version issuance from moving the watermark backward while previously issued
lifetimes remain relevant. Once the container expires, PostgreSQL's current
user version still governs authentication.

`list_active_sessions` checks the requested user version, prunes expired
entries, and returns active login `iat` values in registration order. These are
login sessions and timestamps, not physical device identifiers.

## Confirmed Logout And Account-Wide Revocation

After decoding the Token and confirming its exact active record, current logout
calls:

```python
await revoke_active_jti(
    redis,
    claims=claims,
    user_token_version=bound_version,
    settings=settings,
)
```

One Lua call compares the exact stored JSON, removes only that JTI field and its
two index entries, and retains the version watermark. Report success only after
confirmed deletion. Missing, expired, or mismatched state is generic `401`;
Redis failure or an unknown deletion outcome is safe `503`. A retry after
successful deletion receives `401`, not another success.

Current-Token logout is the sole exception to the PostgreSQL lookup: it can only
remove the presented credential. Disabled users or users revoked in PostgreSQL
can still discard a present session. Do not reuse this shortcut for business
operations. Deletion cannot cancel a request already past authentication.

Administrator-forced logout, password changes/resets, and account disablement
increment `users.token_version` in the same PostgreSQL transaction as their
mutation and security audit. They need no Redis scan or Token table. Existing
records fail subsequent PostgreSQL version checks; a later login atomically
replaces their Redis generation. Only an authorized administrator may revoke a
strictly lower target's sessions; ordinary users have current-Token logout only.
Never perform Redis I/O while holding authorization locks.

Redis replication/failover can restore older session state. Persistence and
replication guarantees are owner/operations choices; the application must not
claim stronger revocation consistency than the supplied service provides.

## Client Lifecycle And Layout Changes

Use the shared factories in
[app/db/redis.py](../assets/postgresql-rbac/app/db/redis.py), which select ordinary
Redis, Sentinel master discovery, or Cluster from settings and return
`RedisClient`. Reuse the chosen client across requests; close it in lifespan.
Keep `decode_responses=True`, bounded pools, connect/socket timeouts, TLS/ACL
configuration, primary reads, and no blind replay after ambiguous writes.
Connection choices belong to [Redis connections](redis-connections.md);
cluster deployment and maintenance remain outside the application.

The `v2` registry replaces the former `v1` per-JTI-key layout in every mode.
An upgrade requires users to log in again. Do not dual-read the old namespace,
backfill from presented JWTs, or restore missing records automatically. Existing
old keys can expire naturally. Other namespace changes likewise require an
explicit login reset.

## Verification

Use the existing tests instead of reproducing only `eval` mocks:

- [Unit Token contract](../assets/postgresql-rbac/tests/test_security.py) and
  [slot/namespace checks](../assets/postgresql-rbac/tests/test_redis_session_slots.py).
- [Real registry boundaries](../assets/postgresql-rbac/tests/integration/test_redis_session_registry.py):
  mixed lifetimes, read/list/issuance cleanup, version watermark after last
  logout, concurrent caps, oldest eviction, duplicates, and exact deletion.
- [Real topology checks](../assets/postgresql-rbac/tests/test_redis_topology_live.py)
  for the configured standalone, Sentinel, and Cluster clients.

Apply the remaining security matrix from [JWT security](jwt-session-security.md):
signing-key-only forgery, stolen active Token replay, user-version revocation,
weak secrets, exact claim profiles, outages, and safe errors. Use only isolated
disposable test services. Code-test evidence does not certify production
capacity or infrastructure failover.
