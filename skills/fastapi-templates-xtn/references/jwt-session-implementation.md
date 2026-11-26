# JWT Active-JTI Implementation

Read this only for concrete Token or Redis registry work. First apply
[JWT security](jwt-session-security.md), which owns the claims, consent,
authentication order, and failure contract. Use the runnable
[JWT codec](../assets/postgresql-rbac/app/core/security/jwt_tokens.py) for
claims, signing and verification, and the
[Redis login Repository](../assets/postgresql-rbac/app/repositories/redis/login_session_repository.py)
for atomic JTI persistence and
[AuthService](../assets/postgresql-rbac/app/services/auth_service.py) for signing
and registration coordination. Do not maintain a second partial registry
algorithm in generated projects.

## Token Contract And Integration

The default asset uses exact `U` + 14-character user IDs as JWT `user_id`, and a
fresh UUIDv4 as each JWT `jti`. JWT uses the standard hyphenated JTI string;
Redis fields and sorted-set members use its 32-character lowercase `UUID.hex`.
Subject parsing and Redis keys use the same canonical 15-character user ID
directly. See [Identifier policy](identifier-policy.md).

`decode_access_token` verifies the pinned HS256 algorithm, required integer times,
canonical IDs, literal `token_type=access`, maximum configured lifetime, and the
exact claim set. Default claims are only `user_id`, `jti`, `iat`, `exp`, and
`token_type`; the optional `iss`/`aud` pair requires explicit owner consent.
The default lifetime is 86,400 seconds. Tell users where to adjust it for their
business risk and login experience. Neither the user version nor RBAC data
enters JWT. Startup rejects weak secrets; input and output are bounded to
4096 bytes.

Keep the default and optional `iss`/`aud` claim selection beside the actual
decode call in `core/security/jwt_tokens.py`. Do not hide the accepted profile
behind a one-use helper; readers should see which claims are required and
allowed where the Token is verified.

`AuthService.login` owns the complete local-password login. After verifying the
credentials and rechecking the live user under the existing locks, it closes
the database transaction and calls `self.issue_access_token` with the verified
user ID and version. Keep this call in the Service; the route receives `LoginResult`
and only constructs the HTTP response:

```python
from app.core.security.jwt_tokens import decode_access_token
from app.repositories.redis.login_session_repository import login_session_repository
from app.services.auth_service import auth_service

token = await auth_service.issue_access_token(
    redis,
    user_id=verified_user_id,
    user_token_version=verified_token_version,
    settings=settings,
)
```

`AuthService.issue_access_token` signs a fresh Token through the JWT codec and
calls `login_session_repository.register_login_session` with its decoded fields,
user version and simultaneous-login maximum. The Repository returns `True` for
confirmed registration and `False` only for a confirmed JTI collision. The Service
returns the Token only after registration and retries a confirmed collision once
with a new UUIDv4. An expired/invalid script input, unexpected reply, or Redis
failure returns safe `503` without a Token; a superseded user version returns
generic `401`. Never replay an ambiguous Redis write or activate a missing
record from a presented JWT.

Protected authentication then performs:

```python
token_info = decode_access_token(presented_token, settings)
bound_version = await login_session_repository.check_login_session(redis, token_info=token_info)
# Now load the live PostgreSQL user and current authority through the existing
# authentication dependency. Reject if user.token_version != bound_version.
```

Do not stop after Redis for an ordinary business operation. The existing
PostgreSQL user/status/version and current RBAC checks remain authoritative;
no individual PostgreSQL Token/session table is introduced.

## Shared Redis 7 Registry

The standalone Redis client uses this two-key Lua implementation.
Construct the user's keys and JTI field as:

```text
user_id      = canonical U + 14-character user ID (15 characters total)
sessions_key = login:sessions:<user_id>
sequence_key = login:sequence:<user_id>
jti_field    = canonical UUIDv4 JTI's UUID.hex (32 lowercase hexadecimal characters)
```

Each user's two keys contain the same canonical user ID directly. Neither the
user ID nor JTI is hashed. Redis is dedicated to this service: key names contain
no braces, version segment, service name, environment, or NUL separators.
Service and environment configuration remains for logs and application information.
The optional issuer and audience never determine this namespace.

For example, user `UABCDEFGHIJKLMN` uses
`login:sessions:UABCDEFGHIJKLMN` and `login:sequence:UABCDEFGHIJKLMN`.
JWT JTI `11111111-1111-4111-8111-111111111111` uses Redis field/member
`11111111111141118111111111111111`.

The Repository's `check_login_session`, `delete_login_session` and
`list_active_sessions` methods do not take `settings`.
`register_login_session(redis, *, token_info, user_token_version, max_active_sessions)`
receives the already signed Token's fields and explicit persistence inputs;
it neither signs nor returns a Token. `AuthService.issue_access_token` takes
`settings` for signing, Token lifetime and the simultaneous-login maximum.

| Key | Type | Stored data |
| --- | --- | --- |
| `login:sessions:<user_id>` | Hash | `jti_field → exact JSON record`, plus reserved `_version` |
| `login:sequence:<user_id>` | Sorted set | The same 32-character JTI fields ordered by registration time from Redis `TIME`, with a monotonic tie/clock fallback |

An exact record contains only:

```json
{"exp":1800003600,"iat":1800000000,"token_version":3,"typ":"access","user_id":"UABCDEFGHIJKLMN"}
```

No raw JWT, username, password, role, or permission data is stored. Authentication
validates exact fields, canonical serialization, and the Token's
`user_id`/`iat`/`exp`; it also requires login-order membership and agreement with
the session hash's `_version`.

Every Lua invocation explicitly passes both keys as `KEYS`. The scripts
only access those keys; members are hash fields, never dynamically discovered
Redis key names. Do not pin all users to one constant hash tag or implement
separate near-identical algorithms per Redis mode.

Keep each active-JTI Lua script and its Python result checks together in
`repositories/redis/login_session_repository.py`. Explain known result codes at the branch
that interprets them. Confirmed missing, expired or mismatched session state is
an authentication failure; an unexpected script result is a service failure,
not proof that the client's Token was invalid.

## Atomic Issuance, Limits, And Expiry

The activation script runs these steps as one Redis operation:

1. Read server `TIME`; validate the deadline, positive configured login maximum,
   and nonnegative user version.
2. Reject an incoming version lower than the session hash's `_version` before
   registering anything.
3. Retain the larger of the existing session hash's absolute expiry
   (`PEXPIRETIME`) and the incoming session's `exp * 1000`.
4. When the version increases, clear old-version records and the order index.
   For the same version, traverse the login-order index and remove sessions
   whose JSON `exp <= now`. Register the new canonical record with `HSETNX`;
   its result also rejects an existing JTI field. Write the version and add
   the login-order entry.
5. Remove the oldest registered session until the selected simultaneous-login
   maximum is satisfied, then `PEXPIREAT` both surviving containers at the retained
   deadline. Eviction follows registration order, never the earliest `exp`.

An atomic success is `1`, a confirmed duplicate is `0`, stale version is `-2`,
and invalid/expired input is `-1`. Unknown results fail closed. A failed
registration never returns a Token. A lost successful response can still consume
a login slot or evict the previous oldest session, so the client must not silently
replay it as if nothing happened.

The registry does not require newer Redis hash-field expiry commands, so it also
works on Redis 7.0. Each session becomes unusable at its JSON record's `exp`,
checked against Redis server time. `check_login_session` uses one Lua round trip
to read only the current record, the hash's `_version`, and that JTI's order
membership; it rejects an expired current record without traversing the queue.
Activation and online-session listing traverse this user's order index and
remove expired entries after reading each JSON record. That cleanup costs O(n)
for this user's n sessions, an intentional tradeoff for small per-user login
sets. Inactive fields may physically remain until cleanup or container expiry.
Reading sessions never extends the deadline.

Containers may outlive a shorter session. Their deadline covers the maximum
previously retained issuance deadline so a short new login cannot prematurely
erase a longer login. Keep the session hash's `_version` through this same deadline even
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
await login_session_repository.delete_login_session(
    redis,
    token_info=token_info,
    user_token_version=bound_version,
)
```

One Lua call compares the exact stored JSON, removes only that JTI field and its
login-order entry, and retains the version watermark. Report success only after
confirmed deletion. Missing, expired, or mismatched state is generic `401`;
Redis failure or an unknown deletion outcome is safe `503`. A retry after
successful deletion receives `401`, not another success.

Current-Token logout is the sole exception to the PostgreSQL lookup: it can only
remove the presented credential. Its route uses `Depends(check_token)`
directly, without a quota, separate limiter-client dependency or business-permission
check. Disabled users or users revoked in PostgreSQL
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
[app/db/redis_db.py](../assets/postgresql-rbac/app/db/redis_db.py), which create
standalone Redis clients. Reuse the main client across requests; close it in
lifespan. Keep `decode_responses=True`, bounded pools, connect/socket timeouts,
TLS certificate checks for `rediss://`, and no blind replay after ambiguous
writes. Connection choices belong to [Redis connections](redis-connections.md).

The two-key registry uses new key names, so existing users must log in again
when this implementation is deployed. Do not dual-read old layouts, backfill
from presented JWTs, or restore missing records automatically. Old keys expire
naturally through their existing TTL; no active cleanup is needed for this update.

## Verification

Use the existing tests instead of reproducing only `eval` mocks:

- [Unit Token contract](../assets/postgresql-rbac/tests/test_security.py) and
  [session-key namespace checks](../assets/postgresql-rbac/tests/test_redis_session_keys.py).
- [Offline Lua behavior](../assets/postgresql-rbac/tests/test_session_registry_lua.py)
  directly executes production scripts with optional maintainer `fakeredis[lua]`;
  it skips when those dependencies are absent and never connects to real services.
- [Real registry boundaries](../assets/postgresql-rbac/tests/integration/test_redis_session_registry.py):
  mixed lifetimes, current-record expiry and list/issuance cleanup, version watermark after last
  logout, concurrent caps, oldest eviction, duplicates, and exact deletion.
- [Standalone client checks](../assets/postgresql-rbac/tests/test_redis_clients.py)
  for bounded connections, TLS and no command replay.

Apply the remaining security matrix from [JWT security](jwt-session-security.md):
signing-key-only forgery, stolen active Token replay, user-version revocation,
weak secrets, exact claim profiles, outages, and safe errors. Use only isolated
disposable test services. Code-test evidence does not certify production
capacity or infrastructure failover.
