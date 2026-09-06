# JWT Session Security

Read this reference when designing or reviewing JWT claims, signing, login,
logout, access/refresh separation, Redis JTI validation, or token revocation. It
is the canonical token-session policy; do not duplicate it in RBAC code. Read
[JWT session implementation](jwt-session-implementation.md) only when concrete
Python, SQLAlchemy, or Redis code is required.

## Fixed Access-Token Contract

A JWT is a signed bearer credential, not encrypted profile storage. Keep its
payload deliberately small:

| Claim | Baseline rule |
| --- | --- |
| `iss` | Exact configured issuer; required |
| `aud` | Exact API audience; required |
| `sub` | Canonical lowercase UUIDv4 string of immutable `users.id`; required and the only user identity claim |
| `jti` | New random UUIDv4 for every access token; required and never reused |
| `iat` | Integer NumericDate issuance time; required |
| `exp` | Integer NumericDate expiry; required and no more than 10 minutes after `iat` by default |
| `token_type` | Literal `access`; required |
| `nbf` | Omit by default; if an issuer needs it, validate it as an integer NumericDate |

`sub` is the only required user data. The remaining required fields are security
protocol metadata. Do not add application profile or authorization state merely
to avoid a PostgreSQL lookup.

Never place username, email, phone, display name, role names, permission keys,
management tier, ownership, protection flags, account status,
authorization versions, or profile data in an access token. Keep
`users.token_version` and session state in PostgreSQL instead of copying `ver`
into the JWT. Look up display data after authentication when a response needs it.

Use the stable user UUID as `sub`; never use an email, username, role-assignment
ID, or auto-incremented integer. Only when choosing/changing the ID strategy or
migrating a legacy subject, also read
[identifier policy](identifier-policy.md).

## Signing And Validation

- Pin an algorithm allowlist in verifier configuration; never derive accepted
  algorithms from the untrusted JWT header and never accept `none`.
- With an external issuer, use its pinned asymmetric algorithm and an allowlisted
  `kid`/JWKS rotation process. Reject unknown `kid`; bound JWKS cache lifetime and
  fail closed when no valid verification key is available.
- The included asset's HS256 shape is acceptable only when one tightly controlled
  trust boundary both signs and verifies. Use at least 256 random secret bits and
  rotate deliberately; a validator that knows an HMAC secret can mint tokens.
- Before Redis or database access, verify signature, exact `iss` and `aud`, every
  required claim, optional `nbf`, maximum lifetime, `token_type`, and canonical
  UUIDv4 `sub` and `jti`. Use at most 30 seconds clock skew by default.
- Limit bearer-token size at the HTTP boundary. Never log a token, signing key,
  refresh credential, password, or Redis session value.

Map every malformed, expired, or wrong-key/type credential to one generic
`401` response with `WWW-Authenticate: Bearer`; keep diagnostic detail in a safe
internal metric or log. Do not let parsing differences expose account state.

## PostgreSQL Session Authority

Use a durable `authentication_sessions` row whose UUIDv4 primary key is the
access token JTI. It binds `user_id`, status, issuance/expiry times,
revocation time, and the user token version observed at issuance. This supports
single-token logout, account-wide revocation, auditing, and transaction-local
rechecks without adding mutable token claims.

At authentication, require the row to be active and unexpired, require the
current user to be active, compare its stored user version with the current
`users.token_version`, and match row `user_id` to `sub`. Querying only by JTI is
insufficient. Follow the concrete model in
[JWT session implementation](jwt-session-implementation.md).

## Redis Active-JTI Allowlist

Use Redis as a required active-session gate, not as a denylist and not as an RBAC
permission cache. A signed access token is accepted only while its JTI has the
exact expected record. Missing, expired, evicted, malformed, or mismatched keys
deny safely, although unexpected eviction reduces availability.

JTI validation enables targeted revocation; it does not make an access token
one-time or stop replay while the session remains active. Protect bearer tokens
with TLS, narrow storage/exposure, short lifetime, and the product's abuse and
device/session monitoring policy.

- Generate each JTI as UUIDv4 inside the trusted issuer. Never accept or reuse a
  client-supplied JTI.
- Namespace a key by environment and a SHA-256 digest of `issuer + NUL + jti`.
  Store no raw JWT. The value binds canonical `sub`, literal access type, and
  `exp`.
- Activate with `SET ... NX EXAT <exp>`. Duplicate JTI is an issuance conflict;
  make one bounded retry with a fresh UUID or fail issuance. The Redis expiry
  must never outlive JWT expiry and reads must never extend it.
- Only a trusted issuance or token-exchange path activates a JTI. Never recreate
  a missing allowlist entry from a presented JWT; doing so reactivates revoked
  credentials.
- Use bounded connection/socket timeouts, TLS and ACLs outside a trusted local
  network, a dedicated namespace, sufficient capacity, and preferably
  `noeviction`. Read through a path whose consistency meets the revocation
  contract.
- Do not put a process-local positive cache in front of the JTI lookup; it creates
  an undocumented revocation window.

The key/value and async Redis code are in
[JWT session implementation](jwt-session-implementation.md).

## Authentication Order And Failures

Apply the same order at HTTP, WebSocket, job, CLI, and service boundaries that
handle an untrusted bearer token:

```text
parse bounded bearer input
-> verify signature, issuer, audience, type, times, sub, and jti
-> require exact Redis active-JTI record
-> load matching active PostgreSQL session and active user
-> load current RBAC authority
-> execute the protected operation
```

- Missing, invalid, expired, inactive-JTI, mismatched, revoked, or unknown
  credentials return generic `401` plus `WWW-Authenticate: Bearer`.
- Redis, PostgreSQL, or verification-key-provider timeout/unavailability returns
  `503`; the protected handler does not execute. Never convert infrastructure
  failure into allow or misreport it as a bad password.
- A valid identity lacking a required permission receives `403`. Missing or
  deliberately concealed business resources follow the RBAC `404` policy.

Redis validation never replaces current PostgreSQL user, session, or RBAC checks.
A valid JTI proves only that this credential remains registered.

## Issuance, Logout, And Atomicity

PostgreSQL and Redis cannot form one ACID transaction. Use a fail-closed
activation state machine:

1. Authenticate credentials and load the current active user from PostgreSQL.
2. Generate one UUIDv4 JTI and the minimal claims. Insert a `pending` PostgreSQL
   session with the current user token version, then commit.
3. Create the exact Redis allowlist record with `SET NX EXAT`.
4. Mark the PostgreSQL session `active`, then commit.
5. Return the JWT only after both stores succeeded. Clean expired pending rows and
   stale Redis keys; neither state authorizes alone.

If the identity provider is external, integrate through a trusted token-exchange
or session-activation boundary. Never lazily activate on first API use, and do
not claim JTI enforcement until issuer integration exists.

For one-session logout, atomically mark its PostgreSQL row revoked and write the
audit/outbox row, commit, then delete Redis. For all-session logout or identity
disablement, increment `users.token_version` and revoke all active session rows in
the same transaction. An outbox retries Redis deletion. Because each protected
request also checks PostgreSQL, a stale Redis key cannot authorize after commit.

For an authorization control-plane or immediate-revocation business write, first
lock the global authorization guard, then lock and reload the user plus
authentication session inside the authoritative PostgreSQL transaction before
the final decision. The entry Redis check is not that proof. Follow
[atomic authorization consistency](atomic-consistency.md); Redis deletion and
other external effects occur after commit through the outbox.

## Refresh Tokens

Never accept a refresh token on an access path. Prefer an opaque random refresh
credential whose keyed digest, family ID, expiry, and consumed/revoked state are
stored server-side. Rotate it once per use in one PostgreSQL transaction. Reuse of
a consumed token revokes the entire family and is audited. Cookies carrying
refresh material use `Secure`, `HttpOnly`, appropriate `SameSite`, narrow
path/domain scope, and CSRF protection where required.

## Required Verification

- Accept a valid minimal token. Reject each missing required claim, prohibited
  business claim at issuance, wrong algorithm/key/issuer/audience/type,
  non-canonical or non-v4 `sub`/`jti`, invalid time type, overlong lifetime,
  future `iat`, expiry, and invalid optional `nbf`.
- Prove every issuance has a distinct JTI, duplicate `SET NX` fails, Redis TTL
  never exceeds `exp`, and no Redis value or log contains raw credentials.
- Redis miss/expiry/malformed/mismatch is `401`; Redis timeout/error is `503`, and
  the protected handler is not called.
- A revoked or missing PostgreSQL session denies with a stale Redis key. Test one
  session logout, all-session logout, identity disablement, version change,
  expiry, and user suspension.
- Exercise activation crash points: database pending only, Redis plus pending,
  active row before response, and cleanup. Only the fully active pair authorizes.
- Test refresh rotation, concurrent refresh, old-token reuse, family revocation,
  and access/refresh type confusion.
- Use deterministic barriers for both commit orders of session revocation racing
  a high-risk write. The lock owner decides first; the waiter reloads and cannot
  use an earlier JWT or ORM snapshot.

## Included Asset Status

The current PostgreSQL asset requires `sub`, `ver`, and `jti`, and validates
`sub` and `jti` as canonical UUIDv4 strings. It has no Redis dependency or
`authentication_sessions` table, so it does not validate active JTI state and
must not be described as active-JTI revocation. Before production use, apply
[JWT session implementation](jwt-session-implementation.md): add both session
stores, remove `ver` from JWT in favor of server-side state, and retain the
transaction-local recheck for privileged writes.
