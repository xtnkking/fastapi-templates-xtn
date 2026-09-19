# JWT Access-Token Security

Read this reference when designing or reviewing JWT claims, signing, login,
logout, Redis JTI validation, or token revocation. It is the canonical token
policy; do not duplicate it in RBAC code. Read
[JWT implementation shapes](jwt-session-implementation.md) only when concrete
Python or Redis code is required.

## Consent-Gated Access-Token Contract

A JWT is a signed bearer credential, not encrypted profile storage. Keep its
payload deliberately small:

| Claim | Baseline rule |
| --- | --- |
| `sub` | Canonical string of immutable `users.id` under the selected identifier policy; required and the only user identity claim |
| `jti` | New random UUIDv4 for every Access Token; required and never reused |
| `iat` | Integer NumericDate issuance time; required |
| `exp` | Integer NumericDate expiry; required and 3600 seconds after `iat` by default |
| `token_type` | Literal `access`; required |
| `iss` | Optional only together with `aud`, after explicit user agreement; exact configured issuer when enabled |
| `aud` | Optional only together with `iss`, after explicit user agreement; exact API audience when enabled |

The default exact claim set is `sub`, `jti`, `iat`, `exp`, and `token_type`.
Before adding `iss` and `aud`, explain in plain language that they help stop a
Token intended for one trusted service from being accepted by another, but add
configuration and coordination between the signer and verifier. Ask whether the
user wants that extra scoping and require explicit consent. No reply is not consent.
An unrelated approval is not consent. Enable or omit the two claims as a pair;
never configure only one. If an existing project already has both
configured, preserve it by default unless the user requests removal or migration.

The one-hour lifetime is a starting default, not a universal security answer.
Expose it as typed configuration and explicitly tell the user to adjust it for
the product's risk, reauthentication cost, and expected user experience. A
high-risk administration surface may need a much shorter lifetime. Never extend
the lifetime silently merely to reduce login frequency.
This required notice is not another blocking question in the initial product
decision batch. Use 3600 seconds unless the owner asks for a different value.

`sub` is the only required user data. The other four baseline claims are security
protocol metadata. The approved `iss`/`aud` pair is optional protocol scoping,
not user data. Do not add profile or authorization state merely to avoid a
PostgreSQL lookup.

Never place username, email, phone, display name, role names, permission keys,
management tier, ownership, protection flags, account status,
`users.token_version`, authorization versions, or profile data in an Access
Token. Read display data after authentication when a response needs it.

Use the stable user ID as `sub`; for example, an exact validated `U...` prefixed
ID or the bundled asset's canonical UUIDv4. Never use an email, username,
role-assignment ID, or auto-incremented integer. When choosing or changing the ID
strategy, or migrating a legacy subject, also read
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
  Validate configuration before application startup: reject missing or blank
  secrets, public/example placeholders, leading or trailing whitespace, control
  characters, invalid UTF-8 text, fewer than 32 or more than 4096 UTF-8 bytes,
  very low character diversity, and a shorter pattern repeated exactly two or
  more times to appear long, regardless of that pattern's width. Generate a
  unique secret with a cryptographically secure random generator; never silently
  substitute a development default.
- Before Redis or database access, verify the signature, the exact configured
  claim profile, configured maximum lifetime, `token_type`, a canonical `sub`
  under the selected user-ID policy, and a canonical UUIDv4 `jti`. In the default
  profile, reject `iss` or `aud` as unexpected. In the explicitly approved
  profile, require both and verify the exact configured issuer and audience. Use
  at most 30 seconds clock skew by default.
- Limit bearer-token size to 4096 bytes at both issuance and the HTTP boundary.
  Reject an oversized encoded Token before writing its JTI to Redis, and reject
  oversized bearer input before JWT parsing. Never log a token, signing key,
  password, or Redis active-JTI value.

Map every malformed, expired, or wrong-key/type credential to one generic `401`
response with `WWW-Authenticate: Bearer`; keep diagnostic detail in a safe
internal metric or log. Do not let parsing differences expose account state.

## Redis Active-JTI Gate

Redis is the only per-token online active-JTI gate in this baseline. Do not add a
PostgreSQL table for individual Token records, and do not add another database
query per request solely to validate a Token record. PostgreSQL remains
authoritative for the existing user row and current RBAC state, which the request
already loads after the Redis check.

A signed Access Token is accepted only while its JTI has the exact expected Redis
record. Missing, expired, evicted, malformed, or mismatched keys deny safely,
although unexpected eviction reduces availability. JTI validation enables
targeted revocation; it does not make an Access Token one-time or stop replay
while its JTI remains active. Protect bearer tokens with TLS, narrow
storage/exposure, the configured lifetime, and product-appropriate abuse and
device monitoring.

- Generate each JTI as UUIDv4 inside the trusted issuer. Never accept or reuse a
  client-supplied JTI.
- Namespace a key by environment and a SHA-256 digest of a stable internal
  service name plus `NUL` plus `jti`. Do not derive the Redis namespace from the
  optional public `iss` claim: enabling, disabling, or migrating that claim must
  be an explicit Token-contract change rather than a hidden registry-key change.
  Store no raw JWT. The value binds canonical `sub`, literal `access` type, `iat`,
  `exp`, and the server-side `users.token_version` read during login.
- Validate an exact schema and exact `sub`, type, `iat`, and `exp` match. After loading
  the current PostgreSQL user, compare the Redis-bound user version with
  `users.token_version`. The version remains server-side and never enters JWT.
- Activate with one Redis 5.0+ Lua operation: read server `TIME`, reject an
  already expired deadline, create with `SET ... NX EX <remaining_seconds>`,
  then set the exact JWT deadline with `PEXPIREAT <exp * 1000>` before returning
  success. A duplicate JTI is an issuance conflict; make one bounded retry with
  a fresh UUIDv4 or fail issuance. Redis expiry must never outlive JWT expiry,
  and reads must never extend it. Unknown script results fail closed.
- Only the trusted login or token-issuance path activates a JTI. Never recreate a
  missing entry from a presented JWT; doing so reactivates a revoked credential.
- Maintain a per-user active-login index with login timestamps in Redis. The
  project owner chooses a positive simultaneous-login maximum before using the
  asset. Issuance atomically registers a new JTI and, only when it succeeds,
  evicts the oldest active login if the account is at its limit. Index entries
  from an older `users.token_version` cannot count or consume slots after
  password rotation or administrator revocation. A login record is not an
  assertion about physical devices; a phone may have several logins.
- Use bounded connection/socket timeouts, TLS and ACLs outside a trusted local
  network, a dedicated namespace, sufficient capacity, and preferably
  `noeviction`. Read through a path whose consistency meets the revocation
  contract.
- Do not put a process-local positive cache in front of the JTI lookup; it creates
  an undocumented revocation window.

The key/value and async Redis code are in
[JWT implementation shapes](jwt-session-implementation.md).

## Authentication Order And Failures

Apply the same order at HTTP, WebSocket, job, CLI, and service boundaries that
handle an untrusted bearer token:

```text
parse bounded bearer input
-> verify signature, the configured five- or seven-claim profile, type, times, sub, and jti
-> when the approved profile is enabled, verify exact issuer and audience
-> require the exact Redis active-JTI record
-> load the existing active PostgreSQL user and current RBAC authority
-> compare the Redis-bound user version with users.token_version
-> execute the protected operation
```

Current-Token logout is the narrow exception: validate the JWT and exact Redis
record, then compare-and-delete that record without querying PostgreSQL. This
operation can only reduce the presented credential's authority, so an already
disabled user or stale user version may still log out. It must not call a
business handler or be reused as an authentication shortcut for any other route.

- Missing, invalid, expired, inactive-JTI, malformed, mismatched, revoked, or
  unknown credentials return generic `401` plus `WWW-Authenticate: Bearer`.
- Redis, PostgreSQL, or verification-key-provider timeout/unavailability returns
  `503`; the protected handler does not execute. Never convert infrastructure
  failure into allow or misreport it as a bad password.
- A valid identity lacking a required permission receives `403`. Missing or
  deliberately concealed business resources follow the RBAC `404` policy.

The Redis check never replaces the current PostgreSQL user-status, user-version,
or RBAC checks. An active JTI proves only that this particular Token remains
registered. This baseline intentionally performs no separate PostgreSQL Token
record lookup.

## Issuance, Logout, And Revocation

Use this fail-closed issuance order:

1. Authenticate credentials and load the current active user plus
   `users.token_version` from PostgreSQL.
2. Generate a fresh UUIDv4 JTI and the minimal claims, then sign the Access Token.
3. Create the exact Redis record with the atomic Redis 5.0+ activation script,
   binding `sub`, type, `iat`, `exp`, and the user version observed in step 1.
4. Return the Token only after Redis confirms creation. On a duplicate JTI, retry
   once with a newly generated JTI; on Redis failure, return `503` and no Token.

If the response is lost after Redis activation, the unused entry is harmless and
expires at `exp`. Never lazily activate a JTI on first API use. If an external
identity provider owns login, enforce the same Redis registration before this API
returns or accepts the resulting application Token.

For logout, atomically compare the stored value and delete the JTI key. Return
success only after Redis confirms deletion of the exact active record. A missing
or mismatched record is `401`; a Redis error or ambiguous deletion outcome is
`503`. Never claim logout succeeded after a failed `DEL` or compare-and-delete.
The client may retry when the outcome is unknown. Confirmed deletion prevents
later gate checks, but cannot cancel a request that already passed the gate.

Redis failover may restore an older snapshot and revive a recently deleted key.
Choose persistence, replication, and failover guarantees for the product's risk,
and document the residual window. This lighter Redis-only gate must not be
described as PostgreSQL-grade linearizable revocation.

For administrator-forced logout of a strictly lower user, password compromise,
or identity disablement, increment
`users.token_version` in the authoritative PostgreSQL transaction. Existing
Redis records may remain until their `exp`, but every later request compares their
bound version with the current user row and rejects them. User status transitions
that must revoke existing Tokens also increment this version. No Token-record
cleanup outbox is required for correctness.

Self password change, administrator password reset, temporary reset completion,
and offline operator reset are account-wide revocation events. Each increments
`users.token_version` in the same transaction as the credential rotation and
account-security audit, issues no replacement Token, performs no Redis scan, and
never stores password state in the JWT. See
[Local password authentication](local-password-authentication.md).

Do not expose self-service account-wide logout. Ordinary users may call only
`POST /api/v1/auth/logout` for the current JTI. A separate administrator
command may revoke a strictly lower target's account-wide sessions only with
the exact capability, locked current hierarchy check, and account-security
audit in one PostgreSQL transaction. It increments the target's
`users.token_version`; never scan Redis keys or claim physical deletion is
required. A failed transaction leaves the version unchanged.

PostgreSQL and Redis do not share an ACID transaction. This design remains
fail-closed because issuance returns no Token until Redis succeeds, and request
validation always compares the Redis record with the current user row. Do not
call Redis while holding authorization locks. Privileged writes still follow
[atomic authorization consistency](atomic-consistency.md) for current user and
RBAC state.

After expiry, the user authenticates again to receive a new Access Token. Do not
invent another credential flow merely to hide reauthentication from the user.

## Signing-Key Compromise Boundary

The active-JTI gate materially limits, but does not erase, signing-key risk:

- An attacker who has only the signing key can mint a correctly signed JWT, but
  its new JTI is absent from Redis and is rejected.
- An attacker who steals a complete currently active bearer Token can replay it
  until its JTI is deleted, its bound user version changes, or it expires.
- An attacker who can also write the trusted Redis namespace may register a
  forged JTI; Redis credentials and network access therefore need strong
  isolation.
- On signing-key compromise, rotate the signing key and change the configured
  active-JTI namespace generation so all old entries become unreachable. Require
  users to authenticate again. Do not claim JTI makes key compromise harmless.

## Required Verification

- Accept a valid default five-claim Token and reject `iss`, `aud`, or any other
  extra claim in that profile. With the consented pair enabled, accept the exact
  seven-claim Token and reject a missing half, wrong issuer/audience, or a Token
  from the other profile. In both profiles reject each missing baseline claim,
  prohibited business claim at issuance, wrong algorithm/key/type,
  non-canonical, wrong-prefix, wrong-length, or otherwise invalid `sub`,
  non-canonical or non-v4 `jti`, invalid time type, overlong lifetime, future
  `iat`, expiry, and every unexpected extra claim.
- Assert the configured default is 3600 seconds, alternate business-approved
  values work, and project documentation tells users to review the value.
- Prove every issuance has a distinct JTI, duplicate `SET NX` fails, no Token is
  returned before successful Redis registration, Redis expiry equals `exp`, and
  no Redis value or log contains raw credentials.
- Redis miss, expiry, malformed data, or `sub`/type/`iat`/`exp` mismatch is `401`;
  Redis timeout/error is `503`, and the protected handler is not called.
- Compare the Redis-bound user version with current `users.token_version`. Test
  one-Token logout, account-wide logout, identity disablement, version change,
  expiry, and user suspension.
- Test compare-and-delete success, mismatch, missing key, Redis failure, and an
  ambiguous outcome. Only a confirmed exact deletion returns logout success;
  also test one request already past the gate and a failover restoration case.
- Reject weak/example startup secrets and oversized input and output Tokens.
  Prove that an oversized encoded Token creates no Redis record. Test
  account-wide logout with two independently issued Tokens: both must fail after
  the committed user-version increment.
- Exercise signing-key-only forgery, stolen-active-Token replay, namespace
  generation rollover, and the documented incident response.
- Use deterministic barriers for both commit orders of a user-version revocation
  racing a high-risk write. The lock owner decides first; the waiter reloads and
  cannot use an earlier JWT, Redis record, or ORM snapshot.

## Included Asset Status

The bundled asset implements the complete local-password login and Redis
active-JTI path:
minimal claims without `ver`, configurable one-hour default, registration before
return after successful username/password verification, Redis-first validation,
current PostgreSQL user/RBAC reload, user-version comparison, confirmed
current-Token logout, and administrator-only lower-target account-wide
revocation through `users.token_version`. Startup rejects weak/example HS256
secrets, and input/output Tokens are bounded to 4096 bytes. It adds no
individual PostgreSQL Token or session table.

Adopters must still supply deployment secrets, choose the simultaneous-login
maximum, configure Redis durability and isolation, and run the required
PostgreSQL/Redis checks for their target deployment. Do not describe an
unverified deployment as production-ready merely because the bundled tests or
reference implementation exist.
