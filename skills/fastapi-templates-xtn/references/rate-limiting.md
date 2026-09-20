# Per-Business Rate Limiting

Read this reference for public authentication, CAPTCHA issuance, protected reads
and writes, or any endpoint whose request frequency must be limited. This is a
starting policy, not a claim that one set of numbers fits every deployment.

## Decide Numbers Once

Before generating a project, show these defaults together and ask the product
owner to accept them or name the values to change. Do not silently add a quota
for an endpoint that the project does not expose. Keep the values in
`app/settings.py`, list corresponding `RATE_LIMIT_*` overrides in `.env.example`,
and explain in the copied asset README that changing the deployment `.env` and
restarting applies new limits. Lua and route files contain no policy numbers.

| Business (one independent key for each named operation) | Default |
| --- | ---: |
| Graphical CAPTCHA issue or refresh, separately for each of five scenes | 10 per 5 minutes |
| CAPTCHA scene sent to the wrong issue endpoint or parsed invalid CAPTCHA body, per trusted IP or authenticated actor | 10 per 5 minutes |
| Login submission, trusted client IP | 20 per 5 minutes |
| Public registration submission, trusted client IP | 5 per hour |
| Complete a temporary password from administrator user creation or optional temporary reset, trusted client IP | 20 per 5 minutes |
| Authenticated ordinary read, per operation and actor user ID | 600 per minute |
| Authenticated ordinary write, per operation and actor user ID | 120 per minute |
| Administrative read, per operation and actor user ID | 300 per minute |
| Administrative change, per operation and actor user ID | 60 per minute |

Each CAPTCHA scene has a separate issuance/refresh quota. Issuing an image does
not spend the login or registration submission quota; submitting one does not
spend the issuance quota. The image itself lasts five minutes and is single-use;
its validity is independent of the five-minute issuance window. An
otherwise valid scene sent to the wrong public/authenticated issue endpoint,
or a parsed CAPTCHA body with invalid fields, spends a separate
`captcha_rejected_scene` quota, not a scene issuance quota. Public requests use
trusted IP; authenticated requests use the server-authenticated actor ID. All
such rejected requests share this one
per-subject rejection quota, using the CAPTCHA limit and window settings; no
challenge is issued. An over-limit request receives `429001`, and missing IP or
Redis authority fails closed with `503001`. Invalid JSON syntax is rejected by
the framework before authentication dependencies run. There is no global quota. An
administrator forcing a lower user's sessions out uses its own administrative
change key, not a special `logout_all` quota. No online super-admin transfer
operation exists.

## Subjects And Boundaries

- For allowed unauthenticated authentication endpoints, key on the fixed
  operation name and a trusted canonical client IP. With a multi-scene route,
  add only a validated server-owned scene name. Never key an anonymous quota
  by submitted username, target account, email, challenge ID, or user-supplied
  forwarding header. A `GET` registration-state endpoint may be public but must
  return only `registration_enabled`, never business data.
- The trusted IP selects the public CAPTCHA issuance and login/registration
  rate-limit buckets; it is not stored as challenge ownership. A public
  challenge remains usable if a VPN or mobile-network exit changes between
  issue and submit. Scene, five-minute TTL, and atomic one-use consumption still
  apply.
- For authenticated routes, key on the fixed operation name and the canonical
  user ID loaded by authentication. Administrative operations use the actor ID,
  not the target ID. A separate key per operation prevents activity in one
  business from consuming another business's budget.
- Do not add an `api_global`, `api_ip` shared across unrelated routes, anonymous
  business read, or any all-user/all-IP/all-business aggregate bucket. This
  prohibition also applies to later optional features. A network connection
  concurrency budget for an external proxy probe is a different capacity
  control, not an API request-frequency bucket.
- Read the address only from the ASGI server's trusted client value, after
  deployment proxy configuration. Validate via `ipaddress.ip_address`. If it
  is absent or invalid, fail closed (`503001`); do not merge unrelated callers
  into an `unknown` bucket. Incorrect proxy trust configuration must be fixed
  by the operator, not hidden by trusting an arbitrary `X-Forwarded-For`.

Never present rate limiting as identity verification or RBAC. After admission,
the route still verifies CAPTCHA, password, token, capability, hierarchy, and
locked PostgreSQL state as applicable. Login's generic invalid-credential result
does not use an account-only Redis lock or failure counter: another person
knowing a username cannot intentionally exhaust a quota specific to that user.

## Redis Fixed Window

Each policy has a positive integer `limit` and `window_seconds`. A single key
contains the count for one named business and subject. The first request starts
the window, and its entire allowance returns at expiry (not continuously).
Perform count and initial expiry atomically in one Redis Lua call:

```lua
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
```

Validate the script result strictly and reject a missing/invalid PTTL. At the
authoritative admission step, a request is admitted only when `count <= limit`;
calls that reach this step after the limit still increment until the window
expires. The authenticated read-only precheck below is the deliberate exception:
once it observes an exhausted window, it rejects without another increment or
database read. This remains a simple fixed window, not a Token Bucket.
Do not silently treat zero or negative limits/windows as disabling protection.
For anonymous login/registration, run the trusted-IP Redis admission before
password work or PostgreSQL writes. For authenticated business routes other
than current-Token logout, first validate JWT shape/signature/time and the Redis
active JTI. Before PostgreSQL, atomically inspect the existing named
operation-and-actor window without creating or incrementing it. If its current
count already equals or exceeds the limit, return `429001` immediately; this
keeps a still-active stolen Token from repeatedly reaching PostgreSQL after the
user's business window is exhausted. A missing or open window continues to
PostgreSQL. Only after the database snapshot confirms the account is active and
its token version is current does the normal atomic `INCR` charge the quota,
before business mutation locks. Concurrent requests may all observe the last
open slot, but the authoritative increment still admits no more than the
configured count; only that bounded race can perform extra account reads.

A forged or already revoked Token therefore does not reach PostgreSQL, while a
disabled/stale identity does not newly consume the legitimate user's business
bucket. Best-effort compare-and-delete the exact JTI rejected by PostgreSQL so
its next use stops at Redis. One explicit tradeoff remains: if an exact JTI is
still present in Redis while its database identity has become stale and the
same operation window is already exhausted, the non-mutating precheck returns
`429001` until the window expires instead of doing another database read to
rediscover `401001`. It neither creates nor increments the user's bucket.
Avoiding that temporary status precedence would require reservation and
rollback logic outside this simple fixed-window baseline. Current-Token logout
is the narrow Redis-only exception: after its named actor quota admits the
still-active JTI, immediately compare-and-delete that exact JTI without a
PostgreSQL authorization read. Limiter outage is not permission to proceed.

The authenticated CAPTCHA route keeps its three scene quotas separate. After
active-JTI validation and before PostgreSQL, parse the closed request schema and
inspect `captcha_create_admin_create`, `captcha_create_admin_reset`, or
`captcha_create_self_change` for a valid private scene. A malformed body or a
public scene sent to that endpoint inspects the independent
`captcha_rejected_scene` actor window. These inspections never increment. After
current-account validation, the existing route path performs the authoritative
increment for the same selected window. Do not replace this with one generic
authenticated-CAPTCHA bucket that would make the scenes consume one another.

Keep Redis keys private:
`rl:v2:{<static_namespace>}:<business>:<subject_type>:<hmac_sha256>`.
HMAC covers the policy name and canonical subject with a distinct deployment
secret; never place a raw IP, username, user ID, challenge, JWT, or target in a
key or log. Validate static names, secret strength, and subject bounds. Keep
Redis timeouts bounded and use a separate limiter client/namespace from active
JWT JTI records. A separately operated limiter Redis is a deployment option,
not another required business feature.

## HTTP And Failure Contract

A real over-limit decision returns HTTP `429`, business code `429001`,
`Retry-After: max(1, ceil(remaining PTTL / 1000))` seconds,
`Cache-Control: no-store`, and
the same server UUIDv4 in the response body and `X-Request-ID`. A Redis error,
malformed result, invalid trusted IP, or missing required limiter authority
returns HTTP `503`, code `503001`, `Cache-Control: no-store`, no `Retry-After`,
and never calls the protected handler. Do not expose Redis keys, raw IPs,
credentials, internal exceptions, or the denying subject in either response.
If used, `RateLimit-Limit` is the fixed-window maximum,
`RateLimit-Remaining` is `max(0, limit - count)`, and `RateLimit-Reset` is the
remaining window seconds (not time until a continuously refilling bucket fills).

The only local bypass is an explicitly selected isolated `dev`, `development`,
`local`, `test`, or `testing` environment; production cannot turn these checks
off. Preserve the existing required `APP_ENVIRONMENT` startup guard.

## Verification

Use real Redis for first-use `INCR`/`EXPIRE` atomicity, TTL, expiry, independent
business keys, concurrent admission, and key privacy. Unit-test malformed Lua
replies, missing/untrusted IP, positive settings validation, `429001` retry
headers, `503001` fail-closed behavior, and absence of global and username
buckets. Route tests must prove every intended dependency actually runs, one
failure never executes the protected action, and CAPTCHA issue/refresh uses its
scene-specific quota. Prove that a valid scene sent to the wrong issue endpoint
uses its separate per-subject quota, never creates an image, cannot consume a
valid scene's quota, and fails closed when Redis is unavailable. Also prove that
parsed invalid fields consume this rejection quota, while a private admitted
invalid request still completes normal identity validation before its `422`.
For authenticated routes, prove the read-only precheck never creates or
increments a bucket, an exhausted bucket avoids PostgreSQL, an open bucket is
charged only after current-account validation, and concurrent last-slot
requests still admit no more than the configured total. Prove all three private
CAPTCHA scenes inspect their own exact windows, while invalid/wrong-endpoint
requests inspect the rejection window; none may hit PostgreSQL after its
selected window is exhausted. Tests for local
quota denial cannot substitute for PostgreSQL RBAC/transaction tests.
