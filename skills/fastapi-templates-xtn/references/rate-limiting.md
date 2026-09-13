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
| Complete an administrator-issued temporary password, trusted client IP | 20 per 5 minutes |
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

Validate the script result strictly and reject a missing/invalid PTTL. A request
is admitted only when `count <= limit`. Calls over the limit still increment
until the window expires; this is a simple fixed window, not a Token Bucket.
Do not silently treat zero or negative limits/windows as disabling protection.
Run Redis admission before opening PostgreSQL authorization locks. A limiter
outage is not permission to proceed.

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
Tests for local
quota denial cannot substitute for PostgreSQL RBAC/transaction tests.
