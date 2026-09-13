# Rate Limiting And Abuse-Control Quotas

Read this reference when a FastAPI project exposes public API routes, login,
registration, explicitly selected verification-code delivery or submission,
administrative writes, or another abuse-sensitive operation. For login failure
risk signals or optional verification challenge behavior, also read
[Verification and abuse defense](verification-and-abuse-defense.md).

The bundled asset uses one concrete mechanism throughout: a continuously
refilled Redis Token Bucket implemented by Lua. Do not describe it as a fixed
window, a calendar-day quota, or another algorithm. Keep policy values in
`app.security_policies`, settings in `app.settings`, and route code free of
embedded limit numbers.

## Confirm The Complete Baseline Before Code

Before generating or changing rate-limit, password-login abuse, or registration
code, show the user the complete baseline tables below. Include the optional
verification tables only after the user explicitly chooses a CAPTCHA,
email/SMS-code, MFA, or another verification feature. Then ask exactly one
decision question for the surfaces being added or changed:

> These are the centralized starting values. Reply `全部接受` / `Accept all` to
> use every value, or list only the settings you want changed.

Do not generate the affected code until the user answers. Silence is not
acceptance. Do not make the user choose the algorithm, Redis key shape, public
error codes, or atomicity behavior; those are fixed by this baseline. In an
existing project, show its effective values alongside any proposed changes and
preserve them unless the user approves the change.

Do not ask a username-and-password-only project to configure verification
channels or providers. Optional verification is disabled unless the user
affirmatively selects it; storing an email or phone number is not that choice.

### Baseline Token Bucket Defaults

`burst_capacity` is the maximum immediately available token count.
`refill_tokens / refill_period` is the continuous replenishment rate. A request
costs one token.

| Group | Policy | Subject used by the asset | Burst | Refill |
| --- | --- | --- | ---: | ---: |
| API | `api_global` | all API traffic | `1000` | `6000 / 60s` |
| API | `api_ip` | trusted client IP | `200` | `1200 / 60s` |
| API | `anonymous_read` | trusted client IP | `120` | `120 / 60s` |
| API | `authenticated_read` | authenticated user ID | `300` | `300 / 60s` |
| API | `management_read` | authenticated user ID | `120` | `120 / 60s` |
| API | `ordinary_write` | authenticated user ID | `60` | `60 / 60s` |
| API | `authorization_write` | authenticated user ID | `30` | `30 / 60s` |
| API | `super_admin_transfer` | authenticated user ID | `3` | `3 / 3600s` |
| API | `logout_all` | authenticated user ID | `5` | `5 / 600s` |
| Login | `login_ip` | trusted client IP | `20` | `20 / 300s` |
| Login | `login_pair` | trusted IP + normalized account | `5` | `5 / 900s` |
| Login | `login_global` | all login attempts | `200` | `1000 / 300s` |
| Registration | `registration_ip` | trusted client IP | `5` | `5 / 3600s` |
| Registration | `registration_target` | normalized account/target | `3` | `3 / 3600s` |
| Registration | `registration_pair` | trusted IP + normalized target | `3` | `3 / 3600s` |
| Registration | `registration_global` | all registration attempts | `100` | `500 / 3600s` |

The three login buckets above are the only hard login-admission limits. There is
no account-only bucket: knowing another person's username must not be enough to
deny that person a correct-password attempt.

The bundled local-password routes map to these existing policies rather than
inventing hidden limits: ordinary login and temporary-password completion use
all three login buckets; public registration uses all four registration buckets;
self password change uses `ordinary_write`; and administrator password reset
uses `authorization_write`. Current-password reauthentication still performs
Argon2 work, but a failed reauthentication never creates a separate
attacker-triggerable account lock. Load
[Local password authentication](local-password-authentication.md) for the
credential and recovery flows.

### Optional Verification Token Bucket Defaults

Show and apply this table only after the user selects a verification feature.
The bundled code-based flow supports email and SMS; CAPTCHA and MFA require
their own product/provider adapter and policy rather than being silently added.

| Group | Policy | Subject used by the asset | Burst | Refill |
| --- | --- | --- | ---: | ---: |
| Verification send | `verification_target_cooldown` | normalized target | `1` | `1 / 60s` |
| Verification send | `verification_target_average` | normalized target | `5` | `5 / 86400s` |
| Verification send | `verification_ip` | trusted client IP | `20` | `20 / 3600s` |
| Verification send | `verification_pair` | trusted IP + normalized target | `5` | `5 / 3600s` |
| Verification send | `verification_channel` | channel enum | `40` | `200 / 60s` |
| Verification send | `verification_global` | all verification sends | `50` | `300 / 60s` |
| Verification submit | `verification_submit_ip` | trusted client IP | `120` | `120 / 3600s` |
| Verification submit | `verification_submit_target` | normalized target | `20` | `20 / 3600s` |
| Verification submit | `verification_submit_pair` | trusted IP + normalized target | `10` | `10 / 3600s` |
| Verification submit | `verification_submit_global` | all submissions | `500` | `3000 / 60s` |

`verification_target_average` is configured by
`RATE_LIMIT_VERIFICATION_TARGET_AVERAGE_PER_DAY`. In plain language, a target
starts with five send credits and earns five credits over each 24 hours, or
roughly one credit every 4 hours 48 minutes, until the bucket is full again. It
does not mean “at most five sends in every possible 24-hour period.” A hard
event-history quota would be a different implementation and test contract.

### Baseline State And Infrastructure Defaults

These values are not additional Token Buckets.

| Setting | Default | Meaning |
| --- | ---: | --- |
| Application environment | required, no default | Every process must explicitly identify its environment; a missing value stops startup instead of silently selecting a local profile |
| Limiter enabled | `true` | The bundled `/api/` admission middleware and selected semantic policies run |
| Public registration enabled | `false` | The registration route is not registered and is absent from OpenAPI until the product owner opts in |
| Limiter namespace | `fastapi_rbac` | Static lowercase namespace and Redis Cluster hash tag; change per deployed service/environment when Redis is shared |
| Dedicated limiter Redis URL | unset | Falls back to the active-JTI `redis_url`; set it for independent production capacity/failure isolation |
| Redis connect timeout | `0.5s` | Bounded connection establishment |
| Redis socket timeout | `0.5s` | Bounded command wait; timeout retry is disabled |
| Login failure-risk retention | `86400s` | The private consecutive-failure signal expires after 24 hours and is cleared after successful credentials; it never blocks an attempt by itself |
| Rate-limit HMAC key | required, no default | At least 32 UTF-8 bytes and unique to limiter fingerprints |

`APP_ENVIRONMENT` is required and has no code default. Omitting it fails settings
construction even when rate limiting remains enabled, so a deployment cannot
silently inherit `development`. `RATE_LIMIT_ENABLED=false` intentionally disables
both API admission and the login/registration `IdentityAbuseFlow`. The asset
therefore accepts it only when `APP_ENVIRONMENT` is explicitly `dev`,
`development`, `local`, `test`, or `testing`; every other environment fails
during settings construction before the application can start. Never use one of
those names merely to bypass the guard in a deployed service. Unit tests may use
this escape hatch when the limiter is not the subject under test, while
route-composition and real-Redis suites must run with it enabled.

The failure counter is a risk signal for logs, monitoring, or an explicitly
selected step-up feature. It is not an account lock, is not consulted as a
pre-password denial, and cannot produce an account-wide `429`. CAPTCHA,
email/SMS verification, or MFA may consume the signal only when the user has
chosen and configured that product feature.

### Optional Verification State Defaults

| Setting | Default | Meaning |
| --- | ---: | --- |
| Verification enabled | `false` | No verification field, secret, route, channel, or provider is required until the user explicitly enables a feature |
| Enabled purposes | empty | Configure only purposes the product actually exposes |
| Enabled channels | empty | Configure only delivery channels the product actually implements |
| Verification code length | `6` digits | Generated with `secrets`; leading zeroes are valid |
| Verification code lifetime | `300s` | Five minutes |
| Verification wrong-attempt maximum | `5` | Fifth mismatch consumes the challenge |
| Verification-code HMAC key | unset | Required only when code verification is enabled; at least 32 UTF-8 bytes and different from limiter/JWT secrets |

The baseline requires a rate-limit HMAC key. A separate verification-code HMAC
key becomes required only when code verification is enabled; neither may equal
the JWT secret or each other. Reject placeholders, whitespace/control
characters, obvious repeated patterns, and low-diversity values at startup.
Accepting applicable defaults accepts these secret rules, not a public example
secret. Generate or provision deployment secrets outside source control.

## Asset Wiring

The bundled asset applies two layers:

1. `ApiRateLimitMiddleware` atomically checks `api_global` and `api_ip` for every
   `/api/` request except `OPTIONS`; `/health/live` is not limited.
2. After authentication, `enforce_principal_rate_limit` selects an actor policy
   from the matched operation: management read, authenticated read,
   authorization write, `super_admin` transfer, or logout-all.

`SecurityPolicies` also exposes anonymous-read and ordinary-write policies for
product routes that need them. `AbuseDefenseService` exposes the login and
registration compositions plus optional verification-send and
verification-submit compositions. The asset does not invent a public
signup/login API or a delivery provider. Wire login after the product settles
its identifier contract; wire verification only after explicit selection of its
purpose, channel, and provider ownership.

Do not bypass limits for privileged users. A `super_admin` remains subject to
the coarse API buckets and the high-impact operation policy.

## Trusted Client IP

The asset deliberately reads only `scope["client"]`, which must already be the
trusted client address produced by the ASGI server or deployment proxy
configuration. It never reads caller-controlled forwarding headers itself.

At deployment, configure exactly which proxies may overwrite forwarding data
and which hop the ASGI server exposes. An untrusted peer must not be able to pick
its limiter identity. Canonicalize the resulting address with
`ipaddress.ip_address(...).compressed`. If it is invalid, the middleware uses one
conservative shared `unknown` subject instead of trusting a header.

## Concrete Token Bucket Contract

The public implementation types are:

```python
RateLimitPolicy(
    name: str,
    burst_capacity: int,
    refill_tokens: int,
    refill_period_seconds: int,
)

RateLimitCheck(
    policy: RateLimitPolicy,
    subject_type: str,
    subject: str,
)

async def check_rate_limits(
    redis: Redis,
    *,
    namespace: str,
    checks: Sequence[RateLimitCheck],
    key_secret: bytes,
) -> RateLimitBatchDecision: ...
```

The single-bucket `check_rate_limit` function delegates to the same batch
function. Preserve these behavior rules:

- Use one direct Redis `EVAL` call and one Redis `TIME` value for the complete
  decision.
- Represent tokens as integer microtokens. One request consumes `1_000_000`
  microtokens, avoiding stored floating-point drift.
- Accept between 1 and 16 unique bucket keys. Validate static lowercase policy,
  namespace, and subject-type identifiers; bound a subject to 1024 UTF-8 bytes.
- Calculate every bucket first. Only when every bucket allows the request does
  the script write every new state. If one bucket denies, no bucket is written
  or has its TTL refreshed.
- Return one result per input bucket plus the longest `retry_after_ms`. On a
  denied batch, an individually allowed result is hypothetical; its token was
  not actually consumed.
- Store only `tokens_micro` and `updated_at_ms`, and set a finite TTL equal to
  the time needed to refill the resulting bucket, with a minimum of one second.
  Policy validation limits full refill time to 30 days.
- Treat Redis errors, malformed script results, or inconsistent state as
  unavailable authority. Never retry by performing separate non-atomic Redis
  commands.

## Redis Key Privacy And Isolation

The exact key shape is:

```text
rl:v1:{<static_namespace>}:<policy>:<dimension>:<hmac_sha256>
```

The HMAC input includes the prefix, namespace, policy, dimension, and subject.
The raw IP, account, target, or user ID never appears in the key. Require at
least 32 bytes for `rate_limit_hmac_key`; never reuse the JWT or verification
secret. Do not log the HMAC digest or complete Redis key either.

The static namespace is also the Redis Cluster hash tag, so all keys in a batch
land in one slot. Never put user-controlled data inside it. Configure
`rate_limit_redis_url` for a separately operated limiter Redis when the product
needs failure or capacity isolation. The asset permits `redis_url` as a
small-project fallback, but still uses separate client instances and namespaces.
Both clients use bounded connect/socket timeouts and no timeout retry.

## Failure And Response Semantics

A real quota denial returns:

- HTTP `429` and business code `429001`;
- `Retry-After: max(1, ceil(retry_after_ms / 1000))`;
- `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` for a bucket
  decision;
- `Cache-Control: no-store`; and
- the same server UUIDv4 in the body and `X-Request-ID`.

`RateLimit-Limit` is the selected bucket's burst capacity.
`RateLimit-Reset` is a relative number of seconds until that bucket is full, not
an epoch timestamp. When several buckets deny, expose only the result requiring
the longest wait. A login failure-risk count is not a quota decision and never
creates rate-limit headers or a `429` by itself.

When limiter Redis is missing, unavailable, times out, or returns invalid state,
return HTTP `503`, business code `503001`, `Cache-Control: no-store`, and the
request ID. Do not return `Retry-After` or invent a denied-bucket result, do not
call the protected logic, and do not disguise dependency failure as `429`. If an
earlier coarse bucket already admitted the request, its ordinary `RateLimit-*`
headers may still be attached to a later downstream `503`; they describe that
successful admission only and never imply a retry time.

The asset fails closed on its limited `/api/` surface. Do not add a fail-open
fallback by accident. If a product explicitly approves fail-open for a named
low-risk read, document that deviation and test it independently; never infer it
from `GET` alone.

## PostgreSQL Boundary

Make the Redis admission decision before opening a PostgreSQL authorization or
business transaction. A limit decision is not authorization. After admission,
the protected service still acquires its canonical PostgreSQL locks, reloads
current authority, applies policy, writes mutation and audit, and commits.
Never call Redis or an external delivery provider while holding those locks.

## Safe Observability

The stable asset events are:

| Event | Level | Meaning |
| --- | --- | --- |
| `rate_limit.denied` | `WARNING` | A valid Token Bucket decision rejected the request |
| `dependency.rate_limit.unavailable` | `ERROR` | Redis could not produce a trustworthy admission decision |

Allow only the static policy name, safe dependency/operation category, HTTP and
business codes where available, safe exception metadata, and server request ID.
Never emit raw IP, account, email, phone, target, HMAC digest, full Redis key,
Token/JTI, Redis URL, exception message, forwarding header, or request body.
Follow [Operational logging](operational-logging.md).

## Required Verification

Use the bundled unit tests for validation and response composition, and a real
supported Redis for Lua, time, TTL, and concurrency behavior. Prove:

- the first request consumes exactly one token and continuous refill follows the
  configured integer-microtoken rate;
- concurrent calls never admit more than available capacity;
- all applicable buckets advance together, while one denied bucket leaves every
  key unchanged;
- batch results preserve input order and return the longest retry delay;
- Redis `TIME`, not the application clock, controls refill;
- idle keys expire, TTL never becomes permanent, and full-refill bounds hold;
- 1 to 16 unique keys work, while duplicates, oversized subjects, invalid policy
  values, malformed results, and wrong result types fail closed;
- all batch keys share the namespace hash slot and keys expose no raw subject;
- `429001` includes the correct rounded-up `Retry-After` and limit headers;
- `503001` includes no `Retry-After`, does not run protected logic, and exposes
  no Redis detail; a middleware-owned limiter outage invents no bucket result;
  and
- successful responses receive limit headers without changing their body or
  request ID.

Run route-composition tests showing that every intended policy is actually wired;
constructing `SecurityPolicies` alone does not enforce a limit.
