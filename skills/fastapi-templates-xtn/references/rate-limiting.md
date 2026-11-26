# Per-Business Rate Limiting

Read this reference for public authentication, CAPTCHA issuance, protected reads
and writes, or any endpoint whose request frequency must be limited. This is a
starting policy, not a claim that one set of numbers fits every deployment.

## Decide Numbers Once

Before generating a project, show these defaults together and ask the product
owner to accept them or name the values to change. Do not silently add a quota
for an endpoint that the project does not expose. Keep the values in
`app/core/config.py`, list corresponding `RATE_LIMIT_*` overrides in `.env.example`,
and explain in the copied asset README that changing the deployment `.env` and
restarting applies new limits. Lua and route files contain no policy numbers;
named request dependencies show the Settings field and window for each business.

Group rate settings in both `app/core/config.py` and the delivered `.env.example`
by login submission, registration submission, CAPTCHA issuance, ordinary user
reads/writes and management reads/writes. Put connection settings and the HMAC
secret first; rate-limit keys have no configurable namespace. Explain each
setting's counting subject, window unit, default maximum,
affected operations and restart requirement. Counts apply to requests reaching
the charging step, not only successful operations. A shared threshold setting
does not merge the separate counters for different operations and users.

## Adding A Business Route

For a new public endpoint, declare a named `rate_limited: None =
Depends(rate_limit_<business>)` parameter on the route. Its dependency in
`app/dependencies/rate_limit.py` shows `scope`, `key_parts`, the Settings limit
and `window_seconds` together. `key_parts` contains actual subject values only:
`[get_limit_ip(request)]` for an anonymous IP or `[login_info.user_id]` for
an authenticated user. The separate named `subject_type="ip"` or
`subject_type="user_id"` identifies the subject kind; it is not another counting
dimension. Do not insert these labels or submitted usernames into `key_parts`.
For example, `subject_type="user_id", key_parts=[login_info.user_id]` means
"limit requests from this currently logged-in user"; it never means the target
user selected in the request body.
Ordinary authenticated business routes use the existing authentication or permission dependency:
it validates JWT and Redis active JTI, then counts the current user window once before
PostgreSQL account checks. Do not add a second limiter to that flow.
Do not add a quota decorator, explicit `operation_id`, or global registry.

Explain ordinary quota names beside the Settings mapping that actually selects
their limits; do not duplicate that mapping with a separate type-only catalog.
The public/private CAPTCHA scene sets are derived from `CaptchaScene` and its
`requires_login` property in `app/core/captcha.py`; import them rather than
hand-maintaining lists in dependencies, routes or Services. These sets check
which uses each issue endpoint accepts at runtime. Explain each purpose beside
its enum member in the shared definition.
Explain PUBLIC as "can request before logging in" and PRIVATE as "must already
be logged in"; PRIVATE also covers a normal user's own password change. Give
both actual issuance paths, their accepted purposes and IP/user-ID subjects.
These sets register CAPTCHA purposes only; adding an ordinary rate-limited
business endpoint does not require changing them.

Keep helper definitions first in `dependencies/rate_limit.py`, then group login
and registration, both CAPTCHA entry points, and authenticated user checks.
`rate_limit_public_captcha` accepts anonymous requests and uses IP;
`rate_limit_private_captcha` uses the current user ID validated by JWT and Redis active JTI.
Keep them adjacent. `get_captcha_scene` only reads the request's CAPTCHA purpose.
`rate_limit_user` counts the current user's business window once before the
database lookup. Explain the counting subject and ordering in each function.

This complete small example returns the current user's own ID. Real domain
queries continue through that domain's Service/Repository rather than adding SQL
to the endpoint:

```python
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import PermissionKey
from app.core.i18n.messages import MessageKey
from app.core.response import ApiResponse, api_response
from app.dependencies.permission import require_permission

router = APIRouter(prefix="/profile")


@router.get("/detail", response_model=ApiResponse[dict[str, str]])
async def get_profile_detail(request: Request,
                             context: Annotated[
                                 AuthorizationContext,
                                 Depends(require_permission(PermissionKey.ACCOUNT_READ)),
                             ]
                             ) -> ApiResponse[dict[str, str]]:
    """
        读取当前已登录用户的本人标识，不接受请求传入的其他用户 ID。
        访问条件：已登录且账号可用。
        所需权限：account:read（查看本人信息）。

    :param request: 当前请求，用于返回统一文案和请求 ID。
    :param context: 已完成登录、账号、普通额度及本人信息权限检查的上下文。
    :return: 当前用户 ID 的统一响应。
    """
    return api_response(
        request,
        message_key=MessageKey.COMMON_QUERY_SUCCESS,
        data={"user_id": context.login_info.user_id},
    )
```

Include this module's router in `app/api/v1/router.py`; that assembler supplies
`/api/v1` once. When an operation needs a permission, use
`Depends(require_permission(PermissionKey.<actual_capability>))`. This defaults
to ordinary user read/write quotas: an ordinary user may hold business permissions.
For a management business such as users, roles or the permission catalog, pass
`management=True` explicitly, for example
`Depends(require_permission(PermissionKey.USERS_READ, management=True))`.
Do not invent a capability that the project has not defined. The permission
dependency receives `Depends(check_token)`, calls
`rate_limit_user(..., management=management)`, then the shared `_load_current_user`,
then checks the exact capability. It does not use `get_current_user`, which
would count another quota. The limiter first selects ordinary user or management
settings from the route's explicit `management` choice, then selects read/write
settings from GET/POST. Here `user` means ordinary authenticated business and
`admin` means the explicitly selected management business; neither the presence
of a permission check nor the caller's role selects this category.
Authentication functions do not pass quota-name strings or repeat that selection.
`get_captcha_user` directly selects the private CAPTCHA quota. Each first receives
the same `check_token` JWT/Redis validation result, then calls the shared
`_load_current_user` once. Do not add a forwarding authentication dependency or
hide ordinary login checks behind a typed route alias.

| Interface | Settings field | `.env` setting | Default requests / 60 seconds |
| --- | --- | --- | ---: |
| Ordinary authenticated `GET`, with or without a permission check | `rate_limit_user_read` | `RATE_LIMIT_USER_READ` | 600 |
| Ordinary authenticated `POST`, with or without a permission check | `rate_limit_user_write` | `RATE_LIMIT_USER_WRITE` | 120 |
| Management `GET`, explicitly selected with `management=True` | `rate_limit_admin_read` | `RATE_LIMIT_ADMIN_READ` | 300 |
| Management `POST`, explicitly selected with `management=True` | `rate_limit_admin_write` | `RATE_LIMIT_ADMIN_WRITE` | 60 |

The defaults live in `app/core/config.py`; `app/dependencies/rate_limit.py`
shows which business uses each setting. Override the documented environment variable and
restart to change a value. Choosing the same setting does **not** share a
counter: `list_orders` and `list_invoices` each get an independent window per
authenticated user.
When constructing a policy, spell out `name=`, `limit=`, and `window_seconds=` rather
than making maintainers infer the meaning of positional numbers such as `300`.

Give every handler a stable, unique function name. FastAPI exposes that name as
the server-side route name, and the limiter uses it as the business part of the
private Redis key. Use a lowercase ASCII letter first and then lowercase letters,
digits, `.`, `_`, or `-`, with at most 64 characters. A business route declares
exactly one `GET` or `POST`. Renaming a handler starts a new short-lived quota
window, so rename it deliberately.
Follow the [request naming convention](api-response-standard.md#methods-paths-and-request-parameters):
resource list/detail reads end in `/list` or `/detail`, GET IDs are query fields, and POST
IDs belong to a closed JSON body. The route name and authenticated current user,
not any target ID from these inputs, still select the quota bucket.

`validate_api_routes(app)` in `app/core/route_validation.py` runs at
the start of the application's lifespan, before creating Redis clients or using
database resources. Missing login dependencies, duplicate/invalid route names,
wrong methods, and incorrect parameter placement fail startup with the exact
method and path. Route-name format uses the limiter's existing identifier rule;
the validator does not create a fake quota policy. Actual limits come from the
business policies and settings. The check includes nested routers; do not remove it to suppress
an error. Fix the indicated route instead. It performs no
DDL, migrations or external I/O. Add a route-wiring test when introducing a
business module so this failure is caught before deployment.

Every authenticated route uses exactly one appropriate authentication or
permission dependency. The authenticated CAPTCHA route uses its dedicated
authorization dependency, which selects three scene-specific windows instead of
a generic write window. Public login, registration and CAPTCHA keep their
explicit guarded flows.
The public CAPTCHA dependency reads the scene and trusted IP and selects the
valid scene's issuance window or the fixed rejected-request window before the
route creates an image. The authenticated CAPTCHA dependency uses that scene
for its single count before current-account validation.
Keep the fixed scene allowlists and key dimensions visible beside these checks.
The dedicated authentication dependency selects the CAPTCHA scene window
instead of the generic write window, then validates the current account.
The generic user limiter accepts no CAPTCHA purpose; the CAPTCHA authentication
dependency must call its dedicated limiter, as checked by the route-wiring rules.
Current-session logout uses
`login_info: LoginInfo = Depends(check_token)` directly. It validates JWT
and the exact active-JTI record, then atomically deletes that login. It has no
quota, limiter-client dependency, PostgreSQL read or business-permission check.
The startup rule allows this reduced flow only for the current-session logout
route; other protected business routes still require their quota and current
database authority. The limiter module never imports authentication dependencies.
The protected business order remains JWT verification, Redis active JTI,
one atomic quota count, then database account validation. Rate limiting has no
feature switch and cannot be omitted by
forgetting an extra route decorator.

## Default Quotas

| Business (one independent key for each named operation) | Default |
| --- | ---: |
| Graphical CAPTCHA issue, separately for each of five scenes | 10 per 5 minutes |
| Missing, unknown or wrong-endpoint CAPTCHA scene, per trusted IP or authenticated current user | 10 per 5 minutes |
| Login submission, trusted client IP | 20 per 5 minutes |
| Public registration submission, trusted client IP | 5 per hour |
| Authenticated ordinary read, per operation and user ID | 600 per minute |
| Authenticated ordinary write, per operation and user ID | 120 per minute |
| Administrative read, per operation and user ID | 300 per minute |
| Administrative change, per operation and user ID | 60 per minute |

Each CAPTCHA scene has a separate issuance quota. Issuing an image does
not spend the login or registration submission quota; submitting one does not
spend the issuance quota. The image itself lasts five minutes and is single-use;
its validity is independent of the five-minute issuance window. An
otherwise valid scene sent to the wrong public/authenticated issue endpoint,
or a missing/unknown scene, spends a separate
`captcha_invalid_scene` (CAPTCHA purpose invalid for the current issue endpoint)
quota, not a scene issuance quota. It counts invalid image requests, not incorrect
CAPTCHA answers submitted to login, registration or password operations. Public requests use
trusted IP; authenticated requests use the server-authenticated current user ID. All
such rejected requests share this one
per-subject rejection quota, using the CAPTCHA limit and window settings; no
challenge is issued. An over-limit request receives `42901`, and missing IP or
Redis authority fails closed with `50301`. Invalid JSON syntax is rejected by
the framework before authentication dependencies run. A valid scene with an
invalid unrelated field (such as an unexpected JSON key) spends that scene's
quota before FastAPI returns `422`; it does not issue an image. An
administrator forcing a lower user's sessions out uses its own administrative
change key, not a special `logout_all` quota. No online super-admin transfer
operation exists.

## Subjects And Boundaries

- For allowed unauthenticated authentication endpoints, key on the fixed
  operation name and a trusted canonical client IP. With a multi-scene route,
  add only a validated server-owned scene name. Never key an anonymous quota
  by submitted username, target account, email, challenge ID, or user-supplied
  forwarding header. Public registration has no separate state endpoint.
- The trusted IP selects the public CAPTCHA issuance and login/registration
  rate-limit buckets; it is not stored as challenge ownership. A public
  challenge remains usable if a VPN or mobile-network exit changes between
  issue and submit. Scene, five-minute TTL, and atomic one-use consumption still
  apply.
- For authenticated routes, key on the fixed operation name and the canonical
  user ID loaded by authentication. Administrative operations use the current user ID,
  not the target ID. A separate key per operation prevents activity in one
  business from consuming another business's budget.
- Read the address only from the ASGI server's trusted client value, after
  deployment proxy configuration. Validate via `ipaddress.ip_address`. If it
  is absent or invalid, fail closed (`50301`); do not merge unrelated callers
  into an `unknown` bucket. Incorrect proxy trust configuration must be fixed
  by the operator, not hidden by trusting an arbitrary `X-Forwarded-For`.

Never present rate limiting as identity verification or RBAC. After the rate-limit check,
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
rate-limit step, a request passes only when `count <= limit`;
calls that reach this step after the limit still increment once until the window
expires. Every call uses this same counting operation. This remains a simple
fixed window, not a Token Bucket.
Do not silently treat zero or negative limits/windows as disabling protection.
For anonymous login/registration, run the trusted-IP Redis rate-limit check before
password work or PostgreSQL writes. For authenticated business routes other
than current-Token logout, first validate JWT shape/signature/time and the Redis
active JTI. Before PostgreSQL, atomically count the named
operation-and-current user window by performing one `INCR` with atomic initial expiry.
If the new count exceeds the limit, return `42901` immediately without a database
read. Otherwise load the PostgreSQL account/current authority and confirm its
status and Redis-bound token version before protected work. Concurrent requests
compete through that same increment, so only requests within the allowance
reach PostgreSQL. There is no later count or refund after account validation.

A forged or already revoked Token therefore spends no current user quota and does not
reach PostgreSQL. A still-active Redis JTI whose account is disabled or stale
has already spent this request's count when PostgreSQL rejects it. Best-effort
compare-and-delete that exact JTI so its next use stops at Redis. If the window
is already exhausted, the single count rejects with `42901` and skips PostgreSQL;
the database identity is not rechecked on that request. Current-Token logout
is the narrow Redis-only exception: validate JWT and the exact active JTI, then
immediately compare-and-delete it without a quota or PostgreSQL authorization
read. It does not access the optional separate limiter client. For rate-limited
business requests, a limiter outage is not permission to proceed.

The authenticated CAPTCHA route keeps its three scene quotas separate. After
active-JTI validation and before PostgreSQL, read the fixed scene once and
count `captcha_create_admin_create_user`, `captcha_create_admin_reset_user_password`, or
`captcha_create_user_change_password` for a valid private scene. A missing/unknown scene or a
public scene sent to that endpoint counts the independent
`captcha_invalid_scene` current user window. Perform exactly one increment of the
selected window; denial stops before PostgreSQL, and admission continues to
current-account validation. Other body
fields are validated by the route after the dependency. Do not replace this with one generic
authenticated-CAPTCHA bucket that would make the scenes consume one another.

Keep Redis keys private. Redis is dedicated to this service; active JWT JTI,
CAPTCHA, and quotas may share its client. Rate-limit keys have this fixed form:
`rate_limit:<business>:<subject_type>:<hmac_sha256>`.

| Key part | Meaning |
| --- | --- |
| `rate_limit` | Fixed prefix identifying a request counter, not an environment or application name |
| `<business>` | The server-owned policy name, such as `login` or a stable route handler name; different businesses have different counters |
| `<subject_type>` | Exactly `ip` for an anonymous trusted IP or `user_id` for the authenticated current user |
| `<hmac_sha256>` | The full 64-character lowercase hexadecimal HMAC-SHA256 digest; the raw subject is not included in the key |

For example, `rate_limit:login:ip:<64-character digest>` counts login requests
from one trusted IP; a user-ID key counts the current caller, never a managed
target user. Compute the digest with `RATE_LIMIT_HMAC_KEY` as the HMAC secret
and the following three UTF-8 strings separated by a zero byte (`\x00`):

```text
business + "\x00" + subject_type + "\x00" + canonical_subject
```

`canonical_subject` is the validated canonical IP or the authenticated current
`user_id`. The input contains only these three values: no key prefix,
application/environment identifier, or extra namespace. Do not truncate the
SHA-256 digest. Key-building and limit-check functions accept no namespace
argument, and Settings exposes no rate-limit namespace setting.

Use a secret distinct from the JWT signing secret; never place a raw IP,
username, user ID, challenge, JWT, or target in a key or log. Validate the
business name, secret strength, and subject bounds. Keep Redis timeouts bounded.
A separately operated standalone limiter Redis remains a deployment option;
it is not required to separate counters from session or CAPTCHA records.

Each Lua operation uses one key. Adopting this key format starts a new counting
window per business and subject. Leave previous counters to expire naturally;
do not read them as a fallback, actively delete Redis keys, or add a migration
cleanup. CAPTCHA records still use `captcha:<UUID>` and retain their existing
TTL and verification rules. Quotas, Lua counting, and request order do not change.

## HTTP And Failure Contract

A real over-limit decision returns HTTP `429`, business code `42901`,
`Retry-After: max(1, ceil(remaining PTTL / 1000))` seconds,
`Cache-Control: no-store`, and
the same server UUIDv4 in the response body and `X-Request-ID`. A Redis error,
malformed result, invalid trusted IP, or missing required limiter authority
returns HTTP `503`, code `50301`, `Cache-Control: no-store`, no `Retry-After`,
and never calls the protected handler. Do not expose Redis keys, raw IPs,
credentials, internal exceptions, or the denying subject in either response.
If used, `RateLimit-Limit` is the fixed-window maximum,
`RateLimit-Remaining` is `max(0, limit - count)`, and `RateLimit-Reset` is the
remaining window seconds (not time until a continuously refilling bucket fills).

Rate limiting has no environment or test switch. Development and tests replace
the dependency's Redis call with an explicit fake when isolation is
needed; they do not alter runtime settings to skip protection. A missing limiter
client or an unavailable Redis therefore fails closed in every environment.

## Verification

Use real Redis for first-use `INCR`/`EXPIRE` atomicity, TTL, expiry, independent
business keys, concurrent checks, and key privacy. Unit-test malformed Lua
replies, missing/untrusted IP, positive settings validation, `42901` retry
headers, `50301` fail-closed behavior, and absence of global and username
buckets. Route tests must prove every intended dependency actually runs, one
failure never executes the protected action, and CAPTCHA issue uses its
scene-specific quota. Prove that a valid scene sent to the wrong issue endpoint
uses its separate per-subject quota, never creates an image, cannot consume a
valid scene's quota, and fails closed when Redis is unavailable. Also prove that
missing/unknown scenes consume this rejection quota, while a valid scene with
an invalid unrelated field spends its scene quota and still completes normal
identity validation before its `422`.
For rate-limited authenticated routes, prove each active-JTI request increments its selected
window once, including requests rejected for exceeding the limit or for a later
database identity failure. An exhausted window avoids PostgreSQL; forged or
Redis-revoked Tokens neither count nor reach PostgreSQL. Concurrent last-slot
requests admit no more than the configured total. Prove all three private
CAPTCHA scenes count their own exact windows once, while invalid/wrong-endpoint
requests count the rejection window once; none may hit PostgreSQL after its
selected window denies admission. Tests for local
quota denial cannot substitute for PostgreSQL RBAC/transaction tests.
Prove current-session logout validates and deletes only its own login without
counting a quota, accessing the limiter client or querying PostgreSQL; a separate
limiter outage must not block it. Preserve invalid-Token, inactive-JTI and
session-store failure denials.
