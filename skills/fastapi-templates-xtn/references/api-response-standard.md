# API Response Standard

Use this contract when the task creates or changes JSON HTTP endpoints. Preserve
an established compatible contract in an existing product; otherwise use this
baseline consistently across success responses, validation, authentication,
authorization, routing errors, rate limits, and unexpected failures.

## Methods, Paths, And Request Parameters

New business endpoints use only `GET` and `POST`. Use `GET` for reads, with
collection routes ending in `/list` and single-record reads ending in `/detail`.
The current-user information endpoint uses `GET /api/v1/me/user_info`, returning
the authenticated user's ID, highest effective role level and permission union.
Put filters, pagination and target identifiers in typed query parameters. Use
action-specific `POST` routes for mutations; put target identifiers and other
command fields in one Pydantic JSON body inheriting `RequestBase`.
Do not put business IDs in path segments or read a POST target from the query
string as an alternative to its required body field.

| Operation | Request |
| --- | --- |
| List roles | `GET /api/v1/roles/list?page=1&page_size=20` |
| Read a role | `GET /api/v1/roles/detail?role_id=<id>` |
| Create a role | `POST /api/v1/roles/create` with a JSON creation model |
| Disable a role | `POST /api/v1/roles/disable` with `{"role_id": "<id>", "expected_version": 7}` |
| Disable a user | `POST /api/v1/users/disable` with `{"user_id": "<id>"}` |

The ID location is a naming and client-usage convention, not protection against
an attack. Both query strings and JSON bodies are caller-controlled. Keep bearer
authentication, exact capability checks, object visibility, strict hierarchy,
input validation, parameterized SQL, and credential redaction unchanged. Query
strings can appear in browser history and proxy logs; never put passwords,
Tokens or CAPTCHA answers in them. POST bodies must not be logged by default.
GET must not perform business mutations.

Document each public request/response field with a Chinese
`Field(description=...)` and each query input with `Query(description=...)` so
maintainers can understand identifiers, units and optional choices from source
and framework validation metadata.
Preserve validated types, constraints, defaults and aliases when adding these
descriptions. Keep private authorization state out of public schema descriptions.
These static descriptions are separate from localized runtime messages.

New projects include no `/health/live` or `/health/ready` endpoint. Add health
probes only when the adopter explicitly requests them, and restrict access to
an internal network or trusted probes; they are not business list/detail
endpoints. New projects disable `/docs`, `/redoc`, and
`/openapi.json`; application code does not add alternative public documentation
routes. CORS handling is outside the business-method restriction. Preserve an existing application's established
public contract unless the user has requested its migration; do not silently
break its callers just to match a new-project convention.

## One HTTP Status And One Numeric Business Code

Return the real HTTP status in the HTTP response and a five-digit integer
business code in the JSON body. Do not return every outcome as HTTP `200`, and
do not duplicate the HTTP status in a JSON `http_status` field.

The first three digits of the business code equal the HTTP status. The last
two digits identify an application outcome within that status. Divide those
two digits by business: `00` for a generic success, `01`-`09` for shared errors,
`10`-`19` for authentication/password, `20`-`29` for users, `30`-`39` for
roles, `40`-`49` for permission-specific outcomes, and `50`-`59` for CAPTCHA.
`60`-`99` remain available for future named businesses; do not invent codes
for every endpoint. This is a suffix convention, so `40920` and `40050` still
retain the correct HTTP prefix. Shared authorization denial, concealed targets,
rate limits, and infrastructure failures keep common codes because disclosing
more would not help the client or could leak protected state.

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

```json
{
  "code": 40301,
  "message": "无权执行该操作",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Keep the ordinary JSON envelope to exactly these stable top-level fields:

| Field | JSON type | Contract |
| --- | --- | --- |
| `code` | number | Five-digit integer business code; never a numeric string |
| `message` | string | Short human-readable result; clients do not branch on it |
| `data` | object, array, or `null` | Result data; normally `null` on failure |
| `request_id` | string | Server-generated UUIDv4 for this request |

Do not add redundant `success`, `status`, `http_status`, or `timestamp` fields.
HTTP status plus `code` determines success, while server logs provide timing.
The baseline localizes every client-facing runtime `message` in `zh-CN` and
`en`; keep `code` language-independent. Read
[API internationalization](api-internationalization.md) before changing message
keys, language negotiation, validation text, or catalogs.

Start with this registry and add codes only for a client-visible distinction.
The suffix group lets a client locate the relevant business without parsing
translated messages; it is not a substitute for the explicit enum meaning:

| Group | HTTP | Business code | Meaning |
| --- | --- | ---: | --- |
| Shared | `200` | `20000` | Request succeeded |
| Shared | `201` | `20100` | Resource created |
| Shared | `400` | `40001` | General invalid request |
| Shared | `403` | `40301` | Operation forbidden; protected reason stays hidden |
| Shared | `404` | `40401` | Missing or deliberately concealed resource |
| Shared | `405` | `40501` | Method not allowed |
| Shared | `409` | `40901` | General state conflict |
| Shared | `413` | `41301` | Request body is too large |
| Shared | `415` | `41501` | Media type is unsupported |
| Shared | `422` | `42201` | Request validation failed |
| Shared | `429` | `42901` | Request rate is limited |
| Shared | `500` | `50000` | Unexpected internal failure |
| Shared | `503` | `50301` | A required authority or dependency is unavailable |
| Authentication | `400` | `40010` | New password violates the selected policy |
| Authentication | `401` | `40110` | Missing, invalid, expired, or revoked authentication |
| Users | `400` | `40020` | No roles supplied for a user-role change |
| Users | `409` | `40920` | New user name or ID conflicts |
| Users | `409` | `40921` | User would exceed the role limit |
| Roles | `409` | `40930` | Role key conflicts or is reserved |
| Roles | `409` | `40931` | Submitted role version is stale |
| Permissions | `400` | `40040` | Requested permission selection is invalid |
| CAPTCHA | `400` | `40050` | Challenge is wrong, expired, or for another scene |

Define the registry in `core/codes.py` with an integer enum. Once published, never
reuse a code, renumber it, or give it a new meaning. Internal constant names may
be descriptive, but public routes, handler names, messages, and codes must not
reveal that RBAC is the implementation mechanism. Keep sensitive denial reasons
in internal logs or audit `reason_code`, not in the public `message`.

Reserve the `01` suffix as the generic error for any otherwise-unlisted real
HTTP `4xx` or `5xx` status. A global framework handler must preserve that HTTP
status and may emit `status * 100 + 1`; it must not collapse an uncommon `418`
or `501` into `400` or `500`. Add a named enum member before application code
needs to branch on a more specific outcome.
If an exception incorrectly carries a status outside `400`-`599`, normalize it
to HTTP `500` and code `50000`; an exception must not become a successful
response because it carried `200`.

```python
from enum import IntEnum


class BusinessCode(IntEnum):
    # Shared outcomes and failures.
    OK = 20000
    CREATED = 20100
    BAD_REQUEST = 40001
    ACCESS_FORBIDDEN = 40301
    NOT_FOUND = 40401
    METHOD_NOT_ALLOWED = 40501
    CONFLICT = 40901
    PAYLOAD_TOO_LARGE = 41301
    UNSUPPORTED_MEDIA_TYPE = 41501
    VALIDATION_FAILED = 42201
    RATE_LIMITED = 42901
    INTERNAL_ERROR = 50000
    SERVICE_UNAVAILABLE = 50301

    # Authentication/password: 10-19.
    PASSWORD_POLICY_INVALID = 40010
    INVALID_AUTHENTICATION = 40110

    # Users: 20-29; roles: 30-39; permissions: 40-49; CAPTCHA: 50-59.
    USER_ROLE_SELECTION_INVALID = 40020
    USER_CREATE_CONFLICT = 40920
    USER_ROLE_LIMIT_EXCEEDED = 40921
    ROLE_KEY_CONFLICT = 40930
    ROLE_VERSION_STALE = 40931
    PERMISSION_SELECTION_INVALID = 40040
    CAPTCHA_INVALID = 40050
```

## Named Business Exceptions

In `core/exceptions.py`, fixed-status exception constructors end in their HTTP
status so callers can see the error category directly. Use the following names
and update imports, callers and executable examples together when renaming:

| Constructor | HTTP meaning |
| --- | --- |
| `invalid_request_400` | 请求不符合业务规则 |
| `password_policy_response_400` | 新密码不符合密码策略 |
| `unauthenticated_401` | 未登录或登录凭据无效 |
| `forbidden_403` | 无权执行操作 |
| `not_found_404` | 资源不存在或按可见范围隐藏 |
| `conflict_409` | 当前业务状态冲突 |
| `stale_resource_version_409` | 提交的资源版本已过期 |
| `unavailable_503` | 必需依赖暂不可用 |

These functions construct `AppError`; the caller still writes, for example,
`raise forbidden_403("missing_operation_permission")`. The suffix is the HTTP
status, not the five-digit JSON business code. Keep the existing business codes,
message keys and internal reason codes. Do not add old-name forwarding aliases.
`AppError` and the specialized `InvalidLoginCredentialsError` remain exception
classes, with their existing handlers and behavior.

## Request And Response Bases

All HTTP request models inherit `RequestBase` from `schemas/common.py`, directly
or through an existing shared request model. All HTTP response models inherit
`ResponseBase` from `core/response.py`, including nested response objects,
`ApiResponse[T]` and `PageResponse[T]`. Both bases extend Pydantic `BaseModel`
and own `ConfigDict(extra="forbid", frozen=True)`; concrete models retain their
business fields, validators and constraints rather than repeating this config.
Keep intentional local metadata, such as `RoleUpdateRequest.json_schema_extra`,
alongside the inherited rules. Do not add another module or inheritance layer.

`extra="forbid"` rejects fields absent from the model. `frozen=True` prevents
reassigning a parsed object's fields, such as `body.user_name = "Bob"`; reading
fields remains allowed. This is not recursive freezing: contents of a list or
dictionary field can still change. These bases provide consistent data contracts;
password handling, log redaction and permission checks remain separate duties.

## Response And Pagination Models

Keep these models and response builders in `core/response.py`; business exceptions
belong in `core/exceptions.py`, while `core/exception_handlers.py` converts them
to HTTP responses. Use a generic envelope and a deliberately small page object:

The existing `api_response(request, *, message_key, data, code=BusinessCode.OK)`
defaults ordinary success to `20000`. Keep the message key and business data
explicit; creation passes `code=BusinessCode.CREATED` and keeps HTTP 201 on its
route. `error_content` still requires its error code and forwards it explicitly.
The response model's `code` field remains required and strict; the builder default
does not loosen validation. Do not add a separate forwarding success helper.

For commands, return success and the final resource state when the client needs
it; otherwise use `data: null`. Do not expose a `changed` field or add a response
model solely for that boolean. Role mutations retain
`RoleMutationResponse.role`, and user-role mutations retain
`UserRoleResponse.user`; enable/disable commands retain their existing
user or role response. Password changes/resets and session termination return
`data: null`.

An authorized repeated enable/disable or bind/unbind request that already has
the requested result remains successful and returns the final state. Keep the
internal change check to avoid unnecessary writes or version increments, and
preserve the existing audit decision/reason. This does not bypass authorization,
visibility or role `expected_version` checks: an authorized stale role version
still returns `40931`. The new `request_id` and separate audit event may differ
between requests without changing this business-state idempotency.

The same builder centrally records `request.state.operation_outcome` from the
five-digit business code: `2xxxx` sets `success`, while `4xxxx`/`5xxxx` sets
`failure` unless a previous response already marked `success`. Routes do not
repeat this assignment or set `request.state.action`; request logs obtain the
action from the existing endpoint function name. Preserve affected
`target_user_id`/`target_role_id` recording and database audit action enums.
When no unified response is assembled, the logging middleware keeps its existing
fallback. Preparing a successful response and subsequently failing to send it
must remain distinguishable as `operation_outcome=success` with `outcome=error`;
see [Operational logging](operational-logging.md) for lifecycle ownership.

```python
# 普通成功响应只填写实际文案和数据。
return api_response(request, message_key=MessageKey.COMMON_QUERY_SUCCESS, data=data)

# 创建明确覆盖业务码；对应路由仍声明 status_code=201。
return api_response(request, code=BusinessCode.CREATED,
                    message_key=MessageKey.COMMON_OPERATION_SUCCESS, data=data)
```

```python
from typing import Generic, TypeVar

from pydantic import UUID4, BaseModel, ConfigDict, Field

T = TypeVar("T")


class ResponseBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApiResponse(ResponseBase, Generic[T]):
    code: int = Field(strict=True, ge=10000, le=59999)
    message: str = Field(min_length=1)
    data: T | None
    request_id: UUID4


class PageResponse(ResponseBase, Generic[T]):
    items: list[T]
    page: int = Field(strict=True, ge=1)
    page_size: int = Field(strict=True, ge=1, le=200)
    total: int = Field(strict=True, ge=0)
```

The returned page data contains only `items`, `page`, `page_size`, and `total`.
The request uses `page` and `page_size`. Default to page `1` and page size `20`,
cap page size at `200`, apply the same filters to rows and `total`, and use a
deterministic order with a unique final tie-breaker. An empty page has
`items=[]`; it is not a `404`.

```json
{
  "code": 20000,
  "message": "查询成功",
  "data": {
    "items": [],
    "page": 1,
    "page_size": 20,
    "total": 0
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Do not add `meta`, `pagination`, `total_pages`, `has_next`, `has_previous`, or a
cursor to this baseline. A client can calculate `ceil(total / page_size)`. If a
product later proves offset pagination unsuitable, introduce a versioned cursor
contract deliberately rather than mixing both shapes.

For a validation failure, keep the same envelope. Safe field feedback may live
under `data.errors`; do not serialize raw exception contexts, submitted secret
values, database errors, or stack traces.

```json
{
  "code": 42201,
  "message": "请求参数校验失败",
  "data": {
    "errors": [
      {"field": "body.name", "message": "此字段为必填项"}
    ]
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Request ID Boundary

Use a server-generated UUIDv4 as the authoritative request ID. Generate a new
value at the first application middleware for every request.
Put exactly the same value in `request.state.request_id`, every ordinary JSON
body, and the `X-Request-ID` response header. Generate it before authentication,
routing, or validation so even `401`, `404`, `405`, `422`, `429`, and `500`
responses have correlation.

Do not treat a caller-supplied `X-Request-ID` as the authoritative server ID.
When upstream correlation is needed, validate it under a strict length and
character policy and store it separately as `client_request_id`. Never use a
request ID as authentication, authorization, an Access Token JTI, an
idempotency key, or a database entity identifier.

```python
import uuid

from fastapi import Request


@app.middleware("http")
async def bind_request_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response
```

The post-`call_next` line does not run when an exception escapes the application
stack. The global unexpected-error and dependency-error handlers must therefore
build the same envelope and set `X-Request-ID` explicitly. Do not rely on only
the middleware's normal return path for `500` or `503` correlation.

All normal business endpoints should return JSON instead of `204` so the body
can carry `request_id`. A response that inherently has no ordinary JSON body,
such as `204`, `304`, a file, or a stream, carries the mandatory ID in the header
only. When browser JavaScript must read it cross-origin, expose `X-Request-ID`
through the product's CORS policy.

Record the same server request ID in structured access/application logs and in
`operation_audit_events` for a privileged decision. Also record
`http_status_code` and `business_code` in the completion log. Never log bearer
tokens, cookies, Access Token JTI values, passwords, or request bodies by
default. Follow [Operational logging](operational-logging.md) for the log event
contract and [Audit module](audit-module.md) for durable evidence.

## Rate-Limit And Security-Dependency Responses

The local Redis limiter has two different outcomes. Do not merge them:

| Outcome | HTTP/code | Required headers | Forbidden headers |
| --- | --- | --- | --- |
| A trustworthy fixed-window decision denies the request | `429` / `42901` | `X-Request-ID`, `Cache-Control: no-store`, integer `Retry-After` | None of the required headers may be omitted |
| Limiter or verification authority is missing, unavailable, times out, or returns malformed state | `503` / `50301` | `X-Request-ID`, `Cache-Control: no-store` | `Retry-After` |

For a fixed-window decision, both allowed responses and `429` may carry:

```text
RateLimit-Limit: <window maximum>
RateLimit-Remaining: <requests remaining in this window>
RateLimit-Reset: <seconds until this window expires>
```

`RateLimit-Reset` is a relative duration, not a timestamp. A denied limit adds:

```text
Retry-After: <max(1, remaining window TTL in seconds)>
```

Each protected operation checks only its own business/subject key. There is no
cross-business, global, or username-specific bucket. Do not reveal the private
subject in headers or errors.

The bodies retain the ordinary four-field envelope:

```json
{
  "code": 42901,
  "message": "请求过于频繁，请稍后重试",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

```json
{
  "code": 50301,
  "message": "服务暂时不可用",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

A `50301` means no trustworthy rate-limit or verification decision was made. It
must fail closed and must not call the protected handler. Do not turn it into a
fake quota denial, expose a Redis/provider error, or guess a retry duration.
When the per-route limiter cannot decide, it has no quota result to
publish. If an earlier layer already admitted a request, its ordinary
`RateLimit-*` headers may remain on a later downstream `503`; those headers
describe the successful earlier check and never authorize `Retry-After`.

Runtime exception handlers must return `42901` and its response headers wherever
the application actually enforces a limit, and `50301` when Redis-backed rate
limiting or verification fails closed. Do not add per-route documentation-only
`responses` declarations to repeat this shared behavior. If browser code reads
these headers cross-origin, expose `X-Request-ID`, `Retry-After`,
`RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` in CORS.

## Resource Version Instead Of A Strong Envelope ETag

The response body's `request_id` changes on every request. Therefore the entire
JSON representation is byte-different on every response and cannot truthfully
share a stable strong `ETag` based only on resource state.

For role concurrency, return the existing nonnegative `version` inside the role
data. Require `expected_version` in each role information, lifecycle, deletion,
or permission mutation body. After the global guard and canonical
rows are locked and the current user and affected authority are reloaded, first perform
the complete authorization and hierarchy decision and only then compare the
submitted strict JSON integer to the current `roles.version`. This order prevents
an unauthorized current user from learning the current version through a `403`/`409`
oracle. A mismatch after authorization returns HTTP `409` with business code
`40931`; no mutation, version increment, or allowed audit may commit.

```json
{
  "role_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Operations",
  "expected_version": 7
}
```

```json
{
  "code": 40931,
  "message": "资源已被其他操作更新，请刷新后重试",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Build the returned role snapshot, including its new version, while the same
transaction still owns the locks. `expected_version` is a concurrency condition,
never proof of authorization. User-role bind/unbind remains incremental and
idempotent and does not require a user version in this baseline. Its response,
and user disable/enable responses, must nevertheless be immutable snapshots built
inside the same locked authorization transaction. Filter nested fields such as
`bound_role_ids` through the current user's read-visibility predicate while retaining
the complete unfiltered state for the internal policy and audit. After commit,
return the snapshot directly; do not reconstruct it with a request-scoped or new
database `Session`.

If an existing product must retain standards-compliant strong `ETag` semantics,
keep the server request ID in `X-Request-ID` but omit it from that successful
ETag-protected representation body. Do not claim both a stable strong ETag and a
per-request-changing body for the same representation.

## Error And Completion Rules

- One known domain failure maps to one registered numeric code at the HTTP
  boundary. Public clients never receive raw internal `reason_code` values.
- Use `40001` for a structurally valid request whose requested operation is
  semantically invalid and has no registered business-specific outcome.
  Reserve `42201` for schema, path, query, and body validation failures.
- Error handlers for domain errors, validation, framework HTTP errors, and
  unexpected exceptions all use the envelope and server request ID.
- Authentication failures use one public `40110` result to avoid distinguishing
  missing, expired, revoked, or malformed credentials. Include
  `WWW-Authenticate: Bearer`.
- Use generic `40301` and `40401` messages where extra detail would disclose a
  protected resource, tier, role, or permission.
- A `429` from a downstream probe or other explicitly rate-limited operation is
  not rewritten as authentication, authorization, or connectivity failure.
- A local limiter `42901` and limiter/verification `50301` follow the exact
  header and fail-closed contract above. In particular, a dependency `50301`
  never carries `Retry-After`.
- A successful create uses HTTP `201` and `20100`; ordinary reads and commands
  use HTTP `200` and `20000` unless the client needs another registered success
  distinction.
- The frontend branches on HTTP status and numeric `code`, never localized
  `message` text.
- Missing or unsupported `Accept-Language` falls back to `zh-CN`. Every response
  returns canonical `Content-Language` and `Vary: Accept-Language`;
  language choice changes human-facing text, including built-in permission
  descriptions, while codes, machine values inside `data`, and the request ID
  remain stable. Custom database descriptions are returned as stored.
- Return `X-Request-ID` as a UUID response header on every ordinary success and
  error response. Return `41301`, `41501`, or `42901` only when the
  application actually enforces the matching behavior with this envelope.

## Verification

Test the observable contract rather than only model definitions:

- business methods are only `GET` and `POST`, list/detail reads have the stated
  suffixes, and route dependency metadata places target IDs in GET query fields
  or required POST bodies, never path parameters;
- missing or invalid target IDs fail validation; POST query parameters cannot
  supply a missing body ID, and unknown JSON fields are rejected;
- success, create, domain error, validation error, unknown route, unsupported
  method, authentication failure, dependency outage, uncommon framework error,
  and unexpected failure all use the original correct HTTP status and matching
  five-digit integer code;
- every ordinary JSON body has exactly `code`, `message`, `data`, and
  `request_id`, and the header/body request IDs are equal UUIDv4 values;
- a caller-supplied request ID is not adopted as the server ID;
- pagination defaults, maximum size, filtered `total`, deterministic ordering,
  empty pages, and the absence of extra pagination metadata are covered;
- stale `expected_version` returns `40931` and cannot write domain rows, audit
  success, versions, or cache invalidations;
- an unauthorized stale write returns its authorization failure rather than
  `40931`, and non-integer versions such as strings, floats, and booleans return
  `42201`;
- successful role and user administration writes return the immutable
  in-transaction snapshot without a post-commit query, and nested assigned-role
  IDs reveal only roles visible to the caller;
- logs and privileged audit rows use the response request ID without recording
  credentials, Token/JTI values, or secret request fields; and
- local quota denial has the documented `42901` limit headers and rounded-up
  `Retry-After`, while Redis/verification `50301` omits `Retry-After` and cannot
  invoke protected logic; a limiter outage invents no quota result;
  and
- `/docs`, `/docs/oauth2-redirect`, `/redoc`, and `/openapi.json` return `404`
  by default, while runtime response-model validation still rejects an invalid
  successful response shape; and
- default Chinese, English, language quality ordering, unsupported and hostile
  language headers, catalog-key parity, localized validation details, response
  language/cache headers, and concurrent request isolation are covered.

The bundled PostgreSQL asset demonstrates this contract. When adapting it,
preserve the target project's naming and localization while retaining the wire
invariants above.
