# API Response Standard

Use this contract when the task creates or changes JSON HTTP endpoints. Preserve
an established compatible contract in an existing product; otherwise use this
baseline consistently across success responses, validation, authentication,
authorization, routing errors, rate limits, and unexpected failures.

## One HTTP Status And One Numeric Business Code

Return the real HTTP status in the HTTP response and a six-digit integer
business code in the JSON body. Do not return every outcome as HTTP `200`, and
do not duplicate the HTTP status in a JSON `http_status` field.

The first three digits of the business code equal the HTTP status. The last
three digits identify an application outcome within that status. Use `000` for
a generic outcome when no finer client-visible distinction is useful, and
register every nonzero suffix centrally.

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

```json
{
  "code": 403001,
  "message": "无权执行该操作",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Keep the ordinary JSON envelope to exactly these stable top-level fields:

| Field | JSON type | Contract |
| --- | --- | --- |
| `code` | number | Six-digit integer business code; never a numeric string |
| `message` | string | Short human-readable result; clients do not branch on it |
| `data` | object, array, or `null` | Result data; normally `null` on failure |
| `request_id` | string | Server-generated UUIDv4 for this request |

Do not add redundant `success`, `status`, `http_status`, or `timestamp` fields.
HTTP status plus `code` determines success, while server logs provide timing.
Use a localized `message` when the product localizes API text; keep `code`
language-independent.

Start with this registry and add codes only for a client-visible distinction:

| HTTP | Business code | Meaning |
| --- | ---: | --- |
| `200` | `200000` | Request succeeded |
| `201` | `201000` | Resource created |
| `400` | `400001` | Malformed or semantically invalid request |
| `401` | `401001` | Missing, invalid, expired, or revoked authentication |
| `403` | `403001` | Visible operation is forbidden |
| `404` | `404001` | Missing or deliberately concealed resource |
| `405` | `405001` | Method not allowed |
| `409` | `409001` | Current resource or uniqueness state conflicts |
| `409` | `409002` | Submitted resource version is stale |
| `413` | `413001` | Request body is too large |
| `415` | `415001` | Media type is unsupported |
| `422` | `422001` | Request validation failed |
| `429` | `429001` | Request rate is limited |
| `500` | `500000` | Unexpected internal failure |
| `503` | `503001` | A required authority or dependency is unavailable |

Define the registry in one module with an integer enum. Once published, never
reuse a code, renumber it, or give it a new meaning. Internal constant names may
be descriptive, but public routes, OpenAPI metadata, messages, and codes must not
reveal that RBAC is the implementation mechanism. Keep sensitive denial reasons
in internal logs or audit `reason_code`, not in the public `message`.

Reserve the `001` suffix as the generic error for any otherwise-unlisted real
HTTP `4xx` or `5xx` status. A global framework handler must preserve that HTTP
status and may emit `status * 1000 + 1`; it must not collapse an uncommon `418`
or `501` into `400` or `500`. Add a named enum member before application code
needs to branch on a more specific outcome.

```python
from enum import IntEnum


class BusinessCode(IntEnum):
    OK = 200000
    CREATED = 201000
    BAD_REQUEST = 400001
    INVALID_AUTHENTICATION = 401001
    ACCESS_FORBIDDEN = 403001
    NOT_FOUND = 404001
    METHOD_NOT_ALLOWED = 405001
    CONFLICT = 409001
    STALE_RESOURCE_VERSION = 409002
    PAYLOAD_TOO_LARGE = 413001
    UNSUPPORTED_MEDIA_TYPE = 415001
    VALIDATION_FAILED = 422001
    RATE_LIMITED = 429001
    INTERNAL_ERROR = 500000
    SERVICE_UNAVAILABLE = 503001
```

## Response And Pagination Models

Use a generic envelope and a deliberately small page object:

```python
from typing import Generic, TypeVar

from pydantic import UUID4, BaseModel, ConfigDict, Field

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: int = Field(strict=True, ge=100000, le=599999)
    message: str = Field(min_length=1)
    data: T | None
    request_id: UUID4


class PageData(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid", frozen=True)

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
  "code": 200000,
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
  "code": 422001,
  "message": "请求参数校验失败",
  "data": {
    "errors": [
      {"field": "body.name", "message": "Field required"}
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
`rbac_audit_events` for a privileged decision. Also record
`http_status_code` and `business_code` in the completion log. Never log bearer
tokens, cookies, Access Token JTI values, passwords, or request bodies by
default. Follow [Operational logging](operational-logging.md) for the log event
contract and [Audit module](audit-module.md) for durable evidence.

## Rate-Limit And Security-Dependency Responses

The local Redis limiter has two different outcomes. Do not merge them:

| Outcome | HTTP/code | Required headers | Forbidden headers |
| --- | --- | --- | --- |
| A trustworthy Token Bucket decision denies the request | `429` / `429001` | `X-Request-ID`, `Cache-Control: no-store`, integer `Retry-After` | None of the required headers may be omitted |
| Limiter or verification authority is missing, unavailable, times out, or returns malformed state | `503` / `503001` | `X-Request-ID`, `Cache-Control: no-store` | `Retry-After` |

For a Token Bucket decision, both allowed responses and `429` also carry:

```text
RateLimit-Limit: <burst capacity>
RateLimit-Remaining: <whole tokens remaining>
RateLimit-Reset: <seconds until this bucket is full>
```

`RateLimit-Reset` is a relative duration, not a timestamp. A denied bucket adds:

```text
Retry-After: <max(1, ceil(retry_after_ms / 1000))>
```

When several buckets deny atomically, use the one with the longest wait for the
public headers and do not reveal which subject dimension caused the denial. A
login-failure risk signal is not a quota decision: it never returns `429` or
creates `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining`, or
`RateLimit-Reset` by itself.

The bodies retain the ordinary four-field envelope:

```json
{
  "code": 429001,
  "message": "请求过于频繁，请稍后重试",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

```json
{
  "code": 503001,
  "message": "服务暂时不可用",
  "data": null,
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

A `503001` means no trustworthy admission or verification decision was made. It
must fail closed and must not call the protected handler. Do not turn it into a
fake quota denial, expose a Redis/provider error, or guess a retry duration.
When the limiter middleware itself cannot decide, it has no bucket result to
publish. If an earlier layer already admitted a request, its ordinary
`RateLimit-*` headers may remain on a later downstream `503`; those headers
describe the successful earlier admission and never authorize `Retry-After`.

OpenAPI must declare `429001` and its response headers on every route where the
application or controlled gateway actually enforces a limit. It must declare
`503001` where Redis-backed admission or verification can fail closed. Reuse
components to avoid drift, but never advertise these responses on an unprotected
route merely because the registry contains the codes. If browser code reads
these headers cross-origin, expose `X-Request-ID`, `Retry-After`,
`RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` in CORS.

## Resource Version Instead Of A Strong Envelope ETag

The response body's `request_id` changes on every request. Therefore the entire
JSON representation is byte-different on every response and cannot truthfully
share a stable strong `ETag` based only on resource state.

For role concurrency, return the existing nonnegative `version` inside the role
data. Require `expected_version` in each role information, lifecycle, deletion,
permission, or delegation mutation body. After the global guard and canonical
rows are locked and the actor and affected authority are reloaded, first perform
the complete authorization and hierarchy decision and only then compare the
submitted strict JSON integer to the current `roles.version`. This order prevents
an unauthorized actor from learning the current version through a `403`/`409`
oracle. A mismatch after authorization returns HTTP `409` with business code
`409002`; no mutation, version increment, allowed audit, or outbox row may commit.

```json
{
  "name": "Operations",
  "expected_version": 7
}
```

```json
{
  "code": 409002,
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
`assigned_role_ids` through the actor's read-visibility predicate while retaining
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
- Use `400001` for a structurally valid request whose requested operation is
  semantically invalid; reserve `422001` for schema, path, query, and body
  validation failures.
- Error handlers for domain errors, validation, framework HTTP errors, and
  unexpected exceptions all use the envelope and server request ID.
- Authentication failures use one public `401001` result to avoid distinguishing
  missing, expired, revoked, or malformed credentials. Include
  `WWW-Authenticate: Bearer`.
- Use generic `403001` and `404001` messages where extra detail would disclose a
  protected resource, tier, role, or permission.
- A `429` from a downstream probe or other explicitly rate-limited operation is
  not rewritten as authentication, authorization, or connectivity failure.
- A local limiter `429001` and limiter/verification `503001` follow the exact
  header and fail-closed contract above. In particular, a dependency `503001`
  never carries `Retry-After`.
- A successful create uses HTTP `201` and `201000`; ordinary reads and commands
  use HTTP `200` and `200000` unless the client needs another registered success
  distinction.
- The frontend branches on HTTP status and numeric `code`, never localized
  `message` text.
- Declare `X-Request-ID` as a UUID response header on every documented success
  and error response. Declare `413001`, `415001`, or `429001` for an endpoint
  only when the application or its controlled gateway actually enforces the
  matching body-size, media-type, or rate-limit behavior with this envelope.

## Verification

Test the observable contract rather than only model definitions:

- success, create, domain error, validation error, unknown route, unsupported
  method, authentication failure, dependency outage, uncommon framework error,
  and unexpected failure all use the original correct HTTP status and matching
  six-digit integer code;
- every ordinary JSON body has exactly `code`, `message`, `data`, and
  `request_id`, and the header/body request IDs are equal UUIDv4 values;
- a caller-supplied request ID is not adopted as the server ID;
- pagination defaults, maximum size, filtered `total`, deterministic ordering,
  empty pages, and the absence of extra pagination metadata are covered;
- stale `expected_version` returns `409002` and cannot write domain rows, audit
  success, versions, cache invalidations, or outbox records;
- an unauthorized stale write returns its authorization failure rather than
  `409002`, and non-integer versions such as strings, floats, and booleans return
  `422001`;
- successful role and user administration writes return the immutable
  in-transaction snapshot without a post-commit query, and nested assigned-role
  IDs reveal only roles visible to the caller;
- logs and privileged audit rows use the response request ID without recording
  credentials, Token/JTI values, or secret request fields; and
- local quota denial has the documented `429001` limit headers and rounded-up
  `Retry-After`, while Redis/verification `503001` omits `Retry-After` and cannot
  invoke protected logic; a middleware-owned outage invents no bucket result;
  and
- OpenAPI documents the closed envelope and page schemas, numeric code, UUID
  request ID header, actual error statuses and rate-limit headers, and required strict
  `expected_version` fields instead of the framework's default error shape.

The bundled PostgreSQL asset demonstrates this contract. When adapting it,
preserve the target project's naming and localization while retaining the wire
invariants above.
