# Proxy Availability Detection

Read this reference only when the request explicitly needs proxy availability,
latency, exit-IP diagnostics, cached check results, or single/batch checks. The
existence of a proxy model or ordinary proxy CRUD is not a loading condition.
Do not add proxy management to an unrelated FastAPI or RBAC service.

Search terms: `proxy check`, `availability`, `latency`, `exit IP`, `ip-api`,
`connection_version`, `MGET`, `worker pool`.

## Load Only The Needed Detail

Start here, then load only the implementation surface being changed:

| Task | Read next |
| --- | --- |
| FastAPI route, HTTPX transport, proxy credentials, PostgreSQL snapshot, Redis write, or list hydration | [Backend and cache](proxy-availability-backend.md) |
| Row action, cached-result display, cross-page target collection, counters, or five-worker batch | [Frontend](proxy-availability-frontend.md) |
| Parser/unit tests, real routing proof, Redis races, security checks, or UI acceptance tests | [Verification](proxy-availability-testing.md) |

For an end-to-end implementation, read backend, frontend, and verification in
that order. A backend-only change does not need the frontend example; a
frontend-only change does not need HTTPX or Lua. Load this Skill's migration
reference only when adding `connection_version`, changing proxy identifiers, or
seeding `proxies:check`. Load the general RBAC references only when the task also
changes authorization policy.

## Inspect The Existing Product First

Inspect the proxy model and credential-encryption boundary, access-controlled query,
router and response envelope, service ownership, async HTTP client, Redis
wrapper and topology, list filters and pagination, frontend API/table/query
state, and relevant tests. Preserve intentional boundaries and naming.

The defaults below resolve missing product choices. Adapt route prefixes,
dependency aliases, error envelopes, serialization helpers, and frontend state
APIs when the repository has equivalents. Do not replace established HTTP or
Redis abstractions merely to copy an example.

## Fixed Behavior

Unless the user supplies a conflicting requirement:

- Add `POST /api/v1/proxies/{proxy_id}/availability-check` with no body, adapted
  only to the repository's route naming. The browser sends only a proxy UUID.
- In an RBAC product, require the stable `proxies:check` capability. Query by
  `proxy_id`, apply any independent row policy, and return the same generic `404`
  for missing and deliberately concealed UUIDs.
- Keep `protocol`, `host`, `port`, username, and encrypted password or secret
  reference backend-only. Decrypt only after authorization and outbound-policy
  checks. Neither API returns credentials or a complete proxy URL.
- Send one `GET` to exactly
  `http://ip-api.com/json/?lang=zh-CN`. The target is a backend constant, remains
  HTTP, follows no redirect, and has no automatic retry.
- Force that request through the selected proxy. Disable environment proxies and
  every direct-network fallback. Unsupported protocols fail safely.
- Apply one ten-second wall-clock deadline to connect, response streaming, JSON
  parsing, and validation. Measure successful `latency_ms` with a monotonic clock
  from immediately before the request until validation finishes.
- A completed diagnostic returns HTTP `200` even when `success=false`. Cache all
  completed transport and provider outcomes, including connection, DNS,
  authentication, timeout, `429`, invalid JSON, `status=fail`, unsupported
  protocol, and invalid stored connection data.
- Authentication, authorization, missing resources, an outbound destination
  rejected by security policy, application rate limiting, a configuration race,
  and Redis infrastructure failure are request errors, not proxy observations.
  They keep normal HTTP semantics and are not written as `success=false` cache
  results. This is the sole preflight/infrastructure exception to caching failed
  diagnostics.
- Store the latest completed result at `proxy:latency:{proxy_id}` as one complete
  JSON replacement with no TTL. A later explicit check always performs a new
  request and replaces the prior result when its configuration is still current.
- List, refresh, pagination, search, filter, and sort operations only hydrate
  cached results; they never trigger detection. A healthy cache miss is
  `未检测`; an unavailable cache is `检测结果暂不可用`.
- With selected rows, batch-check exactly the deduplicated selection. Without a
  selection, freeze the active filters and collect every matching ID across
  pages of at most 200. Run at most five checks concurrently; one failure never
  stops the remaining work.

The result is display-only diagnostic data. The HTTP target and an untrusted
proxy can expose or fabricate the exit IP and location, so never use the result
for authorization, resource access, billing, fraud decisions, or proof of trust.
Confirm the provider's current terms, privacy constraints, and rate limits before
production use; do not retry a `429` automatically.

## Public Result Contract

Use a discriminated result and replace it as a whole. A failure must not retain
the IP or latency from an older success. The server supplies `updated_at` in both
the direct response and cached list snapshot.

```python
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class ProxyCheckSuccess(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: Literal[True] = True
    latency_ms: int = Field(ge=0)
    ip_address: str = Field(max_length=64)
    country: str | None = Field(default=None, max_length=128)
    country_code: str | None = Field(default=None, max_length=2)
    region: str | None = Field(default=None, max_length=128)
    city: str | None = Field(default=None, max_length=128)
    message: Literal["代理连接成功"] = "代理连接成功"
    updated_at: datetime


class ProxyCheckFailure(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: Literal[False] = False
    message: str = Field(min_length=1, max_length=160)
    updated_at: datetime


ProxyCheckResponse = Annotated[
    ProxyCheckSuccess | ProxyCheckFailure,
    Field(discriminator="success"),
]
```

Map a successful `ip-api.com` object exactly:

| Response field | Source field |
| --- | --- |
| `ip_address` | `query` |
| `country` | `country` |
| `country_code` | `countryCode` |
| `region` | `regionName` |
| `city` | `city` |

Success requires HTTP `200`, valid JSON object data, `status="success"`, and a
non-empty syntactically valid IP in `query`. Preserve missing optional location
values as explicit `null`; the frontend renders them as `--`.

Use stable localized codes when the product has them. Otherwise use these exact
Chinese messages:

| Condition | Message |
| --- | --- |
| Successful validated response | `代理连接成功` |
| Proxy returned `407` | `代理认证失败` |
| Proxy host DNS failure | `代理地址解析失败` |
| Overall or client timeout | `代理检测超时` |
| Connection failure | `代理连接失败` |
| Unsupported protocol | `不支持的代理协议` |
| Invalid stored connection data | `代理配置无效` |
| Target returned `429` | `检测服务请求频率受限` |
| Other non-`200` target response | `检测服务返回 HTTP {status_code}` |
| Invalid JSON | `检测服务返回的数据不是有效 JSON` |
| Valid JSON with invalid shape | `检测服务响应格式无效` |
| Response body over the limit | `检测服务响应数据过大` |
| `status="fail"` or another non-success status | `检测服务返回失败` |
| Missing `query` | `检测服务响应缺少出口 IP` |
| Invalid `query` | `检测服务响应包含无效出口 IP` |
| Other client/protocol failure | `代理请求失败` |

Never return `str(exception)`, upstream bodies, stored hosts, usernames,
passwords, `Proxy-Authorization`, or complete proxy URLs. Keep raw transport
details out of API responses, Redis, browser state, logs, traces, metrics, and
audit documents.

## Cross-Boundary Invariants

- Proxy IDs are globally unique random UUIDv4 values. `connection_version` and
  attempt counters may be integers because they are concurrency state, not IDs.
- Increment `connection_version` whenever protocol, host, port, username, or
  password changes. Cache metadata and list hydration must reject stale versions.
- PostgreSQL and Redis are not one ACID boundary. Do not hold a database
  transaction during the network call. During finalization, briefly lock and
  recheck the proxy row through the conditional Redis write, so a connection edit
  cannot race between version validation and cache persistence.
- The exact cache key assumes globally unique IDs. Inspect Redis topology:
  ordinary Redis Cluster cannot issue one cross-slot `MGET` for many differently
  tagged proxy keys without a cluster-aware wrapper.
- No TTL is an explicit retention policy. Remove result and coordination keys
  after proxy deletion, restrict access to exit-IP/location data, and
  do not duplicate it into indefinite telemetry.
