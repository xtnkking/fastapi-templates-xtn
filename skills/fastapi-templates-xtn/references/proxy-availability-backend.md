# Proxy Availability Backend And Cache

Read [the shared contract](proxy-availability-detection.md) first. Use this file
for the FastAPI route, outbound transport, PostgreSQL snapshot/version boundary,
Redis latest-result cache, and list hydration. Preserve the repository's service,
HTTP-client, encryption, and Redis abstractions when they can enforce the same
invariants.

## HTTPX Transport

For HTTPX 0.28, use the singular `proxy=` parameter and `trust_env=False`.
Support only protocols proven with the installed transport. The baseline below
supports HTTP and TLS-to-proxy connections commonly stored as `https`. Enable
SOCKS5 only with the pinned SOCKS extra and real tests for remote DNS,
authentication, and error mapping. Reject SOCKS4 or unknown protocols; never
silently reinterpret one as HTTP.

Keep credentials separate from the URL with `httpx.Proxy(..., auth=...)`.
Decrypt the password immediately before client construction, use a non-repr
snapshot, and discard the snapshot after the client closes. Credentials sent to
an `http` proxy are not transport-confidential; use a tested TLS-to-proxy setup
or an isolated trusted network when that matters.

The caller must validate the stored proxy destination before invoking this
example. `_build_httpx_proxy()` validates shape but is not an SSRF defense.

```python
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from datetime import UTC, datetime
from time import perf_counter_ns
from typing import Any

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .schemas import ProxyCheckFailure, ProxyCheckSuccess


CHECK_URL = "http://ip-api.com/json/?lang=zh-CN"
TOTAL_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 64 * 1024
SUPPORTED_PROTOCOLS = {
    "http": "http",
    "https": "https",
}


class ProxyConnection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    protocol: str = Field(min_length=1, max_length=16, repr=False)
    host: str = Field(min_length=1, max_length=253, repr=False)
    port: int = Field(ge=1, le=65535, repr=False)
    username: str | None = Field(default=None, max_length=512, repr=False)
    password: SecretStr | None = Field(default=None, repr=False)

    @field_validator("protocol", "host", "username")
    @classmethod
    def text_is_utf8(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise ValueError("invalid text encoding") from None
        return value

    @model_validator(mode="after")
    def credentials_are_complete(self) -> ProxyConnection:
        if (self.username is None) != (self.password is None):
            raise ValueError("incomplete proxy credentials")
        if self.password is not None:
            password = self.password.get_secret_value()
            try:
                encoded = password.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise ValueError("invalid secret encoding") from None
            if len(encoded) > 4096:
                raise ValueError("proxy password is too long")
        return self


class InvalidProxyConfiguration(ValueError):
    pass


class ResponseTooLarge(ValueError):
    pass


def validate_connection_snapshot(data: dict[str, object]) -> ProxyConnection:
    try:
        return ProxyConnection.model_validate(data, strict=True)
    except ValidationError:
        raise InvalidProxyConfiguration("invalid_connection") from None


class IpApiPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str = Field(max_length=16)
    query: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=128)
    country_code: str | None = Field(
        default=None,
        validation_alias="countryCode",
        max_length=2,
    )
    region: str | None = Field(
        default=None,
        validation_alias="regionName",
        max_length=128,
    )
    city: str | None = Field(default=None, max_length=128)


def _now() -> datetime:
    return datetime.now(UTC)


def _failure(message: str) -> ProxyCheckFailure:
    return ProxyCheckFailure(message=message, updated_at=_now())


def _build_httpx_proxy(connection: ProxyConnection) -> httpx.Proxy:
    protocol = connection.protocol.strip().lower()
    scheme = SUPPORTED_PROTOCOLS.get(protocol)
    host = connection.host.strip()
    if scheme is None:
        raise InvalidProxyConfiguration("unsupported_protocol")
    if (
        not host
        or any(character in host for character in "/\\?#@")
        or any(ord(character) < 33 or ord(character) == 127 for character in host)
    ):
        raise InvalidProxyConfiguration("invalid_host")
    if not 1 <= connection.port <= 65535:
        raise InvalidProxyConfiguration("invalid_port")

    has_username = connection.username is not None
    has_password = connection.password is not None
    if has_username != has_password:
        raise InvalidProxyConfiguration("incomplete_credentials")

    auth = None
    if connection.username is not None and connection.password is not None:
        auth = (
            connection.username,
            connection.password.get_secret_value(),
        )

    try:
        proxy_url = httpx.URL(scheme=scheme, host=host, port=connection.port)
        return httpx.Proxy(proxy_url, auth=auth)
    except (httpx.InvalidURL, ValueError):
        raise InvalidProxyConfiguration("invalid_url") from None


def _has_dns_cause(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, socket.gaierror):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


async def _read_limited_json(response: httpx.Response) -> Any:
    body = bytearray()
    async for chunk in response.aiter_raw():
        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge
        body.extend(chunk)

    def reject_nonstandard_number(_value: str) -> None:
        raise ValueError("nonstandard JSON number")

    return json.loads(
        bytes(body),
        parse_constant=reject_nonstandard_number,
    )


async def detect_proxy(
    connection: ProxyConnection,
) -> ProxyCheckSuccess | ProxyCheckFailure:
    try:
        configured_proxy = _build_httpx_proxy(connection)
    except InvalidProxyConfiguration as error:
        message = (
            "不支持的代理协议"
            if error.args == ("unsupported_protocol",)
            else "代理配置无效"
        )
        return _failure(message)

    try:
        async with httpx.AsyncClient(
            proxy=configured_proxy,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(TOTAL_TIMEOUT_SECONDS),
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=0,
            ),
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        ) as client:
            started_ns = perf_counter_ns()
            async with asyncio.timeout(TOTAL_TIMEOUT_SECONDS):
                async with client.stream("GET", CHECK_URL) as response:
                    if response.status_code == 429:
                        return _failure("检测服务请求频率受限")
                    if response.status_code == 407:
                        return _failure("代理认证失败")
                    if response.status_code != 200:
                        return _failure(
                            f"检测服务返回 HTTP {response.status_code}"
                        )
                    content_encoding = response.headers.get(
                        "Content-Encoding",
                        "identity",
                    ).strip().lower()
                    if content_encoding not in {"", "identity"}:
                        return _failure("检测服务响应格式无效")
                    try:
                        payload = await _read_limited_json(response)
                    except ResponseTooLarge:
                        return _failure("检测服务响应数据过大")
                    except (ValueError, RecursionError, UnicodeDecodeError):
                        return _failure("检测服务返回的数据不是有效 JSON")

                try:
                    ip_api = IpApiPayload.model_validate(payload)
                except ValidationError:
                    return _failure("检测服务响应格式无效")

                if ip_api.status != "success":
                    return _failure("检测服务返回失败")
                if ip_api.query is None or not ip_api.query.strip():
                    return _failure("检测服务响应缺少出口 IP")

                try:
                    exit_ip = str(ipaddress.ip_address(ip_api.query.strip()))
                except ValueError:
                    return _failure("检测服务响应包含无效出口 IP")

                latency_ms = max(
                    0,
                    (perf_counter_ns() - started_ns) // 1_000_000,
                )
                return ProxyCheckSuccess(
                    latency_ms=latency_ms,
                    ip_address=exit_ip,
                    country=ip_api.country or None,
                    country_code=ip_api.country_code or None,
                    region=ip_api.region or None,
                    city=ip_api.city or None,
                    updated_at=_now(),
                )
    except (TimeoutError, httpx.TimeoutException):
        return _failure("代理检测超时")
    except httpx.ProxyError:
        return _failure("代理连接失败")
    except httpx.ConnectError as error:
        return _failure(
            "代理地址解析失败" if _has_dns_cause(error) else "代理连接失败"
        )
    except httpx.HTTPError:
        return _failure("代理请求失败")
```

The outer `asyncio.timeout()` is the total wall-clock deadline through body
reading, JSON decoding, schema validation, and exit-IP validation. HTTPX also
bounds individual transport operations. Client cleanup and cache persistence are
outside measured latency. Requesting identity encoding, rejecting another
`Content-Encoding`, and limiting `aiter_raw()` avoids automatic decompression
before the 64 KiB bound and keeps synchronous parsing work bounded.

Test exception mapping against the pinned client. A `407` is the reliable HTTP
proxy authentication signal. A SOCKS adapter must expose a typed authentication
failure that can map safely; otherwise leave that protocol unsupported. Never
parse exception text for a public response.

## Outbound Destination Policy

The target URL is constant, but the stored proxy host is still a caller-managed
outbound destination. Before decrypting credentials or constructing the client:

1. Validate a bare hostname or IP and a port in `1..65535`; reject URL syntax,
   userinfo, paths, fragments, control characters, and ambiguous encodings.
2. Resolve all A and AAAA records with a bounded async resolver. Normalize an
   IPv4-mapped IPv6 address to IPv4, then require every result to be globally
   routable (`ipaddress.ip_address(value).is_global`). This also rejects ranges
   such as carrier-grade NAT that are neither `is_private` nor `is_reserved`.
   Independently deny known cloud metadata and deployment control-plane ranges.
3. A product that intentionally uses private proxies needs an explicit narrow
   network allowlist and preferably an isolated worker. Never add a blanket
   `allow_private=true` bypass.
4. Enforce the same rule with deployment egress firewall or network policy.
   Application DNS validation alone cannot close DNS-rebinding races.

An invalid protocol/host/port/credential shape is a completed safe diagnostic
failure and is cached. A syntactically valid destination forbidden by network
policy is instead a stable application `422`, for example
`proxy_destination_not_allowed`; it makes no HTTP-client call and is not cached.

## Service And Route Boundary

Do not keep a PostgreSQL transaction, ORM object, authorization lock, or database
connection checked out during the external request. Use this sequence:

1. Authenticate, resolve tenant scope, and require `proxies:check`.
2. Load by `(tenant_id, proxy_id)` and copy protocol, host, port, username,
   encrypted credential/secret reference, and monotonically increasing
   `connection_version`; finish the database read.
3. Strictly validate bounded protocol, host, port, and username values without
   coercion, then apply destination policy. A forbidden destination returns
   `422`; retain a safe result for invalid stored connection shape.
4. `INCR proxy:latency:sequence:{proxy_id}` to claim the attempt before any
   outbound request. If Redis is unavailable, return `503`; do not perform a
   request whose required result cannot be persisted.
5. For valid non-secret data, decode decrypted bytes as strict UTF-8 into a
   short-lived `SecretStr`, construct the strict `ProxyConnection`, and call the
   detector under the server-side
   concurrency bound. A typed malformed-ciphertext result is invalid stored
   configuration; a KMS/secret-store timeout or outage is infrastructure `503`
   and is not cached. For invalid stored data, use its safe `success=false`
   result without opening a client.
6. Open a short finalization transaction and lock the tenant-scoped proxy row
   with PostgreSQL `FOR SHARE`, or the project's equivalent lock that conflicts
   with connection edits and deletion. Re-read `connection_version`. If the row
   disappeared or changed, do not cache or return the stale result; use the
   concealed `404` or stable `409 proxy_changed_during_check`.
7. While retaining that short row lock, atomically persist only if this is still
   the most recently started attempt and no newer configuration is cached. If
   superseded, return stable `409 proxy_check_superseded`. Retry an ambiguous
   Redis write only with the exact same attempt and serialized result; never
   repeat the outbound request. Bound Redis I/O so the row lock cannot be held
   indefinitely. If retry and read-back cannot resolve whether Redis committed,
   return `503 cache_write_outcome_unknown` and make no claim about the stored
   value, then release the transaction.

The route exposes only the shared discriminated result:

```python
from uuid import UUID

from fastapi import APIRouter

from .dependencies import ProxyCheckAccess, ProxyAvailabilityServiceDependency
from .schemas import ProxyCheckFailure, ProxyCheckResponse, ProxyCheckSuccess


router = APIRouter(prefix="/api/v1/proxies", tags=["proxies"])


@router.post(
    "/{proxy_id}/availability-check",
    response_model=ProxyCheckResponse,
)
async def check_proxy_availability(
    proxy_id: UUID,
    access: ProxyCheckAccess,
    service: ProxyAvailabilityServiceDependency,
) -> ProxyCheckSuccess | ProxyCheckFailure:
    return await service.check(
        tenant_id=access.tenant.id,
        proxy_id=proxy_id,
    )
```

Apply a server-side per-actor or per-tenant rate limit and a bounded outbound
concurrency budget. Five browser workers are not a global capacity limit. Bound
queue wait and release semaphore slots in `finally`; do not retry provider `429`,
timeouts, or connection failures inside one explicit check.

## Redis Latest-Result Cache

Use these two same-slot keys for each globally unique UUIDv4 proxy:

```text
proxy:latency:{proxy_id}
proxy:latency:sequence:{proxy_id}
```

The braces are Redis Cluster hash tags, so one proxy's conditional-write script
can access both keys. A list page spans many tags, so native Redis Cluster cannot
run one cross-slot `MGET`. The required list behavior therefore needs
standalone/Sentinel Redis or an existing cluster-aware wrapper that groups keys
by slot and performs bounded `MGET` fan-out. Surface an unsupported topology
instead of silently adding N+1 `GET` calls or changing the required result key.

Centralize key construction so both keys retain the same literal hash tag:

```python
from uuid import UUID


def proxy_check_keys(proxy_id: UUID) -> tuple[str, str]:
    tag = str(proxy_id)
    return (
        f"proxy:latency:{{{tag}}}",
        f"proxy:latency:sequence:{{{tag}}}",
    )
```

The complete JSON contains the public result plus internal `tenant_id`,
`connection_version`, and `attempt_sequence`. A success resembles:

```json
{
  "success": true,
  "latency_ms": 320,
  "ip_address": "1.2.3.4",
  "country": "美国",
  "country_code": "US",
  "region": "California",
  "city": "Los Angeles",
  "message": "代理连接成功",
  "updated_at": "2026-09-06T08:30:00Z",
  "tenant_id": "6a88fb2c-5f7c-4f5e-a457-98ad5ed0d8f3",
  "connection_version": 7,
  "attempt_sequence": 12
}
```

A failure contains only `success`, `message`, `updated_at`, and internal
metadata. Preserve absent optional success locations as explicit `null`. Use the
repository's canonical JSON encoder and one `SET` without `EX`, `PX`, `EXAT`, or
`PXAT`; `TTL` is `-1`. The sequence key also has no TTL. Never reuse a deleted
proxy UUID.

Validate cache JSON with an internal union, compare metadata, then explicitly
strip it into the public model. Do not feed internal fields to public models with
`extra="forbid"`:

```python
from typing import Annotated
from uuid import UUID

from pydantic import Field, TypeAdapter

from .schemas import ProxyCheckFailure, ProxyCheckSuccess


REDIS_LUA_SAFE_INTEGER_MAX = 9_007_199_254_740_991


class CachedProxyCheckSuccess(ProxyCheckSuccess):
    tenant_id: UUID
    connection_version: int = Field(
        ge=0,
        le=REDIS_LUA_SAFE_INTEGER_MAX,
    )
    attempt_sequence: int = Field(
        ge=1,
        le=REDIS_LUA_SAFE_INTEGER_MAX,
    )


class CachedProxyCheckFailure(ProxyCheckFailure):
    tenant_id: UUID
    connection_version: int = Field(
        ge=0,
        le=REDIS_LUA_SAFE_INTEGER_MAX,
    )
    attempt_sequence: int = Field(
        ge=1,
        le=REDIS_LUA_SAFE_INTEGER_MAX,
    )


CachedProxyCheck = Annotated[
    CachedProxyCheckSuccess | CachedProxyCheckFailure,
    Field(discriminator="success"),
]
CACHED_CHECK_ADAPTER = TypeAdapter(CachedProxyCheck)


def to_public_check(
    cached: CachedProxyCheckSuccess | CachedProxyCheckFailure,
) -> ProxyCheckSuccess | ProxyCheckFailure:
    data = cached.model_dump(
        exclude={"tenant_id", "connection_version", "attempt_sequence"}
    )
    if cached.success:
        return ProxyCheckSuccess.model_validate(data)
    return ProxyCheckFailure.model_validate(data)
```

Use a Lua compare-and-set so a later-started check wins even if an older request
finishes later. The sequence watermark check matters: comparing only the result
JSON would still let an older request write before the newer request completes.

```lua
local MAX_SAFE_INTEGER = 9007199254740991

local function is_integer_in_range(value, minimum)
  return value
    and value >= minimum
    and value <= MAX_SAFE_INTEGER
    and value == math.floor(value)
end

local new_version = tonumber(ARGV[1])
local new_attempt = tonumber(ARGV[2])
if not is_integer_in_range(new_version, 0)
  or not is_integer_in_range(new_attempt, 1) then
  return redis.error_reply("invalid proxy-check cache metadata")
end

local latest_attempt = tonumber(redis.call("GET", KEYS[2]))
if not is_integer_in_range(latest_attempt, 1) then
  return redis.error_reply("missing proxy-check attempt sequence")
end
if latest_attempt ~= new_attempt then
  return 0
end

local candidate_ok, candidate = pcall(cjson.decode, ARGV[3])
if not candidate_ok or type(candidate) ~= "table" then
  return redis.error_reply("invalid proxy-check candidate JSON")
end
local candidate_version = tonumber(candidate["connection_version"])
local candidate_attempt = tonumber(candidate["attempt_sequence"])
if not is_integer_in_range(candidate_version, 0)
  or not is_integer_in_range(candidate_attempt, 1)
  or candidate_version ~= new_version
  or candidate_attempt ~= new_attempt then
  return redis.error_reply("proxy-check candidate metadata mismatch")
end

local existing = redis.call("GET", KEYS[1])
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if ok and type(decoded) == "table" then
    local old_version = tonumber(decoded["connection_version"])
    local old_attempt = tonumber(decoded["attempt_sequence"])
    if is_integer_in_range(old_version, 0)
      and is_integer_in_range(old_attempt, 1) then
      if old_version > new_version then
        return 0
      end
      if old_version == new_version and old_attempt > new_attempt then
        return 0
      end
    end
  end
end

redis.call("SET", KEYS[1], ARGV[3])
return 1
```

Pass the result key and sequence key as `KEYS[1..2]`, then version, claimed
sequence, and full JSON as `ARGV[1..3]`. Corrupt existing JSON or nonnumeric
metadata is repaired by a valid current write. Generate all three arguments from
one validated `CachedProxyCheck`; never accept independent caller values. The
script also verifies that JSON metadata equals its comparison arguments. A `0`
is superseded, not a proxy failure. Re-reading PostgreSQL before the script and
comparing versions during list hydration remain necessary because PostgreSQL and
Redis are not one atomic transaction.

Redis Lua numbers are IEEE-754 doubles. Constrain PostgreSQL
`connection_version`, the `INCR` result, Pydantic cache models, and every script
argument to `0..2^53-1` (attempts start at `1`). If `INCR` ever exceeds the safe
range, fail before outbound I/O and repair coordination only after proving that
no check is in flight; do not reset the counter opportunistically.

Redis acknowledgement loss makes the write outcome ambiguous: the script may
have completed even when the client saw an I/O error. Retry the script a bounded
number of times with the same keys, attempt number, version, and byte-identical
JSON; this is idempotent. If it still errors, use one same-slot Lua read-back that
atomically reads both the result and sequence watermark:

```lua
local MAX_SAFE_INTEGER = 9007199254740991

local function is_integer_in_range(value, minimum)
  return value
    and value >= minimum
    and value <= MAX_SAFE_INTEGER
    and value == math.floor(value)
end

local expected_attempt = tonumber(ARGV[1])
if not is_integer_in_range(expected_attempt, 1) then
  return redis.error_reply("invalid expected attempt")
end

local latest_attempt = tonumber(redis.call("GET", KEYS[2]))
if not is_integer_in_range(latest_attempt, 1) then
  return -1
end
if latest_attempt > expected_attempt then
  return 2
end
if latest_attempt ~= expected_attempt then
  return -1
end

local stored = redis.call("GET", KEYS[1])
if stored == ARGV[2] then
  return 1
end
return 0
```

Pass the expected attempt and byte-identical JSON as `ARGV[1..2]`. Result `1`
confirms success, `2` is `409 proxy_check_superseded`, and `0`/`-1` is a definite
unconfirmed write failure after retries. If the atomic read-back itself remains
unavailable, return `503 cache_write_outcome_unknown`; do not claim the old value
was preserved and do not launch another proxy request. Checking only the result
JSON is insufficient because a newer attempt may already have advanced the
watermark without writing its result yet.

Every connection-field edit takes the same conflicting proxy-row lock, increments
`connection_version`, and enqueues a cache-invalidation outbox row in the same
database transaction. The check finalizer's short row lock makes the version
recheck and Redis write indivisible with respect to that database writer: either
the check writes before the edit, or it observes the new version and cannot write.

After commit, the idempotent outbox handler conditionally deletes only a malformed
cache value or one whose `connection_version` is lower than the committed edit
version. Perform GET, version comparison, and optional DEL in one Lua script, not
as a client-side read followed by delete:

```lua
local MAX_SAFE_INTEGER = 9007199254740991

local function is_integer_in_range(value, minimum)
  return value
    and value >= minimum
    and value <= MAX_SAFE_INTEGER
    and value == math.floor(value)
end

local committed_version = tonumber(ARGV[1])
if not is_integer_in_range(committed_version, 0) then
  return redis.error_reply("invalid committed connection version")
end

local existing = redis.call("GET", KEYS[1])
if not existing then
  return 0
end

local ok, decoded = pcall(cjson.decode, existing)
local cached_version = nil
if ok and type(decoded) == "table" then
  cached_version = tonumber(decoded["connection_version"])
end

if not is_integer_in_range(cached_version, 0)
  or cached_version < committed_version then
  redis.call("DEL", KEYS[1])
  return 1
end
return 0
```

It must not unconditionally advance the attempt sequence or delete an equal/newer
version: a new-version check can legitimately finish before delayed outbox
delivery. List-time version comparison is the correctness fallback while cleanup
is pending. Proxy and tenant deletion instead enqueue durable cleanup whose
handler removes result and sequence keys together with one `DEL` before marking
the outbox row delivered.

For each authorized list page:

1. Query PostgreSQL with tenant, search, filter, deterministic order, and
   pagination predicates.
2. Build result keys only for proxy IDs in that returned page.
3. Issue one `MGET` through the supported topology path. Validate each internal
   object, require matching `tenant_id` and `connection_version`, strip internal
   metadata, and merge `availability_check` by proxy ID.
4. Treat missing, malformed, or version-mismatched values as `null` without
   invoking the detector.

On a Redis read outage, prefer keeping the authorized list available with an
envelope flag such as `availability_cache_available=false`; the UI then shows
`检测结果暂不可用`. If the existing envelope cannot represent degradation, return
a cache-specific `503` rather than claiming `未检测`. A definite or unresolved
Redis write failure from a check is a distinct `503`; in an unresolved case the
new value may already exist, so the frontend should reload rather than infer
either the old or new snapshot.

## Logging And Abuse Controls

- Log stable event names, tenant ID, proxy UUID, duration category, outcome code,
  and request correlation ID only. Never log the connection object, stored host,
  username, password, `httpx.Proxy`, proxy URL, raw exception, or upstream body.
- Disable or redact HTTPX/httpcore debug logging and tracing hooks that can expose
  proxy authorization. Test raw and percent-encoded credentials plus base64
  `Proxy-Authorization` absence in telemetry.
- Create only minimal outbound headers. Never forward inbound `Authorization`,
  `Cookie`, tracing baggage, or arbitrary user headers.
- Authorize before proxy lookup and decrypt only after destination approval. Do
  not reveal whether a cross-tenant UUID exists.
- Rate-limit checks per actor and tenant, and use a process/distributed capacity
  control appropriate to deployment. Audit initiation only when needed, without
  credentials. This display diagnostic is not an RBAC control-plane write.
- Treat no-TTL exit-IP and location data as retained operational data. Document
  access and deletion, and do not copy it into indefinite logs or analytics.
