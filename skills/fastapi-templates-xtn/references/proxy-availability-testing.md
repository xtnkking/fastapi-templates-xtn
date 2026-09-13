# Proxy Availability Verification

Read [the shared contract](proxy-availability-detection.md) first and load the
[backend](proxy-availability-backend.md) or
[frontend](proxy-availability-frontend.md) reference for the surface under test.
Use the repository's existing test stack. Controlled fixtures, not live provider
behavior or timing sleeps, must prove the invariants.

## Prove Real Proxy Routing

A mocked HTTP call can verify parsing but cannot prove that traffic used the
selected proxy. Build an isolated integration topology:

1. Put a mock `ip-api` upstream on a test network the application cannot route to
   directly.
2. Put a real forward proxy between the application and that network. Assert at
   the proxy that it receives the absolute-form request and at the upstream that
   the source is the proxy.
3. Return a synthetic successful payload whose `query` is a known fixture IP.
4. Set misleading environment proxy variables and `NO_PROXY=ip-api.com`; prove
   the selected stored proxy still receives the request.
5. Disconnect the selected proxy and prove the request fails instead of using
   server egress.

Use a separate fixture for every supported proxy protocol and authentication
mode. Keep live `ip-api.com` checks opt-in because they are rate-limited,
nondeterministic, and disclose test traffic.

## Backend Matrix

Cover these behaviors with unit, integration, and security tests as appropriate:

- Application-level `proxies:check`, concealed-resource behavior, canonical
  non-sequential proxy IDs under the selected profile, and request bodies or
  query values unable to replace the fixed target.
- Exact `GET http://ip-api.com/json/?lang=zh-CN`, redirect refusal, selected-proxy
  routing, environment-proxy isolation, no direct fallback, and minimal outbound
  headers.
- Destination rejection for IPv4/IPv6 non-global addresses, IPv4-mapped IPv6,
  carrier-grade NAT, metadata, control-plane ranges, and mixed multi-address DNS,
  plus the explicit private-network allowlist path. Policy rejection opens no
  client and writes no diagnostic cache value.
- Successful field mapping, valid JSON with invalid shape, explicit `null`
  optional locations, valid IPv4/IPv6 `query`, invalid or missing `query`, and
  latency measured only after parsing and schema validation.
- `Accept-Encoding: identity`, rejection of encoded responses, raw streamed-body
  enforcement of the 64 KiB ceiling, and a compressed expansion fixture that
  cannot consume unbounded memory before the size check.
- Deeply nested JSON, over-limit integer literals, and nonstandard numeric
  constants map to a safe parse failure rather than escaping as a server error.
- Connection refusal, proxy-host DNS failure, `407`, total timeout, unsupported
  protocol, invalid connection shape, other non-`200`, exact `429` message with
  no retry, `status=fail`, malformed JSON, and oversized response.
- Strict connection snapshots reject null/wrong-type/overlong protocol, host,
  port, username, and secret combinations as safe configuration failures. Typed
  malformed ciphertext, strict UTF-8 decode failure, and isolated surrogates are
  distinct from KMS/secret-store outage `503`.
- The ten-second outer deadline covering response streaming and parsing; no
  database connection or transaction remains held during that wait.
- Credential decryption only after authorization and destination approval.
  Assert raw and percent-encoded username/password, base64 proxy authorization,
  proxy host, and complete proxy URL are absent from responses, cache documents,
  exception chains exposed by the app, HTTPX/httpcore logs, traces, metrics,
  audits, and browser-visible data.
- Server rate/concurrency limits with barriers proving the configured peak,
  bounded queue wait, and slot release after success, domain failure,
  cancellation, and unexpected exceptions.

## Redis And Race Matrix

- Each completed diagnostic performs one full-result conditional write; a later
  explicit check performs real I/O and replaces the earlier success or failure.
- Result and sequence keys have `TTL=-1`; proxy deletion commits a durable
  cleanup outbox row, whose idempotent handler deletes both keys in one command.
  Redis failure is retried, and a deleted proxy ID is never reused.
- Every connection field change increments `connection_version`. A list ignores
  malformed or version-mismatched cache objects.
- Check finalization briefly holds a proxy-row lock that conflicts with edit and
  delete writers. Test both commit orders: the old result is written before the
  edit or rejected after observing its new `connection_version`, never written
  through the version-check/cache-write gap.
- A delayed edit-outbox Lua handler atomically compares and deletes only malformed
  or lower-version cache data. Test both interleavings with a concurrent
  new-version write; delayed invalidation always preserves the new value. Proxy
  deletion removes result and sequence keys together.
- Corrupt JSON, scalar JSON, and nonnumeric metadata are repaired by the next
  valid current write rather than permanently breaking compare-and-set.
- Cache models and all Lua scripts reject negative, fractional, and greater-than
  `2^53-1` versions/sequences. Candidate JSON whose metadata differs from CAS
  arguments is rejected without modifying Redis.
- For the same version, use barriers to start attempt 1 then attempt 2 and finish
  them in reverse order. Attempt 1 cannot overwrite attempt 2 and receives
  business code `409004` rather than returning its stale local observation.
- Start attempt 1, then claim attempt 2 without completing it; prove the attempt
  watermark prevents attempt 1 from writing as the latest result.
- Edit the proxy during a request; its old-version completion cannot replace a
  newer-version cache document or appear during list hydration.
- Test Redis failure before execution and acknowledgement loss after `EVAL` has
  executed. Bounded byte-identical retry and an atomic result-plus-watermark
  read-back resolve a committed value. If a later attempt only advances the
  watermark, the older ambiguous caller is superseded rather than falsely
  successful. An unresolved read returns distinct
  business code `503002` without claiming which value exists or
  repeating the outbound request.
- Redis read failure returns the documented cache-specific HTTP `503` / business
  code `503002`, never a fifth envelope flag or `未检测`.
- A list page builds keys only for authorized returned rows, uses one supported
  `MGET` path, maps values by proxy ID, and makes zero detector calls.
- Exercise the declared standalone/Sentinel or cluster-aware grouped-`MGET`
  path against the deployment topology. Assert no N+1 `GET` fallback and no
  unhandled cross-slot failure.

## Frontend Matrix

Use controlled deferred promises rather than sleeps:

- A readable cache miss renders `未检测`; degraded cache state renders
  `检测结果暂不可用`; a new failure replaces all older success-only fields.
- Row state cleans up on success, domain `success=false`, and transport failure.
  A completed click can be run again and sends another request.
- A row receiving business code `503002` performs one cache-only list
  reload and never repeats detection; a batch waits for its single final reload.
- Selected IDs bypass all-page collection. With no selection, 450 rows fetch as
  200, 200, and 50 and every deduplicated ID is checked.
- The list response contains only `items`, `page`, `page_size`, and `total`; the
  client derives the page count and does not require extra pagination metadata.
- Empty and product-maximum target sets do not leave the batch lock stuck. If
  cancellation exists, unstarted work is not counted as proxy failure.
- Instrument active promises and prove the peak never exceeds five; releasing
  any promise immediately starts the next queued item.
- One rejected item does not stop queued work. Final `total`, `completed`,
  `succeeded`, and `failed` counts are exact.
- Inject one progress-update exception and prove all active/queued workers settle
  before the scheduler unlocks; a new row or batch run cannot overlap them.
- Duplicate batch starts are rejected synchronously. A running row blocks batch
  start, and a claimed batch blocks row requests before rendered state updates.
- Filters and selection are frozen for the run, pagination order is stable, and
  an inconsistent page number or early empty page fails safely before an
  unbounded loop. An older list response cannot overwrite a newer row result.
- Completion produces one final list reload. Mount, refresh, pagination, sort,
  search, filter changes, and query-library retries produce zero check calls.
- Request payloads and browser logs contain proxy IDs only, with no username,
  password, host, proxy authorization, or complete proxy URL.

Run formatter, lint, type checks, backend tests, frontend unit/component tests,
and the controlled-proxy integration test. Report every live provider, Redis
topology, browser, or proxy-protocol path not exercised. Never claim a mocked
HTTP client proves use of the configured proxy.
