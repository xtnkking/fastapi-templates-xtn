# Operational Logging

Read this reference only for application or access logging, request correlation,
safe exception telemetry, log transport, or operational retention. Durable RBAC
audit is a separate security record; use [Audit module](audit-module.md) for it.

## Non-Negotiable Boundary

Operational logging is best-effort observation. A formatter, handler, queue,
socket, or stdout failure must never change a database commit, authorization
decision, background result, or HTTP response. Route all application-owned log
emission through a non-throwing adapter and test that adapter with failing sinks.
Do not use log delivery as a prerequisite for business success.

Emit one-line JSON only for application-owned events. Use stable event names and
bounded, typed fields. Keep raw request and dependency messages outside this
pipeline because redaction is not a proof that an arbitrary string is safe.

## Request Completion Contract

Implement request observation as pure ASGI middleware around `receive` and
`send`. `BaseHTTPMiddleware` and the return of `call_next` are not final response
boundaries: streaming bodies and response background work may still fail.

Every HTTP request emits exactly one `http.request.completed` event. Record it
only after one of these terminal outcomes is known:

| Outcome | Completion fields |
| --- | --- |
| Final response body was sent | Actual status and business code, `response_started=true`, `response_completed=true`, and `outcome=success` below 400 or `failure` at 4xx/5xx |
| Application failed before response start | Effective status `500`, `response_started=false`, `response_completed=false`, and `outcome=error` |
| Streaming/application failure after response start | The status already sent, `response_started=true`, `response_completed=false`, and `outcome=error` |
| ASGI `send` failed | Whether response start had previously completed, `response_completed=false`, `outcome=error`, and `failure_phase=send` |
| Cancellation or client disconnect prevented completion | The observed response state, `response_completed=false`, `outcome=error`, and a stable cancellation/disconnect phase |
| Application returned without a final body | The observed response state, `response_completed=false`, `outcome=error`, and `failure_phase=response_incomplete` |
| Final body was sent without a successful response start | Unknown status, `response_started=false`, `response_completed=true`, `outcome=error`, and `failure_phase=response_without_start` |

Set `response_started` only after the downstream `send` of
`http.response.start` succeeds. Set `response_completed` only after the final
`http.response.body` with `more_body=false` succeeds. Wrap `receive` so an
observed `http.disconnect` can be represented without logging client data.

An exception after the final response has already been sent, including a
Starlette background-task or cleanup failure, cannot revise what the client
received. Keep the existing completion and emit one separate
`http.request.post_response_failed` event. Never emit a second completion.

Exception handlers prepare responses; they do not emit completion events. A
handled exception is completed only when its final response body is sent. If an
unexpected exception escapes before response start, the ASGI observer records
one effective `500` completion and re-raises it to the framework's server-error
handler. The handler must not record it again. This keeps one completion even
though the fallback response is produced outside ordinary application routing.

The completion event contains only:

- server-generated `request_id`;
- HTTP method and matched route template, never the raw path or query string;
- actual HTTP status and six-digit business code when known;
- monotonic `duration_ms`;
- `outcome`, `response_started`, `response_completed`, `client_disconnected`,
  and an allowlisted `failure_phase` when applicable;
- canonical `actor_user_id` only after full authentication succeeds.

Use `ERROR` for `outcome=error` regardless of a previously sent `2xx` status.
Use `WARNING` for completed `4xx`, `ERROR` for completed `5xx`, and `INFO` for
completed success.

## Authentication Identity Boundary

Do not bind `actor_user_id` after JWT parsing or Redis JTI lookup alone. Set it
only after all required authentication state has succeeded: JWT validation,
the exact Redis active-JTI check, current PostgreSQL user status, and the bound
`users.token_version` comparison. Consequently:

- every authentication failure reported as `401` omits `actor_user_id`;
- a fully authenticated identity denied authorization with `403` may include it;
- logout may correlate by request ID without exposing a user ID if it deliberately
  follows the Redis-only reduced-authority path.

## Safe Exception Telemetry

Default exception logging records only:

- a new non-sequential `error_id` suitable for support correlation;
- `exception_type` and `exception_module`;
- one safe application location expressed as module, function, and line number.

Choose an allowlisted application frame, not simply the deepest traceback frame.
Never record the exception message, `args`, source line, local variables,
absolute file path, raw traceback, chained exception text, or dependency request
URL. Public responses expose only the normal business error contract and, when
useful, the unrelated server request ID.

Classify low-level dependency failures with a small stable vocabulary instead of
copying library messages:

`timeout`, `connection`, `dns`, `tls`, `protocol`, `pool_exhausted`,
`rate_limited`, or `unknown`.

Map from known exception types/statuses at the dependency boundary. Keep the
dependency name and operation as allowlisted identifiers. Do not serialize an
HTTPX request, SQLAlchemy statement, Redis command, URL, DSN, host with
credentials, or exception string.

## Caught And Uncaught Exception Ownership

Give each failure one logging owner:

- Expected domain failures such as validation, missing resources, stale versions,
  authentication failures, and authorization denials use the request completion
  plus durable audit where required. They do not need an exception event or
  traceback.
- A PostgreSQL, Redis, or outbound HTTP boundary that converts a dependency
  exception emits one `dependency.<name>.unavailable` event with allowlisted
  `dependency`, `dependency_operation`, `error_category`, and safe exception
  metadata before returning the public error. Higher layers do not log the same
  exception again.
- Code that catches an unexpected internal exception and continues, retries, or
  substitutes a result must emit one stable operation-failure event at that
  catch boundary. A bare `except Exception: pass` is forbidden. Preserve the
  original exception when re-raising; do not replace it with a logging failure.
- An exception that escapes request processing is owned by the ASGI request
  observer. An exception after the final body is owned by the separate
  post-response event. A detached worker or task is owned by its supervised
  top-level runner.
- Catch `asyncio.CancelledError` only to record lifecycle state or perform bounded
  cleanup, then re-raise it. Do not broadly catch `BaseException` and do not
  convert process termination into an HTTP response.

Startup, shutdown, queue consumers, schedulers, and worker loops also need a
top-level safe failure event because no HTTP completion exists for them. Keep
their retry count, backoff state, job type, and operation as bounded allowlisted
fields; never log payloads or arbitrary job arguments.

## Rate-Limit And Verification Events

The bundled security-admission components use these stable application events:

| Event | Level | Logging owner | Safe event fields |
| --- | --- | --- | --- |
| `rate_limit.denied` | `WARNING` | The middleware or exception handler that converts a valid denial to `429001` | Static `rate_limit_policy`; HTTP/business code when available; server request ID from context |
| `dependency.rate_limit.unavailable` | `ERROR` | The boundary that converts missing, failed, timed-out, or malformed limiter state to `503001` | Static dependency and operation identifiers, optional static policy, safe exception metadata, server request ID |
| `dependency.verification.unavailable` | `ERROR` | The challenge/delivery boundary that converts verification Redis or provider failure to `503001` | Static dependency and operation identifiers, safe exception metadata, server request ID |

A quota denial is an expected security decision, not an exception traceback.
Emit the warning once and let the canonical `http.request.completed` event record
the resulting `429`. A dependency event owns safe exception classification; the
request observer records the `503` completion without serializing the exception
again. Logging failure never changes the denial, dependency response, or whether
protected logic ran.

For these events, never record the raw client IP, account, email, username,
phone, verification target/code, challenge ID, HMAC digest, complete Redis key,
Token/JTI, forwarding header, Redis or provider URL, credentials, request body,
provider request/response, exception message, or traceback. Do not put any of
those values into metric labels. A policy name, purpose enum, channel enum, route
group, allow/deny/error outcome, and bounded latency/retry bucket are acceptable
only when they come from a closed server-owned vocabulary.

The public `429001` response contains a calculated `Retry-After`; the log does
not need the exact subject or key that produced it. A limiter/verification
`503001` contains no `Retry-After`, and its event must not invent one. Follow
[Rate limiting and abuse-control quotas](rate-limiting.md) for the decision
contract and [Verification and abuse defense](verification-and-abuse-defense.md)
for challenge ownership.

## Formatter And Emitter Safety

The formatter must be total for the accepted input domain and conservative for
everything else:

- Accept only `None`, booleans, bounded integers/floats, strings, UUIDs,
  datetimes, and bounded exact built-in lists, tuples, and dictionaries.
- Require dictionary keys to be strings. Omit non-string keys with one bounded
  counter; omit overlong keys and values behind them; never call their `str` or
  `repr`.
- Detect cycles, cap nesting, item counts, key length, and string length, and
  replace unsupported objects with a constant type marker without formatting
  the object.
- Do not use `record.getMessage()` and do not interpolate arbitrary logging
  arguments. Application events are already-complete, validated string names;
  unexpected messages become `logging.invalid_event`, and their original message
  template and parameters are omitted.
- Reserve `timestamp`, `level`, `event`, `logger`, `service`,
  `service_version`, `environment`, `request_id`, and formatter-owned message
  fields. `extra` can never overwrite them.
- Recursively redact sensitive allowlisted field names as defense in depth, but
  do not rely on regex redaction to make arbitrary messages acceptable.
- Produce finite JSON values and one physical output line.

The non-throwing emission adapter catches ordinary logging failures around the
entire `logger.log` call. A defensive handler also contains formatter, queue, and
stream failures. It may increment an in-process metric, but that fallback must
not recursively log through the failing pipeline.

## Third-Party Loggers

Do not attach the safe application formatter to the root logger and then forward
uncontrolled library messages into it. HTTPX/httpcore can include full URLs,
SQLAlchemy can include statements or parameters, Redis clients can include
connection details, and Uvicorn access logs can duplicate the canonical event.

Attach the JSON handler to the `app` logger namespace with propagation disabled.
Install a `NullHandler` on the root logger and disable or separately configure at
least `uvicorn.access`, `uvicorn.error`, `fastapi`, `httpx`, `httpcore`,
`sqlalchemy`, `sqlalchemy.engine`, `redis`, and `asyncio`. Re-enable a third-party
source only through a tested adapter that emits stable fields without its raw
message or arguments.

## Async Context And Detached Work

Bind the server request ID for request processing and streaming, then clear it
immediately after the final response body is sent. Starlette background work and
cleanup that occurs afterward must not inherit the request identity implicitly;
pass an explicit correlation field when the product needs linkage.

`ContextVar` values are copied into newly created tasks and commonly propagated
into thread-pool work. A streaming response may also send its final body from a
child task, where a token created by the parent cannot be reset. Bind a small
shared request-context object with an active flag: final-body handling marks it
inactive from any copied context, and only the owning outer task resets its token
in `finally`. Provide a project helper for detached tasks that starts with an
empty context, or explicitly clears request context at task entry. Do not call
bare `asyncio.create_task` for detached application work. Concurrent requests,
thread-pool callbacks, streaming iterators, post-response work, and detached
tasks must not leak request IDs into one another.

Because raw `asyncio` diagnostics are disabled with other uncontrolled third-party
logs, the detached-task helper must also consume its task result and emit one safe
`background.task.failed` event for an unhandled exception. It records only the
safe exception metadata above, never the task result, coroutine representation,
task name, exception message, or inherited request context. Expected cancellation
does not produce an error event.

## Forbidden Data

Never emit raw paths, query strings, request/response bodies, arbitrary headers,
email, username, phone, passwords or hashes, cookies, bearer tokens, JWT/JTI
values, signing keys, API keys, proxy URLs or credentials, database/Redis URLs,
SQL parameters, or complete outbound URLs. Treat log storage as a production
data system: define access, encryption, retention, rotation, shipping backpressure,
and deletion policy without blocking requests on delivery.

## Required Verification

Use deterministic tests and controlled ASGI apps/handlers. Cover at least:

- ordinary `2xx`, handled `4xx`, handled `5xx`, and an uncaught exception;
- multi-chunk streaming success and a stream that fails after response start;
- background-task and cleanup failure after a completed response;
- client disconnect, task cancellation, response-start send failure, body send
  failure, and application return without a final body;
- exactly one `http.request.completed` in every path and a separate post-response
  event only when appropriate;
- formatter, handler, queue, and stdout failure without a changed status, body,
  transaction result, or propagated logging exception;
- concurrent request context, thread-pool propagation, streaming context,
  post-response clearing, and detached-task isolation;
- no actor on every `401`, and actor presence on an authenticated `403`;
- `rate_limit.denied` is one `WARNING` with only the static policy and safe
  correlation fields, while limiter and verification unavailable paths emit the
  matching `dependency.*.unavailable` `ERROR` once;
- `429001` and `503001` still produce exactly one canonical request completion,
  and a failing log sink cannot change headers, body, status, or protected-handler
  execution;
- attempted overwrite of every reserved field;
- malicious `__str__` and `__repr__`, non-string dictionary keys, cycles, deep
  and oversized structures, non-finite floats, and newline-bearing strings;
- HTTPX, SQLAlchemy, Redis, Uvicorn, and other third-party logs cannot emit raw
  URLs, query parameters, credentials, statements, or duplicate access lines;
- secret-marker scans across success and every failure path.

For rate-limit and verification tests, include raw IP/account/target markers,
HMAC digests, complete Redis keys, verification codes, Token/JTI values, Redis
URLs, provider errors, and request bodies in controlled inputs and dependency
exceptions, then prove none appears in any emitted line.

The bundled asset is a reference shape, not proof about a target deployment.
Re-run these checks after adapting logging configuration, ASGI middleware,
server workers, or log shipping.
