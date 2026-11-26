# Operational Logging

Read this reference only for application or access logging, request correlation,
safe exception telemetry, log transport, or operational retention. Durable RBAC
audit is a separate security record; use [Audit module](audit-module.md) for it.

## Non-Negotiable Boundary

Operational logging is best-effort observation. A formatter, handler,
socket, or stdout failure must never change a database commit, authorization
decision, background result, or HTTP response. Route all application-owned log
emission through a non-throwing adapter and test that adapter with failing sinks.
Do not use log delivery as a prerequisite for business success.

Emit one-line JSON only for application-owned events. Use stable event names and
bounded, typed fields. Keep raw request and dependency messages outside this
pipeline because redaction is not a proof that an arbitrary string is safe.

## Request Completion Contract

In the asset, `core/middleware/request_logging.py` owns HTTP observation;
`core/logging/context.py` owns request identity isolation;
`core/logging/events.py` owns safe emission and formatting;
`core/logging/details.py` owns bounded body summaries, requested targets and
independent-key new-password fingerprints;
`core/logging/output.py` owns console/file output and logger setup.
`main.py` only mounts the middleware and manages the process logging lifetime.
Exception response conversion lives in `core/exception_handlers.py`.

Implement request logging as pure ASGI middleware around `receive` and
`send`. `BaseHTTPMiddleware` and the return of `call_next` are not final response
boundaries: streaming bodies and response background work may still fail.

Every HTTP request attempts to emit exactly one `http.request.completed` event.
Construct and submit it only after one of these terminal outcomes is known:

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
This is an event-ownership guarantee, not guaranteed log delivery: a failed or
oversized or failed output may discard a runtime event. Database audit records have
their own transaction contract and never use operational stdout logging.

Completion and post-response failure use the same small builder for safe request
ID, route template, method, status, business code, duration and authenticated
current user fields. Keep their outcome, send state and failure phase in the respective
event functions. This removes a duplicated field list without hiding the two
different lifecycle decisions behind a generic dispatcher.

The completion event contains:

- server-generated `request_id`;
- HTTP method and matched route template, never the raw path or query string;
- actual HTTP status and five-digit business code when known;
- monotonic `duration_ms`;
- `outcome`, `response_started`, `response_completed`, `client_disconnected`,
  and an allowlisted `failure_phase` when applicable;
- canonical `user_id` only after full authentication succeeds;
- affected `target_user_id`/`target_role_id`, action, operation outcome and safe
  internal reason code;
- bounded, redacted `request_data`/`response_data` and a new-password fingerprint
  only for the four documented password-setting operations.

The formatter keeps the same core request, target, body and diagnostic fields
on all application events, using null when absent. Runtime events may add their
small event-specific identifiers. File logs omit `target_type`/`target_id` and
service metadata; this does not delete target fields from PostgreSQL audits.

For HTTP events, derive `action` from the matched route endpoint's existing
function name, such as `reset_user_password`; leave it null when no endpoint is
known. Routes do not assign `request.state.action`, `operation_outcome`,
`target_user_id` or `target_role_id` for logging. `HttpLogDetails` reads managed
user/role IDs from GET query parameters or POST bodies, excluding creation and
total-list inputs. The self-password-change target is the authenticated user;
user-session queries still identify their requested user. For successful
registration, administrator user creation and role creation, `api_response`
passes the prepared business data to `HttpLogDetails.record_created_target`
before sending. It saves only the new ID, preserving it even if sending fails.
Creation failures ignore client-supplied IDs, and total lists keep null targets.
Database audit action enums and audit logic retain their own contract; the file
action does not replace them.

`core/response.py::api_response` centrally marks `operation_outcome` from the
five-digit business code: `2xxxx` means `success`, and `4xxxx`/`5xxxx` means
`failure`. A later error response must not overwrite an existing `success`.
If no unified response was assembled, keep the middleware's existing fallback.
This business-result marker is separate from the HTTP lifecycle `outcome`:
a prepared successful result followed by a send failure keeps
`operation_outcome=success` and records `outcome=error`.

All application-owned events use the event creation time in fixed Beijing time
(UTC+8), formatted as ISO 8601 with milliseconds and an explicit `+08:00`
offset. Do not depend on the machine's local timezone. The timestamp and the
`logs/YYYY-MM-DD/` date must use the same Beijing date for that event.

Use `ERROR` for `outcome=error` regardless of a previously sent `2xx` status.
Use `WARNING` for completed `4xx`, `ERROR` for completed `5xx`, and `INFO` for
completed success.

### 当前请求日志的数据案例

文件实际保存为一行 JSON，不包含注释。下面展示管理员重置密码的已实现字段，
日期、ID、耗时为示意值；密码指纹来自离线日志检查，同密钥同密码能重复得到。
`SERVICE_NAME`/`SERVICE_VERSION` 只用于 FastAPI 应用信息。

```jsonc
{
  "timestamp": "2026-10-14T22:55:40.675+08:00", // 固定北京时间 UTC+8，ISO 8601 毫秒精度。
  "level": "INFO", // 正常请求；4xx 为 WARNING，5xx 为 ERROR。
  "event": "http.request.completed", // 本次 HTTP 请求已经结束。
  "logger": "app.core.middleware.request_logging", // 哪个代码模块记录的日志。
  "message_template": "http.request.completed", // 固定事件模板，不记录任意消息正文。
  "request_id": "5992102b-fb1f-4b67-ac44-5c570d90957c", // 与响应头 X-Request-ID 对应。
  "http_method": "POST", // 请求使用的方法。
  "route": "/api/v1/users/password/reset", // 管理员重置密码接口，不含原始查询字符串。
  "http_status_code": 200, // 实际发送的 HTTP 状态码。
  "business_code": 20000, // 统一响应中的业务码；未设置时为 null。
  "duration_ms": 0.834, // 从请求开始到响应发送完成的耗时，单位毫秒。
  "user_id": "U5N9B2LK7QR4X6D", // 已完成认证的当前用户；未完成认证时为 null。
  "target_user_id": "U1N2B3LK7QR4X6D", // 被重置密码的用户；普通请求没有目标时为 null。
  "target_role_id": null, // 本请求不操作角色；修改角色时记录该角色 ID。
  "action": "reset_user_password", // 自动取路由函数名；数据库审计仍用原有动作枚举。
  "operation_outcome": "success", // 统一响应按 2xxxx 标记成功；随后发送失败仍保留该结果。
  "reason_code": null, // 失败时可记录服务端内部原因，正常成功时为空。
  "request_data": { // 脱敏请求摘要；GET 则是脱敏查询参数，不是原始 URL。
    "user_id": "U1N2B3LK7QR4X6D", // 请求指定的目标，不替代上面的已认证操作人。
    "new_password": "[REDACTED]", // 不记录新密码原文或数据库密码哈希。
    "captcha_id": "[REDACTED]", // 验证码标识也遮盖。
    "captcha_answer": "[REDACTED]" // 验证码答案绝不记录。
  },
  "response_data": { // 实际发送的 JSON 的脱敏摘要，Token 等敏感字段仍遮盖。
    "code": 20000,
    "message": "密码重置成功", // 保留响应最外层的普通业务提示，仍做通用凭据过滤和长度限制。
    "data": null, // 密码重置成功，不返回密码或额外的修改标记。
    "request_id": "5992102b-fb1f-4b67-ac44-5c570d90957c"
  },
  "password_fingerprint": "3a166777f70713fdadd6004df6bf4634", // 独立密钥的 HMAC-SHA256 前 32 位 hex。
  "outcome": "success", // success 正常完成、failure 请求被拒绝、error 执行或收发异常。
  "response_started": true, // 响应头已经成功交给服务端发送。
  "response_completed": true, // 最后一段响应体已经成功交给服务端发送。
  "client_disconnected": false, // 是否观察到客户端断开连接。
  "failure_phase": null, // 收发或应用失败时指出阶段。
  "error_id": null, // 异常关联 ID，不是用户输入。
  "exception_type": null, // 只记录异常类型，不记录异常原文。
  "exception_module": null, // 异常类型所在模块。
  "exception_location": null // 安全代码位置：模块、函数、行号，不含局部变量。
}
```

没有匹配路由时 `route` 为 `<unmatched>`；固定字段无信息时仍保留 `null`。
失败请求中的 `target_user_id`/`target_role_id` 是本次请求指定的目标，不代表
权限通过或实际已经修改。新建成功后的目标 ID 由统一响应入口从 Service 的实际
返回数据中提取，路由无需填写日志字段；发送失败也保留已提取的新 ID。

### 正文脱敏与密码指纹

中间件只旁观业务实际读取的请求和成功发送的响应，不额外读取正文、重复验证
或改变限流顺序。每侧最多暂存 16 KiB，脱敏摘要最多 4 KiB；超过限制、正文未完整、
非 JSON 或非法 JSON 只记录省略原因，不把原文退回日志。GET 参数遵循相同大小
限制，不保存原始查询字符串。已知机器字段按格式保留，密码、用户名、验证码、
Token 等敏感字段遮盖。仅响应封套最外层的 `response_data.message` 保留普通文本，
仍执行现有通用文本凭据过滤和长度限制；业务提示不得拼入密码、Token 或原始用户
输入。请求中的 `message`，以及响应 `data` 中嵌套的 `message`、`name`、
`description` 等自由文本仍遮盖；未知字段只计数，避免敏感内容藏在任意键名或字段中。
业务完全没有读取的请求体，不会仅为了日志主动读取，因此摘要和指纹可为空。

四个静态 POST 操作记录设置新密码的指纹：注册 `password`、管理员新增用户
`password`、管理员重置 `new_password`、本人改密 `new_password`。登录密码和
`current_password` 不做指纹。读取了完整的合适 JSON 时，拒绝、参数错误和验证码
失败也能记录新密码指纹，便于识别反复提交同一密码的行为。

`.env` 的独立必填 `LOG_HMAC_KEY` 由 `Settings.log_hmac_key` 读取；至少 32 个
随机 UTF-8 字节，不能与 `JWT_SECRET`/`RATE_LIMIT_HMAC_KEY` 相同。
准确计算是 `HMAC-SHA256(LOG_HMAC_KEY, b"password\x00" + password.encode("utf-8"))`
的小写十六进制前 32 个字符。这里表示真正的零字节，不是四个可见字符。
不加入用户 ID，所以同密钥同原文跨被操作人也能比对；不裁剪或规范化密码。
它是无法解密的比对标识，不是数据库 Argon2id 哈希或 MD5。换密钥后新旧指纹
不能直接比较；密钥不可写入日志。格式器只允许该专用字段为 null 或 32 位小写 hex。

## Authentication Identity Boundary

Password login records its user through
`core/logging/context.py::set_log_user_id` only after `AuthService.login`
has completed account/password checks and Redis registration. The helper uses
the active context's existing HTTP details to update the middleware-owned
request state; the login route does not assign log identity. Missing or expired
HTTP context is a no-op. This retains the same user field for send failures and
post-response errors without adding another identity store or changing the
ordinary authentication dependencies used by CAPTCHA and authorization.

For requests using an existing bearer Token, do not bind `user_id` after JWT
parsing or Redis JTI lookup alone. Set it
only after all required authentication state has succeeded: JWT validation,
the exact Redis active-JTI check, current PostgreSQL user status, and the bound
`users.token_version` comparison. Consequently:

- every authentication failure reported as `401` leaves `user_id` null;
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
The default asset classifies its actual PostgreSQL failures in `db/postgres_db.py`
and Redis session failures at the
`repositories/redis/login_session_repository.py` catch site. Redis timeout,
connection failure and other Redis errors become `timeout`, `connection` and
`unknown` respectively. The larger vocabulary above is for an integration that
really exists; do not generate a generic classifier for unused HTTP/TLS clients.

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

Startup, shutdown, schedulers, and worker loops also need a
top-level safe failure event because no HTTP completion exists for them. Keep
their retry count, backoff state, job type, and operation as bounded allowlisted
fields; never log payloads or arbitrary job arguments.

## Rate-Limit And Verification Events

The bundled rate-limit and authentication-guard components use these stable application events:

| Event | Level | Logging owner | Safe event fields |
| --- | --- | --- | --- |
| `rate_limit.denied` | `WARNING` | The middleware or exception handler that converts a valid denial to `42901` | Static `rate_limit_policy`; HTTP/business code when available; server request ID from context |
| `dependency.rate_limit.unavailable` | `ERROR` | The boundary that converts missing, failed, timed-out, or malformed limiter state to `50301` | Static dependency and operation identifiers, optional static policy, safe exception metadata, server request ID |
| `dependency.verification.unavailable` | `ERROR` | The challenge/delivery boundary that converts verification Redis or provider failure to `50301` | Static dependency and operation identifiers, safe exception metadata, server request ID |

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

The public `42901` response contains a calculated `Retry-After`; the log does
not need the exact subject or key that produced it. A limiter/verification
`50301` contains no `Retry-After`, and its event must not invent one. Follow
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
- Reserve `timestamp`, `level`, `event`, `logger`, `request_id`, and
  formatter-owned message fields. `extra` can never overwrite them.
  Logs omit `service`, `service_version`, and `environment`; ignore these names
  in `extra` as well so business callers cannot restore them. `SERVICE_NAME`
  and `SERVICE_VERSION` only supply FastAPI title/version. Runtime settings and
  environment examples have no `APP_ENVIRONMENT` requirement.
- Recursively redact sensitive allowlisted field names as defense in depth, but
  do not rely on regex redaction to make arbitrary messages acceptable.
- Produce finite JSON values and one physical output line.

For the default formatter, `_safe_value` handles scalar types and dispatches
ordinary dictionaries and lists/tuples to their own bounded conversions in the
same module. Cycle tracking is path-scoped: remove a container ID on return so
two fields may safely refer to the same object without a false cycle marker.
This is a concrete security boundary, not a reason to add a generic serializer.
Keep one-use field-name normalization beside `_safe_value`'s redaction decision;
it has no independent resource or policy boundary to justify another helper.

The non-throwing emission adapter catches ordinary logging failures around the
entire `logger.log` call. The output handler also contains formatter and stream
failures without recursively logging through the failing pipeline.

## Default Console And File Output

The default project installs two handlers on the `app` logger: `SafeStreamHandler`
writes to stdout, and `DailyFileHandler` appends UTF-8 JSON to
`logs/YYYY-MM-DD/app.log` under the project root. The first event creates the
directory/file; each event's creation time determines its Beijing (UTC+8) date.
Crossing midnight switches files and closes the previous file. Restarting on the
same day appends to the existing file. The path does not depend on the shell's
working directory; `LOG_ROOT_DIR` in `core/logging/output.py` owns the default.

`Settings.log_file_max_mb` defaults to 100. Configure `LOG_FILE_MAX_MB` as a
positive integer in `.env` and restart; 1 MB means 1024 × 1024 bytes. Before
writing, check the existing file's byte length plus the next UTF-8 line and its
LF newline. If that would exceed the limit, append to the next numbered file:
`app.log`, `app.1.log`, `app.2.log`, and so on. Restarting chooses the highest
existing numeric segment and advances again if it is full; a new date starts
its own sequence. Lowering the limit preserves old files and starts a new segment
when necessary. Do not rename or delete existing files to perform size splitting.
The check is performed under each handler's process-local lock; it does not
provide an atomic size bound across separate processes sharing one directory.

Both handlers use the same safe formatter and 16 KiB line limit. A file failure
does not prevent console output or change a business result. Each file line is
flushed; this is ordinary file persistence, not an `fsync` or guaranteed delivery
contract. Slow stdout or storage can delay the current request. No queue, writer
thread, delivery counter, automatic history deletion, or shutdown-drain setting
is generated. The application removes and closes both handlers on exit without
closing shared stdout. `logs/` is ignored by Git; generated projects contain no
pre-existing log files. `LOG_LEVEL` applies to both destinations, so raising it
above `INFO` suppresses normal successful request events in both places.

Default account/permission evidence shares PostgreSQL `operation_audit_events`
and `AuditService`; general business audit is opt-in. Required audit remains
separate from request/runtime files. It reuses safe bounded request summaries
and new-password fingerprints; its response is a business result snapshot staged
before commit, while files observe actual HTTP completion. No post-response
audit UPDATE or background writer is added. A collector, retention policy, or
asynchronous output can be added by the adopter when needed; file output alone
does not prove throughput capacity or crash-safe audit durability.

## Third-Party Loggers

Do not attach the safe application formatter to the root logger and then forward
uncontrolled library messages into it. HTTPX/httpcore can include full URLs,
SQLAlchemy can include statements or parameters, Redis clients can include
connection details, and Uvicorn access logs can duplicate the canonical event.

Attach the JSON handler only to the `app` logger namespace with propagation
disabled. Disable raw `uvicorn.access` lines because they may include query
strings and duplicate the canonical request event. Do not clear the root logger
or disable `uvicorn.error` and all dependency loggers globally: those are owned
by the runtime or deployment and may be needed for diagnosis. Do not route
uncontrolled third-party messages through the safe application formatter.
Operators should review their independent third-party log destinations for
URLs, SQL arguments, and credentials before enabling verbose levels.

## Async Context And Detached Work

HTTP middleware binds the server request ID once for request processing and
streaming, then clears it immediately after the final response body is sent.
Audit constructors automatically read this same active context through the
no-argument `core/audit.py::get_audit_request_id()`; routes and Services do not
forward `request_id` parameters. A missing or inactive context raises
`RuntimeError` for audit construction instead of creating a new correlation ID.
Non-HTTP entrypoints generate and bind one safe operation ID before processing,
then deactivate and reset it in `finally`, even if resource cleanup fails.
Starlette background work and
cleanup that occurs afterward must not inherit the request identity implicitly;
pass an explicit correlation field when the product needs linkage.

`ContextVar` values are copied into newly created tasks and commonly propagated
into thread-pool work. A streaming response may send its final body from a
child task, where a token created by the parent cannot be reset. The small
shared request-context object has an active flag: final-body handling marks it
inactive from any copied context, and only the owning outer task resets its token
in `finally`. The default project creates no detached background tasks and
therefore adds no generic task launcher. If a product adds workers or detached
tasks, their owner must explicitly clear inherited request identity and observe
and safely log failures at the task boundary.

## Forbidden Data

Never emit raw paths, query strings, unredacted request/response bodies, arbitrary headers,
email, username, phone, plaintext passwords or database password hashes, cookies, bearer tokens, JWT/JTI
values, signing keys, API keys, proxy URLs or credentials, database/Redis URLs,
SQL parameters, or complete outbound URLs. Treat log storage as a production
data system: define access, encryption, retention, rotation, shipping backpressure,
and deletion policy without blocking requests on delivery. The only password
correlation value is the independent-key fingerprint described above; it does
not authorize logging arbitrary HMAC digests, CAPTCHA digests or stored hashes.

## Required Verification

Use deterministic tests and controlled ASGI apps/handlers. Cover at least:

- ordinary `2xx`, handled `4xx`, handled `5xx`, and an uncaught exception;
- multi-chunk streaming success and a stream that fails after response start;
- background-task and cleanup failure after a completed response;
- client disconnect, task cancellation, response-start send failure, body send
  failure, and application return without a final body;
- exactly one attempted `http.request.completed` in every path and a separate
  post-response event only when appropriate; with a healthy drained sink, exactly
  one corresponding completion line;
- formatter, handler, stdout and file failure without a changed status, body,
  transaction result, or propagated logging exception;
- files are created under the project root by Beijing date, restarts append,
  crossing midnight closes the old file, and both outputs keep safe JSON;
- configurable byte limits include UTF-8 and LF; exact-fit lines stay in the
  current file, the next line splits without loss, numeric segments continue
  after restart, and a new date begins its own sequence;
- oversized events are ignored, and closing both handlers leaves stdout open;
- output configuration does not clear the root logger or disable server error logs;
- concurrent request context, thread-pool propagation, streaming context,
  and post-response clearing;
- no current user on every `401`, and current user presence on an authenticated `403`;
- `rate_limit.denied` is one `WARNING` with only the static policy and safe
  correlation fields, while limiter and verification unavailable paths emit the
  matching `dependency.*.unavailable` `ERROR` once;
- `42901` and `50301` still produce exactly one canonical request completion,
  and a failing log sink cannot change headers, body, status, or protected-handler
  execution;
- attempted overwrite of every reserved field;
- malicious `__str__` and `__repr__`, non-string dictionary keys, cycles, deep
  and oversized structures, non-finite floats, and newline-bearing strings;
- application-owned logs do not emit raw URLs, query parameters, credentials,
  statements, or duplicate access lines; review separately configured third-party logs;
- secret-marker scans across success and every failure path.

For rate-limit and verification tests, include raw IP/account/target markers,
HMAC digests, complete Redis keys, verification codes, Token/JTI values, Redis
URLs, provider errors, and request bodies in controlled inputs and dependency
exceptions, then prove none appears in any emitted line.

The bundled asset is a reference shape, not proof about a target deployment.
Re-run these checks after adapting logging configuration, ASGI middleware,
server workers, or log shipping.
