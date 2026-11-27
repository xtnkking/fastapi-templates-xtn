# FastAPI PostgreSQL RBAC Reference Asset

This is the maintained reference asset, not a folder to copy wholesale into a
new project. Use [New-project delivery](../../references/new-project-delivery.md)
and the Skill's `scripts/create_project.py` to produce the selected application
files and small starter test set. Historical `alembic/`, `sql/`, integration
fixtures, cluster helpers and load tooling remain here for maintenance
regression; they are not default project output.

The Skill delivers ORM models and application code. The user generates, reviews,
and executes their own migration files, DDL, database protections, and initial
data. Generation, startup and ordinary tests must not create tables, seed rows,
or repair schema automatically. See the
[database handoff](../../references/migrations.md) for requirements that ORM
metadata does not install, including custom triggers and fixed initial roles.

The asset needs Python 3.12+, PostgreSQL and Redis. It is not deployment
credentials or proof that an adapted project passed real integration tests.
The repository's official verification combination is Python 3.12,
PostgreSQL 17 and Redis 7; other versions require project-owned verification.

Default business IDs are `U`/`R`/`P`/`UR`/`RP` plus uppercase random
characters (15 total). Default `operation_audit_events` uses `OA` plus China
time `YYMMDDHHMMSSmm` and six random characters (22 total). The final `mm`
means hundredths of a second; query order still uses `created_at`. JWT `user_id`
uses the `U...` user ID. Request IDs, JWT JTIs, CAPTCHA IDs and log error IDs
remain UUIDv4. See the Skill's identifier policy before changing ID lengths.
The optional business-audit resources retain `BA` IDs and are not part of the
default project registry/export.

Role models and request/response fields use `level` for that role's level.
User authority and user responses use `role_level` for the highest level among
the user's active, non-deleted roles, or `0` when there are none. Larger values
mean higher authority; the fixed system-role levels are `1000`/`0`
for `super_admin`/`user`, and custom-role levels remain `1..999`.
There is no default `admin` role or reserved level `500`. Create an ordinary
custom role and grant its required permissions when an administrator is needed;
the key `admin` alone grants no special authority.
Updating the source does not remove an existing database's former system
`admin`. Its owner must review the role, bindings, constraints and immutable-role
protections, then choose a reviewed conversion to a normal custom role or
unbind it before removal. No role, permission or account is automatically
deleted, and the historical Alembic sequence is not a fresh current-baseline
schema recipe.

## Source Layout

The selected application code is a default starting point for a service without an established
framework. When adding features to an existing application, use its own layout,
components, and transaction conventions; do not replace its application tree
with this asset. Directory reorganization is a separate, explicitly requested
scope. An empty module directory inside an existing project is not a new service.

The application groups modules by responsibility, then by business inside each
directory. `app/main.py` wires the application. The other top-level Python file
is `app/__init__.py`.

Read `main.py` as lifecycle plus explicit application assembly. Its cleanup stack
releases acquired resources in reverse order, including after a partial startup
or teardown failure; request logging lives in
`core/middleware/request_logging.py`, error response conversion in
`core/exception_handlers.py`. These modules own the implementations, not
forwarding wrappers.

Read routes use `db: Annotated[AsyncSession, Depends(get_postgres_session)]` from
`db/postgres_db.py`: FastAPI supplies one request session and closes it afterward,
without committing writes. Protected write Services create their own transaction
so the authorization recheck, business change and audit stay together.
Authentication closes its short database read before Redis or a write transaction.
`db/postgres_db.py` also classifies PostgreSQL availability failures; ordinary
business errors remain in `core/exceptions.py`. There is no separate database
error module in the generated project.

Every application function has a Chinese multi-line docstring describing its
behavior, declared parameters and return/yield result. See the
[comment contract](../../references/python-comments.md) and
[directory conventions](../../references/project-structure.md) when extending it.
Comments explain the real invocation order: declaring or passing a callback does
not mean its credential checks or writes have run. Keep long endpoint inputs and
multi-field response/audit mappings individually readable, and document public
fields with Chinese `Field`/`Query` descriptions so their validation meaning is
clear from source. Swagger, ReDoc, and OpenAPI JSON routes are disabled by default.

```text
app/
  __init__.py
  main.py
  api/v1/router.py     Version-one business router assembly
  api/v1/route_validation.py Version-one startup authentication rules
  api/v1/endpoints/    Authentication and access HTTP endpoints
  core/                Configuration, errors, i18n, logs, middleware, security
  db/                  PostgreSQL/Redis clients and PostgreSQL pool-failure handling
  dependencies/        Request, authentication, CAPTCHA, and quota adapters
  models/postgres/     ORM base, user, role, permission, state and audit models
  repositories/postgres/  Named role, user, permission, assignment and authority queries
  repositories/redis/     Login-session records, atomic checks and login-order maintenance
  schemas/             Shared fields, CAPTCHA, authentication, user, role and permission contracts
  services/            Named *_service.py business implementations
  assets/locales/      zh-CN and en message catalogs
  commands/reset_super_admin_password.py Offline sole-super-admin password recovery
```

Add later businesses inside these layers, for example `api/v1/endpoints/orders.py`,
`models/postgres/order.py`, `repositories/postgres/order_repository.py`, and
`services/order_service.py`. Only create files that own actual
behavior. Business Services own pagination, missing-target errors, result
construction and transactions; named Repositories own SQL and persistence.
An already-locked ORM field can be assigned inside the Service transaction.
Do not create a Service pass-through or a per-field setter solely to match the tree.
Models and schemas do not import services. Workers and generic utilities are
added only when actual functionality needs them.

Follow one business through explicit owners:

| Business | Endpoint | Service | PostgreSQL queries |
| --- | --- | --- | --- |
| Role list/detail and changes | `api/v1/endpoints/roles.py` | `services/role_service.py` (`RoleService`) | `role_repository.py`; current-user authority comes from `user_repository.py` |
| User list/detail, creation, reset, status and assignments | `api/v1/endpoints/users.py` | `services/user_service.py` (`UserService`) | `user_repository.py`, `user_role_repository.py` |
| Permission catalog | `api/v1/endpoints/permissions.py` | `services/permission_service.py` (`PermissionService`) | `permission_repository.py` |

The repository modules live under `repositories/postgres/` and export stateless
named instances. Services pass the active session explicitly.
`repositories/redis/login_session_repository.py` exports
`login_session_repository`, which owns Redis login registration, validation,
deletion, listing and atomic Lua scripts. `AuthService.issue_access_token`
coordinates JWT signing and registration; it returns a Token only after the
Repository confirms registration. `core/security/jwt_tokens.py` owns only the
JWT codec, without Redis I/O.
User lookup, account/permission reads and visible-user projections belong to
`UserRepository`; visible-role queries belong to `RoleRepository`. Ordinary
single-user reads use `get_user`: supply an ID and/or username, optionally select
enabled state, and default to non-deleted users. Explicitly include deleted rows
for login-state reads and occupied-name checks; this does not permit deleted
accounts to log in or release their reserved usernames. Locking and visibility
queries retain their dedicated methods.
Common allowed/
denied audit lifetime belongs to `services/user_role_transaction.py`; command
bodies run directly inside that context instead of nested callback executors.
`services/audit_service.py` exposes `audit_success` for adding an event to the
current transaction and `audit_denied` for best-effort auditing after rollback.
It derives the category from the action enum and identity/source from trusted
context. `user_role_transaction` yields only the session, so business code records
success after its mutation instead of filling an audit object field by field.
`models/postgres/operation_audit.py` has the
single 16-field table. It preserves redacted request data, business response
snapshots, optional new-password fingerprints and reviewed before/after state.
Success audit commits with mutation; the response snapshot is not HTTP delivery
confirmation. See [Operation audit](../../references/audit-module.md) for fields
and shared redaction limits.
Endpoints contain no SQL. Related actions stay in five business modules:
`auth.py` owns login, registration, logout and public CAPTCHA;
  `me.py` owns current-account permissions, password changes and private
  CAPTCHA; `users.py` owns administrative user creation, queries, visible-user
  session lists, status, role bindings, password reset and forced logout of all
  target sessions. `roles.py` and `permissions.py`
own role administration and permission queries. Request authentication,
permission, CAPTCHA and rate-limit adapters live in `dependencies/`.

The same authentication business uses `auth.py`, `auth_service.py` and
`AuthService` across layers. User registration uses `RegisterRequest`,
`AuthService.register` and `MessageKey.AUTH_REGISTER_SUCCEEDED` consistently;
the message catalog key remains `auth.registration_succeeded`.
Its route shows named rate-limit dependencies,
one-time CAPTCHA verification/consumption and authentication/registration in that
visible order.

API input models use a `Request` suffix and output models use `Response`:
for example, `CaptchaCreateRequest` and `CaptchaResponse`. An output model
is still placed inside the unified JSON envelope's `data` field.
Reusable user creation with the initial password hash, default-role binding and
one account creation audit belong to
`UserService.create_user`. Registration and `UserService.admin_create_user`
reuse it while retaining their own checks and outer transaction ownership;
default-role binding is explained in comments rather than a method-name suffix.
CAPTCHA storage and
consumption belong to `CaptchaService`. Shared response, logging, username and
startup route checks live in `core/response.py`, `core/logging/events.py`,
`core/security/user_name.py` and `core/route_validation.py` respectively.
The five-digit code registry lives in `core/codes.py`; business exceptions live
in `core/exceptions.py`, and `core/exception_handlers.py` converts them to HTTP.

Business routes use GET/POST and static paths. For example,
`GET /api/v1/roles/detail?role_id=<id>` takes a validated query ID, while
`POST /api/v1/users/disable` takes `{"user_id":"<id>"}` in its JSON body.
List/detail queries end in `/list` or `/detail`; exact permissions and target
visibility are checked independently of parameter placement. Shared business
prefixes/tags live on routers. Multi-input class methods retain the receiver and
first input on the definition line, align subsequent inputs one per line and
place the closing parenthesis in that same column. Multi-argument business calls
are expanded so each input is easy to follow; simple calls and decorators may
stay on one line. Use the hanging-indent fallback for excessively long method
names or annotations, as described in the Python comment reference. The existing
autopep8 settings support this layout without additional lint ignores.
`api/v1/router.py` supplies the version prefix once; the business routers declare
only `/roles`, `/users` and their other resource prefixes.

`GET /api/v1/users/list` requires `users:read` and supports these query filters:

| Query | Default | Meaning |
| --- | --- | --- |
| `user_id` | Omitted | Exact immutable user ID |
| `user_name` | Omitted | Exact username after the shared normalization |
| `is_active` | Omitted | Either enabled state; `true` selects enabled users and `false` selects disabled users |
| `is_deleted` | `false` | Only non-deleted users; `true` selects only soft-deleted users |

Supplied conditions combine with AND. The page and `total` use the same SQL
visibility and filter conditions, so searching an ID or deleted account cannot
bypass hierarchy, self or protected-user restrictions. Deleted-user results
have empty role/permission collections and `role_level=0`; their former grants
are not restored. This explicit management-list query adds no new capability,
model field, deletion or restoration command. User detail and authentication
continue to exclude deleted users.

`pyproject.toml` declares dependencies, packaging and code-tool settings;
`LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md` preserve copied-source licensing
and attribution in this maintained asset. A generated application keeps required
copyright/permission text in its README's collapsed appendix instead of exporting
these three files. It does not receive a source manifest or separate database
handoff document; brief database prerequisites also live in that README.
This does not assign an open-source license to the user's business code or
authorize deleting files from an existing project.

## Configure And Run

For a generated project, follow its Chinese quick start. Start in a dedicated
virtual environment and install runtime dependencies first:

```powershell
python -B -m venv .venv
.\.venv\Scripts\Activate.ps1
python -B -m pip install -e .
```

Generated projects use `.[dev]` only when developing or running tests. Maintainers reproducing
the historical Python 3.12/Linux CI environment use
`python -B -m pip install -c constraints-ci-py312.txt -e ".[test]"` in this asset;
those pinned resolutions and maintenance extras are not the user's minimum
startup requirement. Copy
`.env.example` to an untracked `.env` and replace every example credential and
endpoint. New projects default to one standalone PostgreSQL and one standalone
Redis. Set `DATABASE_URL` for PostgreSQL/asyncpg and `REDIS_URL` for login state,
CAPTCHA, and quotas; no cluster settings or second Redis are needed.
Only if requested, use a distinct `RATE_LIMIT_REDIS_URL` for rate-limit counters.
The bundled client accepts only standalone Redis URLs; see
[connection examples](../../references/redis-connections.md). Without a limiter
override, the same client handles both purposes.
Generate three different random values for `JWT_SECRET`, `RATE_LIMIT_HMAC_KEY`
and `LOG_HMAC_KEY` as shown in `.env.example`; example placeholders cannot
start the application. Ask the product owner for a positive
`MAX_ACTIVE_SESSIONS_PER_USER`: these are login sessions, not physical devices.
Administrator creation and password reset set a password the user can use
immediately. The administrator must deliver it privately; the API does not echo
it. Neither operation requires a second password-setup step.
New-password fields default to 8..32 visible ASCII characters and require at
least one uppercase letter, lowercase letter, digit and special symbol.
Registration, administrator creation, self-change and administrator reset reuse
`validate_new_password` in `app/core/security/password_rules.py`. Change
`MIN_PASSWORD_CHARACTERS` and `MAX_PASSWORD_CHARACTERS` in
that file, then restart; request constraints, field text
and Chinese/English policy messages use those shared bounds. Login and
current-password input instead permit nonempty text up to the independent
`MAX_PASSWORD_INPUT_CHARACTERS` ceiling, default 1024; changing the new-password
policy does not invalidate existing passwords. Keep a separately developed
frontend's input limits aligned. `passwords.py` owns Argon2 hashing, verification
and the bounded calculation queue, while `password_rules.py` owns input rules.
The Access Token lasts 86,400 seconds (24 hours) by default. Shorten it for
high-risk or administrative surfaces, and choose a lifetime appropriate for
this product. Leave `JWT_ISSUER` and `JWT_AUDIENCE` both unset unless the
owner has explicitly accepted the extra issuer/audience restriction.

Configure the PostgreSQL and Redis endpoints supplied by the user. The retained
Compose/SQL files are historical maintenance conveniences, not generated-project
initialization instructions. The user prepares their database separately:
generate and review their migrations from the delivered models, execute them,
install database-only protection, and initialize system roles, permission grants
and the single `rbac_state(scope='global')` row. This row contains only `scope`
and provides the RBAC write lock. The application must not do these setup steps for them.

After that user-owned setup, start development with
`uvicorn app.main:app --reload`. Registration remains available and assigns only
`user`. The intended first administrator registers through that normal flow;
the user then prepares and executes their own reviewed offline transaction to
bind `super_admin` to that immutable user ID, preserving the guard, versions,
role limit, and audit contract in the database handoff. No initialization SQL
file or public bootstrap/transfer route is generated. Missing setup remains an
explicit prerequisite, not a reason to create rows automatically.

If the sole super administrator later needs offline password recovery, an
authorized operator can run
`python -B -m app.commands.reset_super_admin_password --user-id <canonical-users.user_id>` from this
folder. The command prompts privately for the new password; it never
accepts a password argument. This recovers the existing holder and does not
create or transfer super-administrator authority.

The default asset includes no `/health/live` or `/health/ready` endpoint or
health-probe module. Add probes only when the adopter explicitly requests them,
and restrict access to an internal network or trusted probes. Keep any requested
liveness check separate from dependency readiness checks; bound their timeouts
and expose only an overall result. Checks must never create or repair database
state or disclose connection strings, keys, or exception details. A readiness
result cannot certify every database constraint or custom trigger.

## Capacity And Multiple Instances

Pool and timeout defaults live in `app/core/config.py`; their environment
overrides are listed in `.env.example`:

| Setting | Default |
| --- | ---: |
| `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW` | 5 / 5 connections per process |
| `DATABASE_POOL_TIMEOUT_SECONDS` / `DATABASE_CONNECT_TIMEOUT_SECONDS` | 5 / 5 seconds |
| `DATABASE_COMMAND_TIMEOUT_SECONDS` | 20 seconds per driver command, including checkout ping |
| `DATABASE_STATEMENT_TIMEOUT_MS` / `DATABASE_LOCK_TIMEOUT_MS` | 15000 / 3000 milliseconds |
| `REDIS_MAX_CONNECTIONS` | 50 per created client, per node, per process |
| `REQUEST_BODY_MAX_BYTES` | 1048576 bytes (1 MiB) per HTTP request |
| `PASSWORD_MAX_RUNNING` | 2 password calculations per worker |
| `PASSWORD_MAX_WAITING` | 4 additional waiting password calls per worker; 0 means no waiting |
| `PASSWORD_WAIT_TIMEOUT_SECONDS` | 0.5 seconds maximum wait before calculation starts |

The existing `PasswordManager` applies these three password-capacity settings
to hashing and verification. A free slot starts immediately; a full queue or
expired wait returns HTTP `503`, business code `50301` and a Chinese/English
service-busy message without starting that work. Only waiting is timed out.
A started native calculation keeps its slot until it finishes even if the
caller is cancelled. Change `.env` and restart to apply new values.
Each worker on each server has its own slots and waiting callers; there is no
shared queue or automatic transfer. Two workers at the defaults can run four
calculations and hold eight waiting calls in total. At 64 MiB per calculation,
that is about 256 MiB of Argon2 working memory, plus the application's memory.
These resource bounds are separate from Redis business rate limits.
The CAPTCHA was already consumed before reaching the password queue; a busy
response does not restore it. Obtain a new CAPTCHA for another submission and
do not automatically retry the request.

PostgreSQL's app ceiling is `instances * workers * (pool_size + max_overflow)`:
two instances with four workers each can use 80 connections at these defaults.
Leave room for other applications, maintenance, migrations, and overlapping
workers during deployment. Each worker normally creates one Redis client shared
by sessions, CAPTCHA, and rate limits. A second client exists only when an
independent standalone rate-limit URL is configured. Keep lock
timeout no larger than statement timeout and fit all waits inside the deployment
request deadline. Classified exhaustion and dependency timeouts fail with safe
`50301`; the app does not automatically replay arbitrary writes.

The command timeout bounds client network waits that PostgreSQL's own statement
timeout cannot stop when replies never arrive. It is not a 20-second total
request or transaction limit: multiple SQL commands and SQLAlchemy prepare/
execute stages have separate budgets. Set any end-to-end request deadline in
the actual deployment. SQLAlchemy's built-in `pool_pre_ping` checks an existing
pooled connection when it is borrowed. A detected disconnection may reconnect
to the configured endpoint; a new connection is established normally. The
driver command timeout also applies to the ping, but there is no separate total
checkout deadline or custom retry counter. Business SQL is never replayed.

A driver deadline maps to `50301` at the database boundary and retires only
that connection, using local `terminate()` so broken-network cancellation/close
cannot hold cleanup indefinitely. External task cancellation propagates, and
an unrelated application `TimeoutError` retains normal `500` handling. If a
commit times out, the write may already have succeeded: verify authoritative
business state before retrying. Neither this timeout nor an optional readiness
probe provides automatic database failover. See
[Capacity and availability](../../references/application-capacity-and-availability.md)
for the full boundaries and verification requirements.

All instances must share their authoritative PostgreSQL and Redis targets,
secrets, namespaces, session/claim/quota policy, trusted-proxy interpretation,
and synchronized clocks. Set `DATABASE_URL` to the stable writable endpoint
provided by operations; operations owns replication, promotion, and endpoint
failover. The app handles bounded waits, bad connections, reconnection to the
same endpoint, and transaction failures without replaying writes. Read/write splitting requires an
explicit need and an agreed deployment design; it is not enabled by default.
Current authentication and RBAC reads use the primary, including behind a proxy
that must not send every `SELECT` to a replica. There is no local positive JTI
cache. Optional business replicas serve only selected lag-tolerant reads.
The global authorization lock serializes its
protected writes; more workers do not remove that limit, and unrelated business
writes should not acquire it by default. Ordinary authentication reads current
authority without reading this guard row or returning an authorization counter.

The Redis factory supports only standalone URLs. Session, CAPTCHA and quota
operations retain their atomic Redis scripts. Connection errors do not automatically replay writes.
Each user has exactly two session keys: `login:sessions:<user_id>` stores
JTI-field-to-canonical-JSON records and `_version`; `login:sequence:<user_id>`
stores strict login order. Both keys use the canonical 15-character
`U` + 14-character user ID directly. Hash fields and sorted-set members use the
JTI's `UUID.hex`: 32 lowercase hexadecimal characters. JWT `jti` remains the
standard hyphenated UUID string; neither Redis user IDs nor JTI fields are
hashed. Key names have no version segment, braces, service name, or environment.
Service name and version are FastAPI application information only; logs omit
service and environment metadata, and no application-environment setting is required.
Expiry comes directly from each JSON record's `exp`. Login and online-session
listing traverse that user's order index to remove expired entries; this O(n)
cleanup suits small per-user login sets. Authentication checks only the current
record, version, and order membership in one Lua round trip. Atomic registration
preserves the version watermark and latest retained container deadline; excess
logins evict the earliest registration, never the earliest expiry.
Deploying this layout requires existing users to log in again. Old keys expire
through their existing TTL, without compatibility reads or active cleanup.
Quota key changes start fresh windows once; no database migration is required.
See [JWT registry implementation](../../references/jwt-session-implementation.md)
for the complete key, expiry, and atomic-operation contract.
See [Redis connections](../../references/redis-connections.md) for configuration
and test commands. Operators own the chosen load balancer, process supervision, dependency replication,
failover, and backup/recovery. Optional readiness checks and load results do not prove those
systems are highly available. Production topology and zero-downtime release
decisions belong to the adopter; they are not prerequisites for ordinary coding
tasks. The load tool below is optional for a requested performance investigation.

### Runtime Logging

Application events are formatted as safe single-line JSON and written directly
to stdout and to `logs/YYYY-MM-DD/app.log` under the project root. Date folders
use Beijing time (UTC+8); the first event creates the file, midnight switches
files, and restarting appends. Change `LOG_ROOT_DIR` in
`app/core/logging/output.py` to change the location. `LOG_LEVEL` and
`LOG_INCLUDE_EXCEPTION_DETAILS` are in
`app/core/config.py` and `.env.example`; individual lines are capped at 16 KiB.
`LOG_FILE_MAX_MB=100` limits each file to 100 × 1024 × 1024 bytes by default.
Set a positive integer in `.env` and restart to change it. Before a line would
exceed that limit, output switches to `app.1.log`, `app.2.log`, and so on in the
same date directory. UTF-8 bytes and the newline count toward the limit; a
restart continues from the highest existing segment. Files are appended, never
renamed, overwritten, or deleted by size splitting.
The level applies to both outputs; normal requests use `INFO`. Logging errors
cannot replace a business result; a file failure still allows console output.
Slow stdout or disk may delay a request. Files are flushed after each line but
are not a guaranteed delivery or crash-safe audit channel. The default project
does not create a background queue, writer thread, or automatic log deletion.
`logs/` is ignored by Git. Database audits use PostgreSQL separately. Read
[Operational logging](../../references/operational-logging.md) before adapting it.

### Bounded Read Load Check

This optional maintenance tool is not copied into generated projects. Only for
a separately requested performance investigation, with the test extra installed,
set `LOAD_TEST_BEARER_TOKEN` privately in the
process environment to a valid test account's Access Token. Then run from this
folder against a test service you own or are authorized to load-test. Every
`--url` must be a trusted endpoint: each receives the same bearer Token. Start
with small values; a production load run needs explicit authorization.

```powershell
python -B scripts/load_test.py --url http://127.0.0.1:8000/api/v1/me/user_info --requests 100 --concurrency 5 --timeout 10 --token-env LOAD_TEST_BEARER_TOKEN
```

Run a small warm-up separately, compare increasing concurrency, then use duration
mode for a sustained read test, for example:

```powershell
python -B scripts/load_test.py --url http://127.0.0.1:8000/api/v1/me/user_info --duration 60 --concurrency 10 --timeout 10 --token-env LOAD_TEST_BEARER_TOKEN
```

`--requests` and `--duration` are mutually exclusive. With neither, the default
is 100 requests. Duration is in seconds, greater than 0 and at most 3600. At its
deadline no new requests start; in-flight requests finish or time out, so total
elapsed time can exceed that duration by approximately one request timeout.
The output separates total `requests_per_second` from
`successful_requests_per_second`. p50/p95/p99 include all completed requests,
including failures. Latency storage is limited to a 10000-entry uniform reservoir;
the JSON reports `latency_samples`, `latency_sample_limit`, and
`latency_percentiles_estimated` so sampled percentiles are not mistaken for exact
tail measurements.

Repeat `--url` with a second instance's full GET address to alternate between
them. The script sends only GET, does not retry or follow redirects, and reports
aggregate latency percentiles, throughput, status counts, and transport errors;
it does not print URLs, Tokens, or response bodies. These reads still spend their
normal quota, so count `429` separately from useful successful throughput.
Record hardware, worker count, concurrency, duration, and settings with results.
Observe CPU, memory, event-loop delay, database pool/lock waits, Redis latency,
and log loss under the actual output sink using existing process/profiling tools.
An isolated write scenario needs its own business-specific design; this script
never sends POST. See the staged validation guidance in
[Capacity and availability](../../references/application-capacity-and-availability.md).
The script does not create accounts, disable security, or simulate failover.
Use the separate two-process integration tests for shared session/revocation and
quota behavior; test actual node loss and recovery only on the intended isolated
topology. Profile remaining log-formatting and CAPTCHA-generation costs before
adding further queues or workers.

## Select API Language

All client-facing runtime response messages support Simplified Chinese and
English. Chinese is the default. Send the standard header below when a client
needs English:

```http
Accept-Language: en
```

The response reports canonical `Content-Language: zh-CN` or
`Content-Language: en` and includes `Vary: Accept-Language`. Language selection
changes only human-readable `message` values, including safe field-validation
messages. HTTP status, numeric business code, `data`, `request_id`, permission
keys, log events, audit actions, and internal reason codes remain stable.
A specific `q=0` language exclusion overrides a parent range or wildcard.
Database-authored product content and static schema descriptions are outside
this runtime message module and are not translated by it. The asset's public
field and query descriptions remain Chinese when an English API response is
selected. `/docs`, `/redoc`, and `/openapi.json` are disabled by default.

To add another language, update the static registry in `app/core/i18n/language.py`, add a
complete UTF-8 JSON file under `app/assets/locales/`, and add parser, catalog-parity,
response-header, error, validation, and concurrency tests. Never derive a file
path from the request header. No database locale field, Cookie, query parameter,
or translation service is required by this baseline.

## Read The Login Checks

Ordinary account routes show
`context: AuthorizationContext = Depends(get_current_user)` directly. The flow
is JWT/Redis validation in `check_token`, one visible quota call in
`get_current_user`, then one account/role/permission read in `_load_current_user`.
The returned `AuthorizationContext` is not an ORM `User` object.
`token_info: AccessTokenInfo` holds the user ID, login identifier and times parsed
from the signed Token; Redis must still confirm that login remains active.
`LoginInfo` holds the verified Token/session facts; `context.login_info` exposes
them, while `context.user_info` contains the current account state, roles, role
level and permissions from PostgreSQL.

The callback returned by `require_permission` receives `Depends(check_token)`,
calls `rate_limit_user(..., management=management)`, calls `_load_current_user`, then
checks the exact permission. It reuses the Token check and account loader
directly, without another context dependency or a second quota. Permission checks
use ordinary user quotas by default. Built-in user, role and permission management
routes explicitly pass `management=True`, for example
`require_permission(PermissionKey.USERS_READ, management=True)`. An ordinary
business with a permission requirement uses `require_permission(key)`; requiring
a permission does not make the caller an administrator.
Private CAPTCHA uses `get_captcha_user` and its scene quota.
`rate_limit_user` first selects ordinary user or management settings from
`management`, then selects read/write settings from GET/POST. In setting names,
`user` means ordinary authenticated business and `admin` means an explicitly
selected management business; neither determines the caller's role or grants permission.
Authentication functions do not repeat method checks or pass quota-name strings.
Current-session logout uses `Depends(check_token)` directly to validate
JWT/Redis before deleting that login, without a quota, limiter-client dependency,
PostgreSQL query or business-permission check. These paths share the actual checks without adding hidden route
aliases or pass-through dependencies. Business writes still recheck authority
under their existing transaction locks.

## Edit Rate Limits

Defaults live in `app/core/config.py`. Change the corresponding `RATE_LIMIT_*`
values in the deployed `.env`, then restart the service. Show the defaults to
the project owner and agree on changes before generating a new project.

| Operation and independent subject | Environment setting | Default |
| --- | --- | ---: |
| CAPTCHA issue, each scene and trusted IP or current user | `RATE_LIMIT_CAPTCHA_CREATE_PER_FIVE_MINUTES` | 10 / 5 min |
| Missing, unknown or wrong-endpoint CAPTCHA scene, trusted IP or current user | Same CAPTCHA setting; separate rejection key | 10 / 5 min |
| Login, trusted IP | `RATE_LIMIT_LOGIN_IP_PER_FIVE_MINUTES` | 20 / 5 min |
| Public registration, trusted IP | `RATE_LIMIT_REGISTER_IP_PER_HOUR` | 5 / hour |
| Ordinary authenticated GET, with or without a permission check, per operation and user ID | `RATE_LIMIT_USER_READ` | 600 / 60 s |
| Ordinary authenticated POST, with or without a permission check, per operation and user ID | `RATE_LIMIT_USER_WRITE` | 120 / 60 s |
| Management GET, explicitly selected with `management=True`, per operation and user ID | `RATE_LIMIT_ADMIN_READ` | 300 / 60 s |
| Management POST, explicitly selected with `management=True`, per operation and user ID | `RATE_LIMIT_ADMIN_WRITE` | 60 / 60 s |

Redis is dedicated to this service. Counter keys use
`rate_limit:<business>:<subject_type>:<hmac_sha256>`: the fixed `rate_limit`
prefix, the server-owned business name, `ip` or `user_id`, and the full
64-character lowercase hexadecimal digest. The digest uses
`RATE_LIMIT_HMAC_KEY` and HMAC-SHA256 over the UTF-8 business name, subject type,
and trusted canonical IP or authenticated current user ID, separated by zero
bytes (`\x00`). It contains no key prefix or application/environment identifier.
There is no rate-limit namespace configuration or function argument; the current
user, never a target user from the request, selects an authenticated counter.
See [Rate limiting](../../references/rate-limiting.md) for the exact key and
digest contract.

Adopting this counter-key format starts new windows. Previous counters expire
on their existing TTL; there is no compatibility read or active Redis cleanup.
Quota numbers, Lua counting, and request-check order stay the same.

CAPTCHA records use `captcha:<UUID>` in the Redis dedicated to this service.
Each record contains only the bound answer digest and expires after five minutes;
verification atomically retrieves and deletes it, whether the answer is right or wrong.
The digest binds the scene and authenticated user. Image-request and business-request
counts remain in their separate per-business rate-limit keys. A counter-key
change does not change CAPTCHA records or invalidate their existing TTL.

The five CAPTCHA scenes are `login`, `register`, `admin_create_user`,
`admin_reset_user_password`, and `user_change_password`. A missing/unknown scene
or a valid scene submitted to the wrong issue endpoint uses the separate
rejection quota and produces no image.
A valid scene with an invalid unrelated field spends its scene quota, then
returns `422` without an image. Invalid JSON syntax is rejected before
authentication dependencies run.
A limit returns HTTP 429;
unavailable Redis or missing trusted IP fails closed with HTTP 503. Rate limiting
is a mandatory security baseline and has no configuration switch that can disable
it in local, test, or production environments.

## Maintainer Checks Without Database Setup

The generated project includes its own smaller documented test set. The full
asset suite below is for maintaining this reference, not the default burden of
every new service. These offline checks run from the asset folder without
creating a database:

```powershell
python -B -m autopep8 --diff --exit-code --recursive app tests alembic
ruff check --no-cache app tests
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" app tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" tests
pip-audit --local --skip-editable --progress-spinner off
```

### Code Style And Tool Caches

Business Services and Repositories use named classes. Multi-input methods keep
the receiver and first input on the definition line, align remaining inputs on
separate lines, and place the closing parenthesis in that same column. Long
names or annotations can use ordinary hanging indentation. Expand multi-argument
business calls rather than forcing them onto one line.
Long endpoint signatures likewise give each input its own line, and substantial
response/audit mappings give each field its own line. Chinese
docstring prose is indented four spaces inside the triple quotes; parameter and
return fields align with the quotes. `autopep8` preserves that layout; Ruff
checks lint and imports. To apply formatting, replace `--diff --exit-code` above
with `--in-place`. Do not also run `ruff format` or Black on these sources.
The style settings live in `pyproject.toml`.

`.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `__pycache__` and `.pyc` are
generated tool data, not application layers. They are excluded from the asset
and installation package. `.gitignore` alone does not prevent local generation.
This asset disables pytest's cache by default and directs bare Ruff/mypy commands
to `~/.cache/fastapi-templates-xtn/ruff` and `~/.cache/fastapi-templates-xtn/mypy`,
outside the project. The Ruff command above disables its cache; the mypy command
uses an OS temporary folder instead. Python `-B` suppresses bytecode for that
process. For child Python processes in the current shell, use:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:MYPY_CACHE_DIR = "$env:TEMP\fastapi-templates-xtn-mypy-cache"
python -B -m mypy --cache-dir "$env:MYPY_CACHE_DIR" app tests
```

POSIX shell equivalent:

```sh
export PYTHONDONTWRITEBYTECODE=1
export MYPY_CACHE_DIR="${TMPDIR:-/tmp}/fastapi-templates-xtn-mypy-cache"
python -B -m mypy --cache-dir "$MYPY_CACHE_DIR" app tests
```

An editor or a command using different settings can still recreate local caches.
Remove only identified generated cache folders when cleaning a copied project;
never delete source, `.venv`, uploads, logs or application data as cache cleanup.

The test extra requires `pytest>=9.0.3,<10` together with
`pytest-asyncio>=1.4,<2`. Do not lower those ranges or the `pip>=26.2` audit
baseline without rerunning `pip-audit` in the target environment.

The following live-test setup is retained solely for separately requested
maintainer regression; do not run it while generating a project or copy these
fixtures into the output. The user generates and executes their own migrations
and initialization, then validates their own schema. Real Redis-only tests in
this maintenance asset run when a separately confirmed, initially empty
`TEST_CAPTCHA_REDIS_URL` is provided; otherwise they skip. Its logical Redis
database number must differ from both integration targets because the test
intentionally leaves keys behind. Integration tests require a **new empty
database ending in `_test`** and two **different, empty, disposable Redis
targets**. Set
`TEST_DATABASE_URL`, matching `TEST_DISPOSABLE_DATABASE`, `TEST_REDIS_URL`,
`TEST_RATE_LIMIT_REDIS_URL`, and `TEST_REDIS_ISOLATION_CONFIRMED=yes` only
after confirming the database and all Redis targets. Then run
`python -B -m pytest -p no:cacheprovider tests/integration`.
Fixtures migrate, downgrade, truncate, and clear those targets; never aim them
at an existing application database or Redis instance. If integration services
are unavailable, report that PostgreSQL/Redis behavior remains unverified.
