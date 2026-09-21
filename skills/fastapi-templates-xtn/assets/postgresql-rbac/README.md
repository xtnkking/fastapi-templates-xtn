# FastAPI PostgreSQL RBAC Reference Asset

Adapt this runnable baseline to one project. It needs Python 3.12+, PostgreSQL,
and Redis. The files in this folder are not deployment credentials or proof that
an adapted project has passed integration tests. The repository's official CI
combination is Python 3.12, PostgreSQL 17, and Redis 7; test any other versions
in the generated project's own environment before claiming support.

## Source Layout

This asset is a default starting point for a new service without an established
framework. When adding features to an existing application, use its own layout,
components, and transaction conventions; do not replace its application tree
with this asset. Directory reorganization is a separate, explicitly requested
scope. An empty module directory inside an existing project is not a new service.

The application groups modules by responsibility, then by business inside each
directory. `app/main.py` wires the application. The other top-level Python file
is `app/__init__.py`.

```text
app/
  __init__.py
  main.py
  api/                 HTTP routes: authentication and access administration
  core/                Configuration, errors, i18n, logs, middleware, security
  db/                  ORM base, PostgreSQL sessions, Redis clients
  dependencies/        Request, authentication, CAPTCHA, and quota adapters
  models/              Access, account-security, and business-audit tables
  repositories/        Access queries and canonical locking
  schemas/             Authentication and access request/response contracts
  services/            Authentication, access commands, provisioning, audit writer
  assets/locales/      zh-CN and en message catalogs
  commands/passwords.py Offline sole-super-admin password recovery
```

Add later businesses inside these layers, for example `api/orders.py`,
`models/orders.py`, and `services/orders/`. Only create files that own actual
behavior. Simple authorized reads may call a repository directly; a service
owns business transactions and may directly add or update ORM objects. Do not
create a Service pass-through or an ORM wrapper solely to match the tree.
Models and schemas do not import services. Workers and generic utilities are
added only when actual functionality needs them.

## Configure And Run

From this folder, first run
`python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"`,
then reproduce the official Python 3.12/Linux verification environment with
`python -B -m pip install -c constraints-ci-py312.txt -e ".[test]"`. The
project dependency ranges remain the adaptation contract; the constraints file
pins only the repository's verified CI resolution. Copy
`.env.example` to an untracked `.env` and replace every example credential and
endpoint. New projects default to one standalone PostgreSQL and one standalone
Redis. Set `DATABASE_URL` for PostgreSQL/asyncpg and `REDIS_URL` for login state,
CAPTCHA, and quotas; no cluster settings or second Redis are needed.
Only if requested, use a distinct `RATE_LIMIT_REDIS_URL` for rate-limit counters.
For explicitly requested or existing Sentinel/Cluster, replace the main URL with
`REDIS_CONNECTION__...` settings in the
[connection examples](../../references/redis-connections.md); do not configure
both. Without a limiter override, its separate client inherits the whole main
connection configuration. Set `APP_ENVIRONMENT` explicitly; there is no default.
Generate two different random values for `JWT_SECRET` and
`RATE_LIMIT_HMAC_KEY` as shown in `.env.example`; example placeholders cannot
start the application. Ask the product owner for a positive
`MAX_ACTIVE_SESSIONS_PER_USER`: these are login sessions, not physical devices.
Ask whether administrator password reset uses `direct` (the default permanent
password) or `temporary` (one required formal-password setup), then set
`ADMIN_PASSWORD_RESET_MODE`. This is one project-wide policy; the reset request
cannot choose it. `direct` is simpler but the administrator knows and privately
delivers the final password; `temporary` adds a step but lets the user choose
the final password. Administrator-created new users still start with a temporary
password in either mode.
The Access Token lasts 86,400 seconds (24 hours) by default. Shorten it for
high-risk or administrative surfaces, and choose a lifetime appropriate for
this product. Leave `JWT_ISSUER` and `JWT_AUDIENCE` both unset unless the
owner has explicitly accepted the extra issuer/audience restriction.

If using the optional local Compose file,
`docker compose -f compose.dev.yaml up -d` starts only PostgreSQL and one Redis.
Only for a requested separate limiter backend, add `--profile separate-rate-limit`
before `up -d` and uncomment `RATE_LIMIT_REDIS_URL` in your local configuration.

With your own local database ready, run `alembic upgrade head`, then
`uvicorn app.main:app --reload` for development. Registration initially opens,
but assigns only the `user` role. After the intended first administrator has
registered, have an authorized operator run `sql/bootstrap_super_admin.sql`
against that immutable user ID from a trusted database session. There is no
HTTP super-admin bootstrap or transfer route.

If the sole super administrator later needs offline password recovery, an
authorized operator can run
`python -B -m app.commands.passwords --user-id <canonical-users.id>` from this
folder. The command prompts privately for the new temporary password; it never
accepts a password argument. This recovers the existing holder and does not
create or transfer super-administrator authority.

`GET /health/live` confirms only that the application process can answer.
`GET /health/ready` concurrently checks PostgreSQL, active-JTI Redis, and the
rate-limit Redis with the configured bounded timeout. PostgreSQL must report a
writable primary and have the single expected Alembic head and the readable
global `rbac_state` row, so the
runtime database role needs `SELECT` access to `alembic_version` as well as the
application tables. Each Redis must allow `PING` and a one-key Lua write/read/delete
probe; the probe uses a random non-secret key, deletes it atomically on success,
and gives an interrupted key a five-second TTL. The response exposes only the
overall ready/unavailable result, never per-component states, connection strings,
keys, or exception details. Use readiness, not liveness, to decide whether a
deployment should receive traffic.

## Capacity And Multiple Instances

Pool and timeout defaults live in `app/core/config.py`; their environment
overrides are listed in `.env.example`:

| Setting | Default |
| --- | ---: |
| `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW` | 5 / 5 connections per process |
| `DATABASE_POOL_TIMEOUT_SECONDS` / `DATABASE_CONNECT_TIMEOUT_SECONDS` | 5 / 5 seconds |
| `DATABASE_COMMAND_TIMEOUT_SECONDS` | 20 seconds per driver command and checkout probe |
| `DATABASE_STATEMENT_TIMEOUT_MS` / `DATABASE_LOCK_TIMEOUT_MS` | 15000 / 3000 milliseconds |
| `REDIS_MAX_CONNECTIONS` | 50 per client, per node, per process |

PostgreSQL's app ceiling is `instances * workers * (pool_size + max_overflow)`:
two instances with four workers each can use 80 connections at these defaults.
Leave room for other applications, maintenance, migrations, and overlapping
workers during deployment. Each worker also has two Redis clients, even when both
target the same server. Cluster adds a pool per node and Sentinel has separate
discovery pools; count their combined budget. Keep lock
timeout no larger than statement timeout and fit all waits inside the deployment
request deadline. Classified exhaustion and dependency timeouts fail with safe
`503001`; the app does not automatically replay arbitrary writes.

The command timeout bounds client network waits that PostgreSQL's own statement
timeout cannot stop when replies never arrive. It is not a 20-second total
request or transaction limit: multiple SQL commands and SQLAlchemy prepare/
execute stages have separate budgets. Set any end-to-end request deadline in
the actual deployment. Built-in `pool_pre_ping` is disabled; a bounded asyncpg
`SELECT 1` checks every checkout, including new connections, without starting
an explicit transaction. Only a detected disconnection during this preflight
may reconnect automatically; business SQL is never replayed.

A driver deadline maps to `503001` at the database boundary and retires only
that connection, using local `terminate()` so broken-network cancellation/close
cannot hold cleanup indefinitely. External task cancellation propagates, and
an unrelated application `TimeoutError` retains normal `500` handling. If a
commit times out, the write may already have succeeded: verify authoritative
business state before retrying. Neither this timeout nor readiness provides
automatic database failover. See
[Capacity and availability](../../references/application-capacity-and-availability.md)
for the full boundaries and verification requirements.

All instances must share their authoritative PostgreSQL and Redis targets,
secrets, namespaces, session/claim/quota policy, trusted-proxy interpretation,
and synchronized clocks. Set `DATABASE_URL` to the stable writable endpoint
provided by operations; operations owns replication, promotion, and endpoint
failover. The app handles bounded waits, bad connections, reconnection, and
transaction failures without replaying writes. Read/write splitting requires an
explicit need and an agreed deployment design; it is not enabled by default.
Current authentication and RBAC reads use the primary, including behind a proxy
that must not send every `SELECT` to a replica. There is no local positive JTI
cache. Optional business replicas serve only selected lag-tolerant reads.
The global authorization lock serializes its
protected writes; more workers do not remove that limit, and unrelated business
writes should not acquire it by default.

The Redis factory supports standalone, Sentinel master discovery, and native
Cluster routing with primary reads. Shared session scripts use three same-slot
keys per user; quota scripts use one distributed key. CAPTCHA refresh keeps its
namespace in one slot for atomic replacement, so this path is not horizontally
distributed. Connection errors do not automatically replay writes. The new
`auth:sessions:v2` format requires existing users to log in again, and quota
key changes start fresh windows once; no database migration is required.
See [Redis connections](../../references/redis-connections.md) for configuration
and test commands. Operators own the chosen load balancer, process supervision, dependency replication,
failover, and backup/recovery. Readiness and load results do not prove those
systems are highly available. Production topology and zero-downtime release
decisions belong to the adopter; they are not prerequisites for ordinary coding
tasks. The load tool below is optional for a requested performance investigation.

### Bounded Runtime Logging

Runtime events are safely formatted in the emitting thread and passed as final
JSON strings to one bounded background stdout writer per process. Configuration
is in `app/core/config.py` and `.env.example`: `LOG_QUEUE_CAPACITY=1000` (at most
10000 events) and `LOG_SHUTDOWN_TIMEOUT_SECONDS=2` (0..30 seconds). Individual
events are capped at 16 KiB. Full queues, oversized events, or shutdown can drop
runtime logs; a blocked sink never triggers a synchronous fallback. Internal
loss/output counters are available through `app.state.log_handler.snapshot()`.
Shutdown drains for at most the configured interval; stdout already blocked in
the daemon writer cannot be forcibly interrupted. This is not durable delivery.
Database audits do not use this queue. Read
[Operational logging](../../references/operational-logging.md) before adapting it.

### Bounded Read Load Check

With the test extra installed, set `LOAD_TEST_BEARER_TOKEN` privately in the
process environment to a valid test account's Access Token. Then run from this
folder against a test service you own or are authorized to load-test. Every
`--url` must be a trusted endpoint: each receives the same bearer Token. Start
with small values; a production load run needs explicit authorization.

```powershell
python -B scripts/load_test.py --url http://127.0.0.1:8000/api/v1/me/access --requests 100 --concurrency 5 --timeout 10 --token-env LOAD_TEST_BEARER_TOKEN
```

Run a small warm-up separately, compare increasing concurrency, then use duration
mode for a sustained read test, for example:

```powershell
python -B scripts/load_test.py --url http://127.0.0.1:8000/api/v1/me/access --duration 60 --concurrency 10 --timeout 10 --token-env LOAD_TEST_BEARER_TOKEN
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
The script does not provision accounts, disable security, or simulate failover.
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
Database-authored product content and OpenAPI developer metadata are outside
this runtime message module and are not translated by it.

To add another language, update the static registry in `app/core/i18n.py`, add a
complete UTF-8 JSON file under `app/assets/locales/`, and add parser, catalog-parity,
response-header, error, validation, and concurrency tests. Never derive a file
path from the request header. No database locale field, Cookie, query parameter,
or translation service is required by this baseline.

## Edit Rate Limits

Defaults live in `app/core/config.py`. Change the corresponding `RATE_LIMIT_*`
values in the deployed `.env`, then restart the service. Show the defaults to
the project owner and agree on changes before generating a new project.

| Operation and independent subject | Environment setting | Default |
| --- | --- | ---: |
| CAPTCHA issue/refresh, each scene and trusted IP or actor | `RATE_LIMIT_CAPTCHA_CREATE_PER_FIVE_MINUTES` | 10 / 5 min |
| CAPTCHA scene at wrong issue endpoint or parsed invalid CAPTCHA body, trusted IP or actor | Same CAPTCHA setting; separate rejection key | 10 / 5 min |
| Login, trusted IP | `RATE_LIMIT_LOGIN_IP_PER_FIVE_MINUTES` | 20 / 5 min |
| Public registration, trusted IP | `RATE_LIMIT_REGISTRATION_IP_PER_HOUR` | 5 / hour |
| Temporary-password completion for administrator-created users or optional temporary reset, trusted IP | `RATE_LIMIT_TEMPORARY_COMPLETE_IP_PER_FIVE_MINUTES` | 20 / 5 min |
| Authenticated ordinary read/write, operation and actor ID | `RATE_LIMIT_AUTHENTICATED_READ_PER_MINUTE` / `RATE_LIMIT_ORDINARY_WRITE_PER_MINUTE` | 600 / min; 120 / min |
| Administrative read/change, operation and actor ID | `RATE_LIMIT_MANAGEMENT_READ_PER_MINUTE` / `RATE_LIMIT_AUTHORIZATION_WRITE_PER_MINUTE` | 300 / min; 60 / min |

The five CAPTCHA scenes are `login`, `register`, `admin_create`, `admin_reset`,
and `self_change`. A valid scene submitted to the wrong issue endpoint or a
parsed request with invalid fields is rejected without an image and does not
spend a normal issuance quota. Invalid JSON syntax is rejected before
authentication dependencies run.
There is no all-site or shared all-user quota. A limit returns HTTP 429;
unavailable Redis or missing trusted IP fails closed with HTTP 503. Production
cannot set `RATE_LIMIT_ENABLED=false`; the local/test escape hatch must not be
used for deployment.

## Test Without Touching Project Data

Run these offline checks from the asset folder:

```powershell
ruff format --check --no-cache app tests
ruff check --no-cache app tests
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" app tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" tests
pip-audit --local --skip-editable --progress-spinner off
```

The test extra requires `pytest>=9.0.3,<10` together with
`pytest-asyncio>=1.4,<2`. Do not lower those ranges or the `pip>=26.2` audit
baseline without rerunning `pip-audit` in the target environment.

Real Redis-only tests run when a separately confirmed, initially empty
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
