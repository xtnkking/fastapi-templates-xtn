# FastAPI PostgreSQL RBAC Reference Asset

Adapt this runnable baseline to one project. It needs Python 3.12+, PostgreSQL,
and Redis. The files in this folder are not deployment credentials or proof that
an adapted project has passed integration tests. The repository's official CI
combination is Python 3.12, PostgreSQL 17, and Redis 7; test any other versions
in the generated project's own environment before claiming support.

## Configure And Run

From this folder, first run `python -B -m pip install --upgrade "pip>=26.2"`,
then install with `python -B -m pip install -e ".[test]"`. Copy
`.env.example` to an untracked `.env` and replace every example credential and
endpoint. Set `DATABASE_URL` for PostgreSQL/asyncpg, `REDIS_URL` for active JWT
JTI and CAPTCHA state, and preferably a distinct `RATE_LIMIT_REDIS_URL` for
rate-limit counters. Set `APP_ENVIRONMENT` explicitly; there is no default.
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
The Access Token lasts 3600 seconds by default; choose a lifetime appropriate
for this product. Leave `JWT_ISSUER` and `JWT_AUDIENCE` both unset unless the
owner has explicitly accepted the extra issuer/audience restriction.

With your own local database ready, run `alembic upgrade head`, then
`uvicorn app.main:app --reload` for development. Registration initially opens,
but assigns only the `user` role. After the intended first administrator has
registered, have an authorized operator run `sql/bootstrap_super_admin.sql`
against that immutable user ID from a trusted database session. There is no
HTTP super-admin bootstrap or transfer route.

`GET /health/live` confirms only that the application process can answer.
`GET /health/ready` concurrently checks PostgreSQL, active-JTI Redis, and the
rate-limit Redis with the configured bounded timeout. PostgreSQL must have the
single expected Alembic head and the readable global `rbac_state` row, so the
runtime database role needs `SELECT` access to `alembic_version` as well as the
application tables. Each Redis must allow `PING` and a one-key Lua write/read/delete
probe; the probe uses a random non-secret key, deletes it atomically on success,
and gives an interrupted key a five-second TTL. The response exposes only the
overall ready/unavailable result, never per-component states, connection strings,
keys, or exception details. Use readiness, not liveness, to decide whether a
deployment should receive traffic.

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

To add another language, update the static registry in `app/i18n.py`, add a
complete UTF-8 JSON file under `app/locales/`, and add parser, catalog-parity,
response-header, error, validation, and concurrency tests. Never derive a file
path from the request header. No database locale field, Cookie, query parameter,
or translation service is required by this baseline.

## Edit Rate Limits

Defaults live in `app/settings.py`. Change the corresponding `RATE_LIMIT_*`
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
