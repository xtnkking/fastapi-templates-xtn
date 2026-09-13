# FastAPI PostgreSQL RBAC Reference Asset

Adapt this runnable baseline to one project. It needs Python 3.12+, PostgreSQL,
and Redis. The files in this folder are not deployment credentials or proof that
an adapted project has passed integration tests.

## Configure And Run

From this folder, install with `python -m pip install -e ".[test]"`. Copy
`.env.example` to an untracked `.env` and replace every example credential and
endpoint. Set `DATABASE_URL` for PostgreSQL/asyncpg, `REDIS_URL` for active JWT
JTI and CAPTCHA state, and preferably a distinct `RATE_LIMIT_REDIS_URL` for
rate-limit counters. Set `APP_ENVIRONMENT` explicitly; there is no default.
Generate two different random values for `JWT_SECRET` and
`RATE_LIMIT_HMAC_KEY` as shown in `.env.example`; example placeholders cannot
start the application. Ask the product owner for a positive
`MAX_ACTIVE_SESSIONS_PER_USER`: these are login sessions, not physical devices.
The Access Token lasts 3600 seconds by default; choose a lifetime appropriate
for this product. Leave `JWT_ISSUER` and `JWT_AUDIENCE` both unset unless the
owner has explicitly accepted the extra issuer/audience restriction.

With your own local database ready, run `alembic upgrade head`, then
`uvicorn app.main:app --reload` for development. Registration initially opens,
but assigns only the `user` role. After the intended first administrator has
registered, have an authorized operator run `sql/bootstrap_super_admin.sql`
against that immutable user ID from a trusted database session. There is no
HTTP super-admin bootstrap or transfer route.

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
| Temporary-password completion, trusted IP | `RATE_LIMIT_TEMPORARY_COMPLETE_IP_PER_FIVE_MINUTES` | 20 / 5 min |
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
ruff format --check app tests
ruff check --no-cache app tests
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" app tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" tests
```

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
