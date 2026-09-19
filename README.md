# fastapi-templates-xtn

**English** | [简体中文](README.zh-CN.md)

A Codex Skill maintained by XTN for single-project FastAPI services with
PostgreSQL RBAC, a strict administrative hierarchy, username/password login,
graphical CAPTCHA, Redis-gated Access Tokens, per-business rate limits,
structured logging, and separate durable audits.

## Status

`v0.5.1` is the latest published tag. Install the tagged release for a
reproducible baseline; later `main` changes may not be released yet.

## Upstream And Attribution

This Skill independently extends
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
from [`wshobson/agents`](https://github.com/wshobson/agents), based on commit
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`. The upstream work is
Copyright (c) 2024 Seth Hobson under MIT. XTN's additions are independently
maintained and are not affiliated with or endorsed by upstream. Preserve
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Baseline In v0.5.1

- Greenfield services use only `user_name` and password, not email login or
  self-service forgot-password. Usernames trim edge whitespace, require 3..32
  ASCII letters/digits/underscores, reject 12 reserved complete names, and
  cannot be reused after soft deletion. Ask the project owner whether casing
  matters; preserve a pre-existing project's intentional identity contract.
  Passwords default to 8..60 characters and three simple weak-pattern checks;
  ask whether to require upper/lowercase, digits, or symbols.
- Public registration is enabled by default, but `super_admin` may turn off its
  persisted server-side switch. `GET /api/v1/auth/registration/status` returns
  only `registration_enabled` to anonymous callers; only the current
  `super_admin` may use `POST` on that path to change it. Closing signup does
  not close existing-user login or authorized administrator creation. Both
  creation paths bind only `user`.
  Ordinary business reads and writes are never anonymous by default.
- Five fixed graphical-CAPTCHA scenes protect login, registration, admin user
  creation, admin password reset, and self password change: `login`, `register`,
  `admin_create`, `admin_reset`, and `self_change`. The first two use public
  `POST /api/v1/auth/captcha`; the other three use authenticated
  `POST /api/v1/me/captcha`. A challenge expires after five minutes and is
  atomically consumed on every submission, whether
  the answer is right or wrong. Refresh replaces only the matching old image.
  Authenticated scenes bind to the current server-authenticated user ID.
  CAPTCHA issuance/refresh is limited to 10 per scene and subject per five
  minutes by default. A valid scene sent to the wrong issue endpoint is denied
  without creating an image and has a separate per-subject rejection quota.
  Email/SMS and MFA providers are not bundled into the
  baseline; a product that needs them designs them separately.
- A user may leave only the current login. Authorized administrators may force
  a strictly lower target's logins out after current RBAC checks and audit.
  Ask each project owner for a positive maximum simultaneous login count;
  the bundled settings do not support an unlimited value. Redis stores
  active JTI records with login timestamps and atomically evicts the oldest
  when a successful new login reaches that limit. This does not identify
  physical devices. Password changes/reset also invalidate old Tokens.
- Exactly one `super_admin` exists after the initial operator-run SQL bootstrap.
  Changing that holder is another guarded, audited offline PostgreSQL script,
  never an HTTP transfer route. The immutable `admin` and `user` system roles,
  ten-live-role maximum, strict lower-only administration, anti-self-elevation,
  soft deletion, and PostgreSQL transaction/audit coupling remain enforced.
  A grantor can grant only permissions it currently holds; there is no separate
  `can_delegate` switch or delegation-management API.
- JWT defaults to one configurable hour and only `sub`, `jti`, `iat`, `exp`, and
  `token_type`. `sub` is a non-sequential immutable user ID. `iss`/`aud` may be
  added together only after explicit project-owner consent. Redis must contain
  the active JTI for every accepted Token; PostgreSQL still supplies current
  user status and authority. There is no second token-issuance flow or
  per-Token PostgreSQL table.
- Redis fixed-window quotas are independent for each operation and subject:
  anonymous authentication uses trusted IP, authenticated operations use the
  actor's immutable user ID. There are **no global or cross-business quotas**,
  no anonymous username buckets, and no shared `/api/` IP bucket. A valid
  over-limit decision is `429001` with `Retry-After`; Redis/IP authority
  failure is fail-closed `503001`. All settings are editable in `app/settings.py`
  and `.env.example`; defaults are listed below and must be shown to the
  project owner before generating a service.
- Every ordinary JSON API response has `code` (six-digit number), `message`,
  `data`, and a server-generated `request_id`; the same ID is in
  `X-Request-ID`. Structured operational logs, append-only `rbac_audit_events`,
  account-security audits, and opt-in catalogued business audits have separate
  responsibilities. No password, JWT/JTI, or raw request body belongs in logs
  or audit snapshots.

| Separate operation | Default |
| --- | ---: |
| Graphical CAPTCHA issue/refresh, per scene | 10 / 5 min |
| CAPTCHA scene at wrong issue endpoint, per trusted IP or actor | 10 / 5 min |
| Login, per trusted IP | 20 / 5 min |
| Registration, per trusted IP | 5 / hour |
| Temporary-password completion, per trusted IP | 20 / 5 min |
| Authenticated ordinary read / write, per operation and actor | 600 / min; 120 / min |
| Admin read / change, per operation and actor | 300 / min; 60 / min |

See [the canonical quota contract](skills/fastapi-templates-xtn/references/rate-limiting.md)
for the atomic Redis implementation and failure behavior. Values are starting
points, not fixed security guarantees; adjust actual deployment `.env` values
and restart. For large shared-NAT audiences, a per-IP public limit can affect
legitimate users. Never solve that by trusting unverified forwarding headers.

The bundled reference asset is deliberately not every product: the optional
[proxy availability guide](skills/fastapi-templates-xtn/references/proxy-availability-detection.md)
and [country catalog guide](skills/fastapi-templates-xtn/references/country-catalog.md)
are loaded only on request. Neither makes ordinary business reads anonymous,
and neither creates a global API quota. The country dataset is not bundled.

## Install

Install the immutable latest published release:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.5.1/skills/fastapi-templates-xtn
```

The installer does not overwrite an installed Skill. Back up local changes
before replacing it. A repository-scoped installation can copy
`skills/fastapi-templates-xtn` into `.agents/skills/fastapi-templates-xtn`.

## Use And Verify

Use `$fastapi-templates-xtn` for a FastAPI PostgreSQL RBAC project; it is not
automatically selected for unrelated FastAPI or optional proxy/country work.
Start with the [Chinese architecture overview](skills/fastapi-templates-xtn/references/architecture-overview.zh-CN.md)
for the module boundaries, request flow, tables, and API inventory. Detailed
English references remain the executable specification loaded by the Skill on
demand.

The official verification environment is Python 3.12, PostgreSQL 17, and
Redis 7. A generated project may support other versions only after that project
tests them; this repository does not claim those combinations are verified.
`GET /health/live` reports only that the process is alive. `GET /health/ready`
requires PostgreSQL to report exactly Alembic head `0004_password_auth` and a
readable `rbac_state(scope='global')` row. It also requires both the active-JTI
and rate-limit Redis targets to pass `PING` plus a Lua write/read/delete probe
using a random, non-secret key with a five-second TTL. Checks use bounded
timeouts; the response exposes only the overall ready/unavailable result with
`Cache-Control: no-store`, never component details, keys, URLs, or exceptions.
Readiness, not liveness, should control deployment traffic.
The supplied Compose file and dedicated disposable-test checks support
integration verification.
See the [asset setup and quota guide](skills/fastapi-templates-xtn/assets/postgresql-rbac/README.md)
before adapting or running the copied service.

From this repository root:

```powershell
python -B -m pip install --upgrade "pip>=26.2"
python -B -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff format --check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
pip-audit --local --skip-editable --progress-spinner off
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/validate_release.py
```

The `v0.5.1` test baseline requires `pytest>=9.0.3,<10` together with
`pytest-asyncio>=1.4,<2`; do not lower those ranges or the `pip>=26.2` audit
baseline without rerunning the dependency audit.

Run PostgreSQL/Redis migration, concurrency, authentication, CAPTCHA, and
quota tests against **fresh disposable targets only**. Never aim the test suite
at a database containing real project data. A generated project is not
production-ready until its target deployment and integration behaviors pass.
See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before publishing a new tag.

## Governance And License

The canonical [XTN repository](https://github.com/xtnkking/fastapi-templates-xtn)
is maintained solely by XTN. Issues and private security reports are welcome;
external pull requests are not accepted. Downloaded forks may be modified and
redistributed under the applicable licenses but are not official releases.
Except for identified third-party portions, XTN's additions use Apache-2.0;
upstream and adapted Alembic material retain MIT notices. See [LICENSE](LICENSE),
[CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
