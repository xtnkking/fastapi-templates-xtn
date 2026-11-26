# fastapi-templates-xtn

**English** | [简体中文](README.zh-CN.md)

A Codex Skill maintained by XTN for single-project FastAPI services with
PostgreSQL RBAC, a strict administrative hierarchy, username/password login,
graphical CAPTCHA, Redis-gated Access Tokens, per-business rate limits,
structured logging, and separate durable audits.

## Status

`v0.7.0` is the latest published tag; the authoritative version value is in
[`skills/fastapi-templates-xtn/VERSION`](skills/fastapi-templates-xtn/VERSION).
Install this immutable tag for the current baseline.

Unreleased local changes introduce [curated new-project delivery](skills/fastapi-templates-xtn/references/new-project-delivery.md):
runtime code, ORM models, one concise Chinese README and focused offline tests.
Users generate, review and execute their own migration files and prepare initial
data. The Skill does not create tables or export migration history, SQL/bootstrap
tools, the full maintainer suite or caches. Existing applications are preserved.
Generated projects omit standalone source manifests, database handoff and legal
files. Essential database prerequisites and necessary copied-code license text
stay in the README, with license text collapsed; this does not assign an
open-source license to the user's business application. Dependency configuration
remains, and existing projects' documents are not automatically deleted.
See [new-project delivery](skills/fastapi-templates-xtn/references/new-project-delivery.md)
for the output contract; these changes are not yet in the published download.

The unreleased template also follows the approved auth_pay entrypoint style:
`main.py` shows lifecycle and explicit handler, middleware and router assembly;
request logging and error responses have separate owners.
See [reuse and abstraction](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md)
for the maintained ownership and call-flow conventions.

Current source also uses the same `auth` name across routes, schemas, dependencies
and `AuthService`. Shared response, logging, username and route-validation modules
use direct names; the generated README points to each owner. Authentication routes
declare named limit and scene-bound CAPTCHA dependencies, then call business
Services directly. CAPTCHA checks only read challenge fields and the previously
authenticated user; limits and permissions remain separate route dependencies
declared before CAPTCHA. Response composition stays in routes.
Their server-side route names come from clear handler names, and password policy receives one optional
username instead of a generic identity collection. The generator's help explains
every required option and its accepted format before it writes files.
These changes are part of Unreleased, not the `v0.7.0` download.

`v0.7.0` keeps new projects simple: one standalone PostgreSQL and one shared
standalone Redis. Sentinel, Cluster, read/write splitting, and separate backends
remain opt-in. It adds responsibility-based source directories, bounded
connections and timeouts, safer concurrent work and logging, and tested Redis
client/script adaptations. Infrastructure deployment remains operator-owned.
See [the changelog](CHANGELOG.md) for details and `RELEASE_CHECKLIST.md` for
release evidence; the earlier [v0.6.1 optimization plan](V0.6.1_OPTIMIZATION_PLAN.zh-CN.md)
is retained as a historical repair record.

Updating this Skill alone does not change a running application. Deploying its
new session implementation to an existing application requires users to log in
again, and the changed rate-limit keys start fresh windows once. Account data
and PostgreSQL schema are unchanged; no new Alembic migration is needed.

Administrator creation, password reset, and offline recovery of the sole
`super_admin` set a password that can be used immediately. Password delivery
remains private; CAPTCHA, capability and strict-lower checks, old-Token
revocation, atomic audit, and secret-free responses/logs remain in place.

`v0.6.0` also adds request-level API internationalization. Every
client-facing runtime response message, including safe validation details,
supports default `zh-CN` and requested `en` through `Accept-Language`.
Responses declare `Content-Language` and `Vary: Accept-Language`; status codes,
numeric business codes, data, request IDs, logs, audit fields, and internal
reason codes remain language-independent. Additional languages are explicit
project extensions. Database-authored product content and static schema
descriptions are not translated by this module.

## Upstream And Attribution

This Skill independently extends
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
from [`wshobson/agents`](https://github.com/wshobson/agents), based on commit
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`. The upstream work is
Copyright (c) 2024 Seth Hobson under MIT. XTN's additions are independently
maintained and are not affiliated with or endorsed by upstream. Preserve
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Current Baseline

- Greenfield services use only `user_name` and password, not email login or
  self-service forgot-password. Usernames trim edge whitespace, require 3..32
  ASCII letters/digits/underscores, reject 12 reserved complete names, and
  cannot be reused after soft deletion. Ask the project owner whether casing
  matters; preserve a pre-existing project's intentional identity contract.
  Passwords default to 8..60 characters and three simple weak-pattern checks;
  ask whether to require upper/lowercase, digits, or symbols.
- Public registration remains available without a backend switch or registration-status
  endpoint. It still requires its own CAPTCHA and per-IP rate limit. Public registration
  and authorized administrator creation both bind only `user`.
  Ordinary business reads and writes are never anonymous by default.
- New-project business APIs use only GET/POST and static paths: list/detail
  reads end in `/list` or `/detail` and take query parameters; POST commands
  take target IDs and other inputs in validated JSON. Endpoints are grouped
  into authentication, current account, managed users, roles and permissions.
  Authentication and target authorization remain required regardless of where
  the input is placed. Existing projects retain their intentional contracts
  unless the owner asks to change them.
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
- Exactly one `super_admin` exists after the developer's manual database binding.
  Changing that holder is another user-owned guarded, audited offline action,
  never an HTTP transfer route. The immutable `admin` and `user` system roles,
  ten-live-role maximum, strict lower-only administration, anti-self-elevation,
  soft deletion, and PostgreSQL transaction/audit coupling remain enforced.
  A grantor can grant only permissions it currently holds; there is no separate
  `can_delegate` switch or delegation-management API.
- JWT defaults to a configurable 24 hours and only `sub`, `jti`, `iat`, `exp`, and
  `token_type`. `sub` is a non-sequential immutable user ID. `iss`/`aud` may be
  added together only after explicit project-owner consent. Redis must contain
  the active JTI for every accepted Token; PostgreSQL still supplies current
  user status and authority. A stolen Token can still be replayed while its JTI
  remains active, so high-risk or administrative surfaces should shorten the
  24-hour default. There is no second token-issuance flow or per-Token
  PostgreSQL table.
- Redis fixed-window quotas are independent for each operation and subject:
  anonymous authentication uses trusted IP, authenticated operations use the
  actor's immutable user ID. There are **no global or cross-business quotas**,
  no anonymous username buckets, and no shared `/api/` IP bucket. A valid
  over-limit decision is `42901` with `Retry-After`; Redis/IP authority
  failure is fail-closed `50301`. All settings are editable in `app/core/config.py`
  and `.env.example`; defaults are listed below and must be shown to the
  project owner before generating a service.
- Every ordinary JSON API response has `code` (five-digit number), `message`,
  `data`, and a server-generated `request_id`; the same ID is in
  `X-Request-ID`. File logs are separate from the unified append-only
  `operation_audit_events` account/permission evidence. Requests and business
  result snapshots are bounded and redacted; new-password comparison uses an
  independent keyed fingerprint. General business audit is opt-in and excluded
  from default export. No plaintext password, JWT/JTI or raw request dump belongs
  in logs or audit snapshots.

| Separate operation | Default |
| --- | ---: |
| Graphical CAPTCHA issue/refresh, per scene | 10 / 5 min |
| CAPTCHA scene at wrong issue endpoint, per trusted IP or actor | 10 / 5 min |
| Login, per trusted IP | 20 / 5 min |
| Registration, per trusted IP | 5 / hour |
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

Install the immutable latest published release for a new destination:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.7.0/skills/fastapi-templates-xtn
```

The installer does not overwrite an installed Skill and must not be described as
an updater. For an existing installation, use the staged, hash-checked,
rollback-capable procedure in [Install And Update](INSTALL.md). It preserves the
complete old directory as a timestamped backup. A repository-scoped installation
uses the same updater with the exact target
`.agents/skills/fastapi-templates-xtn`.

## Use And Verify

Use `$fastapi-templates-xtn` for a FastAPI PostgreSQL RBAC project; it is not
automatically selected for unrelated FastAPI or optional proxy/country work.
Start with the [Chinese architecture overview](skills/fastapi-templates-xtn/references/architecture-overview.zh-CN.md)
for the module boundaries, request flow, tables, and API inventory. Detailed
English references remain the executable specification loaded by the Skill on
demand.

Permission definitions live in
[`app/core/access/permissions.py`](skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/access/permissions.py),
grouped by business; system-role specifications and grants live in
[`app/core/access/roles.py`](skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/access/roles.py).
`PERMISSION_CATALOG` values are description message keys. Prepare initial text
with `get_permission_description(key)` (Chinese by default); built-in descriptions
follow the request language, while permission codes and custom database text remain stable.
Add both locale entries for each new permission description, following
[API internationalization](skills/fastapi-templates-xtn/references/api-internationalization.md).

For code changes, the [reuse and abstraction rules](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md)
explain when to share a parameterized implementation, keep simple code inline,
or retain a function that owns a security, transaction, or framework boundary.

For an empty project without an established framework, the optional default is
the [responsibility-first layout](skills/fastapi-templates-xtn/references/project-structure.md):
`api`, `core`, `db`, `dependencies`, `models`, `repositories`, `schemas`, and
`services`. As businesses grow, add modules or packages inside these layers.
Use `api/v1/endpoints/<business>.py`, `services/<business>_service.py`,
`repositories/postgres/<business>_repository.py`, and
`models/postgres/<business>.py`; create other database categories only when used.
Every delivered Python function has a clear multi-line docstring explaining its
purpose, parameters and return/yield value, following the default
[Chinese comment format](skills/fastapi-templates-xtn/references/python-comments.md).
The same guide covers aligned method inputs, individually readable long endpoint
inputs and response/audit mappings. Comments explain actual permissions, field
meaning and execution order, including when deferred callbacks run. Public
`Field`/`Query` descriptions explain validation metadata in source. New projects
disable `/docs`, `/redoc`, and `/openapi.json`; `Accept-Language` selects only
Chinese/English runtime text, including built-in permission descriptions.
Create workers and utilities only for actual implementations. Business endpoints
call named Services that own pagination, business errors and result construction;
SQL belongs to their Repositories. Do not add a Service that merely forwards
to another Service or a setter for each already-locked ORM field.
Existing applications retain their framework, directories, and call conventions;
integrate the requested feature into them. Using this Skill does not authorize
a rewrite or wholesale template replacement. Reorganization requires an explicit
request for that scope.

This Skill focuses on code conventions and correctness. Zero-downtime updates,
cluster operations, production sizing, and recovery exercises are project-owner
choices, not default implementation tasks or delivery gates. For connection
pools, timeouts, shared process state, or a measured bottleneck, load
[Capacity and availability](skills/fastapi-templates-xtn/references/application-capacity-and-availability.md).
New projects default to one standalone PostgreSQL and one standalone Redis,
configured through `DATABASE_URL` and `REDIS_URL`; login state, CAPTCHA, and
quotas share Redis. The bundled code supports one PostgreSQL endpoint and standalone
Redis only; Sentinel, Cluster, node discovery and read/write splitting are not
built in. An adopter who needs a cluster implements and verifies that integration
in their own project. Existing projects retain their current topology; a second
standalone Redis for quotas is optional, as described in
[connection settings](skills/fastapi-templates-xtn/references/redis-connections.md).
Existing runtime safeguards, concurrency tests, and
the optional GET load tool remain available; no production platform is required.

The official verification environment is Python 3.12, PostgreSQL 17, and
Redis 7. A generated project may support other versions only after that project
tests them; this repository does not claim those combinations are verified.
The default project includes no `/health/live` or `/health/ready` endpoint.
Add deployment probes only when the adopter explicitly requests them, and
restrict access to an internal network or trusted probes. Any requested checks
must use bounded timeouts, avoid exposing dependency details, and never create
or repair database state.
The supplied Compose file and dedicated disposable-test checks support
integration verification.
See the [asset setup and quota guide](skills/fastapi-templates-xtn/assets/postgresql-rbac/README.md)
before adapting or running the copied service.

Maintainers follow the canonical [Skill](skills/fastapi-templates-xtn/SKILL.md)
and its [reuse and abstraction guidance](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md).
Local agent configuration and private maintenance records are not published or
exported into generated applications.

From this repository root:

```powershell
python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"
python -B -m pip install -c skills/fastapi-templates-xtn/assets/postgresql-rbac/constraints-ci-py312.txt "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
python -B -m autopep8 --diff --exit-code --recursive skills/fastapi-templates-xtn/assets/postgresql-rbac
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
pip-audit --local --skip-editable --progress-spinner off
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/test_update_installed_skill.py
python -B scripts/test_validate_ci_environment.py
python -B scripts/validate_asset_wheel.py skills/fastapi-templates-xtn/assets/postgresql-rbac skills/fastapi-templates-xtn/VERSION
python -B scripts/validate_release.py
```

The project metadata intentionally keeps bounded dependency ranges for adapted
projects. Official Python 3.12/Linux verification additionally uses
`constraints-ci-py312.txt`, so rerunning the same repository revision does not
silently select newer dependencies. Regenerate those exact pins deliberately;
do not change them without rerunning the dependency audit and full suite.

Run PostgreSQL/Redis migration, concurrency, authentication, CAPTCHA, and
quota tests against **fresh disposable targets only**. Never aim the test suite
at a database containing real project data. Report code-test evidence accurately;
production deployment validation remains the adopter's responsibility.
See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before publishing a new tag.

## Governance And License

The canonical [XTN repository](https://github.com/xtnkking/fastapi-templates-xtn)
is maintained solely by XTN. Issues and private security reports are welcome;
external pull requests are not accepted. Downloaded forks may be modified and
redistributed under the applicable licenses but are not official releases.
Except for identified third-party portions, XTN's additions use Apache-2.0;
upstream and adapted Alembic material retain MIT notices. See [LICENSE](LICENSE),
[CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
