---
name: fastapi-templates-xtn
description: Build or harden a single-project FastAPI service that explicitly adopts this opinionated PostgreSQL 17, Redis 7, local username/password, fixed hierarchical RBAC, Redis-gated JWT, CAPTCHA, bilingual API-message, logging, and audit baseline. Use when the user names this Skill or asks for this exact architecture; do not auto-apply it to generic FastAPI/RBAC work, other identity providers, non-PostgreSQL/Redis systems, or a different authorization model.
---

# FastAPI Templates XTN

> Independently maintained by XTN as an extension of [`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates).
> See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md).

## Scope And Starting Point

This Skill owns application code conventions and the documented single-project
baseline. Infrastructure operations, capacity certification, zero-downtime
deployment and recovery drills are outside an ordinary coding task.

For an existing project, inspect the requested code's owners, direct dependencies
and relevant tests; preserve its architecture, topology and intentional contracts.
An empty subdirectory is not a new service. Skill adoption or a feature request
does not authorize replacing a mature framework or reorganizing unrelated code.

For a genuinely new service, read [Local password authentication](references/local-password-authentication.md)
before asking about unresolved product choices. Ask once in one batch, explain
the documented defaults and tradeoffs, and reuse answers already given in the
project. A generic instruction to continue does not supply a required choice.
Then read [Project structure](references/project-structure.md) and
[New project delivery](references/new-project-delivery.md). The default layout
is optional for a new service; an explicitly chosen alternative takes precedence.

The Skill owns ORM models; the user owns migration generation, review, execution
and initial database preparation. Do not generate, copy or run migrations,
table-creation SQL, seed/bootstrap scripts or startup schema repair. Explain
initial rows and database-only protections in the existing project README.
ORM metadata does not install triggers. Preserve user-owned migration tooling.

## Essential Baseline

The references below own full rules, values, examples and implementation details.
These entrypoint boundaries apply whenever their business is in scope:

- Verified stack: Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2 async, asyncpg,
  PostgreSQL 17 and Redis 7. Alembic is optional user-owned tooling. Verify other
  versions separately; prefer ordinary type aliases, `TypeVar` and `Generic`
  rather than PEP 695 syntax.
- New projects use standalone PostgreSQL and Redis through `DATABASE_URL` and
  `REDIS_URL`. Cluster clients, node discovery, failover and read/write splitting
  are project-specific extensions. Preserve an existing project's topology.
- Local accounts use usernames and Argon2id hashes stored on `users`.
  Mutable records/relationships use soft deletion; audit rows are append-only.
  A deleted username stays reserved. Public registration has no runtime switch;
  both registration and administrator creation atomically assign only `user`.
- Purpose-bound graphical CAPTCHA is mandatory for its documented operations;
  each submission consumes it once, including a wrong answer. Mandatory Redis
  limits use trusted IP for anonymous operations and business + authenticated
  user ID for logged-in operations, without site-wide or username quotas.
  Count each request once before protected work; logged-in requests validate
  JWT and Redis active JTI first, then count before PostgreSQL account checks.
  Current-Token logout only validates and deletes that login, without a quota.
- Default JWT claims are exactly `user_id`, `jti`, `iat`, `exp` and `token_type`,
  with a 24-hour lifetime. Add `iss`/`aud` together only with explicit owner
  agreement. An ordinary business request requires signature/profile validation,
  exact Redis active JTI, a live PostgreSQL account/current authority and the
  Redis-bound user-version match. Never recreate missing sessions from a JWT.
  Current-Token logout has its documented reduced-authority exception.
  Use `user_id` consistently in user models, request/response fields, JWT and
  Redis records; `current_user` names a loaded current-user object, while
  `target_user_id` distinguishes a managed user from the current caller.
  Expose the login dependency directly on ordinary routes with
  `context: AuthorizationContext = Depends(get_current_user)`, returning
  `context.login_info` for the verified login and `context.user_info` for the
  current database account, roles and permissions. The RBAC reference owns the
  short, explicit login/management/CAPTCHA dependency flow.
  `check_token` verifies JWT and the Redis login; permission dependencies reuse
  that check and the account loader directly, with ordinary user quotas by
  default. Business management routes explicitly select `management=True`;
  requiring a permission never determines the caller's role or quota category.
  Parsed Token data uses `AccessTokenInfo` / `token_info`; `LoginInfo` additionally
  means Redis has confirmed the login. Keep GET/POST threshold selection in the
  limiter, without quota-name strings in authentication functions.
- Role fields use `level`; a user's highest effective role level uses `role_level`.
  System roles are only `super_admin`/`user` at levels 1000/0, with one
  super administrator prepared and transferred offline; a user has at most
  10 live role assignments. Exact positive permissions govern operations.
  Administrative roles are ordinary custom roles at levels 1..999, created and
  granted permissions as needed; no `admin` role or level 500 is preconfigured.
  Except for the sole super administrator, manage strictly lower complete
  multi-role authority and grant only currently held permissions.
- Check the exact capability before target visibility. Hide self, peer, higher,
  protected and incomparable administrative targets; concealed and missing
  targets share the same result. Role replacement requires strict integer
  `expected_version`; authorized stale writes use `40931`.
- Authorization writes lock `rbac_state` first, reload authority under ordered
  locks and commit mutation, versions and allowed audit together. Keep Redis
  I/O outside those locks. Roll back before denied auditing; audit failure must
  preserve the original denial. Read live permissions on each request; do not
  add a per-user permission-version counter. Retain the login-revocation
  `token_version` and role edit `version`. The global RBAC row only coordinates
  write locks; do not add an authorization-change counter or return one in APIs.
- New business APIs use only GET/POST, static paths, GET query inputs and
  validated POST JSON bodies. List/detail paths end in `/list`/`/detail`;
  current-user information uses `GET /api/v1/me/user_info`.
  Preserve an existing intentional HTTP contract outside a requested change.
  New projects disable public docs/OpenAPI routes and include no health probes.
- Ordinary JSON responses contain exactly `code`, `message`, `data` and a
  server-generated UUIDv4 `request_id`, also returned in `X-Request-ID`.
  Use real HTTP statuses, five-digit integer business codes and Chinese/English
  runtime messages, defaulting to `zh-CN`. Translate human text, not machine
  keys, fields, permissions, audit actions or reason codes.
- Keep safe operational logs separate from durable audit evidence. The default
  `operation_audit_events` table and `AuditService` combine account-security and
  permission operations, with bounded redacted request/response summaries and
  allowlisted state. Required success audit and mutation share one transaction;
  response data is a business snapshot, not proof of HTTP delivery. Audit
  `user_id` identifies the operation user and `target_user_id` the affected user.
  New-password comparison fingerprints use the existing independent log key,
  never plaintext or database hashes. General business audit is opt-in and is
  excluded from default model registration/export. Ordinary queries use file
  logs. Never expose passwords, CAPTCHA answers, bearer Tokens/JTI, credentials
  or connection URLs. Logging failure must not change business results.
- Write for backend learners: named Service/Repository classes for substantial
  operations, clear business owners, explained constants/fields/stages, Chinese
  function contracts and separate access/permission lines on endpoints.
  Interface input/output models use `Request`/`Response` suffixes, respectively.
  They inherit `RequestBase`/`ResponseBase` directly or through shared schemas;
  [API response](references/api-response-standard.md) owns their common rules.
  New files have only the generation day's author/`V1.000`/`新建` history;
  preserve real history when editing an existing project.

Do not silently add a credential table, Refresh Tokens/session tables, temporary
passwords, anonymous password recovery, email/SMS/MFA, online super-admin transfer,
ordinary-user logout-all, device fingerprinting, permission caches, multi-tenancy
or background systems. Country/proxy modules are opt-in.

## Read By Task

Read the narrowest matching reference completely; add another only when the
requested change crosses its boundary. Do not preload every reference or follow
an optional cross-link merely because it exists. Detailed business instructions
have one reference owner; keep this entrypoint as routing and core boundaries.

| Task | Read |
| --- | --- |
| Chinese maintainer/download-user overview | [Chinese architecture overview](references/architecture-overview.zh-CN.md) |
| FastAPI, Pydantic, SQLAlchemy, settings, lifecycle | [Modern stack](references/modern-fastapi-stack.md) |
| Connection pools, timeouts, shared process state, or measured performance issues | [Capacity and availability](references/application-capacity-and-availability.md) |
| Standalone Redis URL, separate standalone rate-limit backend, TLS, or client changes | [Redis connections](references/redis-connections.md) |
| New project layout, module placement, or requested directory reorganization | [Project structure](references/project-structure.md) |
| Deliver code into an empty new project | [New project delivery](references/new-project-delivery.md) |
| Python functions, signatures, fields/constants, file histories or comment review | [Python comments](references/python-comments.md) |
| Similar functions, shared helpers, service/repository layers, refactoring | [Reuse and abstraction](references/reuse-and-abstraction.md) |
| JSON envelopes, business codes, request IDs, pagination | [API response](references/api-response-standard.md) |
| Runtime API messages, permission descriptions, `Accept-Language`, validation text, new locale | [API internationalization](references/api-internationalization.md) |
| Runtime/access logs and safe exception telemetry | [Operational logging](references/operational-logging.md) |
| RBAC concepts or policy | [RBAC design](references/rbac.md) |
| PostgreSQL RBAC code, models, routes, or bundled asset | [PostgreSQL implementation](references/postgresql-rbac-implementation.md) |
| Administrator hierarchy, delegation, protected targets | [Administrative hierarchy](references/administrative-hierarchy.md) |
| Authorization transactions, locks, races, revocation | [Atomic consistency](references/atomic-consistency.md) |
| Registration, login, password change/reset, local account lifecycle | [Local password authentication](references/local-password-authentication.md) |
| JWT claims, Redis active JTI, sessions, logout | [JWT security](references/jwt-session-security.md); add [JWT implementation](references/jwt-session-implementation.md) only for concrete adapter code |
| Fixed-window quotas, named limit dependencies, trusted client IP | [Rate limiting](references/rate-limiting.md) |
| Graphical CAPTCHA enum, login requirements, issuance and single-use consumption | [Verification](references/verification-and-abuse-defense.md); add [Rate limiting](references/rate-limiting.md) for quotas |
| Explicit email/SMS verification or MFA extension | First gather product/provider/recovery requirements; [Verification](references/verification-and-abuse-defense.md) describes extension boundaries, not a complete implementation |
| User lifecycle, username identity, soft deletion | [Identity lifecycle](references/identity-soft-delete.md) |
| Business/audit IDs, formats and shared validation | [Identifier policy](references/identifier-policy.md); add [Model and database handoff](references/migrations.md) for schema changes |
| Models, constraints, initial-data requirements, user-owned migrations | [Model and database handoff](references/migrations.md) |
| Unified account/permission audit, redacted inputs/results, action catalog | [Operation audit](references/audit-module.md) |
| Business event catalog and boundaries | [Business audit](references/business-audit-module.md); add [PostgreSQL code](references/business-audit-postgresql.md) or [operations](references/business-audit-operations.md) only when needed |
| Explicitly requested country/region catalog | [Country catalog](references/country-catalog.md); add [PostgreSQL code](references/country-catalog-postgresql.md) only for implementation |
| Explicitly requested proxy availability checks | [Proxy detection](references/proxy-availability-detection.md); add only the needed [backend](references/proxy-availability-backend.md), [frontend](references/proxy-availability-frontend.md) or [tests](references/proxy-availability-testing.md) |
| Verification or release evidence | [Testing](references/testing.md) |

## Implement, Verify And Report

Before extracting a helper, search for an existing owner. Share rules that must
change together; keep obvious one-use code local. Shared finite business concepts
use one owned enum and derived classifications, not duplicated option catalogs.
Read the structure/reuse references before introducing layers or abstractions;
read the comment reference before writing Python. Names and layout must reflect
the operation a beginner is looking for, without hiding checks behind wrappers.

Treat [the PostgreSQL asset](assets/postgresql-rbac/) as maintained source, not a
directory to copy wholesale. For matching new projects, resolve required choices
and use `scripts/create_project.py` as described in the delivery reference.
Export relevant runtime/models, a concise README and a small offline test set;
do not overwrite an existing project or export maintenance SQL, tooling, caches
or auxiliary source/handoff/legal documents. Required copied-code attribution
stays in the README appendix, not a license imposed on the whole application.

Run the smallest relevant checks from the testing reference. Documentation-only
work gets content/link and whitespace checks; code changes get directly related
tests and scoped lint/type checks. Keep caches outside delivered source. New
project verification is offline unless the user provides a prepared environment;
never create or migrate a database to make tests pass. Reuse unchanged evidence
and stop when the requested result is verified.

Report the completed change, actual checks and unavailable service checks.
Passing code tests does not certify production capacity or infrastructure
failover. Publishing and deployment require the user's corresponding scope.
