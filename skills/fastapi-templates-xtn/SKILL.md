---
name: fastapi-templates-xtn
description: Build or harden a single-project FastAPI service that explicitly adopts this opinionated PostgreSQL 17, Redis 7, local username/password, fixed hierarchical RBAC, Redis-gated JWT, CAPTCHA, bilingual API-message, logging, and audit baseline. Use when the user names this Skill or asks for this exact architecture; do not auto-apply it to generic FastAPI/RBAC work, other identity providers, non-PostgreSQL/Redis systems, or a different authorization model.
---

# FastAPI Templates XTN

> Independently maintained by XTN as an extension of [`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates).
> See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md).

## Scope And Workflow

This Skill defines code conventions and a coherent single-project authorization
baseline. Keep the deliverable within the requested coding task. Production
sizing, zero-downtime releases, cluster operations, and recovery drills are
user-owned choices, not default features, completion gates, or a backlog of
Skill defects. Before changing code, inspect the repository's Python and dependency
versions, settings, identity contract, database and migrations, transaction
ownership, Redis clients, routes, tests, and deployment model. Preserve an
existing intentional choice unless the owner requests a migration.

For a greenfield local-password service, or when redesigning that surface, read
[Local password authentication](references/local-password-authentication.md)
before asking questions. That document owns the one-time product-decision batch
and defaults. [Rate limiting](references/rate-limiting.md) owns quota values;
[JWT security](references/jwt-session-security.md) owns the Token contract. Ask
all unresolved product choices in one batch, explain the documented tradeoffs,
and never infer a required value or consent from a generic instruction to
continue. Do not ask again after the owner has answered in the same project.

Then read only the narrowest reference matching the actual work. Add another
reference only when the deliverable crosses that boundary. Implement a feature
through settings, models, migrations, services, routes, and tests as applicable;
never copy a route without its authorization, transaction, audit, and negative
test boundaries.

Before adding a function, search for an existing owner of the same behavior.
Share logic that must change together using a small, meaningful parameter set;
keep simple one-use code inline unless a clear boundary justifies extraction.
For new abstractions or repeated flows, read
[Reuse and abstraction](references/reuse-and-abstraction.md).

For a genuinely new service with no established framework, use the optional
default layout: `api`, `core`, `db`, `dependencies`, `models`, `repositories`,
`schemas`, and `services`, with business modules inside them. Honor an explicitly
chosen alternative. In an existing project, follow its architecture, naming,
layers, and infrastructure; place the requested feature in its existing homes.
An empty subdirectory in that project is not a greenfield service. Using this
Skill or asking for a feature, fix, or optimization does not authorize broad
framework replacement or directory reorganization. Read
[Project structure](references/project-structure.md) when placing or reorganizing
code. Directory structure must not introduce empty modules or forwarding layers.

For a new project, default to one standalone PostgreSQL instance and one
standalone Redis instance, configured by `DATABASE_URL` and `REDIS_URL`.
Login state, CAPTCHA, and quotas share that Redis by default. Do not ask a
mandatory cluster-selection question or add a second Redis service. Sentinel,
Cluster, read/write splitting, and separate backends are opt-in requirements;
load their configuration guidance only for an explicit request or an existing
topology that must be preserved. Keep bounded connections, cleanup, and safe
transactions in all modes. When a cluster is requested, connect to the supplied
service; operations owns its deployment and management.

Treat [the PostgreSQL asset](assets/postgresql-rbac/) as output source, not as
instructions to load wholesale. Copy it as one directory for a matching
greenfield service. Never overwrite an existing application's tree with the
asset. When adapting it, inspect only the target symbol, direct dependencies,
and matching tests with `rg`, and integrate the needed behavior into the host
project's components. Reorganize architecture only within an explicitly
requested scope; do not ask again when that scope is already authorized.

## Read By Task

| Task | Read |
| --- | --- |
| Chinese maintainer/download-user overview | [Chinese architecture overview](references/architecture-overview.zh-CN.md) |
| FastAPI, Pydantic, SQLAlchemy, settings, lifecycle | [Modern stack](references/modern-fastapi-stack.md) |
| Connection pools, timeouts, shared process state, or measured performance issues | [Capacity and availability](references/application-capacity-and-availability.md) |
| Explicitly requested or existing Redis Sentinel/Cluster, separate backend, custom TLS, or client/script changes | [Redis connections](references/redis-connections.md); ordinary standalone setup needs only `.env.example` |
| New project layout, module placement, or requested directory reorganization | [Project structure](references/project-structure.md) |
| Similar functions, shared helpers, service/repository layers, refactoring | [Reuse and abstraction](references/reuse-and-abstraction.md) |
| JSON envelopes, business codes, request IDs, pagination | [API response](references/api-response-standard.md) |
| Runtime API messages, `Accept-Language`, validation text, new locale | [API internationalization](references/api-internationalization.md) |
| Runtime/access logs and safe exception telemetry | [Operational logging](references/operational-logging.md) |
| RBAC concepts or policy | [RBAC design](references/rbac.md) |
| PostgreSQL RBAC code, models, routes, or bundled asset | [PostgreSQL implementation](references/postgresql-rbac-implementation.md) |
| Administrator hierarchy, delegation, protected targets | [Administrative hierarchy](references/administrative-hierarchy.md) |
| Authorization transactions, locks, races, revocation | [Atomic consistency](references/atomic-consistency.md) |
| Registration, login, password change/reset, local account lifecycle | [Local password authentication](references/local-password-authentication.md) |
| JWT claims, Redis active JTI, sessions, logout | [JWT security](references/jwt-session-security.md); add [JWT implementation](references/jwt-session-implementation.md) only for concrete adapter code |
| Fixed-window quotas and trusted client IP | [Rate limiting](references/rate-limiting.md) |
| Bundled graphical CAPTCHA behavior | [Verification](references/verification-and-abuse-defense.md), plus [Rate limiting](references/rate-limiting.md) for quotas |
| Email/SMS verification or MFA request | The asset has no complete implementation. First gather product, provider, recovery, and threat-model requirements; then use [Verification](references/verification-and-abuse-defense.md) only as an extension-boundary checklist |
| User lifecycle, username identity, soft deletion | [Identity lifecycle](references/identity-soft-delete.md) |
| Public/non-sequential IDs | [Identifier policy](references/identifier-policy.md); add [Migrations](references/migrations.md) only for schema or backfill work |
| Alembic revisions, seeds, constraints, upgrades | [Migrations](references/migrations.md) |
| RBAC audit events | [RBAC audit](references/audit-module.md) |
| Business event catalog and boundaries | [Business audit](references/business-audit-module.md); add [PostgreSQL code](references/business-audit-postgresql.md) or [operations](references/business-audit-operations.md) only when needed |
| Explicitly requested country/region catalog | [Country catalog](references/country-catalog.md), then [PostgreSQL code](references/country-catalog-postgresql.md) only for implementation |
| Explicitly requested proxy availability checks | [Proxy detection](references/proxy-availability-detection.md), then only the needed [backend](references/proxy-availability-backend.md), [frontend](references/proxy-availability-frontend.md), or [tests](references/proxy-availability-testing.md) |
| Completion audit or release evidence | [Testing](references/testing.md) |

Specialized rows override general ones. Do not follow cross-links unless the
current task meets their loading condition. Country and proxy features are
optional and never enter the default asset merely because related fields exist.

## Non-Negotiable Baseline

### Identity And Authentication

- The verified stack is Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2 async,
  asyncpg, Alembic, PostgreSQL 17, and Redis 7. Verify other versions separately.
- Greenfield services use the documented username/password contract. Store the
  Argon2id hash on `users`, never plaintext or a separate credential table.
  Use non-sequential public/business IDs and soft-delete ordinary mutable rows
  and live relationships. Audit rows remain append-only.
- Public registration defaults on, and only `super_admin` may change it. Public
  registration and administrator creation atomically assign only the mandatory
  `user` role; no client chooses an initial role.
- Require the five purpose-bound graphical CAPTCHA scenes documented in
  [Verification](references/verification-and-abuse-defense.md). A submitted
  challenge is single-use whether correct or wrong. Email/SMS delivery, MFA,
  and anonymous password recovery are not bundled features.
- Use only per-business Redis limits. Anonymous operations use the documented
  trusted-IP subject; authenticated operations use the server-authenticated
  user ID. Never add a whole-site, username, or cross-business shared quota.

### Tokens And Sessions

- By default an Access Token contains exactly `sub`, `jti`, `iat`, `exp`, and
  `token_type`. Add `iss` and `aud` only together after the owner explicitly
  agrees. For a new project, no answer or unrelated approval means both remain
  absent; preserve an existing configured pair unless removal is requested. Do
  not place profile, role, permission, tier, or server-side version data in the
  Token.
- Access Tokens default to 86,400 seconds (24 hours). Tell the owner where to
  shorten that setting for product risk and login experience; high-risk
  administration surfaces usually need a shorter lifetime. Reject weak signing
  secrets at startup and bound presented and encoded Tokens to 4096 bytes.
- A valid signature is insufficient: require the exact active JTI in Redis,
  then load the current live PostgreSQL user and authority and compare the
  Redis-bound `users.token_version`. Never reconstruct missing Redis state from
  a JWT. Do not add Refresh Tokens or a PostgreSQL Token/session table.

### Authorization And Consistency

- Seed immutable system roles `super_admin`, `admin`, and `user` at tiers 1000,
  500, and 0. Exactly one `super_admin` exists and bootstrap or handover is an
  operator-run offline SQL action, never a public API. A user has at most 10
  live role assignments.
- Grants are exact positive `resource:action` permissions. Do not add deny rules,
  wildcards, inheritance, or a separate delegation subsystem. Except for the
  sole super administrator, an actor may manage only strictly lower complete
  multi-role authority and may grant only permissions it currently holds.
- Hide self, peer, higher, protected, and incomparable targets from all
  administrative reads and writes. Public management routes use only `GET` and
  `POST`, and their paths or public schemas never expose the term `rbac`.
- Check the exact capability before target visibility. A missing capability is
  `403001`; after it passes, hidden and unknown targets share `404001`. Role
  replacement commands require strict integer `expected_version`; an authorized
  stale write is `409002`.
- Every authorization write locks the global `rbac_state` first, reloads
  authority under lock, and atomically commits mutation, version changes, and
  the allowed audit. Never perform Redis I/O while those locks are held. Roll
  back before denied auditing; failure to write a denied audit must preserve the
  original client result rather than turn it into `500`.

### API, Language, Logs, And Audit

- Every ordinary JSON response has exactly `code`, `message`, `data`, and a
  server-generated UUIDv4 `request_id`, also returned as `X-Request-ID`. Use real
  HTTP statuses and six-digit integer business codes.
- Localize all client-facing runtime messages in `zh-CN` and `en`, defaulting to
  `zh-CN`. Return canonical `Content-Language` and `Vary: Accept-Language`.
  Routes and services choose stable message keys; never localize codes, fields,
  machine values, permission keys, log events, audit actions, outcomes, or
  private reason codes.
- Emit safe one-line structured operational logs with one canonical completion
  event. Keep operational logs, server-owned append-only RBAC audits,
  account-security audits, and business audits separate. Business audits require
  an explicit action catalog and per-action state allowlist; a successful
  protected mutation and its audit share one PostgreSQL transaction. Never log
  or return passwords, CAPTCHA answers, bearer Tokens, JTI, proxy credentials,
  or database/Redis URLs. Logging failure must not change a business or
  transaction result.

Do not silently add multi-tenancy, a permission cache, online super-admin
transfer, ordinary-user logout-all, device fingerprinting, default country or
proxy data, business-audit delivery workers, or unrelated background systems.

## Verify And Report

Run the smallest relevant matrix from [Testing](references/testing.md), including
format, lint, strict typing, contract, policy/IDOR, secret scans, migrations, and
real PostgreSQL/Redis concurrency where the changed boundary requires them.
Integration tests may use only newly created, empty, disposable targets whose
isolation guards pass. Report actual code verification and unavailable checks.
Ordinary coding tasks do not require production capacity certification or
deployment exercises; passing code tests does not certify production readiness.
