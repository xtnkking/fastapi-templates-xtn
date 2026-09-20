---
name: fastapi-templates-xtn
description: Build or harden single-project FastAPI services with PostgreSQL RBAC, strict administrative hierarchy, username/password authentication and five purpose-bound graphical CAPTCHA flows, Redis-gated Access Tokens, per-business Redis fixed-window limits, zh-CN/en runtime API messages, non-sequential identifiers, atomic authorization writes, structured logging, and durable audits. Use for FastAPI RBAC work, not services without authorization requirements.
---

# FastAPI Templates XTN

> Independently maintained by XTN as an extension of [`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates).
> See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md).

Build a runnable, single-project FastAPI service whose complexity matches the product. Preserve intentional architecture in an existing project. For a new service,
use the bundled PostgreSQL/Redis baseline unless the owner chooses an incompatible requirement.

## Inspect And Decide Once

Inspect the repository before changing it: Python and dependency versions, settings, identity contract, database and migrations, package boundaries,
transaction ownership, Redis clients, routes, tests, and deployment model.
Never replace an established choice merely because this Skill has a default.

For a new local-password project, present all unresolved product choices in one batch and wait for one answer. Show the stated defaults, but do not invent a default where this list requires the owner to choose:

1. Whether username comparison is case-sensitive. Require an explicit choice; neither behavior is a generic recommendation. Always trim both ends and require 3..32 ASCII letters, digits, or underscores.
2. Whether passwords must contain uppercase, lowercase, digits, or symbols. Default: none of those composition rules; length remains 8..60.
3. Maximum simultaneous active logins per user. Require the owner to supply a positive integer; there is no recommended number and `全部接受` / `Accept all` cannot fill it in. Explain that Redis records login sessions and times, not physical devices; at the limit, evict the oldest.
4. Administrator password-reset mode. Default: `direct`, where the administrator sets the user's new permanent password and the user may log in without another password-change step; this is simpler, but the administrator knows and must privately deliver the final password. Optional: `temporary`, where the administrator's password can only complete one formal-password setup; this adds a step, but the user chooses the final password. Explain both and ask the owner to choose; never let the API caller choose per request.
5. Whether to accept the relevant rate limits: CAPTCHA 10/5 minutes per scene; login 20/5 minutes per trusted IP; registration 5/hour per trusted IP; temporary-password
   completion 20/5 minutes per trusted IP; authenticated read 600/minute, management read 300/minute, ordinary write 120/minute, and management change 60/minute per operation and authenticated user.
6. Whether to add both JWT `iss` and `aud`. Explain plainly: the pair prevents a Token from one trusted system being accepted by the wrong service, but adds issuer/audience
   configuration. No answer means keep both absent. Preserve an existing configured pair by default unless removal is explicitly requested.
7. Whether production operations will separate PostgreSQL migration-owner and runtime roles. Recommend separation only when a professional operations team will own it. Otherwise explain that application soft-delete still works but database-owner SQL can bypass it, and do not block a small project.
8. Only for an existing project, how accounts without a local password enroll.

Show only unresolved choices. `全部接受` / `Accept all` accepts only concrete values shown in that batch and cannot answer username case sensitivity or the session maximum until those values have been supplied. A generic instruction to continue does not answer an unasked product choice. Separately tell the owner that the Access Token lifetime starts at 3600 seconds and where to change it; do not turn that notice into another blocking product question unless the owner wants a different value.
Do not ask about Argon2 parameters, lock order, dummy hashes, secret redaction, audit mechanics, or revoking old Tokens; those are engineering invariants.
Once answered, do not ask again during the same project.

## Read By Task

Read this entrypoint first, then only the narrowest matching reference. Add a second reference only when the actual deliverable crosses that boundary.

| Work being done | Read |
| --- | --- |
| FastAPI, Pydantic, SQLAlchemy, settings, lifecycle | [Modern stack](references/modern-fastapi-stack.md) |
| JSON envelopes, business codes, request IDs, pagination | [API response](references/api-response-standard.md) |
| API response text, `Accept-Language`, validation messages, or a new language | [API internationalization](references/api-internationalization.md) |
| Runtime/access logs and safe exception telemetry | [Operational logging](references/operational-logging.md) |
| RBAC policy without concrete PostgreSQL code | [RBAC design](references/rbac.md) |
| PostgreSQL RBAC models, routes, services, or baseline asset | [PostgreSQL implementation](references/postgresql-rbac-implementation.md) |
| Administrator hierarchy, delegation, protected targets | [Administrative hierarchy](references/administrative-hierarchy.md) |
| Authorization transactions, locks, races, revocation | [Atomic consistency](references/atomic-consistency.md) |
| Local registration, login, passwords, reset, or change | [Local password authentication](references/local-password-authentication.md) |
| JWT claims, Redis active JTI, login sessions, logout | [JWT security](references/jwt-session-security.md) |
| Concrete JWT/Redis adapter code | [JWT security](references/jwt-session-security.md), then [JWT implementation](references/jwt-session-implementation.md) |
| Fixed-window quotas, trusted IP, admission failures | [Rate limiting](references/rate-limiting.md) |
| CAPTCHA or explicitly requested email/SMS/MFA extension | [Rate limiting](references/rate-limiting.md), then [Verification](references/verification-and-abuse-defense.md) |
| User lifecycle, username identity, soft delete, relation episodes | [Identity lifecycle](references/identity-soft-delete.md) |
| Public/non-sequential ID choice or backfill | [Identifier policy](references/identifier-policy.md); add [Migrations](references/migrations.md) only for schema work |
| Alembic revisions, seeds, constraints, upgrades | [Migrations](references/migrations.md) |
| RBAC audit events and safe before/after state | [RBAC audit](references/audit-module.md) |
| Business action audit boundaries and event catalog | [Business audit](references/business-audit-module.md) |
| Concrete business-audit PostgreSQL code | [Business audit](references/business-audit-module.md), then [Business audit PostgreSQL](references/business-audit-postgresql.md) |
| Audit read/export, retention, legal hold, backup | [Business audit operations](references/business-audit-operations.md) |
| Explicitly requested country/region directory | [Country catalog](references/country-catalog.md), then [Country PostgreSQL](references/country-catalog-postgresql.md) for code |
| Explicitly requested proxy availability or exit-IP checks | [Proxy detection](references/proxy-availability-detection.md), then only the needed [backend](references/proxy-availability-backend.md), [frontend](references/proxy-availability-frontend.md), or [tests](references/proxy-availability-testing.md) |
| Test implementation, completion audit, release evidence | [Testing](references/testing.md) |

Specialized rows override general ones. A hierarchy-only review need not load the general RBAC design; a logging change need not load either audit reference.
Do not follow cross-links unless the task meets their loading condition.

Treat [the PostgreSQL asset](assets/postgresql-rbac/) as output source, not instructions. Copy it as one directory for greenfield work. When adapting it, use `rg --files`
and `rg -n` to inspect only the target symbol, direct dependency, and matching tests; never recursively load every asset file.

Country and proxy features are optional additions to a project already using this Skill. Do not load or add them because a normal user, address, locale, proxy CRUD,
or geolocation field happens to exist. Never create or seed `countries` in the default PostgreSQL asset. Business audit infrastructure is bundled, but emit events
only after the project defines an explicit action catalog and safe per-action state allowlist; ordinary CRUD alone is not a reason.

## Required Baseline

### Data And Identity

- Use Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2 async, asyncpg, Alembic,
  PostgreSQL 17, and Redis 7 for the officially verified baseline. Other versions
  require project-specific verification.
- Never use autoincrementing or sequential public/business IDs. Prefer a stable
  entity prefix plus a cryptographically random uppercase suffix sized from
  expected lifetime volume, or UUIDv4. `U` plus 10 characters is only a
  low-volume example; unknown volume defaults to 16. Random IDs reduce casual
  enumeration but never replace authorization or non-leaking lookups.
- New services use username/password only. Reject reserved usernames
  `admin`, `administrator`, `root`, `superadmin`, `super_admin`, `sysadmin`,
  `system`, `support`, `user`, `test`, `guest`, and `ceshi`, case-insensitively.
  A soft-deleted username remains reserved forever. Existing services retain
  their chosen identity contract unless the user requests a change.
- Passwords live on `users` as Argon2id hashes, never plaintext and not in a
  separate credential table. Run hashing off the event loop with bounded
  concurrency; unknown users receive equivalent dummy-hash work.
- Every ordinary mutable row and live relationship uses soft deletion. Deleting
  a parent tombstones its live relations atomically; restore revives no old
  privilege. Audit rows are append-only; fixed catalog/state rows are not
  runtime-deletable. Physical purge is only controlled maintenance, disposable
  tests, or a reviewed migration.

### Authentication And Abuse Defense

- Require graphical CAPTCHA for exactly `login`, `register`, `admin_create`,
  `admin_reset`, and `self_change`. Each challenge lasts five minutes, is bound
  to its purpose and trusted IP or authenticated canonical user, and is consumed
  on its first submitted answer, correct or wrong. Refresh replaces the old
  challenge only after new issuance succeeds.
- Login and registration execute trusted-IP business admission before CAPTCHA,
  then credentials or registration, then Token issuance. Invalid, random,
  expired, or wrong-purpose CAPTCHA submissions have already consumed the
  login/registration quota; a quota rejection must not consume the CAPTCHA.
- Use one Redis Lua fixed-window counter per business operation and subject.
  Anonymous operations use purpose plus trusted IP; authenticated operations
  use operation plus server-authenticated user ID. Never add a whole-site,
  all-user, username, or cross-business shared quota. Keep limits in typed
  settings, `.env.example`, and asset documentation.
- A trustworthy denial is HTTP/business `429/429001` with integer
  `Retry-After`; missing IP, unavailable/malformed limiter or verification state
  is fail-closed `503/503001` without `Retry-After`. No protected callback runs
  after denial. Limit keys use HMAC-private subjects and never enter logs or
  responses. Rate limiting may be disabled only in explicitly local/test work.
- Public registration defaults on through the persisted PostgreSQL switch;
  only `super_admin` may change it. Public registration and administrator user
  creation bind only the mandatory `user` role in the same transaction and
  never accept an initial role from the client.
- Self password change requires old password plus CAPTCHA. Administrator reset
  requires capability, CAPTCHA, and a strictly lower target, but not the actor's
  password again. Use the project-selected reset mode: `direct` is the default
  and stores the administrator-supplied value as the permanent password;
  `temporary` requires one formal-password setup before Token issuance. A
  temporary password has no timer and is invalidated by completion, another
  reset, or deletion. Both modes rotate the hash, increment `token_version`,
  revoke old Tokens, and write the same atomic account-security audit without
  exposing the password. There is no anonymous forgot-password route; use
  administrator reset. Administrator-created users and sole `super_admin`
  offline recovery always use temporary credentials and are not changed by the
  administrator-reset mode.
- Email/SMS codes and MFA are not defaults. Add them only when explicitly
  requested; do not add an email field or delivery provider merely for auth.

### Access Tokens And Sessions

- Access Tokens default to one hour (3600 seconds); explicitly tell the owner to
  adjust that value for business risk and login experience. They contain exactly
  `sub`, `jti`, `iat`, `exp`, and `token_type`. `sub` is the canonical immutable
  user ID; `jti` is a fresh UUIDv4. Never include username, email, roles,
  permissions, tier, flags, or versions. Add `iss` and `aud` only together after
  explicit consent.
- Reject weak, blank, example, repetitive, whitespace/control-bearing, or short
  HS256 secrets at startup. Bound encoded and presented Tokens to 4096 bytes.
- Authenticate in this order: validate JWT shape/signature, require the exact
  active JTI in Redis, then load the current live PostgreSQL user and complete
  authority and compare the Redis-bound `users.token_version`. Fail closed on
  unavailable authority. Never recreate Redis state from a JWT.
- Store no Token/session table in PostgreSQL and perform no per-request Token-row
  query. Do not add Refresh Tokens. A successful issuance atomically applies the
  chosen active-login maximum and evicts the oldest Redis session when needed.
- Ordinary logout removes only the current JTI. Ordinary users have no
  logout-all endpoint. A capable administrator may revoke all sessions only for
  a visible, strictly lower user by incrementing `users.token_version` with the
  account-security audit in one PostgreSQL transaction.

### Authorization And Hierarchy

- Seed immutable system roles `super_admin`, `admin`, and `user` at tiers 1000,
  500, and 0. They cannot be deleted, disabled, renamed, re-ranked, or edited by
  public APIs. Custom roles use tiers 1..999, start with no permissions, and use
  exact positive `resource:action` grants. Do not add deny rules, wildcards,
  inheritance, or a separate delegation subsystem.
- Exactly one `super_admin` exists. After the chosen account already has `user`,
  tell the owner to run `sql/bootstrap_super_admin.sql` personally with its
  immutable user ID. Never auto-promote the first registrant or expose online
  bootstrap/transfer APIs. Later handover also uses the guarded offline SQL.
- Each user has at most 10 live role assignments, including `user`, disabled
  roles, and `super_admin`; tombstones do not count. Enforce the final state
  after authoritative locks in every path and again in PostgreSQL.
- Larger tiers are higher. Except for the sole super administrator, an actor may
  manage only strictly lower complete multi-role authority. Hide self, peer,
  higher, protected, and incomparable targets from administrative list, count,
  search, detail, nested, bulk, and export operations. Hidden and unknown detail
  targets use the same `404001`; the actor sees itself only at `/api/v1/me/access`.
- Check the exact capability before target visibility. Missing capability is
  `403001`; after authoritative locks, concealed targets remain `404001`. A
  visible target that fails delegation or affected-user policy is `403001`.
  Role assignment, role definition, and permission replacement are separate
  capabilities. A grantor can grant only permissions it currently holds.
- Public management routes use only `GET` and `POST`. Public paths, tags,
  operation IDs, titles, schemas, and errors never expose the term `rbac`;
  internal module and table names may use it.

### Transactions, Responses, Logs, And Audit

- Every authorization write locks `rbac_state(scope='global')` first, reloads
  actor and all affected authority from PostgreSQL, decides again, and commits
  mutation, version changes, and allowed RBAC audit together. Redis I/O never
  occurs while these locks are held.
- Roll back a denied protected transaction before attempting its denied audit.
  A denied-audit failure must preserve the original `403`/`404`/`409`, never
  become `500`. Role mutations require a strict integer `expected_version`;
  an authorized stale value returns `409002`. Build responses from immutable
  snapshots while locks are still owned.
- Every ordinary JSON response has exactly `code`, `message`, `data`, and a
  server-generated UUIDv4 `request_id`, echoed in `X-Request-ID`. Use real HTTP
  statuses and six-digit integer business codes with matching first three
  digits. Page data contains only `items`, `page`, `page_size`, and `total`.
- Localize all client-facing runtime API messages in Simplified Chinese and
  English. Default to `zh-CN`; select `zh-CN` or `en` from a bounded standard
  `Accept-Language` value, and return canonical `Content-Language` plus
  `Vary: Accept-Language`. Routes and services use stable message keys, not
  rendered text. Never localize HTTP/business codes, response fields, data
  machine values, permission/role keys, logs, audit actions, outcomes, or
  reason codes. Additional languages are explicit project extensions.
- Emit one-line structured operational logs with stable events, UTC time,
  service/build identity, request ID, route template, status, business code,
  duration, and authenticated canonical user ID when available. Never log raw
  paths/queries, bodies, arbitrary headers, username, passwords, CAPTCHA,
  cookies, Token/JTI, proxy credentials, or database/Redis URLs. Logging failure
  never changes business or transaction outcomes.
- Keep operational logs, `rbac_audit_events`, account-security evidence, and
  `business_audit_events` separate. Audits are server-owned and append-only.
  Successful protected changes commit with their audit. Business events exist
  only for an approved catalog such as money, ownership, important state,
  delete/restore, manual override, sensitive export, or compliance. Do not add
  `business_audit_delivery_outbox`, delivery workers, leases, retries, or DLQ.
  Its only outcomes are `succeeded`, `failed`, and `denied`.
- Keep `/health/live` process-only. Under short per-dependency timeouts,
  `/health/ready` requires exactly the expected Alembic head and the global
  `rbac_state` row, plus `PING` and a Lua write/read/delete probe on both the
  active-JTI and limiter Redis targets. Use random non-secret keys with a
  five-second TTL. Return only overall ready/unavailable with
  `Cache-Control: no-store`; expose and log no keys, URLs, or exception text.

## Implement And Verify

1. Settle the single decision batch, define actors/capabilities/row policy, and
   define explicit RBAC or business audit actions before writing code.
2. Copy the whole asset for greenfield PostgreSQL work. In an existing project,
   preserve its policy, transactions, query boundaries, and migration history.
3. Implement settings, models, schemas, dependencies, services, routes,
   migrations, and tests together. Never copy a route without its policy,
   locking query, database constraint, audit path, and negative tests.
4. Keep authentication, capabilities, ownership, row policy, logging, and audit
   as distinct boundaries. Do not add workers or architecture layers without a
   concrete product need.
5. For completion work, read [Testing](references/testing.md) and run only the
   relevant matrix: format, lint, strict typing, OpenAPI/API contract, policy,
   IDOR, audit/log secret scans, real PostgreSQL/Redis behavior, migrations,
   concurrency, rollback, and ASGI requests.

Integration tests may use only newly created, empty, disposable PostgreSQL and
Redis targets whose isolation guards pass. Never use an existing application or
production target. Report every unavailable integration service or skipped
deployment assumption; do not call the result production-ready without the
required PostgreSQL, Redis, migration, and concurrency evidence.

Do not add multi-tenancy, a permission cache, Refresh Tokens, PostgreSQL Token
sessions, whole-site rate limits, online super-admin transfer, ordinary-user
logout-all, anonymous password recovery, default email/SMS/MFA, role inheritance,
deny permissions, device fingerprinting, default country data, default proxy
detection, audit delivery workers, or unrelated background infrastructure.
