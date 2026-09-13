---
name: fastapi-templates-xtn
description: Build or harden single-project FastAPI services that require PostgreSQL RBAC, strict administrative hierarchy, complete Argon2id username/password authentication and recovery, minimal Redis-gated Access Tokens, centralized Redis Token Bucket rate limiting, password-login abuse defense, optional verification extensions, non-sequential identifiers, transactionally consistent authorization writes, structured operational logging, and separate durable RBAC, account-security, and business audits. Use for new or existing FastAPI RBAC work; do not select for FastAPI tasks with no authorization requirement.
---

# FastAPI Templates XTN

> Independently maintained by XTN as an extension of
> [`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
> from `wshobson/agents`. See [NOTICE](NOTICE) and
> [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and licenses.

Deliver a runnable FastAPI service whose complexity matches the product. Preserve
an existing project's intentional architecture; use the opinionated PostgreSQL
baseline when the product has not already made conflicting choices.

## Inspect First

- Determine whether the task is greenfield or extends an existing service.
- Inspect Python and dependency versions, settings, database and migrations,
  identity provider, package layout, transaction ownership, and tests.
- For greenfield authentication, first ask whether `users` stores `email`,
  `user_name`, or both. Separately settle requiredness, login input,
  normalization, uniqueness, cross-namespace ambiguity, and post-deletion reuse
  before modeling users. Preserve an existing project's identity contract unless
  changing it is requested.
- Before generating local-password routes, ask the authentication business
  questions from [Local password authentication](references/local-password-authentication.md)
  once, in one batch. At minimum settle the login identifier, registration mode,
  recovery proof/channel, simultaneous-device policy, and existing-account
  enrollment. Show the recommended answers and accept `全部接受` / `Accept all`
  or only the listed overrides. These are product decisions that change public
  behavior; do not ask the user to choose Argon2 parameters, transaction lock
  order, dummy-hash behavior, secret redaction, or whether old Tokens are revoked.
  If an existing product has already answered a question, preserve that answer
  and ask only the unresolved items.
  A general instruction to proceed, or `全部接受` sent before the complete batch
  was shown, does not answer an unasked product question. Pause implementation
  until the unresolved questions and their recommended defaults have been shown
  together and the user has accepted that batch or supplied overrides.
- Before adding JWT `iss` and `aud`, explain in plain language that the pair helps
  prevent a Token issued by one trusted system from being accepted by the wrong
  service, but adds issuer/audience configuration and coordination. Ask whether
  the user wants that extra scoping and require explicit consent. No reply is not consent.
  Keep both claims absent by default. If an existing project already enables the
  pair, preserve it by default unless changing it is requested.
- Before generating or changing rate-limit, password-login abuse, registration,
  or optional verification code, load the rate-limit reference and show every
  default for the requested surfaces. Ask one question: the user may reply
  `全部接受` / `Accept all`, or list only values to change. Do not write the
  affected code before an answer, and do not make the user choose the fixed
  atomic algorithm, private key shape, or `429`/`503` contract.
- A username-and-password service is the complete authentication baseline; it
  does not require CAPTCHA, email/SMS codes, or MFA. Keep every such enhancement
  disabled unless the user explicitly selects it. Only then show that
  enhancement's defaults and settle its identity field, purpose, provider, and
  recovery contract. An email field alone is not consent to email verification.
  Keep public registration absent from routing and OpenAPI by default as well;
  enable it only when the user explicitly selects self-service registration.
- Preserve the selected database, identity provider, package manager, module
  boundaries, and deployment model unless changing one is requested.
- For a new production deployment, ask whether a professional operations team
  will manage separate PostgreSQL migration and runtime roles. If yes, recommend
  that the migration role own schema changes while the runtime role has only the
  statements its application paths require and no direct hard-delete privilege
  on soft-deleted tables. If no or the user is unsure, do not block a learning or
  small project; explain that application soft-delete rules still hold, but a
  person using database-owner credentials can bypass them with direct SQL. Mark
  least-privilege database roles as a production follow-up instead of silently
  claiming database-level prevention.
- Keep async handlers free of blocking work. Do not add background workers or
  another architecture layer without a product need. An active JTI registry
  requested for token revocation is a valid Redis need; keep it separate from
  any authorization-permission cache.

## Load Only What The Task Needs

Start with this file and choose the narrowest primary reference:

| Task | Read |
| --- | --- |
| General FastAPI setup needed as part of the RBAC service | [Modern FastAPI stack](references/modern-fastapi-stack.md) |
| JSON API responses, numeric business codes, request IDs, pagination, error handlers, or resource-version conflicts | [API response standard](references/api-response-standard.md) |
| Structured application/access logs, request context, redaction, exception telemetry, log shipping, or operational retention | [Operational logging](references/operational-logging.md) |
| RBAC audit tables, access-control event coverage, safe before/after state, append-only controls, audit access, retention, export, or alerts | [RBAC audit module](references/audit-module.md) |
| Main-business or account-security audit boundaries, material action selection, business outcomes, domain event catalogs, or safe payload policy | [Business audit module](references/business-audit-module.md) |
| Concrete PostgreSQL business-audit table, model, writer, migration, transaction code, or database tests | [Business audit module](references/business-audit-module.md), then [Business audit PostgreSQL](references/business-audit-postgresql.md) |
| Business-audit read/export API, retention, partitioning, legal hold, alerts, backups, or recovery | [Business audit operations](references/business-audit-operations.md) |
| JWT payload, signing, Redis active-JTI validation, login, logout, or token revocation | [JWT access-token security](references/jwt-session-security.md) |
| Concrete JWT/Redis code or adapting the included token adapter | [JWT access-token security](references/jwt-session-security.md), then [JWT implementation shapes](references/jwt-session-implementation.md) |
| Username/password registration or login, password hashing, password change, administrator reset, temporary credentials, or account recovery | [Local password authentication](references/local-password-authentication.md) |
| Redis Token Bucket policies, API admission, abuse quotas, trusted client IP, limiter keys, `429`, or limiter `503` | [Rate limiting and abuse-control quotas](references/rate-limiting.md) |
| Login/registration `IdentityAbuseFlow` or a non-blocking login-failure risk signal | [Rate limiting and abuse-control quotas](references/rate-limiting.md), then [Verification and abuse defense](references/verification-and-abuse-defense.md) |
| Explicitly requested CAPTCHA, email/SMS code, MFA, delivery, consumption, or verification abuse defense | [Rate limiting and abuse-control quotas](references/rate-limiting.md), then [Verification and abuse defense](references/verification-and-abuse-defense.md) |
| Login-identifier selection, user lifecycle, soft deletion, restore, or RBAC bind/unbind storage | [Identity and soft-delete lifecycle](references/identity-soft-delete.md) |
| Identifier policy, prefixed business IDs, UUID models, sequence avoidance, or public ID review | [Identifier policy](references/identifier-policy.md) |
| Concrete sequential-ID migration or identifier backfill | [Identifier policy](references/identifier-policy.md), then [Migrations](references/migrations.md) |
| Country/region directory scope, fields, lifecycle, source data, read API, or calling-code semantics | [Optional country catalog](references/country-catalog.md) |
| Concrete country PostgreSQL model, migration, CSV import, routes, or tests | [Optional country catalog](references/country-catalog.md), then [Country catalog PostgreSQL](references/country-catalog-postgresql.md) |
| Database-agnostic RBAC policy, flow, or authorization cache | [RBAC design](references/rbac.md) |
| PostgreSQL models, services, endpoints, or runnable baseline | [PostgreSQL implementation](references/postgresql-rbac-implementation.md) |
| Hierarchy, delegation, ownership, protected identities, or self-elevation | [Administrative hierarchy](references/administrative-hierarchy.md) |
| Authorization writes, immediate revocation, concurrency, commit/rollback outcomes, or cache invalidation | [Atomic authorization consistency](references/atomic-consistency.md) |
| Tables, constraints, permission seeds, backfills, or upgrades | [Migrations](references/migrations.md) |
| Explicit proxy availability, latency, or exit-IP checks; Redis result hydration; or single/batch detection | [Proxy availability detection](references/proxy-availability-detection.md) |
| Test plan, implementation verification, completion audit, or test infrastructure | [Testing](references/testing.md) |

Add another reference only when the deliverable spans its concern. For example,
a concrete PostgreSQL hierarchy write needs the PostgreSQL, hierarchy, and atomic
references; a schema change adds migrations; implementing behavior tests adds
testing. A policy-only review need not load implementation or test files.

Decide this routing from the request and repository evidence before opening a
reference. Do not open a file merely to check whether it might be useful. A
PostgreSQL administrative write with no schema or baseline-policy change does not
need `rbac.md`, `migrations.md`, or `modern-fastapi-stack.md`.
Specialized rows override the general RBAC row: a hierarchy-only question reads
only `administrative-hierarchy.md`, and an atomicity-only question reads only
`atomic-consistency.md` in addition to this entrypoint.
For an audited authorization mutation, read the RBAC audit module for event
schema and the atomic reference for transaction behavior. For an audited business
mutation, read the business audit module and add the atomic reference when the
audit must commit with the mutation or the write promises immediate revocation.
A logging-only change does not need either audit reference. An audit-only schema
review does not need the operational logging reference.

Do not load or add business audit merely because an endpoint performs CRUD. Use
it when the product needs durable evidence for money or balance changes,
ownership transfer, important state transitions, delete/restore, manual
overrides, sensitive export, security changes, or a documented compliance need.

Proxy availability detection is an optional product feature. Load or suggest it
only when the user explicitly asks for availability, latency, exit-IP, cached
results, or single/batch detection. A proxy model, proxy CRUD, or proxy management
page alone is not a loading condition. Never add it to an ordinary RBAC service
merely because this Skill contains the reference.

The country catalog is also optional. Load or suggest it only when the product
needs a maintained country/region table, selector, calling-code directory,
address-country validation, or country filtering. A user table, RBAC service,
proxy geolocation response, locale, currency, or time-zone field alone is not a
loading condition. Never create or seed `countries` in the default PostgreSQL
RBAC asset. Before importing data, require an approved exact code set and a
versioned source whose redistribution terms are known; a local CSV is not
automatically publishable source data.

The PostgreSQL implementation already fixes the baseline policy. Do not also read
the general RBAC reference unless changing its policy, model, or permission
semantics. Do not follow cross-links unless the current task meets their loading
condition.

Treat [assets/postgresql-rbac](assets/postgresql-rbac/) as output source, not
instructions. Copy it as one directory without reading every file. Never load the
asset recursively. Use `rg --files` and `rg -n "symbol-or-route"`, then inspect
only the code being adapted, its direct policy/query dependency, and matching
tests. Running a test does not require reading its implementation first.

## Fixed Baseline And Invariants

Unless existing product decisions conflict, keep these defaults:

- Python 3.12+, FastAPI, Pydantic 2, SQLAlchemy 2 async, asyncpg, Alembic, named
  constraints, explicit foreign keys, and PostgreSQL integration tests. SQLite
  cannot prove this lock or constraint contract.
- Use non-sequential primary/API IDs for users, roles, permissions, audit rows,
  and every business entity. For a new project without an established strategy,
  prefer a registered entity prefix plus a cryptographically random uppercase
  suffix; `U` plus 10 characters is the low-volume user example, while unknown
  volume defaults to 16 characters. Size the suffix from lifetime volume under
  [identifier policy](references/identifier-policy.md). Random UUIDv4 remains
  compliant, and the bundled PostgreSQL asset intentionally uses that profile.
  Access Token JTI remains a fresh random UUIDv4 protocol identifier. Never use
  `SERIAL`, `BIGSERIAL`, `IDENTITY`, integer autoincrement, `max(id)+1`, or a
  hidden sequential public alias. Integer tiers, versions, epochs, and counts
  are not identifiers. Non-sequential IDs reduce casual enumeration; they never
  replace capability checks, object authorization, non-leaking `404`s, rate
  limits, or IDOR tests.
- Use stable, exact `resource:action` positive grants. Active roles union
  permissions and take the maximum tier. Do not add deny rules, wildcards, role
  inheritance, scope languages, or a permission cache to the baseline.
- Seed the immutable system roles `super_admin`, `admin`, and `user` at tiers
  `1000`, `500`, and `0`. They cannot be disabled, soft-deleted, renamed,
  re-ranked, or have their grants changed through public administration APIs.
  Every normally registered or provisioned user receives `user` in the same
  PostgreSQL transaction and cannot lose it through the role-unbind API. Never
  accept an initial role from a public registration body.
- Limit each user to at most 10 live `user_roles` assignments. This is a limit of
  10 live role bindings. Disabled roles still count, and tombstones do not count.
  The mandatory `user` assignment and any `super_admin` assignment both count.
  Enforce the final live total after authoritative locks in every service path,
  including bootstrap and transfer, and again in PostgreSQL so direct SQL and
  concurrent writers cannot exceed the limit.
  In the bundled fresh baseline, this database guard belongs to `0001` and
  `0004_password_auth` is the sole migration head. The password revision is the
  direct baseline addition for the still-unadopted schema, not a compatibility
  shim.
- Make every ordinary runtime removal of a mutable persisted row a soft delete,
  including users, custom roles, business entities, and relationship unbinds.
  Before adding any table, classify its row lifecycle explicitly: mutable rows
  use soft deletion, append-only evidence permits no deletion, and permanent
  state/catalog rows permit no runtime deletion. There is no unclassified table
  whose rows may be hard-deleted by default.
  Tombstone a deleted parent's complete live relation set atomically; a later
  bind creates a new relation episode, and restore never revives old privilege.
  System roles and the fixed permission catalog have no runtime deletion command.
  Audit rows are append-only rather than soft-deletable, and the singleton
  `rbac_state` is never deleted. Limit physical purge to explicit controlled
  non-audit maintenance, disposable tests, or reviewed migrations. Follow
  [Identity and soft-delete lifecycle](references/identity-soft-delete.md).
  These are mandatory application rules. Database privilege separation is a
  deployment hardening choice to discuss as described under Inspect First; the
  database owner can always bypass ordinary application controls.
- Apply capability, ownership, and row policy consistently to detail, list,
  search, count, export, bulk, and nested operations. Keep ownership and row
  policy separate from RBAC.
- Larger tiers are higher. Compare complete current and proposed multi-role
  authority: ordinary actors manage only strictly lower authority. Deny peer,
  higher, incomparable, and protected targets, plus direct and indirect
  self-elevation. The sole `super_admin` uses tier `1000`; `admin` uses `500`;
  custom roles use `1..999`, while strict dominance limits an `admin` to roles
  below `500`.
- Apply the same strict hierarchy to administrative user and role list, count,
  search, detail, export, and nested reads. The current `super_admin` may view
  all non-deleted users and roles. Every other administrator sees only authority
  strictly below its own and never sees itself, a peer, a higher target, or a
  protected target through administration routes. Return a non-leaking `404`
  for a concealed detail; expose the caller's own authority only through
  `/api/v1/me/access`.
- Apply capability before administrative-write visibility. A caller missing the
  operation capability receives `403001` before target existence, visibility,
  or version can affect the response. After locks and the capability recheck,
  conceal a self, peer, higher, or protected user or role with the same `404001`
  as an unknown ID; apply this to every role ID in a bind or unbind request too.
  Only a visible target that fails delegation, affected-user, system-role, or
  another operation-specific policy returns `403001`.
- Keep role assignment, role definition, permission replacement, delegation, and
  super-admin transfer as separate capabilities. `can_delegate` is an explicit
  subset; new roles start with no permissions; only `super_admin` changes
  delegation; delegation control and transfer cannot be delegated. The seeded
  `admin` may manage strictly lower users and custom roles within its explicit
  delegation ceiling, but cannot delete roles, change system roles, change
  delegation policy, or transfer `super_admin`.
- Initialize the first `super_admin` only after the intended person has an
  existing account with the mandatory `user` role. Tell the user to personally
  run the supplied PostgreSQL `sql/bootstrap_super_admin.sql` from a trusted
  host and identify the account only by immutable `users.id`; do not bootstrap
  by email or `user_name`, auto-promote the first registrant, expose an HTTP
  bootstrap route, or execute an ad hoc bare assignment. The script owns one guarded transaction,
  refuses a different existing holder, increments authorization versions only
  when the binding changes, and audits the result.
- Privileged bodies use `extra="forbid"` and never accept super-admin status,
  protection, delegation, or caller-selected current authorization-version fields. A
  required `expected_version` is only an optimistic concurrency condition and
  never chooses the stored version. Protect system roles, the final
  `super_admin`, bootstrap, and break-glass paths explicitly.
- Keep the authorization mechanism private to the implementation. Public paths,
  OpenAPI tags, operation IDs, application titles, and errors must not use
  `rbac`; use resource routes under `/api/v1` and the numeric business-code
  registry in [API response standard](references/api-response-standard.md). The
  baseline administration API uses only `GET` and `POST`. Internal modules such
  as `app.rbac` may remain.
- Every ordinary JSON response uses exactly `code`, `message`, `data`, and the
  mandatory server-generated UUIDv4 `request_id`; return the same value in
  `X-Request-ID`. Use real HTTP status codes and six-digit integer business
  codes whose first three digits match the HTTP status. Simple page-number lists
  return only `items`, `page`, `page_size`, and `total` inside `data`. Do not
  trust a caller's request ID as the server ID. Follow
  [API response standard](references/api-response-standard.md).
- Emit application-owned operational logs as one-line structured JSON to stdout
  with stable event names, UTC timestamp, level, service/build identity, and the
  server request ID. Use a pure ASGI observer and emit exactly one completion at
  the terminal response, send, disconnect, cancellation, or application-failure
  boundary; a failure after the final body gets a separate post-response event,
  never a second completion. Include the route template, observed HTTP status,
  numeric business code, monotonic duration, response state, outcome, and only
  the canonical user ID after full authentication. Never log raw
  paths, query strings, request/response bodies, arbitrary headers, email,
  username, passwords, credentials, cookies, bearer tokens, JWT/JTI values,
  proxy URLs, or database/Redis URLs. Logging failure does not decide transaction
  success. Follow [Operational logging](references/operational-logging.md).
- Keep durable audit separate from operational logs. `rbac_audit_events` is an
  append-only record only for access-control administration and decisions; it is
  not a Token, login, proxy, or general activity table. Server code owns actor,
  targets, action, decision, reason, source, schema version, safe bounded
  before/after state, correlation ID, and database time. Clients cannot submit
  audit rows. An allowed privileged mutation and its audit commit together;
  denied auditing occurs only after protected rollback and cannot turn denial
  into success. Follow [Audit module](references/audit-module.md).
- Keep business evidence separate from RBAC evidence. The bundled asset provides
  a reusable append-only `business_audit_events` model, migration, and staging
  helper, but applications emit rows only for an explicit action catalog with a
  per-action state allowlist. Use `outcome` values `succeeded`, `failed`, and
  `denied`; never copy arbitrary request bodies or exception data. A succeeded
  mutation and its audit row commit in the same PostgreSQL transaction. Write a
  meaningful failed or denied event only after the protected transaction has
  rolled back, and never record an uncertain commit as failed. Follow
  [Business audit module](references/business-audit-module.md).
- Keep rate-limit policy in one typed configuration module. The bundled asset
  uses continuously refilled Redis Token Buckets, HMAC-private subjects, Redis
  server time, and one all-or-nothing Lua decision for every applicable bucket.
  A valid denial is `429001` with `Retry-After`; missing, failed, or malformed
  Redis authority is fail-closed `503001` without `Retry-After`. Keep limiter
  Redis outside PostgreSQL transactions and prefer a separately operated
  limiter Redis when production capacity or failure isolation requires it.
  Never permit a deployment environment to disable these protections. The
  bundled settings require an explicit `APP_ENVIRONMENT` and provide no code
  default; a missing value must stop startup even when rate limiting is enabled.
  This prevents an omitted deployment setting from silently becoming local.
  The
  bundled escape hatch accepts `RATE_LIMIT_ENABLED=false` only when
  `APP_ENVIRONMENT` is explicitly `dev`, `development`, `local`, `test`, or
  `testing`; it intentionally bypasses API admission and `IdentityAbuseFlow` and
  is only for isolated local work or tests.
- Keep the password-login baseline usable without any verification channel. Its
  only hard login-admission limits are trusted IP, trusted IP plus normalized
  account, and global traffic. The expiring per-account failure count is only a
  private risk signal: it never denies an attempt by itself, never creates an
  account-wide `429`, and never prevents correct credentials from being checked.
  Do not add an account-only lock or waiting period that an attacker can trigger
  for another person.
- CAPTCHA, email/SMS codes, and MFA are optional product features and are off by
  default. Add one only after the user explicitly requests it. When none is
  selected, do not require an email or phone field, verification HMAC key,
  purpose/channel allowlist, provider, or verification route.
  The complete asset keeps its tested email/SMS modules dormant; for a
  username/password-only product, leave `VERIFICATION_ENABLED=false` and do not
  ask the user whether to delete those files. Their presence is not a product
  requirement and must not expose any verification API.
- Route product-owned login and registration callbacks through the bundled
  `IdentityAbuseFlow`; do not reconstruct its ordering in a route. Credential
  callbacks return a verified value or `None`, perform real-or-dummy credential
  work, and never issue a Token. Token issuance starts only after the flow has
  admitted the attempt, recorded success, and returned. A registration callback
  runs only after every registration bucket admits it.
- Keep public self-registration absent from both routing and OpenAPI unless the
  product owner explicitly selected it. The bundled asset defaults
  `PUBLIC_REGISTRATION_ENABLED=false`; enabling the setting registers exactly
  the registration router and does not permit caller-selected roles.
- Use the bundled local-password baseline when the project selects passwords:
  Argon2id runs outside the event loop; live hashes use credential episodes whose
  retired rows are soft-deleted with the hash cleared; unknown users perform the
  same class of Argon2 verification against a process dummy hash; and public
  login failures do not reveal whether the user, credential, or account status
  caused rejection. Self-service password change verifies the current password.
  Administrator recovery creates a temporary credential only for a strictly
  lower, visible, non-protected user and requires the administrator's current
  password again. Successful change, reset, or reset completion rotates the
  credential, increments `users.token_version`, and writes its account-security
  audit in one PostgreSQL transaction. It never issues a replacement Token.
  Username alone is not ownership proof: without an explicitly verified recovery
  channel, use human verification plus administrator reset, and reserve sole
  `super_admin` recovery for the offline operator command. Follow
  [Local password authentication](references/local-password-authentication.md).
- By default, an Access Token contains exactly `sub`, `jti`, `iat`, `exp`, and
  `token_type`. `sub` is the only user identity claim and is the canonical string
  of the project's immutable `users.id`, whether a validated prefixed ID or
  UUIDv4; the selected email/`user_name` login policy never changes that subject.
  Add `iss` and `aud` only as a pair after the plain-language explanation and the
  user's explicit consent. When enabled, issue and validate both exactly; when
  disabled, reject either as an unexpected claim. Silence is not agreement, and
  an existing project's configured pair remains enabled unless removal or
  migration is requested. Never put username, email, display name, roles,
  permissions, tier, status, protection flags, or versions in the payload.
  Require a unique random UUIDv4 `jti` and validate it against the server-side
  Redis active-JTI record before authorization. The Access Token lifetime defaults
  to 3600 seconds; expose it as configuration and explicitly tell the user to
  adjust it for business risk and login experience. Do not add a PostgreSQL Token
  table or a per-request Token-record query. After Redis, reload the existing
  PostgreSQL identity and RBAC authority and compare the Redis-bound user version;
  fail closed on unavailable state. Reject missing, blank, example, short,
  repetitive, low-diversity, whitespace-containing, or control-character HS256
  secrets at startup; never fall back to an insecure default. Bound both encoded
  and presented Access Tokens to 4096 bytes. Current-Token logout removes only
  the exact Redis JTI; account-wide logout increments `users.token_version` in
  PostgreSQL and does not scan Redis. Follow
  [JWT access-token security](references/jwt-session-security.md).
- Use HTTP `401`/business `401001` for invalid, expired, missing, or revoked
  credentials; `403`/`403001` for a visible but forbidden action;
  `404`/`404001` for a missing or deliberately concealed resource; and
  `503`/`503001` when a required authentication authority is unavailable.
- Apply the same authorization service at HTTP, WebSocket, job, CLI, and direct
  service trust boundaries. Audit privileged decisions without secrets.

## Atomic Authorization Boundary

Every authorization control-plane write, and every protected business write that
promises immediate revocation, has one authoritative transaction. Under the
shared lock order, every writer acquires the fixed
`rbac_state(scope='global')` guard as its first lock, then reloads the
actor and complete affected authority from PostgreSQL, decides again, and commits
the mutation, all version increments, and the allowed audit together. On denial,
roll back the whole attempt before writing a denied audit in
a separate transaction. A route check, old JWT, cached context, or earlier ORM
read cannot replace this decision. Follow [atomic authorization consistency](references/atomic-consistency.md).
Role update, lifecycle, deletion, and permission or delegation bind/unbind
commands require `expected_version` in the JSON body and compare it with
`roles.version` only after locks, authoritative reload, and the complete policy
and hierarchy decision. An unauthorized caller receives `403001` without learning
whether the submitted version is current. A stale value for an authorized caller
returns HTTP `409` with business code `409002`; it cannot mutate state or write an
allowed audit. Build the successful response body's role and new version from the
same immutable snapshot before releasing those locks. User role bind/unbind
remains an incremental, idempotent, single-transaction command and does not
require a user version in this baseline: under the global guard, bind checks that
the complete final set has at most 10 live assignments, unbind tombstones the
live relation, and a later bind creates a new relation episode instead of
reviving it. PostgreSQL independently enforces the same deferred final-state
limit for direct and concurrent writers.
Redis is outside the PostgreSQL authorization transaction. Never perform Redis
I/O while holding authorization locks, and never recreate a missing active-JTI
entry from a JWT. Account-wide Token revocation increments
`users.token_version`; each request compares it with the version bound in Redis
while loading the existing user and RBAC state. Do not add PostgreSQL Token rows
or a Token-cleanup database queue.

## Implementation Workflow

1. For greenfield work, settle the complete login-identifier contract. Then
   define actors, protected resources, stable capabilities, row-level rules,
   administrative effects, expected failure responses, and which operations
   require RBAC or business audit. For business audit, define the action catalog,
   resource meaning, outcomes, and safe state fields before writing events.
2. For greenfield PostgreSQL RBAC, copy the complete asset. In an existing app,
   preserve its policy, transaction, query, and migration boundaries.
3. Implement complete configuration, models, schemas, dependencies, services,
   routes, migrations, and tests. Never copy a route without its policy, locking
   query, database constraint, audit path, and negative tests.
4. Keep authentication, capability checks, ownership, and row policy
   distinct. Configure safe structured logging at the application boundary and
   keep it independent from audit transaction success. Run formatting, linting,
   typing, migrations, PostgreSQL tests, an ASGI exercise, and secret-marker log
   and audit tests; report anything not verified.

## Completion Gate

For implementation or completion work, load [Testing](references/testing.md) and
apply only the matrix for the delivered surfaces. At minimum:

- install and import in a clean environment; run formatting, linting, strict
  typing, migration, PostgreSQL/Redis behavior, API-contract, policy, audit,
  logging, JWT, IDOR, concurrency, rollback, and secret-leak checks that apply;
- verify the fixed system roles, 10-live-role limit, strict read/write hierarchy,
  soft-delete lifecycle, transaction/audit coupling, response contract, Redis
  active-JTI gate, and both Token-revocation scopes end to end;
- for every delivered limiter surface, run real-Redis tests for Token Bucket
  refill, batch all-or-nothing behavior, longest retry, TTL, Redis time, key
  privacy, and concurrent admission; prove the login failure signal is atomic,
  expires, clears on success, and never blocks correct credentials by itself;
  also prove `429001`/`503001` headers and fail-closed limiter behavior;
- only when the user selected a verification feature, test its challenge
  replacement, single-use consumption, provider boundary, and failure contract;
- prove `IdentityAbuseFlow` never calls credential or registration callbacks
  after admission denial/unavailability, records exactly one login failure for
  `None`, clears failure state before returning success, and keeps the product
  Token issuer outside the credential callback and after the successful return;
- test proxy detection and the country catalog only when the user requested
  those optional features, using their own reference checklists; and
- report every skipped production assumption or unavailable integration service.

Never call the result production-ready while required PostgreSQL, Redis,
migration, concurrency, or deployment behavior remains unverified.
