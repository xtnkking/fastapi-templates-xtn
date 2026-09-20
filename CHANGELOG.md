# Changelog

**English** | [简体中文](CHANGELOG.zh-CN.md)

All notable changes to this project will be documented in this file.

## [0.6.1] - 2026-09-20

- Kept anonymous login and registration CAPTCHA challenges deliberately
  independent of the issuing IP so VPN and mobile-network changes do not make
  a displayed challenge unusable. Each challenge remains scene-bound,
  five-minute, and single-use; issuance and submission keep their independent
  trusted-IP rate limits.
- Authenticated routes now validate the JWT and Redis active JTI, then inspect
  an existing operation-and-user window without incrementing it. An exhausted
  window returns `429` before PostgreSQL; open windows are charged only after
  the current PostgreSQL identity and Token version are confirmed. Stale
  identities therefore do not consume the legitimate user's quota, while an
  active stolen Token cannot keep reaching PostgreSQL after exhaustion. A
  database-rejected stale JTI is removed on a best-effort basis; current-Token
  logout remains Redis-only.
- Limited OpenAPI `429` responses to routes that actually enforce a quota, and
  added ordering, stale-Token cleanup, cross-IP CAPTCHA, and contract tests.
- Reduced the always-loaded `SKILL.md` entrypoint and moved detailed rules to
  task-specific references. Automatic discovery now targets projects that
  explicitly adopt this PostgreSQL/Redis/local-password authorization baseline;
  i18n implementation files and tests are linked directly from the references.
- Added an installed-Skill `VERSION` source, a staged and rollback-capable
  update tool, reproducible Python 3.12/Linux CI constraints, and wheel-content
  validation. Release readiness now distinguishes unchecked plans from recorded
  evidence instead of treating a heading as proof that a release was completed.
- CI now recursively checks the complete dependency closure selected by the
  project and test roots on CPython 3.12/Linux, including `uvloop` selected by
  `uvicorn[standard]`; any selected dependency without an exact pin fails.
- Documented the mandatory independent `JWT_SECRET` and
  `RATE_LIMIT_HMAC_KEY`; packaged third-party notices are now verified in the
  built wheel.
- Changed the configurable Access Token default from 3,600 seconds to 86,400
  seconds (24 hours). This improves ordinary login continuity but lengthens the
  replay window for a stolen Token whose JTI remains active, so adopters must
  shorten it for high-risk or administrative surfaces; Redis JTI revocation,
  logout, password rotation, disablement, and administrator revocation remain
  available to invalidate it early.

## [0.6.0] - 2026-09-20

- Added request-local API internationalization for every client-facing runtime
  response message and safe validation detail. The baseline now ships complete
  `zh-CN` and `en` catalogs, defaults to Chinese, negotiates a bounded standard
  `Accept-Language` value, and returns canonical `Content-Language` plus
  `Vary: Accept-Language`. Stable HTTP/business codes, response data, request
  IDs, logs, audit fields, and internal reason codes are not translated. A
  specific `q=0` exclusion overrides parent ranges and wildcards; safe `422`
  field hints never reflect extra or nested mapping keys; and even an unhandled
  `500` retains both language headers.

- **BREAKING:** Administrator password reset is now a project-wide choice.
  `direct` is the default and immediately stores the administrator-supplied
  value as the user's permanent password; optional `temporary` requires one
  formal-password completion before login can issue a Token. Project generation
  must explain and ask about both modes, while API callers cannot switch modes
  per request. `AdminPasswordResetRequest.temporary_password` is renamed to
  `new_password`. Both paths keep CAPTCHA, exact capability, strict-lower target,
  Token revocation, atomic account-security audit, and secret redaction. The
  existing `users.must_change_password` column supports both, so no migration or
  table change is required. A project upgrading from `v0.5.1` that intentionally
  wants the old mandatory-temporary-reset behavior must explicitly set
  `ADMIN_PASSWORD_RESET_MODE=temporary`.

## [0.5.1] - 2026-09-19

- Corrected login and registration admission order: the public-IP business
  quota runs before CAPTCHA consumption, then CAPTCHA is consumed before any
  password check, user creation, or Token issuance. A rate-limit denial does
  not consume a CAPTCHA, while every accepted invalid-CAPTCHA attempt still
  spends the login or registration quota.
- Made authenticated route quotas fail closed when an operation is missing
  from the explicit immutable policy map. Administrator session revocation now
  uses the management-change quota instead of the ordinary-write quota.
- Moved user/role visibility, exact username filtering, soft-delete filtering,
  pagination, and totals into bounded PostgreSQL queries. User management
  responses now include `user_name`, and hidden peers or higher users remain
  indistinguishable from nonexistent targets.
- Added `Cache-Control: no-store` to the current-session response and added
  separate `/health/live` and dependency-aware `/health/ready` probes. The
  readiness probe requires the single expected Alembic head and global
  `rbac_state` row, then checks both Redis targets with `PING` and a Lua
  write/read/delete round trip over random five-second keys. It uses bounded
  timeouts and exposes only overall readiness, never connection details, keys,
  component states, or internal exceptions.
- Compressed the main Skill entrypoint and added an opt-in Chinese architecture
  overview while preserving on-demand routing to detailed references. Archived
  the [v0.4.0 design discussion](docs/history/v0.4.0/DESIGN_REVIEW.zh-CN.md) so
  it cannot be mistaken for current behavior.
- Hardened CI with full-SHA action pins, Ruff formatting, dependency auditing,
  stricter release validation, and route-policy coverage checks. The official
  verification environment is Python 3.12, PostgreSQL 17, and Redis 7.
- Resolved dependency-audit findings by requiring `pytest>=9.0.3,<10` with the
  compatible `pytest-asyncio>=1.4,<2` line, and upgrading CI to `pip>=26.2`
  before dependency installation and audit.
- This release changes no database table or migration. The four migrations
  published in `v0.5.0` remain immutable.

## [0.5.0] - 2026-09-13

- **BREAKING:** New projects now use required, non-reusable
  `user_name` only. Public registration starts enabled through a persistent,
  super-admin-only server switch; administrator creation remains available when
  public registration is closed. Both paths grant only `user`. The baseline
  requires five distinct one-attempt graphical-CAPTCHA scenes for login,
  registration, administrator user creation/reset, and self password change;
  it does not bundle email/SMS delivery or a self-service forgot-password API.
- **BREAKING:** Replaced global and cross-business Token Bucket
  quotas with per-business Redis atomic fixed windows. Unauthenticated login,
  registration, temporary-password completion and public CAPTCHA issuance use
  trusted IP plus business; authenticated work (including its CAPTCHA) uses
  immutable user ID plus business.
  There is no submitted-username quota or global site budget. CAPTCHA issuance
  defaults to 10 per scene and subject per five minutes. Limits remain
  configurable and must be shown to the project owner before generation.
- **BREAKING:** Removed online super-admin transfer, ordinary
  self logout-all, and the separate `can_delegate` switch and APIs. A guarded,
  audited offline SQL handover replaces online transfer. Ordinary logout revokes
  only its current Token; authorized administrators can revoke a strictly lower
  user's sessions. A project-chosen concurrent-login limit evicts the oldest
  active login on successful issuance; Redis records login times, not devices.
  Grants remain bounded by the grantor's own effective permissions.
- Kept optional country and proxy guidance behind explicit product selection;
  neither opens anonymous ordinary business reads or a global quota. Updated
  release validation and the `v0.5.0` checklist to enforce the simplified
  baseline while keeping the published `v0.4.0` record intact.
- **BREAKING:** Store local Argon2id password state directly on
  `users` with nullable `password_hash` and `password_changed_at`, non-null
  `must_change_password=false`, and the existing `token_version`. Remove the
  separate `user_password_credentials` table and credential-episode versions.
  User soft deletion clears the hash and restoration never revives it. Committed
  password-change counts derive from successful account-security audit events,
  not a second mutable counter. The reference asset is for fresh projects; no
  in-place database migration from the `v0.4.0` asset is provided.
- Corrected CAPTCHA rejection limits for malformed parsed requests, preserved
  the old challenge if image rendering fails during refresh, and fixed
  PostgreSQL downgrade ordering with nonempty data. Added an asset setup guide
  and verified the full PostgreSQL 17 and Redis test suites.

## [0.4.0] - 2026-09-13

- **BREAKING:** Greenfield services must first choose whether `users` stores
  `email`, `user_name`, or both, then separately settle per-flow requiredness,
  login input, normalization, uniqueness, cross-field ambiguity, and
  post-deletion reuse before modeling users. Existing services preserve their
  contract by default. JWT `sub` and the offline
  first-super-admin bootstrap now identify users only by immutable `users.id`;
  the bootstrap parameter is `super_admin_user_id`.
- **BREAKING:** The default Access Token claim contract is now exactly `sub`,
  `jti`, `iat`, `exp`, and `token_type`. `iss` and `aud` are an optional pair:
  before enabling them for a new project, the Skill explains in plain language
  that they reduce cross-service Token confusion but add signer/verifier
  configuration, then requires explicit user consent. No reply is not consent.
  Existing projects that already configure both keep them by default. The Redis
  active-JTI namespace no longer depends on the optional public issuer claim.
- Added centrally configured, two-layer HTTP rate limiting with one atomic Redis
  decision for all buckets applying to an event. The runnable asset covers the
  early global/trusted-IP gate, authenticated read and write classes,
  administration writes, `super_admin` transfer, and logout-all. Denials use
  HTTP `429`/`429001` plus `Retry-After`; an unavailable or malformed limiter
  fails closed as `503001`. Redis keys use purpose-bound HMAC fingerprints and
  never expose raw IPs, account names, user IDs, Tokens, or JTI values. CI and
  the development stack now exercise this state in a dedicated Redis separate
  from the active-JTI service. `APP_ENVIRONMENT` is now required and has no code
  default, so omission cannot silently select `development`. Disabling the
  limiter is rejected outside an explicitly named local or test environment,
  preventing deployed registration, login, temporary-reset, and
  password-reauthentication paths from bypassing `IdentityAbuseFlow` through
  configuration.
- Added reusable username/password login and registration abuse defense, plus an
  optional email/SMS verification service that is disabled by default. The only
  hard login-admission limits are IP, IP plus normalized account, and global
  traffic. Login failures update an atomic, expiring private risk signal; the
  count never denies a request by itself or prevents correct credentials from
  being checked. CAPTCHA, email/SMS codes, and MFA are added only after an
  explicit product choice. When code verification is selected, codes are
  generated with `secrets`, bound to purpose/channel/target, stored only as HMAC
  digests, expire after five minutes, allow at most five wrong attempts, replace
  older active challenges, and can be consumed only once. Provider and public
  login/registration route integration remain product-owned adapter points.
  Before generating a selected control, the Skill shows every applicable default
  and asks the user to accept all values or list changes; silence is not
  acceptance, and production-wide/provider capacities still require
  deployment-specific review. The optional per-target send policy is named
  `verification_target_average`: it begins with five sends and continuously
  refills at an average of five per 24 hours, rather than resetting by calendar
  day or enforcing a hard maximum over every arbitrary 24-hour interval.
- Added the complete local-password baseline that the earlier abuse primitives
  were missing: Argon2id hashing outside the event loop, soft-deleted credential
  episodes, public registration/login, self password change, strictly
  lower-target administrator reset, one-time temporary reset completion, and an
  offline sole-`super_admin` recovery command. Password rotations increment
  `users.token_version` and commit with append-only account-security evidence.
  Authentication uses one short-lived Access Token, requires login again after
  expiry, and introduces no per-Token PostgreSQL table. The Skill now
  asks one compact set of product questions about identity/login input,
  registration, verified recovery proof, simultaneous devices, and enrollment
  of existing accounts while keeping cryptographic and transaction details as
  fixed defaults. Release validation now inspects the Python route, settings,
  Argon2, model, operator, and Alembic structures instead of accepting a set of
  documentation files as proof that this baseline is complete. Credential
  episode versions continue above the user's historical maximum even when only
  tombstones remain; direct service calls cannot reuse the current or temporary
  password as the replacement; and infrastructure failures are not mislabeled
  as denied account-security decisions.
- Public self-registration is now opt-in through
  `PUBLIC_REGISTRATION_ENABLED=false`: when disabled, its route is not registered
  and does not appear in OpenAPI; enabling it preserves the protected `POST`
  flow and mandatory lowest-role assignment.
- **BREAKING:** Each user is limited to 10 live role bindings, including the
  mandatory `user` and any `super_admin` assignment. Disabled-role bindings still
  count; tombstoned history does not. The service validates the complete final
  set under the global guard, bootstrap and `super_admin` transfer apply the same
  rule, and PostgreSQL serializes and rejects direct or concurrent over-limit
  writes. The fresh baseline now installs this database guard in `0001`, removes
  the unnecessary follow-up compatibility revision, and leaves
  `0004_password_auth` as the sole migration head.
- **BREAKING:** Ordinary administrators can now list or view only live users and
  roles with strictly lower authority, while `super_admin` can read every live
  entry; hidden details are indistinguishable from missing resources. Role and
  user list hydration now uses batch queries whose SELECT count does not grow
  with page size. User responses separate `assigned_role_ids` from
  `effective_role_ids` and effective authority: disabled roles remain assigned
  and count toward the limit but grant no current authority. Administrative
  writes now check capability first (`403001`), then conceal self, peer, higher,
  protected, unknown, and hidden requested-role targets uniformly as `404001`;
  `403001` remains the result for a visible target that fails delegation or
  affected-authority policy. Internal bind/unbind service entry points now reject
  unknown operation values before opening a transaction instead of treating a
  misspelling as the opposite operation.
- **BREAKING:** Authentication startup now rejects public example placeholders
  and obviously weak JWT secrets. Incoming Bearer Tokens and generated Access
  Tokens are both limited to 4096 UTF-8 bytes. Added
  `POST /api/v1/auth/logout-all`, which increments `users.token_version` so all
  Tokens previously issued to the account fail subsequent authentication; it
  does not bulk-delete their Redis records.
- **BREAKING:** Removed the unused `roles:permissions:update` and
  `system_owner:transfer` permission keys. Public API responses and OpenAPI now
  use `super_admin` terminology without exposing `is_super_admin` or application-level
  ownership language. The implementation-only role flag is now consistently
  named `is_super_admin`, including ORM, SQL, constraints, indexes, and tests.
  The legacy `owner` role key is no longer reserved or interpreted by the
  system; it is available as an ordinary custom-role key without special
  authority.
- **BREAKING:** Every mutable row that may be removed at runtime now uses soft
  deletion, including users, custom roles, business entities, and RBAC unbinds.
  RBAC joins are non-sequentially identified relation
  episodes with partial live-pair uniqueness; unbind tombstones the live episode,
  rebind inserts a new one, parent deletion tombstones its live relations in the
  same transaction, and restore never revives old privileges or Redis JTI state.
  System roles and the fixed permission catalog expose no runtime deletion
  command. This contract applies to every lifecycle path the product exposes;
  the bundled asset directly implements custom-role deletion and the two RBAC
  unbind paths, while user, permission-catalog, and business-entity lifecycle
  remain explicit product adaptation points.
- Clarified that audit rows remain append-only without a soft-delete path and
  reject runtime update, delete, and truncate. The singleton
  `rbac_state(scope='global')` is never deleted or truncated. Physical purge is
  restricted to separately controlled, eligible non-audit tombstones; destructive
  audit retention requires a separately approved product and legal exception.
- Preserved the original HTTP `403`, `404`, or `409` authorization result when a
  denied-audit write itself fails, while still logging the audit-storage failure.
- Made PostgreSQL migration/runtime-role separation an initialization-time,
  optional production-hardening decision. Recommend separate roles when
  professional operations support can manage them, but do not block small or
  learning projects; PostgreSQL owner or superuser SQL can bypass application
  soft deletion and remains outside the application guarantee.
- Added an optional, progressively loaded country/region catalog contract and
  PostgreSQL implementation guide. It uses the alpha-2 code as a natural key,
  keeps shared calling codes as strings, separates inactive and soft-deleted
  states, defines atomic imports that never infer deletion or restoration, and
  exposes only active read APIs by default. Added a read-only UTF-8 CSV validator
  with exact approved-code-set comparison and focused tests. Formal imports with
  any non-empty `flag_url` now require an explicit allowlist of approved ASCII DNS
  hostnames; `--structure-only` remains non-authoritative and reports
  `membership_checked=false`. Release validation rejects bundled CSV/TSV country
  data and likely country/flag media assets. No third-party country dataset is
  redistributed without documented provenance and permission.
- Added a separate, progressively loaded business-audit module and reusable
  PostgreSQL asset. It provides an explicit per-action catalog and state
  allowlists, `succeeded`/`failed`/`denied` outcome semantics, append-only
  database controls, caller-owned atomic success writes, safe post-rollback
  failure recording, retention/access guidance, and focused unit and PostgreSQL
  tests without broadening `rbac_audit_events`. The asset also rejects
  recognizable email and network values, supports durable outer-transaction
  savepoint evidence, and blocks direct update, delete, and truncate. Operational
  guidance covers read access, export, retention, partitioning, legal hold,
  alerts, backup, and recovery. The proposed
  `business_audit_delivery_outbox` table and its worker, lease, retry, and
  dead-letter design were removed because external audit delivery is not part
  of this Skill's baseline.
- Added progressively loaded operational-logging and durable-audit modules. The
  runnable asset now emits safe one-line JSON request events with request-ID
  correlation and defensive redaction, validates bounded audit snapshots, records
  trusted source and schema version, and enforces append-only RBAC audit rows with
  PostgreSQL constraints and an update/delete trigger.
- **BREAKING:** Added one four-field JSON response envelope with real HTTP
  statuses, six-digit integer business codes, mandatory server-generated
  request IDs in both body and header, and simple `items`/`page`/`page_size`/
  `total` pagination. The runnable asset now applies it to success, domain,
  validation, framework, and unexpected-error responses.
- **BREAKING:** Replaced strong role ETag/`If-Match` handling with body
  `expected_version`, accepted only as a strict JSON integer and checked against
  `roles.version` after authoritative locks and the complete authorization
  decision. Authorized stale writes now return HTTP `409` with business code
  `409002`, avoiding both a version oracle and an invalid strong ETag over
  envelopes whose `request_id` changes per request.
- Renamed the RBAC global guard and administration audit internals from ambiguous
  authorization naming to `rbac_state`, `RbacState`, `rbac_audit_events`, and
  `RbacAuditEvent`. Because the Skill has no adopters yet, the initial revisions
  now create and use the final names directly without compatibility migrations.
- Replaced the Python first-super-admin bootstrap entry point with a supplied
  PostgreSQL transaction script. The intended account must already exist with
  `user`, and the user personally runs the guarded, audited binding against the
  target database; the script never creates an identity or silently promotes
  the first registrant.
- Made UUIDv4 a supported identifier profile rather than a universal mandate.
  New projects without an established strategy now prefer registered business
  prefixes plus CSPRNG uppercase suffixes sized by lifetime namespace volume;
  the published PostgreSQL asset remains on its compatible UUIDv4 profile.
- Standardized authentication guidance on one minimal Access Token with a
  configurable 3600-second default. Implementers must tell users to review the
  lifetime against product risk and login experience.
- Simplified per-Token revocation to a required Redis active-JTI gate followed by
  the existing PostgreSQL user-status, user-version, and RBAC reload. The target
  design adds no individual Token database record or per-request Token-record
  query.
- Required Redis registration before issuance returns a Token, exact
  `sub`/type/`iat`/`exp`/user-version binding, fail-closed outage behavior, and
  confirmed compare-and-delete logout. Documented in-flight request and Redis
  failover limits prevent overstating revocation guarantees.

## [0.3.0] - 2026-09-07

- **BREAKING:** Replaced public `/rbac` routes and non-GET/POST administration
  methods with neutral `/api/v1/permissions`, `/api/v1/roles`, `/api/v1/users`,
  and `/api/v1/system` resource and action routes. Public OpenAPI metadata and
  error codes no longer reveal the internal authorization mechanism.
- Added the thirteen-route minimum permission, role-lifecycle, permission-binding,
  and user-role administration contract with strict capability checks and strong
  ETag/`If-Match` preconditions on shared-role changes.
- Added immutable `super_admin`, `admin`, and `user` system roles, mandatory
  transactional `user` assignment for new identities, custom-role soft deletion,
  restricted administrator authority, and an atomic offline first-super-admin
  bootstrap workflow.
- Added migration and database guards for legacy multi-holder upgrades, exactly
  one `super_admin` after assignment changes, and the reserved legacy `owner`
  role key. Role mutation bodies and ETags now come from one locked snapshot,
  and denied privileged route gates are audited.

## [0.2.0] - 2026-09-06

- **BREAKING:** Reworked authorization into a single-project RBAC baseline built on users,
  user-role assignments, and one global authorization state. Access tokens now
  carry only the minimal identity and protocol claims. This replaces the prior
  table, API route, JWT, and locking contracts and is not an in-place upgrade
  from `v0.1.0`.
- Added optional, progressively loaded proxy availability references covering
  forced proxy routing, safe error mapping, Redis latest-result caching, list
  hydration, a five-worker frontend batch flow, and controlled routing tests.
- Added Simplified Chinese mirrors for the repository documentation and
  bilingual GitHub issue and pull-request guidance.

## [0.1.0] - 2026-09-05

- Prepared the standalone Skill for public preview distribution.
- Added XTN ownership, upstream attribution, third-party notices, repository
  governance, security reporting, and automated validation.
- Rejected empty, public-placeholder, and shorter-than-32-byte JWT secrets in the
  included PostgreSQL RBAC asset.
