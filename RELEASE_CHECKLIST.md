# Release Checklist

**English** | [简体中文](RELEASE_CHECKLIST.zh-CN.md)

Use this checklist for the first public preview and subsequent releases.

## Local package

- [ ] The bundled Skill passes the current `skill-creator` quick validator.
- [ ] The optional country CSV validator's focused unit tests pass without
  modifying or bundling a source dataset.
- [ ] Ruff format and lint, strict mypy, `pip-audit`, and non-PostgreSQL tests
  pass.
- [ ] Test dependencies retain `pytest>=9.0.3,<10` and
  `pytest-asyncio>=1.4,<2`, and CI upgrades to `pip>=26.2` before installation
  and audit. Any lower baseline has a new clean dependency-audit result or an
  explicit temporary exception in both Security documents and CI.
- [ ] PostgreSQL-marked tests pass against PostgreSQL 17.
- [ ] Redis-backed authentication tests pass against Redis 7 for active JTI, and
  rate-limit, login/registration defense, and required graphical-CAPTCHA tests
  pass against a separately configured rate-limit Redis. The Redis-only
  CAPTCHA/session test uses a third empty logical database that does not
  overlap either integration target. Confirm all three CI URLs. Do not claim
  PostgreSQL/Redis behavior is verified until
  all database test groups have actually passed.
- [ ] Local-password tests cover Argon2id offload, real-or-dummy verification,
  password fields on `users`, registration/login, self change, administrator
  reset, temporary completion, offline operator recovery and super-admin
  handover, oldest-login eviction, Token invalidation, hierarchy, atomic
  account-security audit, and secret-free responses/logs.
- [ ] No `.env`, token, credential, private key, cache, database, or build artifact
  is present.
- [ ] `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` are present at repository,
  Skill, and copied-asset boundaries.
- [ ] README limitations match the behavior actually implemented by the asset.
- [ ] Both READMEs identify Python 3.12, PostgreSQL 17, and Redis 7 as the
  official verification environment, link the Chinese architecture overview,
  and document the distinct `/health/live` and `/health/ready` contracts. The
  readiness contract includes the exact migration head, global `rbac_state`,
  both Redis `PING` plus Lua write/read/delete probes, no-store responses, and
  non-disclosure.
- [ ] After all local checks, `python -B scripts/validate_release.py` passes from
  the final clean tree.

## v0.5.1 acceptance baseline

- [ ] A new project uses required `user_name` (3..32 ASCII letters, digits, or
  underscore, trimmed; reserved names and soft-deleted names cannot be reused).
  Ask once about username casing, password composition beyond 8..60 characters,
  the positive maximum simultaneous-login count, relevant rate-limit defaults,
  whether to enable `iss` and `aud` together, and whether professional operations
  will separate PostgreSQL migration-owner and runtime roles. Only an existing
  project also needs a decision for accounts without a local password. Preserve
  the chosen identity contract in an existing project.
- [ ] The PostgreSQL registration switch starts enabled, remains changeable
  through a super-admin-only command, and is checked transactionally on each
  public registration. A public read returns only the switch's boolean; closing
  registration does not block login or authorized administrator creation. Both
  account-creation paths grant only `user`.
- [ ] Each of the five required graphical-CAPTCHA scenes (login, registration,
  administrator create/reset, self password change) is purpose-bound and
  single-attempt: success and failure both consume it atomically. A CAPTCHA
  expires after five minutes, refresh replaces only its indicated old image,
  and issuance is limited to 10 per scene and subject per five minutes. Failed
  image rendering must not invalidate the old challenge. A valid scene at the
  wrong endpoint or parsed invalid CAPTCHA body uses an independent per-subject
  rejection quota without spending a scene's normal issuance budget.
  No email/SMS delivery module or self-service forgot-password route is bundled.
- [ ] Ordinary users can revoke only their current Token. The session read
  returns login count and timestamps, never claims to identify devices; successful
  issuance evicts the oldest when the project-chosen concurrent-login maximum
  is reached. A capability-checked administrator may revoke all sessions of a
  strictly lower user, not self, a peer, or a higher user.
- [ ] Exactly one `super_admin` is first appointed and later handed over only
  with guarded, audited, transactional offline SQL; no online transfer API or
  extra `can_delegate` switch/API remains. Grants are limited to the grantor's
  actual authority. Inventory every table and row-removal path: mutable records
  soft-delete, audits append only, and the 10-role limit and anti-self-elevation
  are enforced under locks.
- [ ] No global or cross-business quota exists, including in optional country
  and proxy guidance. Anonymous authentication is limited by business plus
  trusted IP; authenticated endpoints by business plus user ID. Fixed-window
  Redis admission fails closed when it cannot decide. Verify `429001`,
  `Retry-After`, and configurable defaults; no submitted username is a quota
  subject. Optional country reads are not anonymous ordinary business reads.
- [ ] JWT still defaults to one hour, only minimal claims plus a verified Redis
  active JTI, with no per-Token PostgreSQL table. `iss`/`aud` requires explicit
  adopter consent; password rotation revokes old Tokens. Preserve request IDs,
  safe errors and logs, atomic RBAC/account-security audits, and soft deletion.

The `v0.4.0` section below records the published historical checklist. Its
retired choices (email selection, online transfer, global quotas, or self logout-all)
must not be carried into `v0.5.1`.

## GitHub repository

- [ ] Create the public canonical repository at
  `https://github.com/xtnkking/fastapi-templates-xtn` with `main` as its default
  branch.
- [ ] Do not grant external users, teams, GitHub Apps, or deploy keys write,
  maintain, or administrator access.
- [ ] Enable two-factor authentication on the maintainer account and review
  personal access tokens and authorized applications.
- [ ] Enable private vulnerability reporting.
- [ ] Enable a ruleset for `main` that blocks deletion and force pushes, requires
  CI, and permits rule bypass only for XTN.
- [ ] Protect `v*` tags from deletion or replacement.
- [ ] Keep Issues enabled. Close external pull requests according to
  `CONTRIBUTING.md`.

## Release v0.5.1

- [ ] Review the complete diff, both READMEs, both changelogs, the current
  release checklist, the archived v0.4.0 design record, and the Chinese
  architecture overview. Match version `0.5.1` and date `2026-09-19` in asset
  metadata, installer URLs, changelogs, and the release validator.
- [ ] Confirm `v0.5.1` adds no schema revision and does not modify the four
  migrations published in `v0.5.0`. Any later schema change must add a forward
  Alembic revision instead of rewriting released history.
- [ ] Run Ruff format and lint, strict mypy, `pip-audit`, non-PostgreSQL tests,
  disposable PostgreSQL 17 / Redis 7 integration tests, migration
  upgrade-downgrade-upgrade checks, release validation, and the Skill quick
  validator. Verify live/readiness behavior, including the expected Alembic
  head, global `rbac_state`, both Redis `PING` plus Lua write/read/delete probes,
  cleanup, no-store, and non-disclosure, as well as every explicit route quota map.
- [ ] Confirm the final CI log uses `pip>=26.2`, resolves
  `pytest>=9.0.3,<10` with `pytest-asyncio>=1.4,<2`, and completes `pip-audit`
  without an unrecorded ignore.
- [ ] Commit and push `main`; wait for both CI jobs on that exact commit to
  pass. Create and push immutable `v0.5.1` on that commit without replacing or
  moving `v0.5.0` or any older tag.
- [ ] Publish a non-draft, non-prerelease GitHub Release for `v0.5.1`, then
  verify its source archive and a fresh `$skill-installer` installation from
  the tagged Skill path.

## Release v0.5.0

- [ ] Review the complete diff, the English and Chinese docs, the upstream
  attribution, and the fresh-project migration boundary. Match `0.5.0` and
  its date in the changelogs, asset metadata, installer URLs, and validator.
- [ ] Validate the release tree and run Ruff, strict mypy, unit tests, and
  disposable PostgreSQL 17 / two-Redis integration tests. Confirm the CI
  Redis-only tests use a third distinct logical database and cannot leave
  data in either later integration target.
- [ ] Commit and push `main`; wait for both CI jobs on that exact commit to
  pass. Create and push `v0.5.0` on that commit, without replacing any old tag.
  A signing key is optional, not a release requirement.
- [ ] Publish a non-draft, non-prerelease GitHub Release for `v0.5.0`.
  Highlight the username-only, five-CAPTCHA, per-business limiter, offline
  super-admin handover, and password-table changes as breaking changes.
- [ ] Verify the public tag, the GitHub source download, and a fresh
  `$skill-installer` install from the tagged Skill path. Attach checksums only
  when uploading a separate release archive.

## Release v0.4.0

- [ ] Verify the Skill asks the unresolved authentication product questions once
  with recommended answers: identity/login input, registration mode, verified
  recovery proof/channel, simultaneous devices, and existing-account enrollment.
  It must not delegate fixed Argon2, dummy-hash, transaction, audit, redaction, or
  old-Token revocation behavior to the adopter.
- [ ] Verify the bundled local-password asset exposes the documented five POST
  commands, stores Argon2id in nullable `users.password_hash` with coherent
  password timestamp and temporary flag, clears it on user soft deletion,
  applies real-or-dummy work and uniform login failures, never treats username
  as ownership proof, uses one short-lived Access
  Token with login again after expiry, and adds no per-Token PostgreSQL table.
- [ ] Verify password change/reset/recovery completion increments
  `users.token_version` and commits with the append-only account-security audit.
  Derive password-change counts from succeeded audit actions, excluding
  registration; do not add a password-episode table or independent mutable count.
  Administrator reset must require current-password reauthentication,
  `users:password:reset`, and the full strictly-lower hierarchy policy. The sole
  `super_admin` recovery path must remain an interactive offline operator command.
- [ ] Verify the old Python bootstrap entry point is absent and the supplied SQL
  requires an existing active account with `user`. The user must personally run
  it against the target PostgreSQL database; test first binding, same-user
  replay, invalid identity, different holder, version/epoch changes, audit, and
  rollback.
- [ ] Verify a greenfield adopter is asked whether `users` stores `email`,
  `user_name`, or both before schema work, then separately records per-flow
  requiredness, login input, normalization, uniqueness, cross-namespace
  ambiguity, and post-deletion reuse. Existing identity contracts remain
  unchanged unless migration is requested.
- [ ] Inventory every table and row-removal path. Runtime-mutable entities and
  relationship episodes must use tombstones; append-only audit evidence and
  permanent `rbac_state`/system catalogs must expose no deletion path. No table
  may retain an unspecified hard-delete default.
- [ ] Verify initialization asks whether professional PostgreSQL operations can
  support separate schema-owning migration and restricted runtime roles. When
  selected, verify the runtime role cannot directly delete or truncate
  soft-deleted data. When declined, allow small or learning projects to proceed
  and document that owner/superuser SQL can bypass application soft deletion;
  do not mark the optional hardening as passed.
- [ ] Verify new-project guidance prefers registered business prefixes plus
  random uppercase suffixes sized from lifetime volume, while established UUIDv4
  projects and the bundled UUIDv4 asset remain explicitly compliant. No business
  or RBAC ID may use an integer sequence or public sequential alias.
- [ ] Verify the Access Token default is configurable and equals 3600 seconds,
  and user-facing handoff tells adopters to adjust it for business risk and login
  experience.
- [ ] Verify the default JWT has exactly `sub`, `jti`, `iat`, `exp`, and
  `token_type`. Before a new project adds the optional `iss`/`aud` pair, the
  Skill must explain the cross-service scoping benefit and configuration cost in
  plain language and obtain explicit consent; no reply is not consent. Verify a
  partial pair is rejected and an existing configured pair is preserved by
  default.
- [ ] Verify startup rejects public example placeholders and obviously weak JWT
  secrets, not only values shorter than 32 UTF-8 bytes. Verify incoming Bearer
  Tokens and generated Access Tokens are both capped at 4096 UTF-8 bytes,
  including multibyte input and an oversized generated Token before Redis
  registration.
- [ ] Verify login returns no Token until one Redis 5.0+ Lua operation uses server
  `TIME`, `SET NX EX`, and `PEXPIREAT` to register the exact active-JTI value
  without extending the JWT deadline. Authentication then checks JWT, Redis,
  and the existing PostgreSQL user/RBAC state in that order.
- [ ] Verify no individual Token table or per-request Token-record query is added.
- [ ] Verify logout reports success only after confirmed exact Redis deletion;
  test missing/mismatched keys, outage and unknown outcomes, an in-flight request,
  and failover restoring an older snapshot.
- [ ] Verify `POST /api/v1/auth/logout-all` locks the current user, increments
  `users.token_version` once, and causes every Token issued with the previous
  version to fail its next authentication without scanning or bulk-deleting
  Redis keys. Cover a missing, inactive, or already-version-mismatched identity
  and an in-flight request that passed authentication before the increment.
- [ ] Before generating rate limits or login/registration abuse defense, verify
  the Skill displays every applicable centralized default and asks the adopter
  to accept all defaults or list only changed values. Show verification defaults
  only after the adopter explicitly selects CAPTCHA, email/SMS codes, MFA, or
  another step-up feature. No reply is not acceptance. Record the accepted
  settings and require deployment-specific review of system-wide and
  provider-wide capacities.
- [ ] Verify the early ASGI gate applies system and trusted-client-IP buckets in
  one atomic Redis decision, ignores spoofed forwarding headers outside an
  explicitly trusted proxy contract, and runs before expensive application work.
  Verify the authenticated gate selects the documented read/write/admin/logout
  policy, never exempts `super_admin`, and never exposes raw IP, account, actor,
  Token, or JTI values in Redis keys, logs, metrics, or responses.
- [ ] Verify `APP_ENVIRONMENT` is required with no code default, including when
  rate limiting remains enabled. Verify settings reject `RATE_LIMIT_ENABLED=false`
  outside explicit local and test environment names. Verify public registration
  is absent from both the route table and OpenAPI by default, and appears only after
  `PUBLIC_REGISTRATION_ENABLED=true`.
- [ ] Verify a real quota denial returns HTTP `429`, business code `429001`, the
  standard four-field response, the same `X-Request-ID`, and an integer
  `Retry-After`, without executing protected work. An unavailable, timed-out, or
  malformed limiter must fail closed as `503001` for sensitive flows and must
  not be mislabeled as a quota denial.
- [ ] Verify login's only hard admission buckets are IP, IP plus normalized
  account, and global traffic; registration independently uses IP, normalized
  target, IP plus target, and global traffic. Unknown and existing login
  identities use equivalent public behavior and a real or fixed dummy password
  hash. The login-failure risk signal updates atomically, expires, clears on
  success, never creates an account-only `429`, and never prevents a correct
  password from being checked.
- [ ] Verify a username/password-only configuration starts and operates without
  a verification HMAC key, purpose, channel, provider, email/phone requirement,
  or verification route. No CAPTCHA, email/SMS code, or MFA integration appears
  unless the adopter explicitly selected it.
- [ ] When email/SMS verification is selected, verify codes come from `secrets`,
  preserve six digits, bind challenge ID, purpose, channel, and normalized
  target, and are stored only as HMAC digests in Redis. Test five-minute expiry,
  resend replacement, fifth-wrong-attempt invalidation, exactly-one-success
  under concurrency, delivery-failure cleanup without quota refund,
  enumeration-safe errors, and an adapter boundary that never leaks a code,
  target, provider response, or credential.
- [ ] Verify every ordinary JSON response has exactly `code`, `message`, `data`,
  and a server-generated UUIDv4 `request_id`; the same ID is returned in
  `X-Request-ID` for success and every error path, and caller IDs are not adopted.
- [ ] Verify list endpoints expose only `items`, `page`, `page_size`, and `total`,
  with defaults 1/20, maximum page size 200, matching filters, and deterministic
  ordering.
- [ ] Verify ordinary administrators can list or view only non-deleted users and
  roles whose effective authority is strictly lower than their own; peers,
  higher/protected targets, and self are hidden behind the same `404` as a
  missing resource. Verify `super_admin` can read every non-deleted user and role
  and filtered totals match the visible result set.
- [ ] Verify role and user lists batch-load grants and access views: the SELECT
  count must not grow between page sizes 1 and 200. User responses must separate
  `assigned_role_ids` from `effective_role_ids` and effective authority; a
  disabled role remains assigned but contributes no tier or permission.
- [ ] Verify role mutations require a strict integer body `expected_version`,
  authorization denial is evaluated before version mismatch, authorized stale
  writes return HTTP `409` with `409002`, and no current route or OpenAPI contract
  still requires ETag/`If-Match`.
- [ ] Verify every user is limited to 10 live role bindings, counting mandatory
  `user`, any `super_admin`, and disabled-role bindings while excluding
  tombstones. Cover tenth-role success, eleventh-role rejection, idempotent
  rebind, unbind then reuse, bootstrap, `super_admin` transfer, direct SQL,
  a clean upgrade to the sole `0004_password_auth` head, and two concurrent
  writers competing for the tenth slot. Verify the guard originates in `0001`;
  both the service and PostgreSQL must enforce the final count.
- [ ] Verify the permission catalog contains neither `roles:permissions:update`
  nor `system_owner:transfer`, and public responses and OpenAPI expose only
  `super_admin` terminology, never `is_super_admin` or application-ownership fields.
  Do not confuse this with PostgreSQL's legitimate owner/superuser terminology.
- [ ] Verify every response path emits one structured request-completion event
  with matching server request ID, route template, HTTP/business codes, monotonic
  duration, bounded fields, and no request body, query, headers, Token/JTI,
  credential, email, username, proxy URL, or database/Redis URL.
- [ ] Verify required RBAC audits contain trusted actor/target/action/decision/
  reason/source/schema fields and bounded safe snapshots; allowed audit failure
  rolls back its mutation, denied-audit failure preserves the exact original
  `403`, `404`, or `409` status and reason, and PostgreSQL rejects direct
  audit-row update/delete.
- [ ] Verify business audit remains separate from RBAC audit and records only an
  explicit material-action catalog. Test resource identity, per-action state
  allowlists, `succeeded`/`failed`/`denied` outcomes, atomic success rollback,
  post-rollback failure recording, commit-unknown handling, append-only database
  controls, access/retention policy, and rejection of sensitive data.
- [ ] Verify the country catalog remains opt-in and outside the default RBAC
  asset. Test exact approved code-set comparison, string and non-unique calling
  codes, atomic idempotent upsert, soft-delete collision without implicit restore,
  active-only reads, and absence-based non-deletion. Confirm `--structure-only`
  reports `membership_checked=false` and cannot approve an import. When any
  `flag_url` is non-empty, require an explicit allowlist of approved ASCII DNS
  hostnames. Do not distribute a source CSV/TSV or flag asset without recorded
  provenance and redistribution permission.

### Publication

- [ ] Review the staged diff, bilingual documentation, XTN copyright year, and
  upstream commit. Confirm the asset version, release validator, and changelog
  agree on `v0.4.0` and its release date.
- [ ] Commit and push the reviewed tree. Create the `v0.4.0` tag only on the
  exact commit whose CI checks passed. A cryptographically signed tag is
  recommended when portable key management is available, but is not required.
- [ ] Publish `v0.4.0` as a GitHub release. Mark the changed JWT claim profile,
  strict administrative read visibility, 10-role limit, and role version
  preconditions as breaking; highlight Redis active-JTI validation, Argon2id
  password flows, rate limits, and separate audits.
- [ ] Attach a SHA-256 checksum if a release archive is uploaded manually.
- [ ] Verify installation from the public tagged GitHub tree URL in a clean
  Codex environment.

## Later distribution

- [ ] Package the Skill as a Plugin when public installability beyond standalone
  Codex Skill workflows is required.
