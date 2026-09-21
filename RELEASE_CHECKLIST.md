# Release Checklist

**English** | [简体中文](RELEASE_CHECKLIST.zh-CN.md)

Use this checklist for the first public preview and subsequent releases.

## Prepare v0.7.0

Release readiness: `DRAFT`

Target date: `2026-09-21`. Keep this block `DRAFT` until the pre-tag evidence is
verified for the current candidate. Historical `v0.6.2` results do not establish
readiness for this version. Record the actual candidate commit and successful CI
run before marking `READY`; final branch and tag CI must pass before publication.

Scope: responsibility-based source directories; one standalone PostgreSQL and
one shared standalone Redis by default; opt-in Sentinel/Cluster clients and
configuration; bounded connections, deadlines, concurrent work, runtime logging,
and supporting tests. Cluster deployment and management remain operator-owned.
Updating only the Skill does not alter a running application. Deploying the new
session implementation requires existing users to log in again and changed
quota keys start fresh windows once; no PostgreSQL migration is added.

### Pre-tag evidence

- [ ] `VERSION`, package metadata, current links, bilingual release notes and
  architecture/migration notes consistently identify `0.7.0`; published migration
  revisions remain byte-for-byte unchanged.
- [ ] Current Skill/release validators, updater and country-validator tests,
  Ruff, strict mypy, and the full isolated PostgreSQL 17/Redis 7 suite pass.
- [ ] Disposable standalone, Sentinel promotion and Cluster tests verify client
  configuration, session/CAPTCHA atomicity and per-subject limits. Record any
  untested connection boundary, including real TLS certificate handshakes.
- [ ] Python 3.12/Linux candidate CI verifies dependency closure, `pip check`,
  `pip-audit`, and all applicable tests with no unrecorded vulnerability exception.
- [ ] The `0.7.0` wheel passes isolated import validation and contains both locale
  catalogs plus all three legal notices.
- [ ] Safe-update tests and a dry run verify the intended local Skill target;
  the final reviewed diff preserves attribution and the simple standalone default.
- [ ] Record the candidate commit and successful branch CI for this release;
  verify that no credentials, private configuration, caches or test databases
  enter the release tree.

### Post-release verification

- [ ] Verify final branch CI, create immutable `v0.7.0`, and wait for tag CI.
- [ ] Publish a non-draft, non-prerelease GitHub Release marked latest.
- [ ] Verify the public archive, tagged installation URL and `VERSION`; safely
  update the local Skill, retain its backup, and compare its complete manifest
  with the tagged Skill.

Only this current `Prepare v0.7.0` block participates in automated readiness.

## Prepare v0.6.2

Release readiness: `READY`

Keep `DRAFT` until the pre-tag evidence is verified. Record the reviewed
candidate CI before committing this checklist as `READY`, then require the
final commit's branch CI and tag CI to pass before publishing. A metadata-only
readiness commit does not exempt the final source from those checks.

Reviewed candidate: `4a040a4`,
[successful branch CI](https://github.com/xtnkking/fastapi-templates-xtn/actions/runs/35524548211).
The final readiness commit changes only these two checklists; verify its branch
and tag CI before publishing.

### Pre-tag evidence

- [x] Version metadata, bilingual documentation and release notes consistently
  identify `0.6.2`; published migration revisions remain byte-for-byte unchanged.
- [x] Skill/release validators, updater and country-validator tests, Ruff,
  strict mypy and all 762 tests pass, including disposable PostgreSQL 17 and
  Redis 7 integration and the embedded-migration logging regression.
- [x] Python 3.12/Linux CI validates the exact dependency closure and passes
  `pip check` and `pip-audit`, with no unrecorded vulnerability exception.
- [x] The wheel contains both locale catalogs and all three legal notices.
- [x] Updater tests cover staging, backup, replacement and rollback; a dry run
  resolves the intended installed Skill without changing it.
- [x] The release diff, attribution and bilingual instructions are reviewed
  under XTN's publication authorization, and the candidate branch CI is green.

### Post-release verification

- [ ] Verify final branch CI, create immutable `v0.6.2`, and wait for tag CI.
- [ ] Publish a non-draft, non-prerelease GitHub Release marked latest.
- [ ] Verify the public archive, tagged installation URL and `VERSION`; safely
  update the local Skill and verify its complete file manifest against the tag.

The `Prepare v0.6.2` block is retained as a historical record.

## Prepare v0.6.1

Release readiness: `READY`

Keep this status as `DRAFT` while any pre-tag item is unchecked. Change it to
`READY` only after personally verifying every item against the exact commit that
will be tagged. Ordinary `validate_release.py` runs report unfinished work but
still validate development branches; `validate_release.py --release-ready`
rejects `DRAFT` or an unchecked pre-tag item. Tag CI repeats every automatable
check. A checked box is a maintainer attestation, not evidence created by this
validator.

### Pre-tag evidence

- [x] `VERSION`, asset package metadata, current migration/architecture notes,
  and both changelogs consistently identify `0.6.1`; the configurable Access
  Token default is 86,400 seconds (24 hours), and published migrations remain
  unchanged.
- [x] The Skill quick validator, release validator, updater tests, country-data
  validator tests, Ruff, mypy, dependency audit, unit tests, and disposable
  PostgreSQL 17/Redis 7 integration tests all pass on the exact release commit.
- [x] CI installs the Python 3.12/Linux dependency resolution through
  `constraints-ci-py312.txt`; recursive closure validation confirms every
  package selected by the project and test roots, including `uvloop`, has an
  exact pin; `pip check` passes; and the reviewed versions have no unrecorded
  vulnerability exception.
- [x] Wheel validation proves that both locale catalogs plus `LICENSE`, `NOTICE`,
  and `THIRD_PARTY_NOTICES.md` are present in the built artifact.
- [x] A dry run resolves the intended installed Skill target, and an isolated
  update test proves exact staged copying, complete backup, successful
  replacement, and rollback behavior without deleting the retained backup.
- [x] The final diff, English/Chinese install instructions, release notes,
  attribution, and limitations have been reviewed by XTN; the exact branch CI
  run for this commit is green.

### Post-release verification

- [ ] Create immutable tag `v0.6.1` on the verified commit and wait for tag CI.
- [ ] Publish a non-draft, non-prerelease GitHub Release for `v0.6.1`.
- [ ] Verify the public source archive, tagged first-install URL, `VERSION`, and
  one safe update from the checked-out tag. Record failures in an Issue rather
  than moving or replacing the tag.

Sections for older versions below are historical planning records. Their
unchecked boxes are not evidence that an old release did or did not run a check.
The `Prepare v0.6.1` block is retained as a historical record.

## Reusable Local Review Inventory

- [ ] The bundled Skill passes the current `skill-creator` quick validator.
- [ ] The optional country CSV validator's focused unit tests pass without
  modifying or bundling a source dataset.
- [ ] Ruff format and lint, strict mypy, `pip-audit`, and non-PostgreSQL tests
  pass.
- [ ] Project dependency ranges remain bounded, while CI installs the exact
  reviewed Python 3.12/Linux resolution from `constraints-ci-py312.txt` after
  installing `pip==26.2.1` and `setuptools==84.0.0`. Any pin change has a new clean dependency-audit
  result or an explicit temporary exception in both Security documents and CI.
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
  reset in default direct and optional temporary modes, temporary completion,
  offline operator recovery and super-admin
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

## v0.6.0 acceptance baseline

- [ ] Every client-facing runtime API message and safe validation detail uses a
  stable message key with complete `zh-CN` and `en` catalogs. Missing or
  unsupported language falls back to Chinese; bounded standard
  `Accept-Language` negotiation returns canonical `Content-Language` and merges
  `Vary: Accept-Language` once without changing the four-field envelope. A
  specific `q=0` exclusion takes precedence over its parent range or `*`.
- [ ] Catalog keys match exactly; hostile or oversized language headers cannot
  select a path, import, Redis key, log, or audit value. Mixed concurrent
  Chinese/English requests stay isolated. HTTP/business codes, response data,
  request IDs, security headers, logs, audit fields, permission keys, and
  private reason codes remain language-independent. Database-authored product
  content and OpenAPI developer metadata remain outside the runtime message
  translation boundary. Validation field hints never reflect extra or deeper
  mapping keys, and an unhandled `500` still carries both language headers.
- [ ] New-project questions explain and require one project-wide administrator
  password-reset choice: `direct` is the stated default and creates a permanent
  password immediately; `temporary` requires one formal-password completion.
  The API always accepts `new_password` and never lets a caller select the mode.
- [ ] Both modes require `users:password:reset`, `admin_reset` CAPTCHA, and a
  visible strictly lower target; neither can target self, peer, or higher users.
  Both increment `token_version`, revoke old Tokens, atomically record the same
  audit action with mode-specific reason codes, and keep the password out of
  responses, logs, and audit snapshots.
- [ ] Default direct-mode integration proves the new password can log in without
  another step. Optional temporary-mode integration proves login returns no
  Token until the one-use completion succeeds. No schema or migration changed.

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

## Release v0.6.0

- [ ] Review the complete diff, both READMEs, both changelogs, the release
  checklist, and the Chinese architecture overview. Match version `0.6.0` and
  date `2026-09-20` in asset metadata, installer URLs, changelogs, and the
  release validator.
- [ ] Confirm `v0.6.0` adds no schema revision and does not modify the four
  migrations published in `v0.5.0`. Any later schema change must add a forward
  Alembic revision instead of rewriting released history.
- [ ] Run Ruff format and lint, strict mypy, `pip-audit`, non-PostgreSQL tests,
  release validation, and the Skill quick validator. Let GitHub Actions run the
  disposable PostgreSQL 17 / Redis 7 integration and migration checks on the
  exact release commit.
- [ ] Confirm the final CI log uses `pip>=26.2`, resolves
  `pytest>=9.0.3,<10` with `pytest-asyncio>=1.4,<2`, and completes `pip-audit`
  without an unrecorded ignore.
- [ ] Commit and push `main`; wait for both CI jobs on that exact commit to
  pass. Create and push immutable `v0.6.0` on that commit without replacing or
  moving any older tag.
- [ ] Publish a non-draft, non-prerelease GitHub Release for `v0.6.0`, then
  verify its source archive and tagged Skill installation URL.

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
  Administrator reset must not ask for the actor's current password again; it
  requires `users:password:reset` and the full strictly-lower hierarchy policy. The sole
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
