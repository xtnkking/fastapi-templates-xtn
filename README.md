# fastapi-templates-xtn

**English** | [简体中文](README.zh-CN.md)

`fastapi-templates-xtn` is an opinionated Codex Skill for building and hardening
FastAPI services with application-scoped PostgreSQL RBAC, strict administrative
hierarchy, non-sequential identifiers, minimal Redis-gated Access Tokens, and
transactionally consistent authorization writes, plus configurable API rate
limits and login/registration abuse defense, with optional verification features
only when the adopter explicitly selects them.

## Status

`v0.4.0` is the current release. It extends the `v0.3.0` single-project RBAC
baseline with Redis-gated authentication and the security and application
contracts below. `v0.1.0` remains the historical first public preview. This
release adds the Redis-only active-JTI gate to the runnable asset without a
per-Token PostgreSQL table, replaces the Python first-super-admin bootstrap with
an operator-run SQL transaction, and makes prefixed random business IDs the
new-project preference while retaining UUIDv4 compatibility. It also adds a
uniform numeric-code response envelope, mandatory server request IDs, simple
page-number pagination, body resource-version concurrency, safe structured
operational logging, a hardened append-only RBAC audit module, and a separate
reusable business-audit contract and PostgreSQL asset. It now also requires a
greenfield project to choose whether `users` stores `email`, `user_name`, or
both, then separately settle creation requirements, login input, normalization,
uniqueness, cross-field ambiguity, and post-deletion reuse. Every mutable row
that may be removed at runtime uses a tombstone, including users, custom roles,
business entities, and relationship unbinds, without reviving old privilege on
restore. The default Access Token now contains only `sub`, `jti`, `iat`, `exp`,
and `token_type`; `iss` and `aud` are an optional pair that is enabled for a new
project only after its benefit and configuration cost are explained in plain
language and the user explicitly consents. No reply is not consent, while an
existing configured pair is preserved by default. Each user is also limited to
10 live role bindings in both the service and PostgreSQL, including `user` and
`super_admin`; disabled roles count and tombstoned history does not. Ordinary
administrators can now list or view only strictly lower live users and roles,
while `super_admin` can read all live entries; list responses are batch-hydrated
without N+1 query growth, and user responses distinguish assigned roles from
roles that currently grant authority. Authentication now rejects obvious weak
or example JWT secrets at startup, caps both accepted and generated Bearer
Tokens at 4096 UTF-8 bytes, and provides `POST /api/v1/auth/logout-all` to
invalidate all Tokens for the current account on their next authentication.
The release also adds application-wide API admission limits, authenticated
actor quotas, a runnable Argon2id username/password registration, login,
self-change, administrator-recovery, and temporary-password completion baseline,
plus an optional single-use email/SMS verification-code service. Login failures form an
expiring private risk signal and never create an account-wide lock; hard login
limits use only IP, IP plus normalized account, and global traffic. Before
generating a control, the Skill presents every applicable starting value and
asks the user to accept them or list the values to change. CAPTCHA, email/SMS
codes, and MFA remain disabled unless the user explicitly selects them. Before
generating authentication, the Skill asks one short batch of product questions
about identity/login input, registration, recovery proof, simultaneous devices,
and existing-account enrollment; fixed cryptographic and transaction details do
not become user choices.
Public API terminology consistently uses `super_admin`, and the unused
`roles:permissions:update` and `system_owner:transfer` keys are gone. Separate
database migration and runtime roles are an initialization choice and optional
production hardening, not a blocker for small or learning projects. Do not
represent an adapted service as production-ready until its identity-provider
assumptions and PostgreSQL/Redis integration tests are verified for the target
deployment.

## Upstream And Attribution

This project is an independently maintained extension of
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
from [`wshobson/agents`](https://github.com/wshobson/agents), based on commit
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`.

The upstream work is Copyright (c) 2024 Seth Hobson and is used under the MIT
License. XTN's changes add the PostgreSQL RBAC model, application-wide
administrative hierarchy and anti-self-elevation rules, atomic authorization
writes, non-sequential identifier policy, minimal revocable JWT guidance,
structured request logging, and separate durable RBAC and business audit
controls, plus configurable rate limiting, login/registration abuse defense,
and optional verification-code primitives. This project
is not affiliated with or endorsed by the upstream project. See
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## What It Provides

- Single-project positive-grant RBAC for PostgreSQL.
- Strict authority tiers that deny peer, upward, protected, and
  direct or indirect self-elevation operations.
- Administrative read and write visibility lets ordinary administrators list,
  view, or target only non-deleted users and roles with strictly lower authority,
  while `super_admin` can see every non-deleted user and role. Missing capability
  returns `403001` before lookup; after that check, a hidden target or requested
  role ID returns the same `404001` as an unknown ID. A visible target rejected
  by delegation or effect policy still returns `403001`.
- Batch-hydrated role and user list pages whose query count does not grow with
  page size. User responses expose assigned and effective roles separately;
  disabled roles remain assigned but contribute no current authority.
- At most 10 live role bindings per user, enforced after authoritative service
  locks and again by PostgreSQL under concurrency. Mandatory `user`, any
  `super_admin`, and disabled-role bindings count; tombstoned history does not.
  The database guard is part of the fresh `0001` schema and
  `0004_password_auth` is the only migration head.
- An explicit greenfield choice of whether `users` stores email, `user_name`, or
  both, followed by separate decisions for per-flow requiredness, login input,
  normalization, uniqueness, namespace ambiguity, and post-deletion reuse;
  existing projects keep their chosen identity contract. JWT `sub` and the
  first-super-admin bootstrap always use immutable `users.id`.
- Soft deletion for every mutable row that may be removed at runtime, including
  users, custom roles, business entities, and relationship unbind episodes;
  atomic parent-relation tombstones, new relation episodes on rebind, and restore
  semantics that never revive old authority. System roles and the fixed
  permission catalog have no runtime deletion command, audit rows remain
  append-only, and `rbac_state` is never deletable.
  This is the required contract for each lifecycle path a product exposes. The
  bundled asset directly implements custom-role soft deletion and the user-role
  and role-permission unbinds; user, permission-catalog, and business-entity
  deletion/restoration remain explicit product adaptation points.
- An initialization-time choice about separate PostgreSQL migration and runtime
  roles. Use the split as optional production hardening when professional
  operations support exists; do not block a small or learning project that lacks
  it. PostgreSQL owner or superuser SQL can still bypass application soft
  deletion and must remain outside the application's guarantee.
- Non-sequential identifiers instead of enumerable autoincrement IDs. New
  projects preferably use registered business prefixes plus random uppercase
  suffixes sized by lifetime volume, such as `U` plus 10 characters for a
  bounded low-volume user namespace; established UUIDv4 designs and the bundled
  UUIDv4 asset remain supported. Access Token JTI stays UUIDv4.
- An operator-run PostgreSQL script for the first `super_admin`: the intended
  account is created normally first, then the user personally runs the guarded,
  audited role-binding transaction from a trusted host.
- A default exact JWT claim set of `sub`, `jti`, `iat`, `exp`, and `token_type`,
  without roles or profile data; `iss` and `aud` may be added only as a pair after
  a plain-language explanation and explicit user consent. Existing configured
  pairs are preserved by default. The Access Token lifetime defaults to one
  configurable hour. Startup rejects public examples and obviously weak JWT
  secrets, and both accepted Bearer input and generated Token output are limited
  to 4096 UTF-8 bytes. Every request passes a required Redis active-JTI gate,
  then reloads the existing PostgreSQL user and RBAC state without a per-Token
  database table or query. `POST /api/v1/auth/logout-all` increments
  `users.token_version`, so every Token for that account fails subsequent
  authentication.
- Two-layer API rate limiting: an early ASGI global/trusted-client-IP gate and
  an authenticated actor gate selected by stable operation class. Related
  buckets are checked atomically in Redis; a denial returns HTTP `429` with
  business code `429001` and `Retry-After`, while an unavailable limiter fails
  closed as `503001`. HMAC-derived keys keep raw IPs and actor identifiers out
  of Redis keys. The reference asset and CI use a dedicated rate-limit Redis so
  high-cardinality quota and any enabled verification state are isolated from
  active JTI state; a small deployment may explicitly accept sharing one Redis.
  `APP_ENVIRONMENT` is required with no code default. Startup rejects a missing
  environment and rejects `RATE_LIMIT_ENABLED=false` outside explicitly named
  local or test environments, because disabling it also bypasses the
  authentication abuse flow and is not a deployment mode.
- Complete local-password authentication plus reusable abuse defense. The asset
  provides Argon2id hashing off the event loop, soft-deleted credential episodes,
  real-or-dummy verification, opt-in public registration and login, authenticated
  self-change, strictly lower-target administrator reset, one-time temporary
  password completion, and offline sole-`super_admin` recovery. Every successful
  password rotation increments `users.token_version` and commits its
  account-security audit atomically, so old Access Tokens fail on their next use.
  Username alone is never treated as account-ownership proof. Authentication uses
  one short-lived Access Token; after expiry the user authenticates again, and no
  per-Token PostgreSQL table is added. Login checks IP,
  IP plus normalized account, and system capacity as its only hard admission
  limits. Failed attempts update an expiring private risk signal atomically, but
  that count never denies a request by itself and never prevents correct
  credentials from being checked.
  Public registration is absent from the API and OpenAPI by default; enable
  `PUBLIC_REGISTRATION_ENABLED` only after the product owner chooses it.
  Registration has independent IP, target, pair, and system quotas and never
  accepts a caller-selected role. The included `IdentityAbuseFlow` orders
  admission, real-or-dummy credential work, failure
  recording or success cleanup, and registration side effects so product routes
  do not accidentally bypass a required step.
- An optional, disabled-by-default email/SMS verification flow with six-digit `secrets`-generated
  codes, purpose/channel/target binding, HMAC-only Redis storage, five-minute
  expiry, at most five wrong attempts, atomic resend replacement, and
  single-use consumption. The asset supplies the orchestration service and a
  delivery-adapter interface rather than inventing a provider or public
  login/registration routes for a product whose identity contract is unknown.
  Username/password projects require none of its fields, secrets, routes, or
  providers. The complete asset keeps these tested modules dormant with
  `VERIFICATION_ENABLED=false`; adopters are not asked to delete them, and their
  presence does not expose a verification API. CAPTCHA and MFA likewise require
  an explicit product choice and their own integration.
- Transaction, lock-order, audit, revocation, and optimistic concurrency
  requirements for privileged writes. If writing a denied audit fails, the
  original HTTP `403`, `404`, or `409` result is preserved.
- A uniform JSON API contract with real HTTP statuses, six-digit numeric
  business codes, mandatory server-generated request IDs, and deliberately
  simple page-number pagination. Public responses and OpenAPI use `super_admin`
  terminology rather than `is_super_admin` or ownership, and the fixed permission
  catalog omits unused `roles:permissions:update` and `system_owner:transfer`
  keys.
- Safe one-line JSON operational logging with request correlation, stable event
  fields, bounded serialization, defensive secret redaction, and one canonical
  request-completion event.
- A dedicated append-only `rbac_audit_events` contract with trusted event source,
  payload version, bounded allowlisted before/after state, database constraints,
  transaction rules, archive guidance, and PostgreSQL
  update/delete/truncate defense without a soft-delete path.
- A separate, progressively loaded
  [business-audit contract](skills/fastapi-templates-xtn/references/business-audit-module.md)
  plus reusable `business_audit_events` PostgreSQL model, migration, and writer.
  It records only cataloged material actions, distinguishes succeeded, failed,
  and denied outcomes, and keeps successful mutations and their audit evidence
  in one caller-owned transaction.
- A progressively loaded
  [local-password authentication contract](skills/fastapi-templates-xtn/references/local-password-authentication.md)
  that defines the small product-decision gate, password/credential model,
  complete route flows, manual and offline recovery boundaries, atomic account
  security audit, quotas, and verification matrix.
- An optional
  [implementation guide for proxy availability checks](skills/fastapi-templates-xtn/references/proxy-availability-detection.md),
  Redis-backed latest-result display, and bounded single or batch checks in an
  existing proxy management UI. This is guidance, not a feature bundled into the
  RBAC asset. It is included in `v0.2.0` and was not part of `v0.1.0`.
- An optional, progressively loaded
  [country/region catalog contract](skills/fastapi-templates-xtn/references/country-catalog.md)
  with a concrete
  [PostgreSQL implementation shape](skills/fastapi-templates-xtn/references/country-catalog-postgresql.md)
  and a read-only CSV validator. It fixes the natural alpha-2 key, shared string
  calling codes, typed timestamps, soft deletion, atomic non-restoring imports,
  active-only reads, and optional management boundaries. It is not created by the
  default RBAC asset, and no third-party country dataset is bundled. A formal
  import with any non-empty `flag_url` requires an explicit allowlist of approved
  ASCII DNS hostnames; `--structure-only` reports `membership_checked=false` and
  is never import approval.
- A runnable FastAPI, SQLAlchemy, Alembic, and PostgreSQL reference asset with
  focused policy and integration tests.

## Default Security Quotas

The complete, authoritative starting tables are in
[rate-limiting.md](skills/fastapi-templates-xtn/references/rate-limiting.md).
Before implementation, the Skill must show every table that applies to the
selected surfaces and ask one question: accept all defaults, or list only the
values to change. It must not treat silence as acceptance. Optional verification
rows are shown only after the user selects that feature. The main defaults are:

| Area | Starting value |
| --- | --- |
| API edge | `6000/min` globally with burst `1000`; `1200/min` per trusted IP with burst `200` |
| Reads and writes | anonymous `120/min`; authenticated `300/min`; management reads `120/min`; ordinary writes `60/min`; authorization writes `30/min` |
| Sensitive account actions | `super_admin` transfer `3/hour`; logout-all `5/10min` |
| Login | IP `20/5min`; IP-plus-account `5/15min`; global burst `200` with refill `1000/5min`; failure-risk signal retained up to `24h`, but never a standalone denial |
| Registration | IP `5/hour`; normalized target `3/hour`; IP-plus-target `3/hour` |
| Optional verification send | When selected, `verification_target_average`: one target once per `60s`, with 5 initial sends and continuous refill averaging `5/24h`; IP `20/hour`; IP-plus-target `5/hour` |
| Optional verification consume | When selected, IP `120/hour`; target `20/hour`; IP-plus-target `10/hour` |
| Optional verification code | Disabled by default; when selected, six digits, valid for `5min`, invalidated after five wrong attempts |

These are safe starting values, not universal production capacity. The user may
raise or lower them for legitimate traffic, risk, shared NAT usage, and provider
quotas. System-wide and provider-wide values must be reviewed for the actual
deployment rather than copied without discussion. The target-average bucket is
not reset at a calendar-day boundary and does not promise a hard maximum of five
sends in every arbitrary 24-hour interval. A username/password-only service does
not need CAPTCHA, an email/SMS channel, an MFA provider, or a verification HMAC
key.

## Install

The repository publishes the Skill at `skills/fastapi-templates-xtn`. To install
the current stable single-project release, ask Codex:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.4.0/skills/fastapi-templates-xtn
```

To install the historical `v0.1.0` preview instead, use its immutable tag:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.1.0/skills/fastapi-templates-xtn
```

The installer places the directory in the configured user Skill location and
stops if a directory with the same name already exists. Codex detects newly
installed Skills automatically; restart Codex if it does not appear. Use the
immutable `v0.4.0` tag for reproducible installation. The `main` branch may
change before the next release.

For repository-scoped use, copy `skills/fastapi-templates-xtn` to
`.agents/skills/fastapi-templates-xtn` in the target repository.

### Update Or Uninstall

The installer does not overwrite an existing Skill. Before updating, preserve
any local modifications, move the installed `fastapi-templates-xtn` directory
to a backup outside the configured Skill directory, and install the desired tag.
Remove the backup only after verifying the replacement. To uninstall, remove the
installed Skill directory and restart Codex; this does not affect the canonical
repository or an independently maintained fork.

## Use

Invoke it explicitly when the request needs its full security baseline:

```text
Use $fastapi-templates-xtn to build a single-project PostgreSQL FastAPI service
with strict RBAC and Redis-gated revocable Access Tokens.
```

For proxy availability work without a broader RBAC request, invoke the Skill
explicitly because its automatic discovery remains intentionally RBAC-focused:

```text
Use $fastapi-templates-xtn to add proxy availability checks, Redis-backed latest
results, and single/batch detection to this existing proxy management module.
```

For an optional country directory, invoke the Skill explicitly and provide the
product's approved country-code scope and licensed source when they exist:

```text
Use $fastapi-templates-xtn to add an optional PostgreSQL country catalog with
Chinese and English names, calling codes, soft deletion, and read-only APIs.
```

Codex may also select it automatically when a request matches the description in
`SKILL.md`.

## Requirements

- A Codex host that supports Agent Skills.
- Python 3.12 or newer for the included FastAPI asset.
- PostgreSQL for lock, constraint, migration, and integration behavior.
- Redis for the normative active-JTI gate in the bundled asset, plus
  a separately configured Redis for rate limits and login/registration defense
  in the reference deployment. Explicitly enabled verification challenges may
  share that limiter Redis.
- Docker Compose v2 for the provided local PostgreSQL and two Redis services.

## Verify Locally

From the repository root:

```powershell
python -B -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/validate_release.py
```

PostgreSQL-marked tests require the services and test database configured by
`compose.dev.yaml`. The CI workflow runs those checks against PostgreSQL, the
active-JTI Redis, and a separate rate-limit Redis; it also tests the optional
verification component without making it a default product requirement. The current
`v0.4.0` asset includes those Redis integrations and related tests. A generated
service still needs its own configuration, identity-contract, and target-deployment
checks before it can be called production-ready.

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before publishing a tag.

## Governance

The canonical repository is
[`xtnkking/fastapi-templates-xtn`](https://github.com/xtnkking/fastapi-templates-xtn)
and is maintained solely by XTN. Issues and private security reports are welcome;
external pull requests are not accepted. Downloads and forks may be modified and
redistributed under the applicable licenses, but they are unofficial and must
not imply endorsement by XTN. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

Except for identified third-party portions, XTN's additions are licensed under
the Apache License 2.0. Upstream `fastapi-templates` and adapted Alembic template
material retain their MIT notices. Redistribution must preserve the applicable
license and attribution files. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
