# fastapi-templates-xtn

**English** | [简体中文](README.zh-CN.md)

`fastapi-templates-xtn` is an opinionated Codex Skill for building and hardening
FastAPI services with application-scoped PostgreSQL RBAC, strict administrative
hierarchy, non-sequential identifiers, minimal revocable JWT sessions, and
transactionally consistent authorization writes.

## Status

`v0.3.0` is the current release. It builds on the single-project baseline from
`v0.2.0` with neutral public administration routes, immutable system roles, and
stricter hierarchy and concurrency controls. `v0.1.0` is the historical first
public preview and does not contain the single-project rewrite. The policy and
runnable PostgreSQL asset are substantial, but the included asset does not yet
implement the complete PostgreSQL-session plus Redis active-JTI adapter described
by the Skill. Do not represent it as production-ready until its documented
identity-provider assumptions and PostgreSQL/Redis integration tests are complete
for the target deployment.

## Upstream And Attribution

This project is an independently maintained extension of
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
from [`wshobson/agents`](https://github.com/wshobson/agents), based on commit
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`.

The upstream work is Copyright (c) 2024 Seth Hobson and is used under the MIT
License. XTN's changes add the PostgreSQL RBAC model, application-wide
administrative hierarchy and anti-self-elevation rules, atomic authorization
writes, UUID identifier policy, and minimal revocable JWT guidance. This project
is not affiliated with or endorsed by the upstream project. See [NOTICE](NOTICE)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## What It Provides

- Single-project positive-grant RBAC for PostgreSQL.
- Strict authority tiers that deny peer, upward, protected, and
  direct or indirect self-elevation operations.
- UUIDv4 identifiers for users, RBAC records, sessions, audits, and
  business entities instead of enumerable autoincrement identifiers.
- Minimal JWT claims without roles or profile data and a PostgreSQL-authoritative, Redis-assisted
  active-JTI session design.
- Transaction, lock-order, audit, outbox, revocation, and optimistic concurrency
  requirements for privileged writes.
- An optional
  [implementation guide for proxy availability checks](skills/fastapi-templates-xtn/references/proxy-availability-detection.md),
  Redis-backed latest-result display, and bounded single or batch checks in an
  existing proxy management UI. This is guidance, not a feature bundled into the
  RBAC asset. It is included in `v0.2.0` and was not part of `v0.1.0`.
- A runnable FastAPI, SQLAlchemy, Alembic, and PostgreSQL reference asset with
  focused policy and integration tests.

## Install

The repository publishes the Skill at `skills/fastapi-templates-xtn`. To install
the current stable single-project release, ask Codex:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.3.0/skills/fastapi-templates-xtn
```

To install the historical `v0.1.0` preview instead, use its immutable tag:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.1.0/skills/fastapi-templates-xtn
```

The installer places the directory in the configured user Skill location and
stops if a directory with the same name already exists. Codex detects newly
installed Skills automatically; restart Codex if it does not appear. Use the
immutable `v0.3.0` tag for reproducible installation. The `main` branch may
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
with strict RBAC and revocable JWT sessions.
```

For proxy availability work without a broader RBAC request, invoke the Skill
explicitly because its automatic discovery remains intentionally RBAC-focused:

```text
Use $fastapi-templates-xtn to add proxy availability checks, Redis-backed latest
results, and single/batch detection to this existing proxy management module.
```

Codex may also select it automatically when a request matches the description in
`SKILL.md`.

## Requirements

- A Codex host that supports Agent Skills.
- Python 3.12 or newer for the included FastAPI asset.
- PostgreSQL for lock, constraint, migration, and integration behavior.
- Docker Compose v2 for the provided local PostgreSQL service.

## Verify Locally

From the repository root:

```powershell
python -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B scripts/validate_release.py
```

PostgreSQL-marked tests require the service and test database configured by
`compose.dev.yaml`. The CI workflow runs those checks against PostgreSQL. Redis
active-JTI support and its integration tests are planned and are not included in
`v0.3.0`.

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
