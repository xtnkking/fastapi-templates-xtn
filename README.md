# fastapi-templates-xtn

`fastapi-templates-xtn` is an opinionated Codex Skill for building and hardening
FastAPI services with tenant-scoped PostgreSQL RBAC, strict administrative
hierarchy, non-sequential identifiers, minimal revocable JWT sessions, and
transactionally consistent authorization writes.

## Status

This repository is preparing its first preview release. The policy and runnable
PostgreSQL RBAC asset are substantial, but the included asset does not yet
implement the complete PostgreSQL-session plus Redis active-JTI adapter described
by the Skill. Do not represent the preview asset as production-ready until its
documented identity-provider assumptions and PostgreSQL/Redis integration tests
have been completed for the target deployment.

## Upstream And Attribution

This project is an independently maintained extension of
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
from [`wshobson/agents`](https://github.com/wshobson/agents), based on commit
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`.

The upstream work is Copyright (c) 2024 Seth Hobson and is used under the MIT
License. XTN's changes add the PostgreSQL RBAC model, tenant isolation,
administrative hierarchy and anti-self-elevation rules, atomic authorization
writes, UUID identifier policy, and minimal revocable JWT guidance. This project
is not affiliated with or endorsed by the upstream project. See [NOTICE](NOTICE)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## What It Provides

- Tenant-scoped positive-grant RBAC for PostgreSQL.
- Strict authority tiers that deny peer, upward, protected, cross-tenant, and
  direct or indirect self-elevation operations.
- UUIDv4 identifiers for users, tenants, RBAC records, sessions, audits, and
  business entities instead of enumerable autoincrement identifiers.
- Minimal tenant-bound JWT claims and a PostgreSQL-authoritative, Redis-assisted
  active-JTI session design.
- Transaction, lock-order, audit, outbox, revocation, and optimistic concurrency
  requirements for privileged writes.
- A runnable FastAPI, SQLAlchemy, Alembic, and PostgreSQL reference asset with
  focused policy and integration tests.

## Install

The repository publishes the Skill at `skills/fastapi-templates-xtn`. For a
reproducible installation of the first preview after its tag is published, ask
Codex:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.1.0/skills/fastapi-templates-xtn
```

The installer places the directory in the configured user Skill location and
stops if a directory with the same name already exists. Codex detects newly
installed Skills automatically; restart Codex if it does not appear. Replace
`v0.1.0` with another published release tag when needed. Use `main` only when
you intentionally want the latest unreleased state.

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
Use $fastapi-templates-xtn to build a tenant-scoped PostgreSQL FastAPI service
with strict RBAC and revocable JWT sessions.
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
integration tests will be added with the active-JTI adapter; the preview release
does not claim that adapter is implemented.

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
