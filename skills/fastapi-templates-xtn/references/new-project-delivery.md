# New Project Delivery

Read for an empty, independent project that explicitly adopts this baseline.
Existing applications keep their architecture and receive scoped integration;
an empty directory inside them is not permission to scaffold a replacement.

## Resolve Choices, Then Export

Read the product-choice batch in [Local authentication](local-password-authentication.md).
Resolve username case and active-login maximum; explain the mandatory
new-password rules and quota defaults. Do not invent a number or choose a case
policy from silence. Apply already confirmed choices without asking again.
For a synthetic verification project, explicitly label test-only choices.

Run `scripts/create_project.py` from the Skill directory with the user's chosen
target and values:

```text
python -B scripts/create_project.py <empty-project-directory> --name <application-name> --username-case <sensitive|insensitive> --max-active-sessions <chosen-positive-number>
```

The script validates choices and refuses nonempty targets. It performs only
file operations; it does not install dependencies, open a service connection,
generate secrets, or build/execute migrations. It stages the export before
publishing the new directory. Package name/version are independent of the Skill's
version. Preserve necessary copied-code attribution and license text in the
README's collapsed appendix without assigning a license to the whole application.

All generated Python files have the required responsibility and `History`
header, including package and test files. Each new file has exactly one entry:
the actual local generation date, project author, `V1.000` and `新建`. Template
maintenance records are not copied. File responsibility is written once in
`# 说明:`; redundant module docstrings are removed while function/class
docstrings remain. Supply
`--author <known-project-author>` when the user's signature is known; otherwise
the explicit role label `项目维护者` is used, without inventing a personal name.
Configuration and Markdown use native comments. JSON, binaries and legal content
keep their valid formats; do not add comment fields or a separate history/source
manifest for them. See [Python comments](python-comments.md)
for maintenance rules; file versions are independent of release versions.

The exporter supports both username policies: insensitive canonicalizes to
lowercase in the shared input path and adds the corresponding model constraint;
sensitive preserves case. It exports `password_rules.py` with the complete
new-password baseline: 8..32 visible ASCII characters containing uppercase,
lowercase, digits and special symbols, plus the documented weak-password checks.
All password-setting paths share it; login and current-password checks retain
their independent input limit. If the user requests a different policy, change
this owner, its descriptions, bilingual errors and relevant tests together.
Other project-specific changes, such as
business-prefixed IDs, follow the same coherent adaptation rule. Do not pretend
the exporter covers a choice it does not implement.

## Deliberate Output

| Included | Excluded |
| --- | --- |
| Runtime `app/`, ORM models, language catalogs | `app/commands`, Alembic history/config, SQL and initialization files |
| Project-specific `pyproject.toml`, simple `.env.example`, `.gitignore` | Reference Compose stack, load tooling, maintainer constraints and CI machinery |
| One concise Chinese README with setup, database prerequisites and a collapsed copied-code license appendix | `SKILL_SOURCE.json`, `DATABASE_HANDOFF.md`, standalone `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` |
| Small offline tests for identity and downward authorization | Test-count targets, copied tests for features the application does not contain |

The complete maintainer regression/integration suite, caches and build/install
artifacts remain excluded. Source tracing or detailed handoff reports are
additional deliverables only when the user requests them.

The default runtime exports the agreed authentication/RBAC/CAPTCHA/JTI/logging
baseline. It does not add country, proxy, example project permissions or empty
business directories. The `projects:*` permissions in historical maintainer
fixtures are filtered from the project catalog and super-administrator allowlist;
do not change released fixture history to make it a new-project seed.

Default audit output is `models/postgres/operation_audit.py` and
`services/audit_service.py`: one append-only account/permission table with safe
request/result summaries. The optional `core/business_audit.py`, its model and
writer remain Skill resources and are not exported or registered by default.
Add them only for a reviewed product event catalog.

Dependencies separate `pip install -e .` for runtime from `pip install -e ".[dev]"`
for development. Alembic is not a runtime requirement. The generated `.env.example`
shows both mandatory secrets, quota parameters and standalone connection values;
real values belong only in the user's private environment.

Explain the small set of root files in the project's README. `pyproject.toml`
owns runtime/development dependencies, packaging and code-tool settings; it is
used by the documented installation commands. Keep only the concise README for
startup, agreed product settings and database preparation. Required copied-code
copyright/permission text belongs in a collapsed README appendix, with a short
source entrypoint pointer; no separate legal files are exported. This does not
declare the user's business code open source. The Skill repository and maintained
asset retain their own legal files. Existing applications keep their files and
dependency management; a smaller default export does not authorize deleting
their documentation, manifests or license notices.

Group HTTP code into authentication, current account, managed users, roles and
permissions. Generated GET list/detail routes end with `/list` or `/detail` and
take typed query parameters; POST commands take their target IDs and payload in
validated JSON. Keep static paths and only GET/POST business methods. Check real
route metadata and negative HTTP cases after adapting the asset, not only the
written convention; also prove the default documentation URLs return `404`.
Follow [Python comments](python-comments.md) for aligned
multi-input class methods and readable business calls. A short route decorator
may stay on one line; this is not a rule to collapse every method or call.

## Models, Not Database Initialization

`from app.models.postgres import Base` exposes all metadata without connecting or
issuing DDL. Deliver names, fields, relations, indexes and constraints, and state
what the user needs to prepare separately. The generated README keeps the short
application-local checklist: system roles, permission catalog, exact grants,
global state, offline first-super-admin binding and database-only guards.
Detailed model and constraint guidance remains in this Skill's references,
instead of exporting another handoff document.
Read [Model and database handoff](migrations.md) when adapting these details.

Do not generate migration files, SQL, bootstrap/seed commands, or automatic
schema repair. Do not invoke `create_all`, migration commands or database-mutating
integration fixtures for acceptance. The user generates, reviews and executes
their own migrations and initial data. Historical maintainer resources remain
available for regression work; they are not the generated project's installation
procedure. Model metadata alone cannot install trigger-based protections.

The default project includes no liveness or readiness endpoint or probe module.
Add health probes only at the adopter's explicit request, with access limited
to an internal network or trusted probes, bounded timeouts and safe overall
results. Such checks must never compare a fixed Alembic head, auto-seed or repair
tables. Complete database setup still needs the user's own acceptance checks;
avoid misleading "ready to use" claims for a database that has not been prepared.

## Verify The Actual Delivered Tree

Use the generated README commands, `python -B`, Ruff `--no-cache`, pytest without
its cache provider, and a mypy cache outside the project. Verify syntax/imports,
route and response-model registration, actual authentication/input rules and that
application startup rejects missing route policy before connecting to services.
When importing configured application code offline, use an isolated process
with temporary synthetic settings; never connect to values from a user's `.env`.

Do not delete tests just to reach a small arbitrary number. Keep tests protecting
the delivered behavior; add focused regressions for actual business additions.
Report which checks were run and which PostgreSQL/Redis checks remain for a
user-prepared environment. Updating the Skill does not update existing projects
or execute their database work.
