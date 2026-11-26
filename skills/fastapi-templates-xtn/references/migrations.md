# Model Handoff, Permission Catalog, And Historical Migrations

Read this reference when adding or changing authorization tables, constraints,
permission keys, seeded roles, assignments, lifecycle fields, or authorization
versions. For any primary/public identifier or sequential-ID conversion, also
read [identifier policy](identifier-policy.md); it owns the non-sequential ID
contract and compatible migration sequence.
For login-identifier columns, uniqueness, user tombstones, relationship
episodes, or restore behavior, also read
[Identity and soft-delete lifecycle](identity-soft-delete.md).

## Model Delivery Boundary

The Skill owns ORM models and application code. The user generates, reviews,
and executes their migration files, DDL, database-only protection, and initial
data. Do not generate or copy migration histories, SQL initialization files,
or seed scripts into a new project. Do not execute Alembic,
`metadata.create_all()`, startup DDL, or automatic seed/schema repair as a
coding step. Ordinary generated-project test fixtures must not create tables
or migrate a database either. Follow
[New-project delivery](new-project-delivery.md) for the selected output.

Deliver typed fields, nullability, defaults, foreign keys, named unique/check
constraints, and indexes in the model. Document changed fields and give the
user an explicit database handoff in the existing README or task response; do
not generate a separate `DATABASE_HANDOFF.md` by default. Keep the short startup
prerequisites in the project's README and detailed design guidance in this Skill.
ORM metadata and Alembic autogeneration do
not install custom triggers, deferred cross-row checks, grants, or initial rows.
The constraint, seed, and bootstrap specifications below describe what the
user must implement and verify; they are not commands for the Skill to execute.
Do not claim those protections are installed merely because models import.

At minimum, the user must initialize the three system roles, exact permission
catalog and explicit grants, and `rbac_state(scope='global')`.
The current `user` role grants exactly `account:read` and
`account:change_password`; both keys also belong to the explicit `admin` and
`super_admin` sets in `core/access/roles.py`. Updating the Skill alone does not
insert these permission rows or bindings into an existing database. Its owner
must prepare a reviewed data change, including any installed system-role
immutability protections; do not edit the historical migrations to add them.
They must also implement the database-only
10-live-role backstop, mandatory `user` binding, sole-super-admin guard,
immutable system-role protection, and audit/global-state deletion protection.
The application retains its own transaction checks but never lazily creates
missing tables, roles, or state. The default project has no readiness endpoint.
Only add probes at the adopter's explicit request, limited to an internal
network or trusted probes. Such checks must not repair database state or use a
fixed Alembic revision, and cannot certify all triggers.

## Historical Reference Only

The maintained PostgreSQL asset retains this previously published chain solely
for maintenance regression and prior-version reference. These files, its
`sql/` directory, and historical migration/integration fixtures are excluded
from new projects; do not copy or run them to initialize a generated project:

1. [`0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py)
   creates the core users, roles, permissions, relationship episodes,
   `rbac_state`, and RBAC audit schema, and installs the database backstop for
   at most 10 live role bindings per user.
2. [`0002_system_roles.py`](../assets/postgresql-rbac/alembic/versions/0002_system_roles.py)
   adds the complete system-role and public administration contract.
3. [`0003_business_audit.py`](../assets/postgresql-rbac/alembic/versions/0003_business_audit.py)
   adds the separate append-only `business_audit_events` table and guards.
4. [`0004_password_auth.py`](../assets/postgresql-rbac/alembic/versions/0004_password_auth.py)
   adds nullable local-password fields to `users`, the persisted
   `public_registration_enabled` switch on `rbac_state`, account-security audit
   evidence, and the `users:password:reset` permission/grants.

These four revisions shipped with `v0.5.0` and are immutable migration history.
The published `v0.7.0` release did not change the database shape. The current
model has since removed the per-user `authz_version` counter, while historical
revisions retain their original column and updates. That history is not the
current model or a new-project deliverable. Existing applications own their
reviewed forward migrations; the Skill does not generate or execute one for
this removal. Never edit, replace, or reorder `0001` through `0004` after publication.

The current default replaces the two legacy account/RBAC audit models with
`OperationAuditEvent` and its 16-field `operation_audit_events` table. Optional
business audit is no longer registered/exported by default. This is a current
model contract, not a rewrite of those old revisions. A new adopter prepares
the unified table and append-only database protections from the current models;
an existing adopter decides how to preserve and map historical evidence in
their own reviewed forward migration. Never delete old audit data during adoption.

Current `user_roles` and `role_permissions` models name their binding metadata
`bound_by_user_id` and `bound_at`. Published migrations, historical SQL examples
and migration-only checks retain `assigned_by_user_id` and `assigned_at` for
their original schema; they are not current-model examples. The Skill does not
generate or run a column-renaming migration for an existing application.

The `v0.7.0` Redis session layout is separate from PostgreSQL migrations. Merely
updating the Skill changes no running service. Deploying the new session code
to an existing application requires users to log in again; changed rate-limit
keys start fresh windows once. No account, role, permission, or audit data is
removed by this change.

The current unreleased template no longer has a registration switch. New
projects follow the two-column `RbacState` model. An existing project using a
published migration must review its own forward schema/data change; this Skill
does not rewrite the published migration or execute that change.

A deployed application must preserve and explicitly map its existing users,
roles, grants, assignments, versions, and audit history. After any revision
ships, never edit it to change the catalog; add a new revision and synchronization
test instead.

For the user's own migration process or separate historical maintenance,
when embedding Alembic in a test process, set
`config.attributes["configure_logger"] = False` before invoking its commands.
The caller retains its log handlers and deliberate third-party logger disables.
Standalone Alembic commands keep their normal `alembic.ini` logging setup.

## User-Owned Migration Strategy

Explain the model differences and database prerequisites. The user writes or
generates the corresponding migrations, reviews them, and executes them. Their
plan preserves existing data and authorization invariants, makes initial data
repeatable, and verifies the resulting PostgreSQL schema. Backfill sizing and
release order are their choices; do not add hypothetical compatibility layers.

The project owner chooses maintenance windows, release order, and rollback
procedures. Zero-downtime upgrades and mixed-version compatibility are separate
requirements, not prerequisites for ordinary migration code. Follow an existing
project's agreed rollout contract; otherwise leave deployment design to the
owner unless explicitly asked to implement it.

Unmapped users and records default to only the mandatory base `user` role, which
has no authorization-management permission. Never grant `admin` merely to make a
migration pass.

## Login-Identifier Schema

The fresh baseline has one required `user_name`, globally unique even after
soft deletion. Trim edge whitespace, validate 3..32 ASCII letters/digits or
underscores, reject the fixed reserved-name list, and ask the project owner
whether casing matters before fixing canonical uniqueness and lookup behavior.
Email login or recovery is a separately designed product extension, not a
nullable field or secondary login namespace in the bundled baseline. Existing
services retain their intentional identity contract unless migration is
requested. Immutable `users.user_id`, not username, remains JWT `user_id` and the
operator-bootstrap input throughout.

## Historical Contracts Remain Reference

The links above preserve the published implementation and regression history.
They illustrate system-role immutability, the final-state 10-role backstop,
mandatory base-role assignment, append-only audits, and password-state checks.
They are not the starting migration sequence for a new application. New models
remain authoritative for current field shape; the user defines their own schema
and initial-data changes without rewriting published history.

## System Role Specifications

The database and domain constants agree on exactly these rows:

| Key | Tier | Required flags | Public mutation |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | `is_system`, `is_protected`, `is_super_admin`, `is_active`, not deleted | Assignment changes only through bootstrap or guarded offline handover |
| `admin` | `500` | `is_system`, `is_active`, `is_protected=false`, `is_super_admin=false`, not deleted | Role definition and grants are immutable; assignment only by a strictly higher current user |
| `user` | `0` | `is_system`, `is_active`, `is_protected=false`, `is_super_admin=false`, not deleted | Mandatory assignment cannot be unbound |

Custom roles use tier `1..999`. Runtime strict hierarchy means `admin` can create,
edit, enable, disable, grant, or assign only custom roles below tier `500` and
using only current capabilities and strict hierarchy. Only custom roles may be soft-deleted.
Their keys remain reserved after deletion. `owner` is not a reserved system key;
it may be an ordinary custom-role key and has no special authority.

System-role permission changes require code plus a user-owned reviewed data
change, never a public API call. That data-change transaction must lock the global
guard, analyze all affected users, update the edited role's version, and
preserve an auditable deployment record.

## Soft-Delete Schema

Apply the selected login-identifier schema above without changing an existing
application's identity contract as a side effect of adopting RBAC.

Add `deleted_at` and trusted deletion-current user metadata to every runtime-deletable
user, custom role, and business entity. Give `user_roles` and
`role_permissions` non-sequential episode IDs, bind metadata, and equivalent
tombstone metadata. Replace whole-pair uniqueness with a PostgreSQL partial
unique index over `deleted_at IS NULL`, so only one live episode exists while
history remains. Effective queries and constraints use only live parent and
relation rows.

The three fixed system roles and the code-owned permission catalog have no
runtime deletion path. If a product deliberately makes permission rows mutable,
give them the same tombstone metadata and tombstone every live grant atomically.

A parent delete tombstones the parent and all live owned relation episodes in
one transaction. A later bind inserts a new episode. Restore never clears old
tombstones; a restored user receives only a new mandatory `user` episode, and
prior privileged roles/grants require new authorized binds. Production runtime
foreign keys use `RESTRICT`, not cascading hard deletion.

## Default User Creation

Every registration, invited-user flow, administrator-created user, identity
synchronization, and import path must bind `user` in the same database
transaction that makes the user usable. Public request bodies cannot choose an
initial role.

Centralize this in one trusted user-creation service. Include in the user's
database handoff a deferred PostgreSQL constraint trigger that rejects commit
whenever a live user lacks one live
assignment to the fixed `user` role. A direct database writer must therefore insert
the user and its relation episode in the same transaction; never create the
system role lazily. User deletion tombstones that episode with the user;
restoration creates a new base-role episode and no former privileged episode.
Tests must cover every supported creation and restore path. A post-commit repair
job is not sufficient because it creates a window with an invalid identity.

Bootstrap never creates an identity. The intended person must first use a normal
trusted registration or user-creation path and receive `user`. The user then
prepares, reviews, and runs their own initialization transaction against
PostgreSQL, passing immutable `users.user_id` as the target. The historical
`sql/bootstrap_super_admin.sql` demonstrates the contract but is not copied
into generated projects. The user-owned transaction locks the
global guard first, verifies the account and system-role contract, binds
`super_admin`, and writes audit in
one transaction. Do not replace it
with a bare `INSERT` into `user_roles`. Never select the holder by email or
`user_name`. The same completed identity is an idempotent replay; a different
second holder is refused without partial writes.

## Constraints To Model Or Hand Off

Express ordinary fields, indexes, foreign keys, uniqueness, and checks in ORM
metadata. Hand off custom PostgreSQL trigger/function and grant requirements
explicitly for the user to implement. No Python import or schema autogeneration
installs those custom protections by itself.

- Follow [identifier policy](identifier-policy.md) for every primary/API ID. The
  bundled new-project asset uses 15-character prefixed business IDs and
  22-character audit IDs; an established UUIDv4 design may remain unchanged.
  Generate and review migrations from the delivered models. Do not introduce `SERIAL`, `BIGSERIAL`,
  `IDENTITY`, integer autoincrement, or a sequential compatibility alias.
  Integer tier/version columns are counters, not identifiers.
- Give tables, foreign keys, unique constraints, triggers, and indexes
  deterministic names.
- Enforce global uniqueness for permission and role keys. Give each
  `user_roles` and `role_permissions` episode a non-sequential ID, keep parent
  foreign keys non-null, and use partial unique indexes for one live logical
  pair where `deleted_at IS NULL`. A Python pre-check is insufficient under
  concurrency.
- Enforce at most 10 live `user_roles` rows per user. The mandatory `user` and
  any `super_admin` row count, a binding to a disabled role still counts, and a
  tombstone does not. Use a statement-level trigger to acquire the global guard
  before assignment writes and a deferred constraint trigger to validate each
  affected user's final count. Check both old and new user IDs for updates, so
  insert, reassignment, unbind, and reactivation cannot bypass the limit. Drop
  the trigger before its function during downgrade. The historical
  `0001_single_project_rbac` demonstrates this backstop; new projects require
  their user's own database implementation.
- Model `rbac_state` and tell the user to initialize exactly one
  `scope='global'` row. Its only column is the non-null `scope` control key.
  Enforce the fixed scope with a primary key and
  check constraint, have the user initialize it, never create it lazily at runtime,
  and use grants/triggers to reject production `DELETE` and `TRUNCATE`.
- Keep `is_system` independent from `is_protected`; require roles with
  `is_protected=true` or `is_super_admin=true` to be system-defined without making the
  reverse implication.
- Enforce `deleted_at IS NULL OR is_active = false`, and prevent a deleted role
  from returning to active authority.
- Require consistent tombstone metadata on soft-deletable users, roles,
  business entities, and relationship episodes. Effective queries and deferred
  role invariants count only live relations.
- Protect system-role shape and every `role_permissions` insert, update, or
  delete for a system role at the database boundary as defense in depth.
  Application services must still reject the mutation before SQL.
- Use a deferred constraint trigger for changes involving the `super_admin`
  assignment. Lock the global guard and require exactly one holder in the final
  transaction state, allowing bootstrap and atomic offline handover while rejecting a
  second holder or deletion of the last holder.
- Add indexes supporting exact permission resolution, stable pagination,
  affected-user scans, and application resource queries.
- Use restrictive production foreign keys. Parent deletion must tombstone all
  live owned child/join relations in the same service transaction; cascades must
  not erase history or silently broaden access through fallback logic.
- Keep every audit table append-only. Audit rows have no soft-delete state, and
  runtime/database controls reject `UPDATE`, `DELETE`, and `TRUNCATE`. Retention
  archives or relocates durable evidence without destroying it. Follow
  [Audit module](audit-module.md).
- Permit physical purge only for eligible non-audit tombstones through a
  separately authorized maintenance procedure, disposable test-schema teardown,
  or a reviewed migration/downgrade. Never expose purge as an ordinary runtime
  endpoint, and never purge `rbac_state` or audit rows under this baseline.

## Permission Catalog Handoff

Keep a version-controlled catalog of stable permission keys and descriptions.
The baseline administration catalog includes:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:delete
roles:bind
roles:unbind
roles:permissions:bind
roles:permissions:unbind
users:read
users:create
users:status:update
users:password:reset
users:sessions:revoke
```

The user implements and runs repeatable initialization; the Skill delivers the
catalog specification, not a runnable seed file. Initial data must not duplicate
rows or reset custom-role composition. Assign stable unique IDs and use the
role specifications and grant allowlists from `app/core/access/roles.py`. Read
`PermissionKey` and `PERMISSION_CATALOG` from `app/core/access/permissions.py`; catalog
values are description `MessageKey` values. Resolve initial stored text with
`get_permission_description(key)` (default `zh-CN`), rather than storing a
message key as the description. Exclude demonstration permissions for business
features that the generated application does not implement.

User-role changes use `roles:bind` and `roles:unbind`. Existing adopters own the
corresponding permission-data update and must preserve existing role grants;
installing this Skill does not update a project's database. Published historical
migrations and historical SQL examples retain their original permission keys.

- Add a new key without granting it until the role policy explicitly says so.
- Add a description `MessageKey` and matching Chinese/English catalog entries
  for each built-in business permission. Permission APIs localize those built-in
  descriptions at read time; custom database descriptions remain as stored.
- Treat a rename as a controlled data migration, often with a compatibility
  period; do not delete the old key before all code is updated.
- Do not automatically delete unknown database permissions because another
  deployed version may still use them.
- Separate the permission catalog from system-role composition, custom-role
  composition, and user assignments.
- Record material seed changes in an audit trail or deployment record.
- Keep `super_admin` grants in an explicit allowlist. Never grant every catalog
  row automatically because future internal or break-glass keys would silently
  broaden authority.

## Safe Administrative Changes

Application-side role assignments, permission bind/unbind, role information and
lifecycle changes, soft deletion, sole-super-admin checks, version increments,
the 10-live-role check, audit events, cache invalidation, and external effects must follow
[atomic authorization consistency](atomic-consistency.md).

Any user-owned data change affecting authority is an authorization writer too.
The user's execution plan must either stop incompatible old writers for a controlled
offline transition, or make it participate in the same guard, lock, version, and
audit protocol. Do not assume PostgreSQL DDL transactions alone supply the
application-level authorization ordering proof.

## Verification Boundaries

For ordinary model delivery, inspect metadata and run isolated code tests
without DDL or initial data. Report real database behavior as unverified until
the user completes their own setup and verification. The user-owned database
acceptance checklist is:

- Model fields, named constraints, indexes, defaults and foreign keys match the
  actual schema; no primary/public ID has an integer sequence or identity.
- Initial system-role shape and explicit grants match code, ordinary `owner`
  remains custom, and repeated initialization does not alter custom authority.
- Password fields have correct nullability and coherent Argon2id state;
  soft-deleted users cannot retain a password hash.
- Public registration has no enable/disable switch. Missing global state still
  fails closed because creating the default `user` assignment needs its guard row.
- Every creation path atomically assigns `user`; direct SQL is subject to the
  same mandatory-base-role and maximum-10-role guards.
- The tenth live assignment succeeds and the eleventh fails, including a race
  for the final slot. Count disabled roles, exclude tombstones, and cover both
  reassigned users.
- Bootstrap and offline handover leave one super administrator, lock first,
  apply changes and audit atomically; invalid/replayed requests cause
  no partial or duplicate authority changes.
- Runtime writes cannot alter fixed system roles or their grants, remove the
  final super administrator, or delete/truncate `rbac_state`.
- Soft-delete and restore preserve relation history, exact live-pair uniqueness,
  permanent username/key reservation, and no restored old authority.
- Runtime roles cannot update, delete or truncate any audit table; audit and
  global state are not maintenance-purge targets.
- PostgreSQL query plans, isolation and locks are tested on PostgreSQL. SQLite
  and mocked SQL execution are not substitutes.

Historical migration and seed regression is separate maintenance work. Its
fixtures can migrate, downgrade, truncate and clear data, are excluded from
generated projects, and must not run as an ordinary generation step. If that
maintenance work is explicitly requested, follow the disposable-target guards
in [Testing](testing.md), preserve published revisions, and report its results
separately. Never aim destructive historical fixtures at a user's project data.
