# RBAC Migrations And Permission Catalog

Read this reference when adding or changing authorization tables, constraints,
permission keys, seeded roles, assignments, lifecycle fields, or authorization
versions. For any primary/public identifier or sequential-ID conversion, also
read [identifier policy](identifier-policy.md); it owns the non-sequential ID
contract and compatible migration sequence.
For login-identifier columns, uniqueness, user tombstones, relationship
episodes, or restore behavior, also read
[Identity and soft-delete lifecycle](identity-soft-delete.md).

The included PostgreSQL asset uses this linear migration chain:

1. [`0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py)
   creates the core users, roles, permissions, relationship episodes,
   `rbac_state`, and RBAC audit schema, and installs the database backstop for
   at most 10 live role bindings per user.
2. [`0002_system_roles.py`](../assets/postgresql-rbac/alembic/versions/0002_system_roles.py)
   adds the complete system-role and public administration contract.
3. [`0003_business_audit.py`](../assets/postgresql-rbac/alembic/versions/0003_business_audit.py)
   adds the separate append-only `business_audit_events` table and guards.
4. [`0004_password_auth.py`](../assets/postgresql-rbac/alembic/versions/0004_password_auth.py)
   adds local-password credential episodes, account-security audit evidence,
   and the `users:password:reset` permission/grants.

The current unreleased baseline intentionally updates these four revisions
because the maintainer confirmed that no adopter database requires compatibility.
This permission applies only to the bundled reference asset; it never authorizes
rewriting an existing user's migration or identity contract. Treat the next
published baseline as fresh-install only. Once that baseline is published or
adopted, freeze all four revisions and put every later database change in a new
revision.

A deployed application must preserve and explicitly map its existing users,
roles, grants, assignments, versions, and audit history. After any revision
ships, never edit it to change the catalog; add a new revision and synchronization
test instead.

## Migration Strategy

Use an expand, compatible rollout, backfill, validate, and contract sequence for
deployed systems:

1. Add new nullable columns, tables, indexes, and non-breaking constraints.
2. Seed stable permission keys and the three deterministic system roles
   idempotently.
3. Deploy code that can read the old and new shapes and dual-writes new authority
   data, or use an equivalent controlled database transition. Confirm it is safe
   while old application instances still exist.
4. Backfill the system-role mapping and mandatory `user` assignments in bounded
   batches when data volume requires it.
5. Switch reads to the new model, stop legacy writers, and verify no old instance
   or job can create invalid authorization data.
6. Validate identity normalization/uniqueness/reuse, role shape,
   unique-super-admin, default-user, live-relation uniqueness, soft-delete, and
   authority-version invariants, then make constraints strict.
7. Remove legacy authorization fields only after rollback and compatibility
   windows close.

Unmapped users and records default to only the mandatory base `user` role, which
has no authorization-management permission. Never grant `admin` merely to make a
migration pass.

## Login-Identifier Schema

Before a greenfield migration, first ask whether `users` stores `email`,
`user_name`, or both. Then separately record per-flow requiredness, accepted
login inputs, normalization, uniqueness, cross-namespace ambiguity, and reuse
after soft deletion. Generate columns, checks, and indexes from those answers
rather than copying an accidental example.

The bundled fallback makes `email` and `user_name` nullable, requires at least
one, and keeps each supplied canonical value globally unique, including after
user soft deletion. If the selected policy allows reuse, replace global
uniqueness with a partial unique index over live users and migrate recovery and
lookup behavior together. An existing service retains its current contract
unless the user explicitly requests this migration. Backfill a new canonical
column, detect normalization collisions, dual-read/write during rollout when
needed, and validate before enforcing uniqueness; never silently merge users.
If one login input accepts either field, reject cross-column collisions through
a shared canonical login-key table/constraint, disjoint syntax, or explicit
typed inputs; separate unique constraints do not solve that ambiguity.
Immutable `users.id` does not change and remains JWT `sub` and the bootstrap
input throughout.

## `0002_system_roles` Contract

The upgrade from `0001` performs these changes without deleting audit or
assignment history:

1. Add `roles.description`, `roles.deleted_at`, and
   `roles.deleted_by_user_id`; a deleted role is inactive and cannot be enabled.
2. Remove the old `is_system = is_protected` constraint. `admin` and `user` are
   system roles but do not make every holder a protected identity.
3. Seed the permission catalog used by the public API, including separate
   `permissions:read`, role information/lifecycle/delete capabilities,
   permission bind/unbind capabilities, and `super_admin:transfer`.
4. Seed deterministic `super_admin`, `admin`, and `user` roles directly. Fix
   their tiers at `1000`, `500`, and `0`. Reject a pre-existing collision on one
   of those three keys unless it already has the exact required system-role
   shape; do not rename or reinterpret any other custom role.
5. Leave an unrelated custom role whose key is `owner` unchanged. The fresh
   baseline has no legacy `owner` system-role alias or compatibility behavior.
6. Seed explicit super-admin and admin grant/delegation allowlists. The admin set
   deliberately omits role deletion, delegation control, and super-admin
   transfer; `user` receives no authorization-management grant.
7. Backfill `user` for every existing user, preserving every other assignment.
   Increment each changed user's `authz_version`, increment the global epoch for
   the shared change, and record the controlled migration outcome.
8. Add database constraints and triggers that protect the fixed key, name,
   description, tier, flags, active/not-deleted shape, and permission/delegation
   composition of all three system roles from direct runtime writes.
9. Add the indexes needed for active/non-deleted role resolution, role list and
   detail lookup, permission detail lookup, and affected-user scans.

The migration is repeatable at the seed level but Alembic still records it once.
Use deterministic identifiers for public stable role and permission keys; never
derive authorization rank from those identifiers.

## `0001` Role Limit, `0003` Business Audit, And `0004` Password Contracts

`0001_single_project_rbac` installs the database backstop for the 10-live-role
rule as part of the fresh schema. After seeding the global `rbac_state` row, its
statement-level trigger makes every direct assignment write take the global
guard, and its deferred constraint trigger validates each affected user's final
live count across inserts, reassignment, unbind, and reactivation. Downgrade
drops the constraint trigger and functions before dropping `user_roles`.

`0003_business_audit` creates the generic business-audit table, its query
indexes, bounded JSON constraints, and database triggers rejecting runtime
`UPDATE`, `DELETE`, and `TRUNCATE`. It does not change RBAC role limits.

`0004_password_auth` creates `user_password_credentials` and
`account_security_audit_events`, installs their live-episode, tombstone,
UUIDv4, and append-only controls, and seeds `users:password:reset` for the
built-in administrator roles. Existing users receive no generated or default
credential and remain unable to use password login until controlled enrollment.

## System Role Specifications

The database and domain constants agree on exactly these rows:

| Key | Tier | Required flags | Public mutation |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | `is_system`, `is_protected`, `is_super_admin`, `is_active`, not deleted | Assignment changes only through bootstrap or atomic `super_admin` transfer |
| `admin` | `500` | `is_system`, `is_active`, `is_protected=false`, `is_super_admin=false`, not deleted | Role definition and grants are immutable; assignment only by a strictly higher actor |
| `user` | `0` | `is_system`, `is_active`, `is_protected=false`, `is_super_admin=false`, not deleted | Mandatory assignment cannot be unbound |

Custom roles use tier `1..999`. Runtime strict hierarchy means `admin` can create,
edit, enable, disable, grant, or assign only custom roles below tier `500` and
within its explicit delegation ceiling. Only custom roles may be soft-deleted.
Their keys remain reserved after deletion. `owner` is not a reserved system key;
it may be an ordinary custom-role key and has no special authority.

System-role permission changes are code-and-migration changes, never public API
calls. A later migration that deliberately changes them must lock the global
guard, analyze all affected users, update role/user versions and the epoch, and
preserve an auditable deployment record.

## Soft-Delete Schema

Apply the selected login-identifier schema above without changing an existing
application's identity contract as a side effect of adopting RBAC.

Add `deleted_at` and trusted deletion-actor metadata to every runtime-deletable
user, custom role, and business entity. Give `user_roles` and
`role_permissions` non-sequential episode IDs, bind metadata, and equivalent
tombstone metadata. Replace whole-pair uniqueness with a PostgreSQL partial
unique index over `deleted_at IS NULL`, so only one live episode exists while
history remains. Effective queries and constraints use only live parent and
relation rows.

The three fixed system roles and the migration-owned permission catalog have no
runtime deletion path. If a product deliberately makes permission rows mutable,
give them the same tombstone metadata and tombstone every live grant atomically.

A parent delete tombstones the parent and all live owned relation episodes in
one transaction. A later bind inserts a new episode. Restore never clears old
tombstones; a restored user receives only a new mandatory `user` episode, and
prior privileged roles/grants require new authorized binds. Production runtime
foreign keys use `RESTRICT`, not cascading hard deletion.

## Default User Provisioning

Every registration, invited-user flow, administrator-created user, identity
synchronization, and import path must bind `user` in the same database
transaction that makes the user usable. Public request bodies cannot choose an
initial role.

Centralize this in one trusted provisioning service. Add a deferred PostgreSQL
constraint trigger that rejects commit whenever a live user lacks one live
deterministic `user` assignment. A direct database writer must therefore insert
the user and its relation episode in the same transaction; never create the
system role lazily. User deletion tombstones that episode with the user;
restoration creates a new base-role episode and no former privileged episode.
Tests must cover every supported creation and restore path. A post-commit repair
job is not sufficient because it creates a window with an invalid identity.

Bootstrap never creates an identity. The intended person must first use a normal
trusted registration or provisioning path and receive `user`. The user then
personally runs the supplied `sql/bootstrap_super_admin.sql` against PostgreSQL,
passing immutable `users.id` as `super_admin_user_id`. The script locks the
global guard first, verifies the account and system-role contract, binds
`super_admin`, updates the affected user's authorization version and global
epoch only when changed, and writes audit in one transaction. Do not replace it
with a bare `INSERT` into `user_roles`. Never select the holder by email or
`user_name`. The same completed identity is an idempotent replay; a different
second holder is refused without partial writes.

## Constraints

- Follow [identifier policy](identifier-policy.md) for every primary/API ID. A
  new project normally uses registered business prefixes with random uppercase
  suffixes sized by lifetime volume; an established UUIDv4 design and the
  bundled UUIDv4 asset remain compliant. Do not introduce `SERIAL`, `BIGSERIAL`,
  `IDENTITY`, integer autoincrement, or a sequential compatibility alias.
  Integer tier/version/epoch columns are counters, not identifiers.
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
  the trigger before its function during downgrade. This enforcement is part of
  the fresh `0001_single_project_rbac` schema, not a later compatibility migration.
- Create `rbac_state` with exactly one `scope='global'` row. Enforce the
  fixed value with a primary key and check constraint, seed it in the migration,
  never create it lazily at runtime, and use grants/triggers to reject production
  `DELETE` and `TRUNCATE`.
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
  transaction state, allowing bootstrap and atomic transfer while rejecting a
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

## Permission Seeding

Keep a version-controlled catalog of stable permission keys and descriptions.
The baseline administration catalog includes:

```text
permissions:read
roles:read
roles:create
roles:update
roles:status:update
roles:delete
roles:assign
roles:revoke
roles:permissions:bind
roles:permissions:unbind
roles:delegation:update
users:read
users:status:update
super_admin:transfer
```

Seeding is repeatable and must not duplicate rows or reset custom-role
composition.

- Add a new key without granting it until the role policy explicitly says so.
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

An online seed or backfill that changes effective authority is an authorization
writer too. Either stop incompatible old writers and run it as a controlled
offline transition, or make it participate in the same guard, lock, version, and
audit protocol. Do not assume PostgreSQL DDL transactions alone supply the
application-level authorization ordering proof.

## Verification

- Upgrade a new empty database through `0004_password_auth` at head and verify
  the role-limit functions and triggers already installed by `0001` remain active.
- Exercise the linear `0001` through `0004` chain with an ordinary
  custom role whose key is `owner`, users with no roles, users with multiple
  roles, and existing custom grants. Verify `owner` remains ordinary custom data
  and only `super_admin`, `admin`, and `user` receive system-role semantics.
- Run each seed helper more than once and verify stable identifiers, role shape,
  grants, assignments, versions, and epoch.
- Prove direct SQL cannot disable, delete, rename, re-rank, or change grants on
  the three system roles, and prove every application service rejects the same
  operations before SQL.
- Prove every supported new-user path commits `user` atomically and that the
  unbind service cannot remove it.
- Prove the operator-run SQL accepts only immutable `users.id`, requires an
  existing live active `user`, creates exactly one live `super_admin` episode,
  is safe when repeated for that identity, and refuses a missing, invalid,
  deleted, different second identity, or target already holding 10 live roles
  without partial writes. A target with nine live roles may take the tenth.
- Prove direct SQL cannot remove the final `super_admin`, cannot add a second,
  and can transfer it only as one remove-plus-add transaction; ordinary base-role
  assignment must still work before the first bootstrap.
- Prove custom-role soft deletion immediately removes effective authority,
  atomically tombstones every live assignment and grant, and permanently
  reserves the role key.
- Prove database constraints reject orphaned relations and concurrent duplicate
  live episodes while allowing multiple historical tombstones for one pair.
- Prove service and direct SQL accept a tenth live role and reject an eleventh;
  disabled roles still occupy a slot, tombstones release one, and two concurrent
  attempts to take the tenth slot cannot both commit. Apply the same limit to
  bootstrap and super-admin transfer.
- Prove the fixed global `rbac_state` row exists and locks first for
  every authorization writer; direct `DELETE` and `TRUNCATE` fail.
- Prove the selected email/`user_name` requiredness, normalization, uniqueness,
  login lookup, and reuse policy from empty and supported prior revisions.
- Prove parent soft deletion and live relation tombstones are atomic, relation
  rebind creates a new episode, and restore revives no old authority.
- Prove runtime roles cannot update, delete, truncate, or soft-delete audit rows,
  and controlled purge paths reject audit and `rbac_state` targets.
- Check query plans for permission resolution and high-volume affected-user
  scans.
- Verify the application during a mixed-version rollout when zero downtime is a
  requirement.
- Run PostgreSQL-specific constraints and optional row-level security against
  PostgreSQL; SQLite is not an adequate substitute.
- Inspect PostgreSQL metadata and prove no authorization or business
  primary/public ID is integer, identity-backed, or has a `nextval(...)` default.
- Treat downgrades that discard system-role, soft-delete, or authorization data
  as destructive. Refuse them or document and test the required backup and
  restore path.
