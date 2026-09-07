# RBAC Migrations And Permission Catalog

Read this reference when adding or changing authorization tables, constraints,
permission keys, seeded roles, assignments, lifecycle fields, or authorization
versions. For any primary/public identifier or integer-to-UUID conversion, also
read [identifier policy](identifier-policy.md); it owns the non-sequential ID
contract and compatible migration sequence.

The included PostgreSQL asset starts with
[`0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py)
and adds the complete system-role/API contract in
[`0002_system_roles.py`](../assets/postgresql-rbac/alembic/versions/0002_system_roles.py).
Revision `0001` has shipped and is immutable. Do not edit it to make a new
checkout appear current; every database change belongs in `0002` or a later
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
6. Validate role shape, unique-super-admin, default-user, soft-delete, and
   authority-version invariants, then make constraints strict.
7. Remove legacy authorization fields only after rollback and compatibility
   windows close.

Unmapped users and records default to only the mandatory base `user` role, which
has no authorization-management permission. Never grant `admin` merely to make a
migration pass.

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
4. Before any schema change, reject an existing owner role with more than one
   holder. Then migrate that role in place to the deterministic `super_admin`
   specification and replace its legacy grants with the new explicit allowlist.
   Do not create a second assignment or rewrite grants on unrelated custom roles.
5. Seed deterministic `admin` and `user` roles. Fix their tiers at `500` and `0`;
   fix `super_admin` at `1000`.
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

## System Role Specifications

The database and domain constants agree on exactly these rows:

| Key | Tier | Required flags | Public mutation |
| --- | ---: | --- | --- |
| `super_admin` | `1000` | `is_system`, `is_protected`, `is_owner`, `is_active`, not deleted | Assignment changes only through bootstrap or atomic ownership transfer |
| `admin` | `500` | `is_system`, `is_active`, not protected, not owner, not deleted | Role definition and grants are immutable; assignment only by a strictly higher actor |
| `user` | `0` | `is_system`, `is_active`, not protected, not owner, not deleted | Mandatory assignment cannot be unbound |

Custom roles use tier `1..999`. Runtime strict hierarchy means `admin` can create,
edit, enable, disable, grant, or assign only custom roles below tier `500` and
within its explicit delegation ceiling. Only custom roles may be soft-deleted.
Their keys remain reserved after deletion. The historical `owner` key is also
permanently reserved because downgrade restores that name for the legacy system
role.

System-role permission changes are code-and-migration changes, never public API
calls. A later migration that deliberately changes them must lock the global
guard, analyze all affected users, update role/user versions and the epoch, and
preserve an auditable deployment record.

## Default User Provisioning

Every registration, invited-user flow, administrator-created user, identity
synchronization, import, and bootstrap path must bind `user` in the same database
transaction that makes the user usable. Public request bodies cannot choose an
initial role.

Centralize this in one trusted provisioning service. Add a deferred PostgreSQL
constraint trigger that rejects commit whenever an existing user lacks the
deterministic `user` assignment. A direct database writer must therefore insert
the user and its `(user_id, role_id)` relation in the same transaction; never
create the system role lazily. Tests must cover every supported creation path. A
post-commit repair job is not sufficient because it creates a window with an
invalid identity.

Bootstrap is the only creation path that additionally binds `super_admin`. Use:

```text
python -m app.rbac.bootstrap --super-admin-email admin@example.com
```

The command locks the global guard first, creates or loads the user, ensures
`user`, binds the pre-seeded `super_admin`, updates versions and epoch, and writes
audit in one transaction. Do not replace it with a bare `INSERT` into
`user_roles`. The same completed identity may be recognized as a no-op; a
different second holder is refused.

## Constraints

- Use native PostgreSQL UUIDv4 primary/API IDs for authorization, session, audit,
  and business entities. Do not introduce `SERIAL`, `BIGSERIAL`, `IDENTITY`,
  integer autoincrement, or a sequential compatibility alias. Integer
  tier/version/epoch columns are counters, not identifiers.
- Give tables, foreign keys, unique constraints, triggers, and indexes
  deterministic names.
- Enforce uniqueness for permission keys, role keys, `(user_id, role_id)`
  assignments, and `(role_id, permission_id)` grants. Keep both assignment
  foreign keys non-null; a Python pre-check is insufficient under concurrency.
- Create `authorization_state` with exactly one `scope='global'` row. Enforce the
  fixed value with a primary key and check constraint, seed it in the migration,
  and never create it lazily at runtime.
- Keep `is_system` independent from `is_protected`; require protected and owner
  roles to be system-defined without making the reverse implication.
- Enforce `deleted_at IS NULL OR is_active = false`, and prevent a deleted role
  from returning to active authority.
- Protect system-role shape and every `role_permissions` insert, update, or
  delete for a system role at the database boundary as defense in depth.
  Application services must still reject the mutation before SQL.
- Use a deferred constraint trigger for changes involving the `super_admin`
  assignment. Lock the global guard and require exactly one holder in the final
  transaction state, allowing bootstrap and atomic transfer while rejecting a
  second holder or deletion of the last holder.
- Add indexes supporting exact permission resolution, stable pagination,
  affected-user scans, and application resource queries.
- Decide delete behavior deliberately. Cascades must not erase audit history or
  silently broaden access through fallback logic.

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
audit events, cache invalidation, and external effects must follow
[atomic authorization consistency](atomic-consistency.md).

An online seed or backfill that changes effective authority is an authorization
writer too. Either stop incompatible old writers and run it as a controlled
offline transition, or make it participate in the same guard, lock, version, and
audit protocol. Do not assume PostgreSQL DDL transactions alone supply the
application-level authorization ordering proof.

## Verification

- Upgrade a new empty database to head.
- Upgrade a realistic database from `0001` to `0002`, including an existing
  legacy owner, users with no roles, users with multiple roles, and existing
  custom grants.
- Prove an upgrade with two legacy owner holders fails before schema changes and
  rolls back without altering the revision, data, or permission catalog.
- Run each seed helper more than once and verify stable identifiers, role shape,
  grants, assignments, versions, and epoch.
- Prove direct SQL cannot disable, delete, rename, re-rank, or change grants on
  the three system roles, and prove every application service rejects the same
  operations before SQL.
- Prove every supported new-user path commits `user` atomically and that the
  unbind service cannot remove it.
- Prove the bootstrap creates exactly one holder with both `user` and
  `super_admin`, is safe when repeated for that identity, and refuses a second
  identity without partial writes.
- Prove direct SQL cannot remove the final `super_admin`, cannot add a second,
  and can transfer it only as one remove-plus-add transaction; ordinary base-role
  assignment must still work before the first bootstrap.
- Prove custom soft deletion immediately removes effective authority but retains
  assignments and grants for audit, and that deleted keys cannot be reused.
- Prove database constraints reject duplicate or orphaned role assignments.
- Prove the fixed global authorization-state row exists and locks first for
  every authorization writer.
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
