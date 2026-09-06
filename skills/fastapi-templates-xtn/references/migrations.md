# RBAC Migrations And Permission Catalog

Read this reference when adding or changing RBAC tables, constraints, permission
keys, seeded roles, assignments, or authorization-version columns.
For any primary/public identifier or integer-to-UUID conversion, also read
[identifier policy](identifier-policy.md); it owns the non-sequential ID contract
and compatible migration sequence.

The included PostgreSQL asset provides a clean initial schema in
[`0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py).
It creates the normalized tables, singleton global guard, constraints, indexes,
and initial permission catalog.

This initial revision is for a new application. Replacing an older schema file is
not an in-place production upgrade. A deployed application must add a new Alembic
revision that preserves and explicitly maps its existing users, roles, grants,
assignments, versions, and audit history. After any revision ships, never edit it
to change the catalog; add a new revision and synchronization test instead.

## Migration Strategy

Use an expand, compatible rollout, backfill, validate, and contract sequence for
deployed systems:

1. Add new nullable columns, tables, indexes, and non-breaking constraints.
2. Seed stable permission keys idempotently.
3. Deploy code that can read the old and new shapes and dual-writes new authority
   data, or use an equivalent database transition mechanism. Confirm it is safe
   while old application instances still exist.
4. Backfill users, system ownership, roles, and assignments in bounded
   batches when data volume requires it.
5. Switch reads to the new model, stop legacy writers, and verify no old instance
   or job can create invalid authorization data.
6. Validate that every protected record and active user has the intended
   authority, then make constraints strict.
7. Remove legacy authorization fields only after rollback and compatibility
   windows close.

Unmapped users and records default to no access. Never grant a broad role merely
to make a migration pass.

## Constraints

- Use native PostgreSQL UUIDv4 primary/API IDs for RBAC, session, audit, and
  business entities. Do not introduce `SERIAL`, `BIGSERIAL`, `IDENTITY`, integer
  autoincrement, or a sequential compatibility alias. Integer tier/version/epoch
  columns are counters, not identifiers.
- Give tables, foreign keys, unique constraints, and indexes deterministic names.
- Enforce uniqueness for permission keys, role keys, `(user_id, role_id)`
  assignments, and `(role_id, permission_id)` grants. Keep both assignment
  foreign keys non-null; a Python pre-check is insufficient under concurrency.
- Create `authorization_state` with exactly one `scope='global'` row. Enforce the
  fixed value with a primary key and check constraint, seed it in the migration,
  and never create it lazily at runtime.
- Add indexes supporting exact permission resolution, affected-user scans, and
  application resource queries.
- Decide delete behavior deliberately. Cascades must not erase audit history or
  silently broaden access through fallback logic.

## Permission Seeding

Keep a version-controlled catalog of stable permission keys and descriptions.
Seeding should be repeatable and should not duplicate rows or reset customized
role composition.

- Add a new key without granting it until the role policy explicitly says so.
- Treat a rename as a controlled data migration, often with a compatibility
  period; do not delete the old key before all code is updated.
- Do not automatically delete unknown database permissions because another
  deployed version may still use them.
- Separate the permission catalog from role composition and user assignments.
- Record material seed changes in an audit trail or deployment record.
- Keep system Owner grants in an explicit allowlist. Never grant every catalog
  row automatically because future internal or break-glass keys would silently
  broaden Owner authority.

## Safe Administrative Changes

Application-side role assignments, permission replacements, state changes,
last-owner checks, version increments, audit events, cache invalidation, and
external effects must follow
[atomic authorization consistency](atomic-consistency.md).

An online seed or backfill that changes effective authority is an authorization
writer too. Either stop incompatible old writers and run it as a controlled
offline transition, or make it participate in the same guard, lock, version, and
audit protocol. Do not assume a database's DDL transaction behavior supplies the
application-level authorization ordering proof.

## Authority Hierarchy Changes

When adding management tiers, scopes, delegable permissions, or protected-role
flags, follow [administrative-hierarchy.md](administrative-hierarchy.md) and use
conservative migration defaults:

- New and unmapped users and roles start with no administrative
  authority. Never infer a high tier from a display name such as `admin`.
- Keep hierarchy and delegation fields out of ordinary public mutation schemas.
- Backfill authority from an explicitly reviewed mapping, then validate that no
  actor can manage a peer, a higher authority, or itself through an indirect role
  change.
- A tier, delegation, protected-role, ownership, or shared-role change must
  increment every authorization version or global epoch used by affected decisions.
- Deploy compatible reads and writes before making hierarchy columns non-null or
  removing legacy checks.

## Verification

- Upgrade a new empty database to head.
- Upgrade a database at every supported prior production revision using data with
  realistic users, roles, grants, and assignments.
- Run the seed step more than once and verify stable results.
- Prove that database constraints reject duplicate or orphaned role assignments.
- Prove that the fixed global authorization-state row exists and locks first for
  every authorization writer.
- Check query plans for permission resolution and high-volume affected-user scans.
- Verify the application during a mixed-version rollout when zero downtime is a
  requirement.
- Run PostgreSQL-specific constraints and optional row-level security against
  PostgreSQL; SQLite is not an adequate substitute.
- Inspect PostgreSQL metadata and prove no RBAC or business primary/public ID is
  integer, identity-backed, or has a `nextval(...)` default. Follow the complete
  matrix in [identifier policy](identifier-policy.md).
- Treat downgrades that discard authorization data as destructive. Refuse them or
  document and test the required backup and restore path.
