# Identity Selection And Soft-Delete Lifecycle

Read this reference when choosing login identifiers, changing the `users`
schema, implementing user or business-resource deletion/restoration, or changing
an RBAC bind/unbind relation. It owns identity-policy questions and the default
runtime deletion contract. Use the PostgreSQL, migration, hierarchy, and atomic
references as well only when implementing those corresponding boundaries.

## Choose The Identity And Login Contract Before Greenfield Work

For a greenfield service, the baseline stores only `user_name` and logs in with
that name and a password. Require trimming, 3..32 ASCII letters/digits/underscores,
global uniqueness even after soft deletion, and the fixed reserved-name list in
[Local password authentication](local-password-authentication.md). Ask only
whether ASCII letter casing is significant, then apply that one canonical rule
consistently to creation, lookup, and uniqueness. Preserve an existing project's
different contract unless a change is requested. The identity decisions are:

| Decision | Required answer |
| --- | --- |
| Stored identifiers | Required `user_name` only in the new-project baseline |
| Creation requirement | Same trimmed and validated username in registration, admin creation, and trusted provisioning |
| Login input | Username only |
| Normalization | Trim and ASCII validation are mandatory; ask whether case is significant |
| Uniqueness | Canonical username is globally unique in PostgreSQL |
| Reuse after soft deletion | Permanently reserve a deleted user's username |

Email/phone login and recovery are not part of this template. A project that
needs them owns a separate explicit adaptation, including ambiguity and
verification policy; do not add it to this new-project baseline.

For an existing project, inspect and preserve its selected identity fields,
normalization, login behavior, uniqueness, and reuse policy unless the user asks
to change them. Adding a second identifier or changing case/reuse semantics is a
data and authentication migration, not incidental RBAC work.

## Canonical Identity Storage

Keep presentation identifiers separate from authorization identity:

- `users.id` is non-sequential, immutable, and never recycled. It is the only
  canonical user identity used by authorization, audit actor/target fields, and
  Access Token `sub`.
- Normalize once through a named, tested function before both write and lookup.
  Preserve a separate presentation value only when the product needs it; never
  use presentation spelling as a unique-key comparison.
- Enforce canonical uniqueness in PostgreSQL with an unconditional unique
  constraint so a deleted username stays reserved. An application-only
  pre-check races. Changing this in an existing project requires an explicit
  identity and data decision.
- Password verification is authentication, not proof of a presentation name.
  Email login, identity-provider linking, and self-service recovery are outside
  this baseline and require a separately requested design.

The bundled asset uses a required, globally unique `user_name`. Its trusted
provisioner, public registration, admin creation, and login lookup use the same
named normalization. A deleted name stays reserved, and SQL uniqueness is the
final authority against concurrent creates.

## JWT Subject And First-Super-Admin Bootstrap

The login choice never changes the Token subject. JWT `sub` is always the exact
canonical string of immutable `users.id`; it is never an email, `user_name`, or
other mutable/reusable lookup value. Login resolves the submitted identifier to
one live user first, then issues the Token for that user's ID. Renaming a
username does not change `sub` and does not create a new identity.

The operator-run first-super-admin script accepts only the intended existing
user's canonical ID, for example:

```powershell
psql $env:PSQL_DATABASE_URL `
  --set=super_admin_user_id=9bb60ae3-cad9-4e07-b072-7f4336044f18 `
  --file sql/bootstrap_super_admin.sql
```

Do not bootstrap by email or `user_name`; normalization changes, renamed values,
or an allowed reuse policy could select the wrong account. The script still
verifies that the ID names one live, active, unprotected user with the mandatory
base `user` role before binding `super_admin`.

## Runtime Soft-Delete Contract

Every ordinary runtime removal of a mutable persisted row is a soft delete. This
includes users, custom roles, business entities, and relationship unbinds.
Ordinary HTTP routes, service methods, jobs, and CLI commands must not physically
delete those rows or rely on `ON DELETE CASCADE`.

Classify every table before creating it; no table is allowed to inherit an
unspecified hard-delete default:

| Table lifecycle | Required deletion behavior |
| --- | --- |
| Mutable runtime data, including entities and relationship episodes | Use a tombstone such as `deleted_at` plus trusted actor metadata; every ordinary remove/unbind path updates the tombstone |
| Append-only evidence, including RBAC and business audit events | Expose no update, soft-delete, hard-delete, or truncate path |
| Permanent control state or immutable system catalog | Expose no runtime deletion path; missing required state fails closed |

When adapting this Skill to a project, inventory all tables and every HTTP,
service, job, CLI, and scheduled cleanup path that can remove rows. A mutable
table is incomplete until its schema, ordinary queries, unique constraints,
parent cleanup, restore policy, audit behavior, and tests all understand the
tombstone. Naming an endpoint "delete" does not permit a physical delete.

The three system roles and the fixed permission catalog expose no runtime delete
command. If a product later makes permission entries runtime-mutable, deleting
one must tombstone the permission and all live grants in the same transaction;
restoring it must not revive those grants.

The bundled PostgreSQL asset directly implements custom-role soft deletion and
the two RBAC unbind paths. It includes the lifecycle columns and tests needed to
adapt user and permission lifecycle safely, but intentionally exposes no public
user-delete, user-restore, permission-delete, or permission-restore endpoint.
Do not claim those product-specific paths are complete until their independent
capabilities, hierarchy decisions, transaction code, audit events, and negative
tests have been added.

Entity tables normally carry `deleted_at` and `deleted_by_user_id` or an
equivalent trusted actor field. Add a bounded reason code only when the product
needs it. A deleted entity is absent from ordinary detail, list, count, search,
export, authorization, ownership, and uniqueness queries except where the
chosen identifier-reuse policy deliberately includes its tombstone.

Model each RBAC relationship as a non-sequentially identified episode:

```text
user_roles:
  id, user_id, role_id, assigned_at, assigned_by_user_id,
  deleted_at, deleted_by_user_id

role_permissions:
  id, role_id, permission_id, assigned_at,
  assigned_by_user_id, deleted_at, deleted_by_user_id
```

Use a partial unique index for one live episode per logical pair, for example
`UNIQUE (user_id, role_id) WHERE deleted_at IS NULL`. An unbind timestamps the
one live episode and records the trusted actor. A later authorized bind creates
a new episode with a new ID; it never clears or reuses the old tombstone. An
unbind with no live episode is an idempotent `changed=false` result.

Permission unbind tombstones the live `role_permissions` episode. The actor
may grant only a permission it currently possesses and still must pass the
strict hierarchy and affected-user checks. There is no independent delegation
flag or runtime delegation-management route.

Every effective-authority and affected-user query must require live users,
roles, `user_roles`, and `role_permissions`. A tombstone never grants authority,
counts as the mandatory base-role binding, satisfies the sole-super-admin
constraint, or participates as a live uniqueness match.

## Parent Delete And Restore

Deleting a parent soft-deletes the parent and every currently live owned child
or join relation whose continued presence could expose data or grant authority.
Lock and tombstone the complete live relation set in the same authoritative
transaction. Do not depend on an asynchronous cleanup job, and do not leave a
live child hidden only by a parent filter.

A restore acts only on the requested entity. It never clears relation
tombstones or silently revives prior ownership, role assignments, permission
  grants, subscriptions, memberships, shares, or other access edges.
Recreate each wanted relation through its normal authorized bind command so a
new live episode, versions, and audit evidence are produced.

When restoring a user, create a new mandatory base `user` episode in the restore
transaction after validating the system-role contract; do not restore any old
custom, `admin`, or `super_admin` episode. Do not decrement `token_version` or
recreate an old Redis active-JTI record, so pre-deletion Tokens remain invalid.
The current fixed custom-role delete is terminal. If a product later adds role
restore, the restored role starts with no live permission grants or user
assignments.

## Records That Are Not Soft-Deletable

Append-only audit rows are not soft-deleted. That is a stronger rule: audit
tables have no `deleted_at`, and runtime roles cannot `UPDATE`, `DELETE`, or
`TRUNCATE` their rows. Correct bad evidence with a new cataloged correction
event; never rewrite or tombstone the original event.

The singleton `rbac_state(scope='global')` row is also never deleted, disabled,
or soft-deleted. It exists for the database lifetime, is created by migration,
and missing state makes runtime authorization fail closed. No runtime or
maintenance endpoint recreates it opportunistically.

Physical deletion is limited to explicit, separately authorized operations:

- a documented maintenance purge of eligible non-audit tombstones after the
  product's retention, legal-hold, backup, and referential checks;
- teardown of an entirely disposable test database or schema; or
- a reviewed migration or downgrade whose compatibility, backup, and recovery
  contract explicitly permits destructive transformation.

These exceptions are never ordinary runtime deletion and never authorize audit
event removal. Production migrations preserve audit evidence and the global
RBAC state. A destructive audit-retention rule requires a separately approved
product/legal exception outside this default baseline; do not infer it from a
generic retention period.

### Direct SQL And Deployment Choice

Soft deletion is first an application contract: routes, services, jobs, and
ordinary commands update tombstones instead of issuing physical `DELETE`. It
cannot stop a person who connects as the PostgreSQL owner or superuser and runs
arbitrary SQL. This is not solvable inside a FastAPI service because that
database identity can also alter grants, triggers, or schema.

During a new production setup, ask whether a professional operations team will
manage database identities:

- With such a team, use a schema-owning migration role separately from the
  runtime application role. Grant the runtime role only its required
  `SELECT`/`INSERT`/`UPDATE` operations and withhold `DELETE`/`TRUNCATE` on
  soft-deleted tables. Test the deployed grants, not merely migration-owner
  credentials.
- For a small learning project or a user who does not manage PostgreSQL roles,
  keep the application soft-delete implementation and explain the direct-SQL
  limitation. Do not force a complex role topology or block delivery. Record
  least-privilege roles as a production hardening follow-up if the service later
  handles real data.

Neither choice changes the rule that public APIs and application services must
never hard-delete mutable rows. Do not claim that database-owner access is safe
or impossible to misuse.

## Transaction And Version Effects

A deletion, unbind, parent-relation tombstone set, or restore owns one
transaction. For authorization-affecting work, lock `rbac_state` first, reload
the actor and complete affected set, apply hierarchy and self-elevation policy,
tombstone or create relation episodes, increment every affected user/role
version and the global epoch, add the allowed audit, and commit once. A failure
rolls back the parent, all relations, versions, and allowed audit together.

Redis invalidation and other external effects happen after commit. User deletion
or another account-wide authentication change also increments
`users.token_version`; do not perform Redis I/O while PostgreSQL locks are held.

## Verification

For the selected surface, prove:

- the greenfield identity decision records all six dimensions above, while an
  existing project's identity contract remains unchanged by default;
- create and login use the same normalization and database uniqueness rule;
- a deleted username remains reserved, including under concurrent registration;
- JWT `sub` and first-super-admin bootstrap use immutable `users.id` only;
- every runtime delete/unbind leaves a tombstone and every rebind creates a new
  live episode with a new ID;
- effective queries ignore every tombstoned entity and relation;
- parent deletion and all live relation tombstones commit or roll back together;
- restore revives no previous privilege and gives a user only a new mandatory
  base-role episode;
- direct and concurrent writes cannot create two live relation episodes;
- database triggers reject ordinary update/delete/truncate attempts against
  audit rows and deletion of `rbac_state`; when separate production runtime
  roles were selected, their grants also withhold those operations and physical
  deletion from mutable soft-delete tables; and
- maintenance, test teardown, and migration exceptions cannot be reached through
  an ordinary application endpoint or service command.

When the user chose not to manage separate database roles, report that direct
owner SQL remains outside the application guarantee instead of marking the
least-privilege deployment check as passed.
