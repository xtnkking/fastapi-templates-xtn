# Administrative Hierarchy And Anti-Escalation

Read this reference when an current user can assign roles, edit roles, manage users,
perform an offline handover of the sole super administrator, reset authentication factors, revoke
Access Tokens, impersonate another identity, or otherwise change another principal's
authority.

Requiring an administrative permission is only the first check. The current user must
also be allowed to manage the target, the proposed result, and every user
indirectly affected by the change.

The complete PostgreSQL example keeps shared authority checks in
[`authorization_policy.py`](../assets/postgresql-rbac/app/core/access/authorization_policy.py),
role decisions in [`role_policy.py`](../assets/postgresql-rbac/app/core/access/role_policy.py),
and user and user-role decisions in
[`user_policy.py`](../assets/postgresql-rbac/app/core/access/user_policy.py).
The respective [`role_service.py`](../assets/postgresql-rbac/app/services/role_service.py)
and [`user_service.py`](../assets/postgresql-rbac/app/services/user_service.py)
apply them to transactions and audits, including
user and custom-role lifecycle, immutable system roles, and offline-only
super-admin handover boundary.

When the task includes login identifiers, user deletion/restoration, or relation
storage, also read
[Identity and soft-delete lifecycle](identity-soft-delete.md). Greenfield work
uses the required `user_name` and password baseline, asks whether ASCII username
case is significant, and reserves soft-deleted usernames; existing work preserves
its identity contract unless a change is requested.

## Model Authority Explicitly

Do not infer rank from display names or database row IDs. The fixed system-role
keys are invariants, but authorization decisions still use the complete
authority model:

- `effective_permissions`: capabilities the user can exercise now;
- `level`: a role's server-controlled level; larger values are higher;
- `role_level`: a user's highest effective role level, or `0` when the user has
  no effective roles; use this name in authority objects and user responses;
- `protected_identity` and `protected_role`: the current `super_admin`,
  break-glass subjects, or other authority excluded from ordinary management;
- `system_role`: an application-defined role whose shape and grants cannot be
  changed through runtime administration.

Calculate permissions and `role_level` only through live assignment and permission-grant
episodes on active, non-deleted users and roles. Never inspect only a
`primary_role`, count a tombstoned relation, compare permission counts, or assume
that a familiar custom-role name dominates another role.

This baseline uses one application-wide hierarchy. If product resources need
department, project, ownership, or other row-level boundaries, model and test
those separately. A high role level never bypasses an independent resource policy.

Granting a permission requires the current user to hold that permission now, along
with the exact operation capability and strict lower-target hierarchy. Do not
add a separate delegation subset or management API.

## Fixed System Roles

The user initializes these roles before creating users; the Skill supplies
models and the [database handoff](migrations.md), not seed scripts or execution:

| Role | Level | Required behavior |
| --- | ---: | --- |
| `super_admin` | `1000` | System, protected, active; exactly one current holder after bootstrap |
| `user` | `0` | System and active; mandatory base role with no authorization-management capability |

The two roles cannot be disabled, soft-deleted, renamed, re-ranked, or have
their permission grants changed through a public API. This restriction
also applies to `super_admin`; the super administrator controls assignments and
custom roles, not the definition of the two system roles. A reviewed migration
is the only way to change a system-role specification.

Every normal signup or trusted user-creation path binds `user` in the same
transaction as user creation using a new live relation episode. Never accept a requested initial role at signup,
never remove `user` through the unbind endpoint, and keep it when adding custom
roles or `super_admin`.

There is no seeded `admin` role or default administrator capability set. An
administrator uses an ordinary custom role with a chosen level in `1..999` and
explicit permissions. The key `admin` is available for such a role and receives
no special treatment; level `500` is also ordinary. Whether that role can read,
create, update, delete, bind, or manage users depends on its current permissions
and the same strict hierarchy checks as every other custom role. It cannot
mutate system roles or change the sole `super_admin` through any API.

## Default Manageability Rule

For an identity- or authorization-changing operation, allow only when all
applicable conditions are true:

1. The current user is active and has the exact capability, such as `roles:bind`,
   `roles:unbind`, `roles:permissions:bind`,
   `roles:permissions:unbind`, `roles:status:update`,
   `users:status:update`, `tokens:revoke`, or
   `identities:impersonate`.
2. Neither the target nor an affected role is protected, and no proposed role
   definition changes an immutable system role.
3. The current user's `role_level` is strictly greater than the target's current
   and proposed `role_level`, and every assigned, proposed, or changed role's
   `level`. Peer, higher, and otherwise incomparable changes are denied.
4. Any newly granted permission is one the current user currently possesses, and
   affected users' complete authority remains manageable by the current user.
5. The change does not increase the current user's own effective permissions,
   `role_level`, `super_admin` status, protected status, impersonation
   reach, or other authorization power.
6. Mandatory-`user`, sole-`super_admin`, separation-of-duties, approval,
   soft-delete, and protected-role invariants still hold after the complete
   proposed change.

An ordinary permission such as `roles:bind` satisfies only condition 1. It is
not a bypass for the remaining checks. Equal-level administration requires a
separate explicit policy and must still forbid self-elevation; it is not part of
this baseline.

## Administrative Read Visibility

Having `users:read` or `roles:read` is necessary but not sufficient to reveal an
administrative object. The baseline read policy is:

- the current `super_admin` may inspect every non-deleted user and role, and
  list every user and role in the selected deletion state;
- every other administrator may see only roles whose `level` and users whose
  `role_level` are strictly lower than the current user's `role_level`;
- the ordinary administrator does not see itself, a peer, a higher target, or a
  protected target through administration endpoints; and
- the current user reads its own identity and current permissions through `/api/v1/me/user_info`.

User and role lists default to `is_deleted=false` (only non-deleted targets);
explicit `is_deleted=true` selects only deleted targets. The selection does not
relax capability, hierarchy or protected-target checks. Detail lookups continue
to exclude deleted targets.

Use the same SQL visibility predicate for list, count, search, export, nested
reads, and detail. A hidden detail returns the same generic `40401` as an
unknown ID. Do not fetch all rows and filter them in Python, and do not issue one
authority query per result row. Batch-load role grants and user authority for
non-deleted entries on the selected page; deleted entries use empty authority
collections without loading old grants. Permission-catalog reads reveal the stable action vocabulary,
not which hidden user or role holds those permissions.

Apply that predicate inside each returned user representation too. Embedded
collections such as `bound_role_ids` contain only roles visible to the
current user: `super_admin` may receive every live, non-deleted assignment,
while every other administrator receives only strictly lower, non-protected
roles it may inspect. A disabled peer or higher role must not leak merely because
its assignment is still live. Keep the complete unfiltered assignment set for
server-side authorization and audit decisions; filter only the public projection.

### Administrative Write Visibility

Use the same visibility boundary for administrative writes, but preserve the
authorization order. First reload the current user under the global guard and check the
exact operation capability. A caller without that capability receives `40301`
before the service reveals whether any target exists. Only then evaluate the
locked target's existence and visibility: an ordinary administrator's self,
peer, higher, or protected user or role is concealed with the same `40401` as
an unknown ID.
For user-role bind or unbind, apply that check to the target user and separately
to every requested role ID; one hidden or unknown role makes the whole atomic
request return `40401`.

After a target passes visibility, run granted-permission, affected-user, system-role,
self-elevation, and operation-specific policy. A visible target that fails one
of those checks returns `40301`. Keep these stages distinct so `40401` does not
become a general substitute for authorization denial and `40301` does not leak
hidden administrative objects.

## Direct And Indirect Self-Elevation

Deny a request whose direct target is the current user when it grants a role,
permission, role level, `super_admin` status, protected status,
or impersonation capability. Detect indirect effects too:

- editing a role currently assigned to the current user;
- creating a role and then assigning it to the current user;
- changing a role template, permission catalog, group, or inheritance edge that
  contributes to the current user's authority;
- modifying a shared role whose change expands the current user's permissions;
- changing the super-admin assignment so the current user can grant itself authority later;
- using a bulk endpoint, background job, alternate route, or service API to
  perform the same effect indirectly.

For every authorization mutation, compute the current user's complete authority before
and after the proposed change inside the authoritative transaction. The after
permissions must contain no new element, and `role_level` must not
increase. Checking only `current_user.user_id != target.user_id` is insufficient.

A dedicated self-service endpoint may let a user remove a non-mandatory role or
reduce its own authority. It cannot add or exchange authority, cannot remove
`user` or the final `super_admin`, and should require recent authentication for
sensitive changes. This is not a substitute for the administrative unbind
endpoint's no-self-target rule.

## Role And User Operations

- Role assignment checks both the target user and every assigned role. The current user
  must dominate the target's complete current and proposed authority. The
  proposal must also leave the target with at most 10 live role bindings.
- Ordinary role binding never grants `super_admin`; only guarded offline SQL
  changes its holder. Custom administrator roles use the normal strict-hierarchy
  and held-permission checks, and no current user can unbind `user`.
- Role creation checks the proposed `level` and starts with no permissions.
  Permission binding is a separate capability and transaction.
- Role information update changes only explicitly mutable custom-role fields.
  System keys, levels, flags, lifecycle fields, and permissions never
  enter an ordinary update body.
- Permission bind and unbind check the complete resulting role and every live
  direct or indirect assignee. They reject an current user-held role, a permission
  outside the current user's effective set, and any affected protected, peer, or higher
  user.
- Disabling, enabling, or deleting a shared custom role affects every live
  assignment that could become effective now or after user reactivation.
  Do not ignore suspended users. Enabling revalidates live assignments; soft
  delete is terminal, immediately removes the role from effective authority,
  atomically tombstones every live grant and assignment, and permanently
  reserves its key.
- User profile or login-identifier changes, suspension, deletion, credential or
  MFA reset, Token revocation, and impersonation use the
  same manageability rule. They can control or disrupt a higher identity without
  directly editing a role.
- Distinguish disable/enable from delete/restore. Enable may revalidate still-live
  assignments. User deletion tombstones the user and every live assignment in
  one transaction; restore creates only a new mandatory `user` episode and never
  revives former custom-role or `super_admin` authority.
- Bulk relationship endpoints reject duplicate IDs and validate every requested ID
  and indirect effect before writing. One invalid item rejects the whole
  transaction. Binding an existing live relationship and unbinding a pair with no live relation are
  idempotent no-ops, not partial failures. Successful unbind tombstones the live
  episode; later bind inserts a new episode and leaves the tombstone unchanged.

## Super Admin Boundary

Reserve level `1000` for `super_admin` and level `0` for the mandatory `user`;
custom roles use `1..999`, including `500`. No administrator role is seeded.
Runtime strict dominance compares the current user's actual role level with
the target's complete authority, independently of role names.

Keep super-admin grants in an explicit allowlist instead of granting every
permission-catalog row automatically. There is no online handover permission,
route, or independent permission-delegation policy.

The offline operator handover script must atomically create a new `super_admin`
episode for the target, tombstone the former holder's live episode, preserve both users' `user` assignment,
and write the allowed audit. There must be exactly one live active holder after
a successful transaction. No administrator can invoke this operation over HTTP.

A deferred PostgreSQL constraint enforces exactly one live holder whenever a
`super_admin` assignment changes. It permits the first offline bootstrap and a
single-transaction offline handover, while rejecting a final-holder tombstone or a
second live holder. There is no legacy `owner` system-role alias or migration
compatibility rule in this fresh baseline; `owner` remains available as an
ordinary custom-role key and receives no special authority.

The user must initialize the first holder by personally operating PostgreSQL
from a trusted host after preparing their schema and initial roles. First
create or register the intended account through the normal trusted identity
flow so it already exists, is active, and holds the mandatory `user` role.
The user then prepares, reviews and executes their own offline transaction
using immutable `users.user_id`, following the contract below. Do not generate,
copy or execute bootstrap SQL as part of a new-project deliverable.

Do not ask an agent or an HTTP endpoint to choose the first holder, do not
auto-promote the first registrant, and do not improvise a bare `INSERT` into
`user_roles`. That user-owned transaction locks the global authorization guard first, verifies
the existing user and migration-owned role/grant shapes, binds only the
pre-seeded `super_admin`, and writes audit in the same
PostgreSQL transaction. It never creates the identity or changes its password,
Token version, or protected flag. Re-running it for the same holder is
idempotent; naming a deleted or different holder after bootstrap is refused and
rolled back. It accepts only immutable `users.user_id`, never a username. For a later
holder change, the user prepares their own guarded transaction from the same
trusted host, supplying both immutable old and new user IDs after operator
verification. It checks sole ownership and eligibility, swaps the relation in one guarded
transaction and audits.
Retained asset SQL illustrates historical maintenance behavior only; it is not
exported into a new project or executed by the ordinary Skill workflow.

## Transaction And Concurrency Boundary

Follow [atomic authorization consistency](atomic-consistency.md) for transaction
ownership, lock order, authoritative reload, affected-set validation, audit
outcomes, and external effects.

For hierarchy decisions, include the current user, direct target, and every user whose
retained assignment changes the result, including suspended users. Calculate
their complete before/after snapshots inside the transaction. Bulk operations
are all-or-nothing. For a shared role with many assignees, use an indexed impact
query while holding the global authorization guard; cost does not justify
omitting impact analysis.

Require a nonnegative body `expected_version` for custom-role update, lifecycle,
deletion, and permission commands. Require a strict JSON integer and
check it only after locks, reload, and the complete authorization and hierarchy
decision. Missing or malformed input returns `42201`; an unauthorized stale
attempt still returns `40301`; an authorized stale value returns HTTP `409` with
business code `40931`; and another client-visible state conflict uses `40901`.
User-role bind/unbind remains an incremental, idempotent transaction without a
user version; unbind tombstones the live episode, and a later bind creates a new
episode. Under the global guard, binding checks the complete proposed live set
and returns the ordinary state conflict when it would exceed 10. The mandatory
`user` and any `super_admin` assignment count, disabled roles still count, and
tombstones do not count. This does not relax its post-lock authority and
affected-user checks. PostgreSQL independently enforces the final total so direct
and concurrent writers cannot bypass the service decision.

For user-role bind/unbind, user disable/enable, and any other administrative
write returning user data, build an immutable, current user-filtered response snapshot
inside this same transaction while the global, user, role, and relation locks
are still held. Return that snapshot only after commit succeeds. Never commit and
then use a request-scoped or new `Session` to reconstruct `bound_role_ids`,
status, or authority: a concurrent change after lock release could otherwise
mix a newer nested collection with the command's older result or turn a committed
success into a later read failure.
Follow [API response standard](api-response-standard.md).

## Errors And Audit

- A caller missing the operation capability receives `40301` before target
  existence, visibility, or version checks.
- After the capability recheck, a missing or concealed self, peer, higher, or
  protected user or role returns `40401`; the same rule covers every role ID in
  a bind or unbind request.
- A visible target that fails granted-permission, affected-user, system-role,
  self-elevation, or another operation-specific rule returns `40301`.
- Use the neutral numeric public business code `40301`; do not reveal RBAC as
  the implementation mechanism through paths, public schemas, or errors.
- Do not reveal the target's role level, protection, assigned roles, or missing
  grantable permission in external errors.
- Audit allowed and denied high-risk administration with current user, target,
  operation, reason code, request ID, and timestamp. Include safe before/after
  summaries when available. Never log credentials, tokens, or secrets.

## Required Test Matrix

| Current user and operation | Expected result |
| --- | --- |
| Authenticated `user` calls any administration endpoint | Deny |
| Custom administrator manages a lower user or custom role with permissions it holds | Allow |
| Custom administrator deletes a manageable role with `roles:delete` | Allow |
| Custom administrator edits a system role or attempts online super-admin transfer | Deny |
| Lower current user modifies, suspends, resets, impersonates, or revokes a higher target | Deny |
| Peer current user modifies an equal-level target | Deny |
| An apparently ordinary target also holds a peer or higher role | Deny using the complete snapshot |
| Current user assigns a role at or above its own role level | Deny |
| Current user grants a permission it does not hold | Deny |
| Current user grants a role, higher role level, or `super_admin` status to itself | Deny |
| Current user edits a shared role it holds | Deny; use dedicated self-reduction for a reduction |
| Current user edits a shared role affecting an unmanageable user | Deny atomically |
| Suspended higher user retains the affected shared role | Deny or revalidate safely before reactivation |
| Any current user disables, deletes, or changes grants on a system role | Deny |
| Ordinary bind attempts `super_admin`, or any unbind attempts `user` | Deny |
| A user has 9 live bindings and receives one new manageable role | Allow; final count is 10 |
| A user already has 10 live bindings and receives another role | Reject atomically as a state conflict |
| A full user repeats a bind for an already-live pair | Idempotent success; count remains 10 |
| A disabled role remains bound | It still consumes one of the 10 slots |
| A role assignment is tombstoned, then a new role is bound | Tombstone does not count; new episode may use the freed slot |
| Runtime unbind targets a live relation | Tombstone the episode; never physically delete it |
| Authorized rebind follows a historical tombstone | Create a new live episode with a new ID |
| User is restored after soft deletion | Restore only the identity plus a new `user` episode; no old privilege |
| Bulk request contains one peer, higher, unknown, or protected target | Deny atomically |
| Missing or malformed `expected_version` | Reject as `42201` before service mutation |
| Unauthorized operation with stale `expected_version` | Reject as `40301` without revealing version state |
| Stale `expected_version` reaches the locked comparison | Reject as `40931` without mutation |

Run the deterministic concurrency and rollback matrix in
[atomic authorization consistency](atomic-consistency.md), including current user
demotion or disablement, target promotion, concurrent role assignment,
concurrent attempts to claim the tenth role slot,
concurrent super-admin changes, and both valid commit orders. Keep direct
self-grant, two-step create-and-assign, alternate API, bulk, and background-job
variants in the suite.
