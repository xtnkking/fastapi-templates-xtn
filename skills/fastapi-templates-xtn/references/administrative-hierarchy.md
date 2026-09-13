# Administrative Hierarchy And Anti-Escalation

Read this reference when an actor can assign roles, edit roles, manage users,
change the sole super administrator, reset authentication factors, revoke
Access Tokens, impersonate another identity, or otherwise change another principal's
authority.

Requiring an administrative permission is only the first check. The actor must
also be allowed to manage the target, the proposed result, and every user
indirectly affected by the change.

The complete PostgreSQL example implements these rules in
[`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) and
[`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py), including
user and custom-role lifecycle, immutable system roles, and the super-admin
delegation and transfer boundary.

When the task includes login identifiers, user deletion/restoration, or relation
storage, also read
[Identity and soft-delete lifecycle](identity-soft-delete.md). Greenfield work
must ask which email/`user_name` fields `users` stores and separately settle the
login-input contract; existing work preserves it unless a
change is requested.

## Model Authority Explicitly

Do not infer rank from display names or database row IDs. The fixed system-role
keys are invariants, but authorization decisions still use the complete
authority model:

- `effective_permissions`: capabilities the user can exercise now;
- `delegable_permissions`: capabilities the user may grant to others;
- `management_tier`: a server-controlled rank; larger values are higher;
- `protected_identity` and `protected_role`: the current `super_admin`,
  break-glass subjects, or other authority excluded from ordinary management;
- `system_role`: an application-defined role whose shape and grants cannot be
  changed through runtime administration.

Calculate permissions and tier only through live assignment and permission-grant
episodes on active, non-deleted users and roles. Never inspect only a
`primary_role`, count a tombstoned relation, compare permission counts, or assume
that a familiar custom-role name dominates another role.

This baseline uses one application-wide hierarchy. If product resources need
department, project, ownership, or other row-level boundaries, model and test
those separately. A high tier never bypasses an independent resource policy.

By default, `delegable_permissions` is a subset of effective permissions. Any
exception must be explicit and must never permit direct or indirect self-grant.

## Fixed System Roles

Seed these roles before provisioning users:

| Role | Tier | Required behavior |
| --- | ---: | --- |
| `super_admin` | `1000` | System, protected, active; exactly one current holder after bootstrap |
| `admin` | `500` | System and active; manages only strictly lower custom roles and users within its delegation ceiling |
| `user` | `0` | System and active; mandatory base role with no authorization-management capability |

The three roles cannot be disabled, soft-deleted, renamed, re-ranked, or have
their permission/delegation grants changed through a public API. This restriction
also applies to `super_admin`; the super administrator controls assignments and
custom roles, not the definition of the three system roles. A reviewed migration
is the only way to change a system-role specification.

Every normal signup or trusted user-creation path binds `user` in the same
transaction as user creation using a new live relation episode. Never accept a requested initial role at signup,
never remove `user` through the unbind endpoint, and keep it when adding `admin`
or `super_admin`.

The seeded `admin` has an intentionally incomplete capability set. It may read
permissions and roles; create, update, enable, disable, and change permissions on
manageable custom roles; assign and revoke manageable roles; and read or update
manageable users. It cannot soft-delete roles, change delegation policy, mutate
system roles, or transfer `super_admin`. Strict tier comparison also prevents
one `admin` from managing another `admin`.

## Default Manageability Rule

For an identity- or authorization-changing operation, allow only when all
applicable conditions are true:

1. The actor is active and has the exact capability, such as `roles:assign`,
   `roles:revoke`, `roles:permissions:bind`,
   `roles:permissions:unbind`, `roles:status:update`,
   `users:status:update`, `tokens:revoke`, or
   `identities:impersonate`.
2. Neither the target nor an affected role is protected, and no proposed role
   definition changes an immutable system role.
3. The actor's current tier is strictly greater than the target's current tier,
   the target's proposed tier, and every assigned, proposed, or changed role
   tier. Peer, higher, and otherwise incomparable changes are denied.
4. The target's current and proposed permissions are subsets of the actor's
   explicit delegable permissions.
5. The change does not increase the actor's own effective permissions, delegable
   permissions, tier, `super_admin` status, protected status, impersonation
   reach, or other authorization power.
6. Mandatory-`user`, sole-`super_admin`, separation-of-duties, approval,
   soft-delete, and protected-role invariants still hold after the complete
   proposed change.

An ordinary permission such as `roles:assign` satisfies only condition 1. It is
not a bypass for the remaining checks. Equal-tier administration requires a
separate explicit policy and must still forbid self-elevation; it is not part of
this baseline.

## Administrative Read Visibility

Having `users:read` or `roles:read` is necessary but not sufficient to reveal an
administrative object. The baseline read policy is:

- the current `super_admin` may list and inspect every non-deleted user and role;
- every other administrator may see only roles and users with effective tier
  strictly lower than the actor's tier;
- the ordinary administrator does not see itself, a peer, a higher target, or a
  protected target through administration endpoints; and
- the actor reads its own current permissions through `/api/v1/me/access`.

Use the same SQL visibility predicate for list, count, search, export, nested
reads, and detail. A hidden detail returns the same generic `404001` as an
unknown ID. Do not fetch all rows and filter them in Python, and do not issue one
authority query per result row. Batch-load role grants and user authority for
the selected page. Permission-catalog reads reveal the stable action vocabulary,
not which hidden user or role holds those permissions.

Apply that predicate inside each returned user representation too. Embedded
collections such as `assigned_role_ids` contain only roles visible to the
current actor: `super_admin` may receive every live, non-deleted assignment,
while every other administrator receives only strictly lower, non-protected
roles it may inspect. A disabled peer or higher role must not leak merely because
its assignment is still live. Keep the complete unfiltered assignment set for
server-side authorization and audit decisions; filter only the public projection.

### Administrative Write Visibility

Use the same visibility boundary for administrative writes, but preserve the
authorization order. First reload the actor under the global guard and check the
exact operation capability. A caller without that capability receives `403001`
before the service reveals whether any target exists. Only then evaluate the
locked target's existence and visibility: an ordinary administrator's self,
peer, higher, or protected user or role is concealed with the same `404001` as
an unknown ID.
For user-role bind or unbind, apply that check to the target user and separately
to every requested role ID; one hidden or unknown role makes the whole atomic
request return `404001`.

After a target passes visibility, run delegation, affected-user, system-role,
self-elevation, and operation-specific policy. A visible target that fails one
of those checks returns `403001`. Keep these stages distinct so `404001` does not
become a general substitute for authorization denial and `403001` does not leak
hidden administrative objects.

## Direct And Indirect Self-Elevation

Deny a request whose direct target is the actor when it grants a role,
permission, tier, `super_admin` status, delegable capability, protected status,
or impersonation capability. Detect indirect effects too:

- editing a role currently assigned to the actor;
- creating a role and then assigning it to the actor;
- changing a role template, permission catalog, group, or inheritance edge that
  contributes to the actor's authority;
- modifying a shared role whose change expands the actor's permissions;
- changing the super-admin assignment or delegation policy so the actor can grant
  itself authority later;
- using a bulk endpoint, background job, alternate route, or service API to
  perform the same effect indirectly.

For every authorization mutation, compute the actor's complete authority before
and after the proposed change inside the authoritative transaction. The after
permissions and delegable set must contain no new element, and the tier must not
increase. Checking only `actor.id != target.id` is insufficient.

A dedicated self-service endpoint may let a user remove a non-mandatory role or
reduce its own authority. It cannot add or exchange authority, cannot remove
`user` or the final `super_admin`, and should require recent authentication for
sensitive changes. This is not a substitute for the administrative unbind
endpoint's no-self-target rule.

## Role And User Operations

- Role assignment checks both the target user and every assigned role. The actor
  must dominate the target's complete current and proposed authority. The
  proposal must also leave the target with at most 10 live role bindings.
- Ordinary role binding never grants `super_admin`; only the dedicated atomic
  `super_admin` transfer command changes that assignment. Only `super_admin` can
  bind or unbind `admin`, and no actor can unbind `user`.
- Role creation checks the proposed tier and starts with no permissions.
  Permission binding is a separate capability and transaction.
- Role information update changes only explicitly mutable custom-role fields.
  System keys, tiers, flags, lifecycle fields, permissions, and delegation never
  enter an ordinary update body.
- Permission bind and unbind check the complete resulting role and every live
  direct or indirect assignee. They reject an actor-held role, a permission
  outside the actor's delegable set, and any affected protected, peer, or higher
  user.
- Disabling, enabling, or deleting a shared custom role affects every live
  assignment that could become effective now or after user reactivation.
  Do not ignore suspended users. Enabling revalidates live assignments; soft
  delete is terminal, immediately removes the role from effective authority,
  atomically tombstones every live grant and assignment, and permanently
  reserves its key.
- User profile or login-identifier changes, suspension, deletion, credential or
  MFA reset, Token revocation, super-admin transfer, and impersonation use the
  same manageability rule. They can control or disrupt a higher identity without
  directly editing a role.
- Distinguish disable/enable from delete/restore. Enable may revalidate still-live
  assignments. User deletion tombstones the user and every live assignment in
  one transaction; restore creates only a new mandatory `user` episode and never
  revives former custom, `admin`, or `super_admin` authority.
- Bulk relationship endpoints reject duplicate IDs and validate every requested ID
  and indirect effect before writing. One invalid item rejects the whole
  transaction. Binding an existing live relationship and unbinding a pair with no live relation are
  idempotent no-ops, not partial failures. Successful unbind tombstones the live
  episode; later bind inserts a new episode and leaves the tombstone unchanged.

## Super Admin Boundary

Reserve tier `1000` for `super_admin`; reserve tier `500` for `admin`; use tier
`0` for the mandatory `user`; custom roles use `1..999`. Runtime strict
dominance means the seeded `admin` can manage only custom roles below `500`.

Keep super-admin grants in an explicit allowlist instead of granting every
permission-catalog row automatically. `roles:delegation:update` and
`super_admin:transfer` are never delegable. Both delegation changes and
`super_admin` transfer require the current `super_admin` identity after canonical
locks and authoritative reload, not merely possession of a permission key.

Transfer must atomically create a new `super_admin` episode for the target,
tombstone the actor's live episode, preserve both users' `user` assignment,
update both users' authorization versions and the global authorization epoch,
and write the allowed audit. There must be exactly one live active holder after
a successful transaction.

A deferred PostgreSQL constraint enforces exactly one live holder whenever a
`super_admin` assignment changes. It permits the first offline bootstrap and a
single-transaction transfer, while rejecting a final-holder tombstone or a
second live holder. There is no legacy `owner` system-role alias or migration
compatibility rule in this fresh baseline; `owner` remains available as an
ordinary custom-role key and receives no special authority.

The user must initialize the first holder by personally operating PostgreSQL
from a trusted host. First create or register the intended account through the
normal trusted identity flow so it already exists, is active, and holds the
mandatory `user` role. Then run the supplied transaction script:

```powershell
$env:PSQL_DATABASE_URL = "postgresql://app_user:password@db.example/app"
psql $env:PSQL_DATABASE_URL `
  --set=super_admin_user_id=9bb60ae3-cad9-4e07-b072-7f4336044f18 `
  --file sql/bootstrap_super_admin.sql
```

Do not ask an agent or an HTTP endpoint to choose the first holder, do not
auto-promote the first registrant, and do not improvise a bare `INSERT` into
`user_roles`. The script locks the global authorization guard first, verifies
the existing user and migration-owned role/grant shapes, binds only the
pre-seeded `super_admin`, increments the user's authorization version and the
global epoch only when the binding changes, and writes audit in the same
PostgreSQL transaction. It never creates the identity or changes its password,
Token version, or protected flag. Re-running it for the same holder is
idempotent; naming a deleted or different holder after bootstrap is refused and
rolled back. It accepts only immutable `users.id`, never email or `user_name`.

## Transaction And Concurrency Boundary

Follow [atomic authorization consistency](atomic-consistency.md) for transaction
ownership, lock order, authoritative reload, affected-set validation, audit
outcomes, and external effects.

For hierarchy decisions, include the actor, direct target, and every user whose
retained assignment changes the result, including suspended users. Calculate
their complete before/after snapshots inside the transaction. Bulk operations
are all-or-nothing. For a shared role with many assignees, use an indexed impact
query while holding the global authorization guard; cost does not justify
omitting impact analysis.

Require a nonnegative body `expected_version` for custom-role update, lifecycle,
deletion, permission, and delegation commands. Require a strict JSON integer and
check it only after locks, reload, and the complete authorization and hierarchy
decision. Missing or malformed input returns `422001`; an unauthorized stale
attempt still returns `403001`; an authorized stale value returns HTTP `409` with
business code `409002`; and another client-visible state conflict uses `409001`.
User-role bind/unbind remains an incremental, idempotent transaction without a
user version; unbind tombstones the live episode, and a later bind creates a new
episode. Under the global guard, binding checks the complete proposed live set
and returns the ordinary state conflict when it would exceed 10. The mandatory
`user` and any `super_admin` assignment count, disabled roles still count, and
tombstones do not count. This does not relax its post-lock authority and
affected-user checks. PostgreSQL independently enforces the final total so direct
and concurrent writers cannot bypass the service decision.

For user-role bind/unbind, user disable/enable, and any other administrative
write returning user data, build an immutable, actor-filtered response snapshot
inside this same transaction while the global, user, role, and relation locks
are still held. Return that snapshot only after commit succeeds. Never commit and
then use a request-scoped or new `Session` to reconstruct `assigned_role_ids`,
status, or authority: a concurrent change after lock release could otherwise
mix a newer nested collection with the command's older result or turn a committed
success into a later read failure.
Follow [API response standard](api-response-standard.md).

## Break-Glass Access

Do not express emergency elevation as a normal high-tier role assignment. Use a
separate time-limited path with strong reauthentication, explicit reason,
approval when required, narrow effects, automatic expiry, Token revocation,
and high-priority audit or alerting. An `admin` cannot grant, renew, or conceal
break-glass access.

## Errors And Audit

- A caller missing the operation capability receives `403001` before target
  existence, visibility, or version checks.
- After the capability recheck, a missing or concealed self, peer, higher, or
  protected user or role returns `404001`; the same rule covers every role ID in
  a bind or unbind request.
- A visible target that fails delegation, affected-user, system-role,
  self-elevation, or another operation-specific rule returns `403001`.
- Use the neutral numeric public business code `403001`; do not reveal RBAC as
  the implementation mechanism through paths, OpenAPI metadata, or errors.
- Do not reveal the target's tier, protection, assigned roles, or missing
  delegable permission in external errors.
- Audit allowed and denied high-risk administration with actor, target,
  operation, reason code, request ID, and timestamp. Include safe before/after
  summaries when available. Never log credentials, tokens, or secrets.

## Required Test Matrix

| Actor and operation | Expected result |
| --- | --- |
| Authenticated `user` calls any administration endpoint | Deny |
| `admin` manages a lower user or custom role within delegation | Allow |
| `admin` deletes a role, edits a system role, changes delegation, or transfers `super_admin` | Deny |
| Lower actor modifies, suspends, resets, impersonates, or revokes a higher target | Deny |
| Peer actor modifies an equal-tier target | Deny |
| An apparently ordinary target also holds a peer or higher role | Deny using the complete snapshot |
| Actor assigns a role at or above its own tier | Deny |
| Actor grants a permission outside its delegable set | Deny |
| Actor grants a role, tier, `super_admin` status, or delegation to itself | Deny |
| Actor edits a shared role it holds | Deny; use dedicated self-reduction for a reduction |
| Actor edits a shared role affecting an unmanageable user | Deny atomically |
| Suspended higher user retains the affected shared role | Deny or revalidate safely before reactivation |
| Any actor disables, deletes, or changes grants on a system role | Deny |
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
| Missing or malformed `expected_version` | Reject as `422001` before service mutation |
| Unauthorized operation with stale `expected_version` | Reject as `403001` without revealing version state |
| Stale `expected_version` reaches the locked comparison | Reject as `409002` without mutation |

Run the deterministic concurrency and rollback matrix in
[atomic authorization consistency](atomic-consistency.md), including actor
demotion or disablement, target promotion, concurrent role assignment,
concurrent attempts to claim the tenth role slot,
concurrent super-admin changes, and both valid commit orders. Keep direct
self-grant, two-step create-and-assign, alternate API, bulk, and background-job
variants in the suite.
