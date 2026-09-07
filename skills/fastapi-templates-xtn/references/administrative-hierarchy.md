# Administrative Hierarchy And Anti-Escalation

Read this reference when an actor can assign roles, edit roles, manage users,
change the sole super administrator, reset authentication factors, revoke
sessions, impersonate another identity, or otherwise change another principal's
authority.

Requiring an administrative permission is only the first check. The actor must
also be allowed to manage the target, the proposed result, and every user
indirectly affected by the change.

The complete PostgreSQL example implements these rules in
[`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) and
[`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py), including
user and custom-role lifecycle, immutable system roles, and the super-admin
delegation and transfer boundary.

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

Calculate permissions and tier from every active, non-deleted assigned role.
Never inspect only a `primary_role`, compare permission counts, or assume that a
familiar custom-role name dominates another role.

This baseline uses one application-wide hierarchy. If product resources need
department, project, ownership, or other row-level boundaries, model and test
those separately. A high tier never bypasses an independent resource policy.

By default, `delegable_permissions` is a subset of effective permissions. Any
exception must be explicit and must never permit direct or indirect self-grant.

## Fixed System Roles

Seed these roles before provisioning users:

| Role | Tier | Required behavior |
| --- | ---: | --- |
| `super_admin` | `1000` | System, protected, owner, active; exactly one current holder after bootstrap |
| `admin` | `500` | System and active; manages only strictly lower custom roles and users within its delegation ceiling |
| `user` | `0` | System and active; mandatory base role with no authorization-management capability |

The three roles cannot be disabled, soft-deleted, renamed, re-ranked, or have
their permission/delegation grants changed through a public API. This restriction
also applies to `super_admin`; the super administrator controls assignments and
custom roles, not the definition of the three system roles. A reviewed migration
is the only way to change a system-role specification.

Every normal signup or trusted user-creation path binds `user` in the same
transaction as user creation. Never accept a requested initial role at signup,
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
   `users:status:update`, `sessions:revoke`, or
   `identities:impersonate`.
2. Neither the target nor an affected role is protected, and no proposed role
   definition changes an immutable system role.
3. The actor's current tier is strictly greater than the target's current tier,
   the target's proposed tier, and every assigned, proposed, or changed role
   tier. Peer, higher, and otherwise incomparable changes are denied.
4. The target's current and proposed permissions are subsets of the actor's
   explicit delegable permissions.
5. The change does not increase the actor's own effective permissions, delegable
   permissions, tier, ownership, protected status, impersonation reach, or other
   authorization power.
6. Mandatory-`user`, sole-`super_admin`, separation-of-duties, approval,
   soft-delete, and protected-role invariants still hold after the complete
   proposed change.

An ordinary permission such as `roles:assign` satisfies only condition 1. It is
not a bypass for the remaining checks. Equal-tier administration requires a
separate explicit policy and must still forbid self-elevation; it is not part of
this baseline.

## Direct And Indirect Self-Elevation

Deny a request whose direct target is the actor when it grants a role,
permission, tier, owner status, delegable capability, protected status, or
impersonation capability. Detect indirect effects too:

- editing a role currently assigned to the actor;
- creating a role and then assigning it to the actor;
- changing a role template, permission catalog, group, or inheritance edge that
  contributes to the actor's authority;
- modifying a shared role whose change expands the actor's permissions;
- changing super-admin ownership or delegation policy so the actor can grant
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
  must dominate the target's complete current and proposed authority.
- Ordinary role binding never grants `super_admin`; only the dedicated atomic
  ownership-transfer command changes that assignment. Only `super_admin` can
  bind or unbind `admin`, and no actor can unbind `user`.
- Role creation checks the proposed tier and starts with no permissions.
  Permission binding is a separate capability and transaction.
- Role information update changes only explicitly mutable custom-role fields.
  System keys, tiers, flags, lifecycle fields, permissions, and delegation never
  enter an ordinary update body.
- Permission bind and unbind check the complete resulting role and every retained
  direct or indirect assignee. They reject an actor-held role, a permission
  outside the actor's delegable set, and any affected protected, peer, or higher
  user.
- Disabling, enabling, or deleting a shared custom role affects every retained
  assignment that could become active now or after user reactivation. Do not
  ignore suspended users. Enabling revalidates retained assignments; soft delete
  is terminal, immediately removes the role from effective authority, retains
  grants and assignments for audit, and permanently reserves its key.
- User profile or login-identifier changes, suspension, deletion, credential or
  MFA reset, session revocation, super-admin transfer, and impersonation use the
  same manageability rule. They can control or disrupt a higher identity without
  directly editing a role.
- Bulk relationship endpoints reject duplicate IDs and validate every requested
  ID and indirect effect before writing. One invalid item rejects the whole transaction. Binding an
  existing relationship and unbinding a missing relationship are idempotent
  no-ops, not partial failures.

## Super Admin Boundary

Reserve tier `1000` for `super_admin`; reserve tier `500` for `admin`; use tier
`0` for the mandatory `user`; custom roles use `1..999`. Runtime strict
dominance means the seeded `admin` can manage only custom roles below `500`.

Keep super-admin grants in an explicit allowlist instead of granting every
permission-catalog row automatically. `roles:delegation:update` and
`super_admin:transfer` are never delegable. Both delegation changes and
ownership transfer require the current `super_admin` identity after canonical
locks and authoritative reload, not merely possession of a permission key.

Transfer must atomically assign `super_admin` to the target, remove it from the
actor, preserve both users' `user` assignment, update both users' authorization
versions and the global authorization epoch, and write the allowed audit. There
must be exactly one active holder after a successful transaction.

A deferred PostgreSQL constraint enforces exactly one holder whenever a
`super_admin` assignment changes. It permits the first offline bootstrap and a
single-transaction transfer, while rejecting direct deletion of the final
assignment or addition of a second holder. Keep the historical `owner` role key
reserved for migration compatibility.

Bootstrap the first holder only through the offline command:

```text
python -m app.rbac.bootstrap --super-admin-email admin@example.com
```

The command locks the global authorization guard, creates or loads the intended
active user, ensures `user`, binds the pre-seeded `super_admin`, increments
versions, and writes audit in one PostgreSQL transaction. Do not promote the
first registrant implicitly and do not perform a bare SQL insert into
`user_roles`. Re-running for the same holder is a no-op; naming a different
holder after bootstrap is refused.

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

Require a strong `If-Match` value for custom-role update, lifecycle, deletion,
permission, and delegation commands. Check it after locks and reload. Missing
preconditions return `428`, stale ones return `412`, and exhausted server-side
concurrency retries return `409`. User-role bind/unbind remains an incremental,
idempotent transaction without a user ETag; this does not relax its post-lock
authority and affected-user checks.

## Break-Glass Access

Do not express emergency elevation as a normal high-tier role assignment. Use a
separate time-limited path with strong reauthentication, explicit reason,
approval when required, narrow effects, automatic expiry, session revocation,
and high-priority audit or alerting. An `admin` cannot grant, renew, or conceal
break-glass access.

## Errors And Audit

- Return `404` for a missing or deliberately hidden identity and `403` for a
  visible target that the actor cannot manage.
- Use a neutral public code such as `access_forbidden`; do not reveal RBAC as the
  implementation mechanism through paths, OpenAPI metadata, or errors.
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
| Actor grants a role, tier, ownership, or delegation to itself | Deny |
| Actor edits a shared role it holds | Deny; use dedicated self-reduction for a reduction |
| Actor edits a shared role affecting an unmanageable user | Deny atomically |
| Suspended higher user retains the affected shared role | Deny or revalidate safely before reactivation |
| Any actor disables, deletes, or changes grants on a system role | Deny |
| Ordinary bind attempts `super_admin`, or any unbind attempts `user` | Deny |
| Bulk request contains one peer, higher, unknown, or protected target | Deny atomically |
| Stale or missing required `If-Match` reaches a mutation | Reject with `412` or `428` before mutation |

Run the deterministic concurrency and rollback matrix in
[atomic authorization consistency](atomic-consistency.md), including actor
demotion or disablement, target promotion, concurrent role assignment,
concurrent super-admin changes, and both valid commit orders. Keep direct
self-grant, two-step create-and-assign, alternate API, bulk, and background-job
variants in the suite.
