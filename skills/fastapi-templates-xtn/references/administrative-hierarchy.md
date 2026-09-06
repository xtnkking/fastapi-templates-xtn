# Administrative Hierarchy And Anti-Escalation

Read this reference when an actor can assign roles, edit roles, manage users,
change system ownership, reset authentication factors, revoke sessions,
impersonate another identity, or otherwise change another principal's authority.

Requiring an administrative permission is only the first check. The actor must
also be allowed to manage the target, the proposed result, and every user
indirectly affected by the change.

The complete PostgreSQL example implements these rules in
[`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) and
[`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py), including
user suspension/reactivation and the system Owner delegation control plane.

## Model Authority Explicitly

Do not compare display names such as `admin`, `editor`, or `user`, and do not use
database row IDs as rank. Define:

- `effective_permissions`: capabilities the user can exercise now;
- `delegable_permissions`: capabilities the user may grant to others;
- `management_tier`: a server-controlled rank; this baseline makes larger values
  higher;
- `protected_identity` and `protected_role`: system, break-glass, or other
  subjects excluded from ordinary administration.

Calculate permissions and tier from every active assigned role. Never inspect
only a `primary_role`, compare the number of permissions, or assume that one
familiar role name dominates another.

This baseline uses one application-wide hierarchy. If product resources need
department, project, ownership, or other row-level boundaries, model and test
those separately. A high tier never bypasses an independent resource policy.

By default, `delegable_permissions` is a subset of effective permissions. Any
exception must be explicit and must never permit direct or indirect self-grant.

## Default Manageability Rule

For an identity- or authorization-changing operation, allow only when all
applicable conditions are true:

1. The actor is active and has the exact capability, such as `roles:assign`,
   `roles:permissions:update`, `users:status:update`, `sessions:revoke`, or
   `identities:impersonate`.
2. Neither the target nor an affected role is protected from this control plane.
3. The actor's current tier is strictly greater than the target's current tier,
   the target's proposed tier, and every assigned or proposed role tier. Peer,
   higher, and otherwise incomparable changes are denied.
4. The target's current and proposed permissions are subsets of the actor's
   explicit delegable permissions.
5. The change does not increase the actor's own effective permissions, delegable
   permissions, tier, ownership, protected status, impersonation reach, or other
   authorization power.
6. Final-Owner, separation-of-duties, approval, and protected-role invariants
   still hold after the complete proposed change.

An ordinary permission such as `roles:assign` satisfies only condition 1. It is
not a bypass for the remaining checks. Equal-tier administration requires a
separate explicit policy and must still forbid self-elevation; it is not part of
this baseline.

## Direct And Indirect Self-Elevation

Deny a request whose direct target is the actor when it grants a role,
permission, tier, ownership flag, delegable capability, protected flag, or
impersonation capability. Detect indirect effects too:

- editing a role currently assigned to the actor;
- creating a role and then assigning it to the actor;
- changing a role template, permission catalog, group, or inheritance edge that
  contributes to the actor's authority;
- modifying a shared role whose change expands the actor's permissions;
- changing system ownership or delegation policy so the actor can grant itself
  authority later;
- using a bulk endpoint, background job, alternate route, or service API to
  perform the same effect indirectly.

For every authorization mutation, compute the actor's complete authority before
and after the proposed change inside the authoritative transaction. The after
permissions and delegable set must contain no new element, and the tier must not
increase. Checking only `actor.id != target.id` is insufficient.

A dedicated self-service endpoint may let a user remove one of its own roles or
reduce its own authority. It cannot add or exchange authority, must preserve the
final Owner, and should require recent authentication for sensitive changes.

## Role And User Operations

- Role assignment checks both the target user and assigned role. The actor must
  dominate the target's current and proposed authority.
- Role creation and permission replacement check the proposed tier and full
  permission set against the actor's delegable authority.
- Changing or deleting a shared role affects every retained direct or indirect
  assignment that could become active now or after user reactivation. Deny the
  whole operation if any affected user is the actor, a peer, higher authority,
  protected, or outside the actor's delegation ceiling. Do not ignore a suspended
  user retaining the role. Reactivation must revalidate retained roles if dormant
  assignments are deliberately excluded from impact analysis.
- User profile or login-identifier changes, suspension, deletion, credential or
  MFA reset, session revocation, ownership transfer, and impersonation use the
  same manageability rule. They can control or disrupt a higher identity without
  directly editing a role.
- Bulk operations validate every target and indirect effect before writing.
  Default to one atomic rejection instead of a partial update.
- System Owner operations are a separate trust boundary. Ordinary administrator
  tiers never authorize them implicitly.

## System Owner

Reserve tier `1000` for the protected system Owner role; ordinary roles use
`0..999`. Keep Owner grants in an explicit allowlist instead of granting every
permission catalog row automatically.

Only the current Owner may change delegation policy or transfer system ownership.
`roles:delegation:update` and `system_owner:transfer` are never delegable. Transfer
must atomically assign the Owner role to the target, remove it from the actor,
update both users' authorization versions and the global authorization epoch, and
write the allowed audit. There must always be exactly one active Owner after a
successful administrative transaction.

Bootstrap the first Owner through an explicit one-time operation that fails once
an Owner exists. Do not promote the first registered user implicitly.

## Transaction And Concurrency Boundary

Follow [atomic authorization consistency](atomic-consistency.md) for transaction
ownership, lock order, authoritative reload, affected-set validation, audit outcomes,
and external effects.

For hierarchy decisions, include the actor, direct target, and every user whose
retained assignment changes the result, including suspended users. Calculate
their complete before/after snapshots inside the transaction. Bulk operations
are all-or-nothing. For a shared role with many assignees, use an indexed impact
query while holding the global authorization guard; cost does not justify
omitting impact analysis.

## Break-Glass Access

Do not express emergency elevation as a normal high-tier role assignment. Use a
separate time-limited path with strong reauthentication, explicit reason,
approval when required, narrow effects, automatic expiry, session revocation,
and high-priority audit or alerting. Ordinary administrators cannot grant, renew,
or conceal break-glass access.

## Errors And Audit

- Return `404` for a missing or deliberately hidden identity and `403` for a
  visible target that the actor cannot manage.
- Do not reveal the target's tier, protection, assigned roles, or missing
  delegable permission in external errors.
- Audit allowed and denied high-risk administration with actor, target,
  operation, reason code, request ID, and timestamp. Include safe before/after
  summaries when available. Never log credentials, tokens, or secrets.

## Required Test Matrix

| Actor and operation | Expected result |
| --- | --- |
| Higher actor manages a lower target within delegation | Allow |
| Lower actor modifies, suspends, resets, impersonates, or revokes a higher target | Deny |
| Peer actor modifies an equal-tier target | Deny |
| An apparently ordinary target also holds a peer or higher role | Deny using the complete snapshot |
| Actor assigns a role at or above its own tier | Deny |
| Actor grants a permission outside its delegable set | Deny |
| Actor grants a role, tier, ownership, or delegation to itself | Deny |
| Actor edits a shared role it holds | Deny; use dedicated self-reduction for a reduction |
| Actor edits a shared role affecting an unmanageable user | Deny atomically |
| Suspended higher user retains the affected shared role | Deny or revalidate safely before reactivation |
| Bulk request contains one peer or higher target | Deny atomically |
| Dedicated self-service operation only removes authority | Allow unless another invariant fails |
| Ordinary administrator attempts to grant break-glass access | Deny |

Run the deterministic concurrency and rollback matrix in
[atomic authorization consistency](atomic-consistency.md), including actor
demotion or disablement, target promotion, concurrent role assignment, concurrent
Owner changes, and both valid commit orders. Keep direct self-grant, two-step
create-and-assign, alternate API, bulk, and background-job variants in the suite.
