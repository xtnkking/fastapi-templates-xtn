# Administrative Hierarchy And Anti-Escalation

Read this reference when an actor can assign roles, edit roles, manage identities,
change ownership, reset authentication factors, revoke sessions, impersonate
another identity, or perform any operation that changes another principal's
effective authority.

The goal is not merely to require an administrative permission. The actor must
also be allowed to manage the target, the proposed result, and every principal
indirectly affected by the change.

The complete PostgreSQL example implements these rules in
[`app/rbac/policy.py`](../assets/postgresql-rbac/app/rbac/policy.py) and
[`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py), including
member suspension/reactivation and the Owner-only delegation control plane.

## Model Authority Explicitly

Do not compare display names such as `admin`, `editor`, or `user`, and do not use
database row IDs as rank. Define these concepts explicitly:

- `effective_permissions`: the capabilities the principal can exercise now.
- `delegable_permissions`: capabilities the principal may grant to others.
- `management_scope`: tenants, organizations, resource domains, or organizational
  units within which the principal may administer identities.
- `effective_grants` and `delegable_grants`: inseparable `(permission, scope)`
  pairs when authority is narrower than a whole tenant.
- `management_tier`: an optional server-controlled rank for products with a true
  administrative hierarchy. Define one direction consistently; this reference
  assumes a larger value means higher authority.
- `protected_identity` and `protected_role`: platform, system, break-glass, or
  other subjects excluded from ordinary tenant administration.

Use a tier only when authority is genuinely ordered. Finance and support
permissions, for example, may be incomparable rather than higher or lower. For a
partial order, combine explicit management scopes with delegable permission sets
and a server-controlled `can_manage` relation instead of inventing a misleading
global number. Missing or incomparable relations deny management. If tiers differ
by scope, model `(scope, tier)` pairs or an equivalent relation; never let a high
tier in one scope dominate another scope implicitly.

Calculate effective permissions, scopes, and tier from every active role and any
explicit membership policy. Do not inspect only a `primary_role`, compare the
number of permissions, or assume that one familiar role name dominates another.
When scopes differ, union complete grants instead of separately unioning a
permission set and a scope set. Independent unions create an unintended Cartesian
product, such as combining a permission from one role with a scope from another.

By default, `delegable_permissions` is a subset of the actor's effective
permissions. A product may intentionally let a help-desk actor delegate a
capability it cannot exercise, but that exception must be explicit and must never
permit direct or indirect self-grant.
For scoped authorization, the corresponding default is
`delegable_grants <= effective_grants`, comparing complete permission-scope pairs.

## Default Manageability Rule

For an identity- or authorization-changing administration operation, allow only
when all applicable conditions are true:

1. The actor is active and has the exact capability for the operation, such as
   `roles:assign`, `roles:permissions:update`, `memberships:suspend`,
   `sessions:revoke`, or `identities:impersonate`.
2. Actor and target are in the same authorized tenant or management scope. A
   cross-tenant target is not made manageable by a high numeric tier.
3. Neither the target nor the affected role is protected from this control plane.
4. The configured management relation says the actor strictly dominates the
   target's current and proposed authority. If tiers apply, the actor's current
   tier is strictly greater than the target's current tier, the target's proposed
   tier, and every assigned or proposed role tier. For a partial order, an
   explicit `can_manage` relation must cover the relevant scope. Peer, higher, and
   incomparable authority changes are denied by default.
5. The target's current and proposed authorization-relevant permissions are
   within the actor's explicit delegable set. The proposed scopes are within the
   actor's management scope. When scopes are granular, compare complete
   `(permission, scope)` grants against the actor's delegable grants rather than
   comparing the two dimensions independently.
6. The change does not increase the actor's own effective permissions, delegable
   permissions, management tier, management scope, ownership, protected status,
   impersonation reach, or other authorization power.
7. Last-owner, separation-of-duties, approval, and protected-role invariants still
   hold after the complete proposed change.

An ordinary permission such as `roles:assign` satisfies only condition 1. It is
not a bypass for the remaining manageability rules. Equal-tier administration or
peer management requires a separate, explicit policy and must still forbid
self-elevation.

## Direct And Indirect Self-Elevation

Deny a request whose direct target is the actor when it grants a role, permission,
tier, scope, ownership flag, delegable capability, protected flag, or
impersonation capability. Detect indirect effects as well:

- editing a role currently assigned to the actor;
- creating a role and then assigning it to the actor;
- changing a role template, permission catalog, group, or inheritance edge that
  contributes to the actor's effective authority;
- modifying a shared role whose change expands the actor's permissions;
- changing tenant ownership, delegation policy, or management scope so the actor
  becomes able to grant itself authority later;
- using a bulk endpoint, background job, alternate tenant context, or service API
  to perform the same operation indirectly.

For every authorization mutation, compute the actor's authority snapshot before
and after the full proposed change. The post-change effective-permission,
delegable-permission, scoped-grant, and scope sets must not contain any new
element, and the post-change tier must not be higher. Checking only
`actor.id != target.id` is insufficient.

A dedicated self-service endpoint may allow a user to remove its own role or
reduce its own authority. It must not add or exchange authority, must obey the
last-owner rule, and should require recent authentication for sensitive changes.

## Role And Identity Operations

- Role assignment checks both the target membership and the assigned role. The
  actor must dominate the target's current and proposed authority.
- Role creation and permission replacement check the proposed role tier, scopes,
  and full permission set against the actor's delegable authority.
- Changing or deleting a shared role affects every retained direct or indirect
  assignment that can become effective now or after reactivation. Deny the
  ordinary administration operation if any such principal is the actor, a peer,
  higher authority, incomparable authority, protected identity, or outside the
  actor's scope. Do not ignore a suspended membership that still retains the
  role. If the product deliberately excludes dormant assignments from impact
  analysis, reactivation must revalidate or replace every retained role before it
  becomes effective. Self-reduction belongs in the dedicated self-service path.
  Clone a role for the manageable population instead of weakening this rule.
- Identity profile or login-identifier changes, suspension, deletion, credential
  or MFA reset, session revocation, ownership transfer, and impersonation use the
  same manageability rule. These operations can control or disrupt a higher
  identity even when they do not edit a role.
- Bulk operations validate every target and every indirect effect before writing.
  Default to one atomic rejection rather than silently applying only the allowed
  subset.
- Platform administration and tenant administration are separate trust domains.
  A tenant tier never authorizes a platform-level mutation.

## Transaction And Concurrency Boundary

Follow [atomic authorization consistency](atomic-consistency.md) for the
transaction owner, canonical lock order, authoritative reload, affected-set
retry, audit outcomes, and external effects.

For hierarchy decisions, the affected set must include the actor, direct target,
and every principal whose retained direct or indirect assignment changes the
result, including suspended memberships. Calculate their complete before and
after authority snapshots inside the authoritative transaction. Bulk operations
are all-or-nothing. For a shared role with many assignees, use an indexed impact
query under the tenant authorization guard; cost is not a reason to omit impact
analysis.

## Break-Glass Access

Do not express emergency elevation as a normal high-tier role assignment. Use a
separate, time-limited path with strong re-authentication, explicit reason,
approval when required, narrow scope, automatic expiry, session revocation, and
high-priority audit or alerting. Normal tenant administrators cannot grant,
renew, or conceal break-glass access.

## Errors And Audit

- Return `404` for a cross-tenant or deliberately hidden identity. Return `403`
  for a visible target that the actor is not permitted to manage.
- Do not reveal the target's tier, protected status, role membership, or missing
  delegable permission in an external error message.
- Audit allowed and denied high-risk administration with actor, target, tenant,
  operation, decision reason code, request ID, and timestamp. Include safe before
  and after summaries when the authoritative decision produced them; a rejected
  request may have no safe post-state. Do not log credentials, tokens, or secrets.

## Required Test Matrix

| Actor and operation | Expected result |
| --- | --- |
| Higher actor manages lower target within scope and delegation | Allow |
| Lower actor modifies, suspends, resets, impersonates, or revokes a higher target | Deny |
| Peer actor modifies an equal-tier target | Deny by default |
| Apparently ordinary target also holds a peer or higher role | Deny using the complete multi-role snapshot |
| High tier acts across an unauthorized tenant or scope | Deny or conceal |
| Actor assigns a role at or above the actor's own tier | Deny |
| Actor grants a permission outside its delegable set | Deny |
| Separate roles grant a permission and a narrow scope independently | Do not cross-compose them into a new scoped grant |
| Actor grants a role, tier, scope, ownership, or delegation to itself | Deny |
| Actor edits a shared role it holds, including an authority increase | Deny; use dedicated self-reduction for a reduction |
| Actor edits a shared role affecting an unmanageable principal | Deny atomically |
| Suspended higher identity retains the affected shared role | Deny, or require safe role revalidation before reactivation |
| Bulk request contains one peer or higher target | Deny atomically |
| Dedicated self-service operation only removes authority | Allow unless it violates another invariant |
| Normal administrator attempts to grant break-glass access | Deny |

Run the deterministic concurrency and rollback matrix in
[atomic authorization consistency](atomic-consistency.md), including actor
demotion or disablement, target promotion, phantom holders, concurrent owner
changes, and both valid commit orders. Keep the direct self-grant, two-step
create-and-assign, alternate API, bulk, background-job, and cross-tenant variants
in the hierarchy suite.
