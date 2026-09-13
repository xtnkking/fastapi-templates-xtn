# Atomic Authorization Consistency

Read this reference for authorization-changing writes, immediate revocation,
concurrent administration, high-risk protected mutations, or coordination of
RBAC state with audits, caches, messages, and other external effects.
For login identity, parent/relationship tombstones, restore behavior, or
physical-purge boundaries, also read
[Identity and soft-delete lifecycle](identity-soft-delete.md).

This is the Skill's canonical transaction and locking contract. Other references
define policy and schema and link here instead of restating the protocol.
Use [RBAC audit module](audit-module.md) for access-control event fields and
[Business audit module](business-audit-module.md) for domain-event fields, safe
payload construction, append-only controls, access, and retention; this file
owns transaction outcomes.

## Scope And Outcomes

Every authorization writer follows this protocol, including RBAC unbind and
authorization-affecting parent soft deletion/restoration. A protected business write
also follows it when the product promises that a revocation which commits first
will prevent that write. Ordinary reads may use a documented bounded stale-cache
window instead.

Distinguish these outcomes:

| Outcome | Database and caller contract |
| --- | --- |
| Allowed | Mutation, versions, allowed audit, and transactional outbox rows all commit, or none do. Return success only after commit. |
| Denied by policy | Mutation, versions, and outbox rows roll back. Attempt the denied audit only after rollback; audit failure never becomes success. |
| Retryable concurrency conflict | Roll back and restart in a fresh transaction within one retry and time budget. Internal retries are not policy denials. |
| Commit outcome unknown | Resolve through an idempotency record or authoritative reread; never blindly replay a non-idempotent command. |
| Infrastructure failure | Roll back when the outcome is known, fail closed, and emit operational telemetry instead of a false policy result. |

An allowed audit insert is part of the allowed transaction; if it fails, the
mutation fails. A denied audit written in a second transaction is deliberately
not atomic with rollback: process exit, cancellation, or database failure can
occur between them. The included asset waits for the audit attempt before
returning denial but cannot claim crash-proof delivery.

If every returned denial requires a durable database audit, use an outer
transaction and nested savepoint. Perform the protected attempt in the savepoint,
roll it back on policy denial, insert the denied audit in the still-active outer
transaction, commit, and only then return denial. Verify the database and ORM
savepoint behavior.

## One Transaction Owner

The final decision for a write belongs in the transaction that owns the mutation.
A route dependency may reject obvious failures early, but its snapshot is not
authoritative for a concurrent write. If that fast gate rejects a privileged
write, attempt its denied audit there; if it allows the request, the transaction
owner still reloads and checks the capability before revealing target existence
or concurrency versions.

The transaction owner must:

1. Acquire the singleton authorization guard first, then all other canonical
   locks that conflict with writers able to change the decision.
2. Reload the actor, target, complete affected users, roles, grants, delegation,
   protection, ownership, versions, and relevant resource state.
3. Re-evaluate complete current and proposed authority.
4. Check any client concurrency precondition.
5. Apply the mutation, including all required parent/relation tombstones or new
   relation episodes, and all affected version or epoch increments.
6. Insert the allowed audit and required transactional outbox rows.
7. Build the immutable public response snapshot from the post-mutation rows while
   the same locks are held, using the actor's read-visibility projection for any
   nested role or grant collection.
8. Commit once and return only that snapshot after commit succeeds.

Called repositories may flush but must not commit independently:

```python
async def run_authorized_write(command: Command) -> Result:
    try:
        async with session_factory() as session:
            async with session.begin():
                await acquire_canonical_locks(session, command)
                current = await reload_authoritative_state(session, command)
                decision = policy.evaluate(current, command)
                decision.require_allowed()
                require_expected_version(current, command)

                result = await apply_mutation(session, current, command)
                bump_authorization_versions(current, result)
                session.add(allowed_audit(decision, current, result))
                session.add_all(outbox_events(result))
                response = await build_immutable_response_snapshot(
                    session,
                    actor=current.actor,
                    result=result,
                )
        return response
    except PolicyDenied as exc:
        # The rejected transaction has exited and rolled back before this call.
        await attempt_denied_audit_in_new_transaction(command, exc.reason_code)
        raise
```

Do not catch policy denial inside `session.begin()`, add a denied audit, and let
that transaction commit; earlier flushes could be committed. Use the savepoint
design above when denial-audit durability is mandatory.

## Global RBAC Guard

Create `rbac_state` with exactly one well-known row. Its fixed
`scope='global'` string is a control key rather than a business or API identifier;
the row carries the shared authorization epoch and serializes all RBAC writers.
Enforce the fixed value with a primary key and check constraint, create the row
in the schema migration, and fail closed if it is missing. Runtime code must
never create it opportunistically.

The global row intentionally serializes authorization changes in this
single-project baseline. This makes assignment, revocation, user status, shared
role edits, delegation, and super-admin transfer participate in one proof. Keep
transactions short; do not perform network I/O while holding the guard.
The row exists for the database lifetime: runtime and production-maintenance
roles cannot delete, truncate, disable, or soft-delete it. Missing state fails
closed and is never repaired opportunistically.

## Soft Delete And Controlled Purge

Every mutable row that may be removed at runtime uses a tombstone, including
users, custom roles, business entities, and relationship unbinds; these paths
never issue physical `DELETE` or rely on a hard cascade. Parent tombstone,
complete live relation tombstones, versions, epoch, and allowed audit are one
transaction. Restore creates only explicitly authorized new relation episodes
and cannot revive tombstones. System roles and the fixed permission catalog have
no runtime deletion path.

A separately authorized maintenance purge may physically remove only eligible
non-audit tombstones after retention, legal-hold, backup, and reference checks.
It uses deterministic lock order and cannot be called through an ordinary HTTP,
service, job, or CLI deletion command. Disposable test-schema teardown and a
reviewed destructive migration/downgrade are the other narrow exceptions.
Append-only audit rows and production `rbac_state` are never purge targets under
this baseline.

## Canonical PostgreSQL Lock Order

Use one order across authorization changes, identity disablement, user-version
revocation, super-admin transfer, and protected business writes:

```text
class 10: singleton rbac_state row
-> class 20: users or principal authorization rows
-> class 30: roles
-> class 40: role permissions, assignments, delegation, and other policy rows
-> class 50+: protected business rows
```

Give tables within a class a stable rank and sort multiple targets by
`(lock_class, table_rank, primary_key)`. A path may skip a class it does not use
but must never acquire an earlier class after a later one. Lock modes must
conflict with the corresponding revocation writer.

Every RBAC writer acquires the same global guard. Protected business writes also
acquire it when their immediate-revocation proof depends on this ordering.

## Authoritative Reload And Affected Sets

State read before waiting for a lock is only a candidate. After locks are held,
reload from PostgreSQL and ignore JWT role claims, route contexts, permission
caches, and earlier ORM values. With SQLAlchemy, use `populate_existing=True`,
explicit expiration, or an equivalent identity-map refresh.

Acquire the global guard before scanning any assignment rows. This freezes the
affected-set topology because every assignment writer must acquire the same guard
first. It also serializes the authoritative count used to keep each user at no
more than 10 live role bindings. For a shared-role edit, discover and lock every
live assignee in the project's canonical ID order while the guard is held,
including suspended users
whose role remains live and could become effective after reactivation. For a
parent delete, lock the parent and every live owned child or relation before
tombstoning them. Reload the actor and each
target's complete current
and proposed multi-role authority after locks are held. Never authorize from a
scan performed before acquiring the guard.

## Isolation And Immediate Revocation

The baseline uses PostgreSQL `READ COMMITTED`, so a post-lock statement sees
commits completed before that statement starts. This gives two valid orders:

- Revocation commits first: the protected transaction reloads revoked state and
  denies.
- The protected transaction locks first: revocation waits, so the protected
  mutation commits before revocation becomes effective.

A permission check in one transaction followed by a business commit in another
leaves a time-of-check/time-of-use gap. Do not reuse this proof under
`REPEATABLE READ` or another fixed snapshot. Use a database-specific equivalent,
or `SERIALIZABLE` with complete transaction retries, and prove the ordering.

## Prevent Authorized Stale Writes

Database locks serialize execution but do not preserve client intent. Two still
authorized administrators can read version 4, then submit different full
replacements; without a precondition, the second silently overwrites the first.

For role information update, lifecycle, soft deletion, and permission or
delegation bind/unbind commands, require a nonnegative `expected_version` in the
JSON body. Compare it with `roles.version` only after locks, fresh reload,
visibility, and manageability checks. Missing or malformed input follows the
ordinary `422001` validation contract. Return HTTP `409` with business code
`409002` on version mismatch and use `409001` for another client-visible state
conflict. Build the successful role body and new version from the same immutable
in-transaction snapshot before locks are released; never requery part of a
response after commit. Follow
[API response standard](api-response-standard.md) for the full wire contract.

User-role bind/unbind is an incremental, idempotent, single-transaction command
and does not require a user version in this baseline. Unbind tombstones the one
live episode; a later bind inserts a new episode rather than clearing history. It
still requires the global guard, post-lock authority reload, and complete
hierarchy decision. Before inserting a genuinely new binding, calculate the
target's complete final live set under the guard and reject the transaction with
`409001` if it would exceed 10. The required `user` and any `super_admin` binding
count, disabled roles still count, and tombstones do not count. A deferred
PostgreSQL constraint trigger checks the same final state, including direct SQL;
its statement-level guard lock prevents concurrent writers from both claiming
the last available slot.

User-role bind/unbind, user disable/enable, and every other administrative write
that returns user state use the same response boundary as role writes. Construct
the response before releasing locks, freeze collection fields, and return it only
after commit. Public nested collections such as `assigned_role_ids` use the
actor-aware read predicate, even though policy and audit evaluate the complete
unfiltered assignment set. Do not reopen a route/request `Session` or another
session after commit to assemble the response; that creates a race in which a
concurrent authority change contaminates the result of the completed command.

An expected version is a concurrency condition, not authorization. It never
allows the caller to skip the post-lock policy decision.

## Retries, Deadlines, And Idempotency

- Retry only classified concurrency failures, normally PostgreSQL `40001`,
  `40P01`, and an intentional lock-not-available path. Use a fresh session and
  transaction.
- Bound attempts and wall-clock time. Set lock and statement timeouts below the
  request deadline.
- Use short jittered backoff while budget remains. Preserve request ID and
  idempotency key across attempts, but never reuse ORM state.
- Return state-aware `409` when the caller should reread and resubmit. Use a
  retryable `503` for exhausted infrastructure contention. Keep policy denial,
  conflict, and operational failure distinct.

For replay-sensitive commands, require `Idempotency-Key`. Store a globally unique
`(operation, key)` record with request digest, processing state, and replayable
result. Claim or complete it in the mutation transaction. Reusing a key with a
different digest is a conflict; a completed key replays its recorded result.

When commit outcome is unknown and no idempotency record exists, require an
authoritative reread or reconciliation before another non-idempotent attempt.

## Versions, Caches, And External Effects

- Increment user authorization versions and the global epoch in the mutation
  transaction.
- Resolve the current version tuple from authoritative state before selecting a
  cached permission entry. Token or old-cache versions are not proof.
- Publish cache invalidation after commit. Versioned keys provide correctness;
  invalidation only improves freshness.
- Insert outbox rows in the database transaction for messages, webhooks, emails,
  indexing, and other tied effects. Deliver after commit with an idempotency key;
  consumers tolerate at-least-once delivery.
- Never call an external service while holding authorization locks.

The Redis active-JTI gate is not a PostgreSQL lock class. Do not add an
individual Token table merely to place it in this order. When an authorization
transaction increments `users.token_version`, later authentication compares the
new value with the version already bound in Redis. A one-Token logout deletes the
exact Redis record outside these PostgreSQL locks. Confirmed deletion prevents
later gate checks but cannot cancel a request already past the gate, and Redis
failover may restore an older key; do not claim database-grade linearizable Token
revocation from this design.

## PostgreSQL Asset Coverage

The included asset implements the core boundary in:

- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py): allowed
  mutation, version, and audit commits plus rollback before the denied-audit
  transaction;
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py): canonical
  user, global guard, role, and policy locks with identity-map refresh;
- [`alembic/versions/0001_single_project_rbac.py`](../assets/postgresql-rbac/alembic/versions/0001_single_project_rbac.py):
  baseline database enforcement of the 10-live-role limit and serialized
  assignment writes;
- [`tests/integration/test_rbac_api.py`](../assets/postgresql-rbac/tests/integration/test_rbac_api.py):
  audit behavior and rollback after forced post-flush denial;
- [`tests/integration/test_postgresql_locking.py`](../assets/postgresql-rbac/tests/integration/test_postgresql_locking.py):
  isolation, lock waits, committed actor revocation, and concurrent assignments.

The asset does not by itself prove crash-proof denied-audit delivery, generic
request idempotency, database lock timeouts, a business outbox, or
product-specific protected writes. It implements body `expected_version` checks
for the shared role commands named above. Add and test other relevant pieces
when adapting those surfaces.

## Verification Matrix

Use transaction barriers or explicit database synchronization, not timing sleeps.
For the changed surface, cover:

- forced denial after flush leaves mutation and versions unchanged;
- allowed-audit failure rolls back the protected mutation;
- denial-audit failure never converts rejection into success;
- role and user mutation responses are immutable snapshots created before lock
  release, with no post-commit requery and no concurrent-state contamination;
- ordinary administrators receive only visible roles in nested
  `assigned_role_ids`, while `super_admin` receives every live assignment to a
  non-deleted role;
- revocation-first and protected-write-first commit orders;
- actor disablement, target promotion, super-admin changes, and a shared-role
  assignment racing the constrained write in both lock acquisition orders;
- two bindings racing for a user's tenth live role slot, proving only one commits,
  plus direct SQL, bootstrap, and `super_admin` transfer attempts against a full
  user;
- parent soft deletion racing a child/relation bind, proving either the new live
  relation commits first and is tombstoned or the bind observes deletion and
  fails;
- unbind racing rebind, proving at most one live relation episode and preserving
  every historical tombstone;
- restore committing only a new mandatory base-role episode and never old
  privilege or an old Redis JTI;
- stale `expected_version` in both administrator commit orders;
- actual isolation, lock and statement timeouts, retry exhaustion, and deadlocks;
- response loss after commit resolves through idempotency rather than replay;
- outbox and cache invalidation remain absent on rollback and occur after commit.
- direct `DELETE`/`TRUNCATE` of audits or `rbac_state` fails, and controlled
  purge entry points reject both as targets.

Run locking, isolation, and PostgreSQL constraint tests against PostgreSQL.
SQLite cannot establish these guarantees.
