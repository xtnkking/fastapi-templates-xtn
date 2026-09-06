# Atomic Authorization Consistency

Read this reference for authorization-changing writes, immediate revocation,
concurrent administration, high-risk protected mutations, or coordination of
RBAC state with audits, caches, messages, and other external effects.

This is the Skill's canonical transaction and locking contract. Other references
define policy and schema and link here instead of restating the protocol.

## Scope And Outcomes

Every authorization writer follows this protocol. A protected business write
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
authoritative for a concurrent write.

The transaction owner must:

1. Acquire the singleton authorization guard first, then all other canonical
   locks that conflict with writers able to change the decision.
2. Reload the actor, target, complete affected users, roles, grants, delegation,
   protection, ownership, versions, and relevant resource state.
3. Re-evaluate complete current and proposed authority.
4. Check any client concurrency precondition.
5. Apply the mutation and all affected version or epoch increments.
6. Insert the allowed audit and required transactional outbox rows.
7. Commit once and return only after commit succeeds.

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
        return result
    except PolicyDenied as exc:
        # The rejected transaction has exited and rolled back before this call.
        await attempt_denied_audit_in_new_transaction(command, exc.reason_code)
        raise
```

Do not catch policy denial inside `session.begin()`, add a denied audit, and let
that transaction commit; earlier flushes could be committed. Use the savepoint
design above when denial-audit durability is mandatory.

## Global Authorization Guard

Create `authorization_state` with exactly one well-known row. Its fixed
`scope='global'` string is a control key rather than a business or API identifier;
the row carries the shared authorization epoch and serializes all RBAC writers.
Enforce the fixed value with a primary key and check constraint, create the row
in the schema migration, and fail closed if it is missing. Runtime code must
never create it opportunistically.

The global row intentionally serializes authorization changes in this
single-project baseline. This makes assignment, revocation, user status, shared
role edits, delegation, and Owner transfer participate in one proof. Keep
transactions short; do not perform network I/O while holding the guard.

## Canonical PostgreSQL Lock Order

Use one order across authorization changes, identity disablement, session
revocation, Owner transfer, and protected business writes:

```text
class 10: singleton authorization_state row
-> class 20: users or principal authorization rows
-> class 30: authentication session rows
-> class 40: roles
-> class 50: role permissions, assignments, delegation, and other policy rows
-> class 60+: protected business rows
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
first. For a shared-role edit, discover and lock every retained assignee in UUID
order while the guard is held, including suspended users whose role becomes
effective after reactivation. Reload the actor and each target's complete current
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

For `PUT`, full-set replacement, status replacement, and similar commands,
require a strong `If-Match` derived from the read model version. Reject a missing
precondition with `428`, weak tags and `*`, and compare the expected version only
after locks, fresh reload, visibility, and manageability checks. Return `412` on
mismatch and `409` for another server-detected state conflict. Return the new
strong `ETag` after success.

Role permission and delegation replacements share `roles.version`. If a user
ETag covers effective authority as well as direct status, include both
`users.authz_version` and `authorization_state.epoch`; a shared-role change may
not increment every assigned user's version.

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

## PostgreSQL Asset Coverage

The included asset implements the core boundary in:

- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py): allowed
  mutation, version, and audit commits plus rollback before the denied-audit
  transaction;
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py): canonical
  user, global guard, role, and policy locks with identity-map refresh;
- [`tests/integration/test_rbac_api.py`](../assets/postgresql-rbac/tests/integration/test_rbac_api.py):
  audit behavior and rollback after forced post-flush denial;
- [`tests/integration/test_postgresql_locking.py`](../assets/postgresql-rbac/tests/integration/test_postgresql_locking.py):
  isolation, lock waits, committed actor revocation, and concurrent assignments.

The asset does not by itself prove crash-proof denied-audit delivery,
`If-Match`, generic request idempotency, database lock timeouts, a business
outbox, or product-specific protected writes. Add and test the relevant pieces
when adapting those surfaces.

## Verification Matrix

Use transaction barriers or explicit database synchronization, not timing sleeps.
For the changed surface, cover:

- forced denial after flush leaves mutation and versions unchanged;
- allowed-audit failure rolls back the protected mutation;
- denial-audit failure never converts rejection into success;
- revocation-first and protected-write-first commit orders;
- actor disablement, target promotion, Owner changes, and a shared-role assignment
  racing the constrained write in both lock acquisition orders;
- stale `If-Match` in both administrator commit orders;
- actual isolation, lock and statement timeouts, retry exhaustion, and deadlocks;
- response loss after commit resolves through idempotency rather than replay;
- outbox and cache invalidation remain absent on rollback and occur after commit.

Run locking, isolation, and PostgreSQL constraint tests against PostgreSQL.
SQLite cannot establish these guarantees.
