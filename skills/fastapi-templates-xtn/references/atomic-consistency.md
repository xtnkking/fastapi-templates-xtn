# Atomic Authorization Consistency

Read this reference for authorization-changing writes, immediate revocation,
concurrent administration, high-risk protected mutations, or coordination of
RBAC state with audits, caches, messages, and other external effects.

This is the skill's canonical transaction and locking contract. Other references
define policy and schema and link here instead of restating the protocol.

## Scope And Outcomes

Every tenant-scoped authorization writer follows this protocol. A protected
business write must also follow it when the product promises that a revocation
which commits first will prevent that write. Ordinary reads may use a documented,
bounded stale-cache window instead.

Distinguish these outcomes:

| Outcome | Database and caller contract |
| --- | --- |
| Allowed | The mutation, authorization versions, allowed audit, and transactional outbox rows all commit, or none do. Return success only after commit. |
| Denied by policy | The mutation, version changes, and outbox rows roll back. Attempt the denied audit only after that rollback, and never turn an audit failure into success. |
| Retryable concurrency conflict | Roll back the whole attempt and restart in a fresh transaction within one retry and time budget. Do not classify internal retries as policy denials. |
| Commit outcome unknown | The connection failed while commit may have succeeded. Resolve through an idempotency record or authoritative reread; never blindly replay a non-idempotent command. |
| Infrastructure failure | Roll back when the outcome is known, fail closed, and emit operational telemetry rather than a misleading allowed or denied policy decision. |

An allowed audit insert is part of the allowed transaction; if it fails, the
mutation fails. A denied audit written by a second transaction is deliberately
not atomic with the rollback: process exit, cancellation, or database failure can
occur between them. The included asset waits for the audit attempt before
returning a denial, but it cannot claim crash-proof delivery.

If every returned denial must have a durable database audit, use one outer
transaction with a nested savepoint: perform the protected attempt inside the
savepoint, roll back that savepoint on policy denial, insert the denied audit in
the still-active outer transaction, commit it, and only then return the denial.
Verify the database and ORM savepoint behavior. A synchronous write to a separate
audit service cannot provide the same atomic guarantee.

## One Transaction Owner

The final authorization decision for a write belongs in the transaction that
owns the mutation. A route dependency may reject obvious failures early, but its
snapshot is not authoritative for a concurrent write.

The transaction owner must:

1. Acquire canonical locks sufficient to conflict with every writer that could
   change the decision. A shared guard may cover related join rows; locking every
   row individually is not required when the serialization proof does not need it.
2. Reload the actor, target, complete affected principals, roles, grants,
   delegation, protection, ownership, versions, and relevant resource state.
3. Re-evaluate the complete policy, including before-and-after authority.
4. Check any client concurrency precondition.
5. Apply the mutation and all affected version or epoch increments.
6. Insert the allowed audit and required transactional outbox rows.
7. Commit once and return only after the commit succeeds.

Called repositories may flush but must not commit independently. The basic
boundary is:

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

Do not catch a policy denial inside `session.begin()`, add a denied audit, and
allow that same transaction to commit. Earlier flushes could be committed. Use
the outer-transaction/savepoint design above if denial-audit durability is a hard
requirement.

## Canonical PostgreSQL Lock Order

Use one order across authorization writes, identity disablement, session
revocation, owner transfer, and protected business writes:

```text
class 10: users or principal authorization rows
-> class 20: authentication session rows
-> class 30: tenant authorization guard
-> class 40: memberships
-> class 50: roles
-> class 60: role permissions, delegation, and other policy rows
-> class 70+: protected business rows
```

Give tables within a class a stable rank and sort multiple targets by
`(lock_class, table_rank, tenant_id, primary_key)`. A path may skip a class it
does not use but may never acquire an earlier class or rank after a later one.
Lock modes must conflict with the corresponding revocation writer.

In the PostgreSQL baseline, every tenant-scoped RBAC writer acquires the same
tenant authorization guard. This includes single-member assignment, revocation,
and status changes because those operations can alter the affected set of a
shared-role writer. High-risk tenant business writes use the guard when their
immediate-revocation proof depends on the same ordering.

## Authoritative Reload And Affected Sets

State read before waiting for a lock is only a candidate. After the locks are
held, reload from PostgreSQL and ignore JWT role claims, route authorization
contexts, permission caches, and earlier ORM values. With SQLAlchemy, use
`populate_existing=True`, explicit expiration, or an equivalent identity-map
refresh.

For a shared-role edit, reload retained holders, including suspended holders
whose assignment can become effective after reactivation. For administration,
reload the actor and every target's complete current and proposed multi-role
authority.

When join rows determine the affected set:

1. Discover candidate IDs with a tenant-scoped query without authorizing from it.
2. Acquire the guard and candidate locks in canonical order.
3. Requery while the guard is held.
4. If a new unlocked object appears, or another change invalidates the proof,
   roll back and retry the whole transaction. A removed candidate need not force
   retry when the remaining locked set still proves the invariant.
5. Never append a newly discovered earlier lock to the current transaction.

## Isolation And Immediate Revocation

The PostgreSQL baseline uses `READ COMMITTED`, so a post-lock statement sees
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

Database locks serialize execution but do not preserve a client's intent. Two
still-authorized administrators can read version 4, then sequentially submit
different full replacements; without a precondition, the second silently
overwrites the first.

For `PUT`, full-set replacement, status replacement, and similar administration
commands, require a strong `If-Match` derived from the version exposed by the
read model. Reject a missing precondition with `428`, reject weak tags and `*`,
and compare the expected version only after canonical locks, a fresh reload, and
the normal visibility and manageability decision. Return `412` on mismatch and
`409` for a server-detected conflict such as exhausted affected-set retries.
Return the new strong `ETag` after success.

Role permission and delegation replacements share `role.version`, so a stale
write in either control plane conflicts with the other. If a membership ETag
covers effective permissions as well as direct membership state, include both
`membership.authz_version` and the tenant authorization epoch; a shared-role
change may not increment the membership version.

An expected version is a concurrency condition, not authorization. It never
allows a caller to skip the post-lock policy decision.

## Retries, Deadlines, And Idempotency

- Retry only classified concurrency failures, normally PostgreSQL serialization
  failure `40001`, deadlock `40P01`, an intentional lock-not-available path, and
  the internal affected-set retry signal. Use a fresh session and transaction.
- Bound both attempts and wall-clock time. Set lock and statement timeouts below
  the request deadline; a small retry count does not bound an unlimited lock wait.
- Use short jittered backoff while budget remains. Preserve the request ID and
  idempotency key across internal attempts, but do not reuse ORM state.
- Return a state-aware `409` when the caller should reread and resubmit. Use a
  retryable `503` for exhausted infrastructure contention. Keep policy denial,
  conflict, and operational error distinct in audit or telemetry.

For a command whose replay could duplicate an effect, require an
`Idempotency-Key`. Store a tenant-scoped unique `(operation, key)` record with a
request digest, processing state, and replayable result. Claim or complete it in
the mutation transaction. The same key with another digest is a conflict; a
completed key replays its recorded result. A request ID used only for tracing or
indexed non-uniquely is not an idempotency guarantee.

When no idempotency record exists and commit outcome is unknown, require an
authoritative reread or reconciliation before another non-idempotent attempt.

## Versions, Caches, And External Effects

- Increment authorization versions and epochs in the mutation transaction.
- Resolve the current version tuple from authoritative state before selecting a
  cached permission entry. Token or old-cache versions are not current proof.
- Publish cache invalidation only after commit. Versioned keys provide
  correctness; invalidation only improves freshness.
- Insert outbox rows in the database transaction for messages, webhooks, emails,
  indexing, and other effects tied to the mutation. Deliver after commit with an
  idempotency key; consumers must tolerate at-least-once delivery.
- Never call an external service while holding authorization locks.

## PostgreSQL Asset Coverage

The included asset implements the core transaction boundary in:

- [`app/rbac/service.py`](../assets/postgresql-rbac/app/rbac/service.py): allowed
  mutation, version, and audit commits; complete rollback before a second
  denied-audit transaction; bounded affected-set retries.
- [`app/rbac/queries.py`](../assets/postgresql-rbac/app/rbac/queries.py): canonical
  tenant, user, membership, role, and policy locks with identity-map refresh.
- [`tests/integration/test_rbac_api.py`](../assets/postgresql-rbac/tests/integration/test_rbac_api.py):
  audit behavior and rollback after forced post-flush denial.
- [`tests/integration/test_postgresql_locking.py`](../assets/postgresql-rbac/tests/integration/test_postgresql_locking.py):
  isolation, lock waits, committed actor revocation, and phantom-holder retry.

The asset does not yet provide crash-proof denied-audit delivery, `If-Match`,
generic request idempotency, database lock timeouts, a business outbox, or tests
for product-specific protected writes. Add the relevant pieces when adapting
those surfaces; do not claim that copying the asset alone proves them.

## Verification Matrix

Use transaction barriers or explicit database synchronization, not timing-based
sleeps. For the changed surface, cover:

- forced denial after a flush leaves mutation and versions unchanged;
- allowed-audit failure rolls back the protected mutation;
- denial-audit failure never converts rejection into success, plus the documented
  crash behavior of the chosen denial-audit design;
- revocation-first and protected-write-first commit orders;
- actor revocation or disablement, target promotion, owner changes, and a phantom
  shared-role holder racing the constrained write;
- stale `If-Match` in both administrator commit orders;
- actual isolation, lock and statement timeouts, retry exhaustion, and deadlocks;
- response loss after commit resolves through idempotency rather than blind replay;
- outbox and cache invalidation remain absent on rollback and occur after commit.

Run locking, isolation, and PostgreSQL constraint tests against PostgreSQL.
SQLite cannot establish these guarantees.
