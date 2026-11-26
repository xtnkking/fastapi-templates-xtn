# Business Audit PostgreSQL

Read [Business audit module](business-audit-module.md) first. Read this reference
only when implementing or changing the SQLAlchemy model, catalog-backed writer,
database handoff, caller-owned transaction, or matching tests.
For read APIs, export, retention, partitioning, legal hold, alerts, backups, or
recovery, load
[Business audit operations](business-audit-operations.md) separately.

This reference owns model and transaction implementation plus database handoff.
The user owns migration generation, review, execution and initial data. The
core reference owns which events exist and what they mean; do not invent a
catalog while preparing the handoff.

## PostgreSQL Model Baseline

This is an opt-in resource, not default generated code. Copy the contract,
model and writer only after approving a product event catalog; explicitly import
`app.models.postgres.business_audit.BusinessAuditEvent` in that project's model
registry. The default registry intentionally contains only the unified operation
audit. User-owned migrations install any optional table and protections.

The Skill delivers models and application code. The user generates, reviews,
and executes their migrations, DDL, database-only protection and initial data.
Do not create a table or automatically initialize one through startup or tests.
Use the [database handoff](migrations.md), not a runnable SQL file.

The complete field, named-constraint and index definition is
[`BusinessAuditEvent`](../assets/postgresql-rbac/app/models/postgres/business_audit.py).
Reuse that model instead of maintaining a duplicate `CREATE TABLE` block here.
It includes the event, operation user/source and target identifiers, stable action
and reason, outcome/entrypoint/schema version, bounded before/after/context JSON, request ID and
PostgreSQL timestamp. Keep these model contracts when adapting it:

- The bundled event ID is `BA` + `YYMMDDHHMMSSmm` + six random characters;
  generate it once per logical operation and reuse it on retry. `user_id` and
  `target_user_id` follow the 15-character `U` format; other target IDs follow
  their owning business's validated non-sequential policy.
- Exact domain/action format and relationship, documented outcome/source-type/
  entrypoint enums, user/source presence rules, user-target equality when
  `target_type="user"`, positive schema version, and bounded request IDs.
- A 2..80-character reason matching `validate_audit_reason()`; before/after
  object values limited to 16 KiB each, context object to 4 KiB, and no
  non-success `after_state`.
- Deterministic indexes for the actual time, domain, operation user/source,
  target user/object, request and action/outcome review paths; no speculative
  JSONB GIN indexes.

Database constraints are defense in depth, not the action catalog. The typed
writer must verify each action, its allowed reasons and fields before insertion.
Do not add `ON DELETE CASCADE` from users or domain resources: audit meaning
survives their lifecycle. Append-only trigger/grant protection is a separate
user-owned database responsibility and is not installed by ORM metadata.

## Asset Adaptation

The bundled PostgreSQL asset separates shared audit safety from RBAC and business
tables:

- `app/core/audit.py` owns `AuditSource`, JSON sanitization, bounded depth and size,
  sensitive key/value rejection, action/reason/request-ID validators, and the
  no-argument `get_audit_request_id()` reader for the bound execution context;
- `app/core/business_audit.py` owns source/outcome types, `BusinessAuditActionSpec`,
  trusted event facts, and pure catalog/payload validation;
- `app/models/postgres/business_audit.py` owns the `BusinessAuditEvent` table and constraints;
- `app/services/business_audit_service.py` owns the transaction-aware `BusinessAuditService`;
- historical `alembic/env.py` imports shared model metadata for maintainer tests;
- historical revisions demonstrate constraints, indexes, and append-only
  controls; they are not copied or executed for a generated project;
- unit tests exercise catalog and sanitizer behavior; and
- PostgreSQL integration tests prove transaction and trigger behavior.

Use the selected output in [New-project delivery](new-project-delivery.md), or
integrate the required components into the existing application. Keep the
writer, shared sanitizer, model imports and relevant tests together, and hand
database-only protections to the user. Do not copy the entire maintenance
asset or its historical migration/SQL files. Do not turn the reusable writer
into an HTTP audit-write route.

The shared `validate_audit_action()` accepts the common audit syntax. The
business action specification must additionally require exactly the catalog's
`[domain].[resource].[verb]` form and ensure the first segment equals `domain`.
The shared `validate_audit_reason()` requires 2 to 80 lowercase alphanumeric or
underscore characters. Keep the SQL constraint at the same minimum; a one-letter
reason must fail in both Python and PostgreSQL.

Configure a catalog once at application composition, not per request. The exact
constructor names may be preserved from the asset, while product values must be
explicit:

```python
BUSINESS_AUDIT_CATALOG = {
    "payment.refund.approve": BusinessAuditActionSpec(
        domain="payment",
        action="payment.refund.approve",
        target_type="refund",
        schema_version=1,
        allowed_outcomes=frozenset(
            {
                BusinessAuditOutcome.SUCCEEDED,
                BusinessAuditOutcome.FAILED,
                BusinessAuditOutcome.DENIED,
            }
        ),
        source_types=frozenset({BusinessAuditSourceType.USER}),
        reason_codes=frozenset(
            {
                "approval_recorded",
                "invalid_refund_state",
                "target_outside_scope",
            }
        ),
        before_fields=frozenset(
            {"status", "amount_minor", "currency", "version"}
        ),
        after_fields=frozenset(
            {"status", "amount_minor", "currency", "version"}
        ),
        context_fields=frozenset({"approval_policy", "channel"}),
    )
}

business_audit = BusinessAuditService(
    session_factory=SessionFactory,
    action_specs=BUSINESS_AUDIT_CATALOG,
)
```

An existing project may use dependency injection instead of a module singleton.
The invariant is one immutable catalog-backed writer, not a specific container.
Startup must fail on duplicate action keys, mismatched domains, invalid reason
codes, unsafe allowlist names, empty outcome sets, or unsupported schema versions.

## Trusted Facts At The Call Site

Construct facts inside the service boundary from authenticated and authoritative
state. Do not pass a request body's operation user/source, target type, action,
outcome, reason, entrypoint, or snapshots directly into the writer.
`BusinessAuditFacts` has no `request_id` input. HTTP middleware binds the
server-generated request ID once; the writer reads and validates that ID through
`get_audit_request_id()` when constructing the ORM event. Non-HTTP entrypoints
generate and bind one safe operation ID before work, then deactivate and reset
the context in `finally`, even if resource cleanup fails. Missing or inactive
context raises `RuntimeError`; neither facts nor the writer create a replacement.

```python
from app.core.ids import new_audit_id

facts = BusinessAuditFacts(
    event_id=new_audit_id("BA"),
    action="payment.refund.approve",
    source_type=BusinessAuditSourceType.USER,
    user_id=authenticated_user.user_id,  # 操作人：当前登录的审批人。
    target_user_id=refund.user_id,  # 被操作人：退款影响的用户，由数据库记录取得。
    target_id=str(refund.id),  # 被操作对象：本次退款，不是审批人或用户 ID。
    reason_code="approval_recorded",
    entrypoint=AuditSource.HTTP,
    before_state=refund_audit_projection(before_refund),
    after_state=refund_audit_projection(after_refund),
    context={
        "approval_policy": policy.code,
        "channel": "admin_console",
    },
)
```

The action specification supplies `domain`, `target_type`, allowed outcomes,
reason codes, state/context field sets, and schema version. This prevents a call
site from relabeling the same facts. The writer validates and sanitizes before
constructing the ORM row.

No nested identity object is needed. For example, a trusted scheduled task uses
`source_type=BusinessAuditSourceType.JOB`, `source_id="refund_reconciliation"`,
`user_id=None` and `entrypoint=AuditSource.JOB`. Here `source_id` identifies the
task, while `entrypoint` identifies its execution entry. A system event has
neither `user_id` nor `source_id`; service/maintenance events require their own
stable non-personal `source_id`. A user-target action must set `target_user_id`
and `target_id` to the same validated user ID. For other target types, set an
independent `target_user_id` only when a user is actually affected.

Do not call `model_dump()`, inspect ORM `__dict__`, or accept a generic dictionary
as a projection. Use a typed per-action projection function. Keep the 16 KiB
limit for each state and an independently enforced 4 KiB limit for context. The
database byte checks are the final guard, not the primary sanitizer.

## Caller-Owned Successful Transaction

The business service owns one PostgreSQL transaction. The writer adds the event
to that session and never commits independently:

```python
async def approve_refund(command: ApproveRefund) -> RefundView:
    async with session_factory() as session:
        async with session.begin():
            current = await refund_repository.lock_and_load(
                session,
                command.refund_id,
            )
            await authorization.require_refund_approval(
                session,
                command.current_user,
                current,
            )
            require_expected_version(current, command.expected_version)

            before = refund_audit_projection(current)
            result = current.approve(command.policy_code)
            after = refund_audit_projection(result)

            session.add(result)
            business_audit.add_succeeded(
                session,
                BusinessAuditFacts(
                    event_id=command.audit_event_id,
                    action="payment.refund.approve",
                    source_type=BusinessAuditSourceType.USER,
                    user_id=command.current_user.user_id,
                    target_user_id=current.user_id,
                    target_id=str(current.id),
                    reason_code="approval_recorded",
                    entrypoint=command.entrypoint,
                    before_state=before,
                    after_state=after,
                    context={
                        "approval_policy": command.policy_code,
                        "channel": command.channel,
                    },
                ),
            )
        return RefundView.from_snapshot(after)
```

Return success only after `session.begin()` exits successfully. Build the response
from the immutable in-transaction snapshot; do not requery pieces after commit.
Called repositories and the audit writer may flush but cannot commit. Audit
validation, audit insertion, idempotency completion, or version-update failure
rolls back both the business change and its audit row.

Never perform Redis, HTTP, broker, email, object-store, or other network I/O in
this transaction. When the write promises immediate authorization revocation,
acquire `rbac_state(scope='global')` first, reload authority after locks, and
follow [Atomic authorization consistency](atomic-consistency.md).

## Denied And Failed Transactions

For the normal baseline, let the protected transaction exit and roll back before
opening the outcome event transaction:

```python
try:
    async with session_factory() as session:
        async with session.begin():
            await run_protected_attempt(session, command)
except PolicyDenied as exc:
    written = await business_audit.write_after_rollback(
        denied_facts(command, exc.reason_code),
        outcome=BusinessAuditOutcome.DENIED,
    )
    if not written:
        safe_log(
            audit_logger,
            logging.ERROR,
            "audit.write.failed",
            extra={
                "audit_domain": "business",
                "audit_action": command.audit_action,
            },
        )
    raise
except MaterialBusinessFailure as exc:
    written = await business_audit.write_after_rollback(
        failed_facts(command, exc.reason_code),
        outcome=BusinessAuditOutcome.FAILED,
    )
    if not written:
        safe_log(
            audit_logger,
            logging.ERROR,
            "audit.write.failed",
            extra={
                "audit_domain": "business",
                "audit_action": command.audit_action,
            },
        )
    raise
```

The helper uses a fresh session and transaction. It never accepts an active or
failed business session. Its failure is operationally visible but cannot convert
the denial or failure to success. This baseline has a crash gap between rollback
and event insertion.

When the product requires every returned denial or failure to be durable, use an
outer transaction and a nested savepoint. Catch the exception only after the
savepoint context has rolled back, insert the non-success event into the outer
transaction, let the outer commit, and raise to the caller afterward:

```python
denial: PolicyDenied | None = None

async with session_factory() as session:
    async with session.begin():
        try:
            async with session.begin_nested():
                await run_protected_attempt(session, command)
        except PolicyDenied as exc:
            denial = exc
            business_audit.add_after_savepoint_rollback(
                session,
                denied_facts(command, exc.reason_code),
                outcome=BusinessAuditOutcome.DENIED,
            )

if denial is not None:
    raise denial
```

Test the selected SQLAlchemy and PostgreSQL savepoint behavior. Do not catch and
suppress denial inside the savepoint before rollback. Never add a denied event to
the same transaction that may still contain flushed protected changes. The
helper can reject a call while a nested transaction is still active, but it
cannot infer whether a previously closed savepoint was released or rolled back;
the shown control flow and an integration test must prove that ordering.

A serialization or deadlock retry is not a separate business failure. Retry with
a new session under one bounded logical-command budget and reuse the preselected
event ID and request ID. For commit outcome unknown, consult the transactional
idempotency record or authoritative state before any replay or outcome event.

## Append-Only Controls

Hand off the append-only database requirements explicitly: application audit
writers receive `INSERT`, not `UPDATE`, `DELETE`, or `TRUNCATE`; reviewers use
a separate read-only role or narrowly authorized service. The user prepares,
reviews and installs database grants and defensive triggers rejecting both
row mutation and table truncation. ORM metadata does not generate those
triggers. The historical `0003_business_audit` is a maintenance reference for
understanding them, not an initialization script to deliver or execute.

The user selects actual deployment role names and verifies installed grants. The
runtime writer must not own the table and receives only the required schema usage,
sequence-free `INSERT`, and no `UPDATE`, `DELETE`, or `TRUNCATE`; a separately
authorized reviewer receives bounded `SELECT` only. The bundled development URL
uses a database owner so migrations and integration cleanup can run; never copy
that privilege profile into production. Runtime code never edits or deletes an
event. Correct an error with a new catalog-defined correction event referencing
the original event ID through a safe context field.

Do not add `deleted_at`, `deleted_by`, or a restore operation to an audit table;
append-only is stronger than soft deletion. Online-retention maintenance moves
closed rows or partitions intact to protected archival storage and does not
drop, truncate, or delete them. Any eventual destructive product/legal exception
is outside this default and outside runtime database roles; follow
[Business audit operations](business-audit-operations.md).

This is tamper resistance, not cryptographic immutability. A database owner,
superuser, table owner, disabled trigger, storage administrator, or compromised
backup operator remains able to alter evidence. Stronger controls belong to the
operations design.

## Database Handoff Sequence

Deliver the model and this checklist. The user owns every schema-generation,
DDL, grant and migration operation below; ordinary Skill generation and tests
execute none of them and never use runtime `create_all()`:

1. Inspect the shared metadata containing the delivered business audit model.
2. Generate, review and execute the user's migration with all named model
   constraints and no sequential default.
3. Confirm it preserves only the review indexes needed by the query surface.
4. Prepare, review and install append-only functions and mutation/truncate guards.
5. Apply and verify actual writer and reader grants after those roles exist.
6. Seed no product events; the catalog is code, not mutable database content.
7. Validate the user's own migration plan for their actual starting schema.
8. Inspect PostgreSQL defaults to prove no sequence or identity was introduced.
9. Exercise downgrade only in a disposable database; dropping an audit table in
   production is destructive and must not be an ordinary rollback procedure.

If replacing a pre-existing business audit table, validate and quarantine legacy
rows before applying stricter constraints. Never rewrite old evidence to resemble
a new schema version. Use a new table or an explicit versioned import event when
legacy rows cannot satisfy the new contract.

Do not switch the baseline model to partitioning by merely adding a partition
clause to generated DDL. PostgreSQL partitioned unique and primary-key constraints must include the
partition key, which changes event-ID uniqueness and lookup/index design. Read
[Business audit operations](business-audit-operations.md) and choose the
partitioned shape before production data exists.

## PostgreSQL Verification

The user's completed schema needs these PostgreSQL checks; SQLite cannot
establish them. Deliver isolated writer/model tests now, report real database
verification as pending, and do not run historical schema-mutating fixtures
to bypass the user's ownership of migration and initialization:

- migration upgrade works from empty and every supported prior revision;
- model metadata, Alembic DDL, constraint names, types, defaults, nullability,
  indexes, triggers, and grants agree;
- IDs follow the selected validated non-sequential policy and never use a
  sequence, identity, `max(id)+1`, or hidden public sequence;
- a 2-character reason passes while a 1-character reason and values over 80 fail
  in both `validate_audit_reason()` and PostgreSQL;
- invalid domain/action relationships, outcomes, source/user presence, source types,
  user IDs, target-user/object consistency, entrypoints, schema versions, request IDs, non-object JSON, oversized JSON,
  and non-success `after_state` fail at the database boundary;
- action-specific allowed source types are enforced by the catalog-backed writer;
- catalog startup rejects unregistered or internally inconsistent actions;
- operation user/source, target user/object, entrypoint and request ID are
  derived from trusted server state;
- audit construction reads the bound context automatically, rejects missing or
  inactive context, and shares the entrypoint's ID across events and retries;
- action-specific typed field allowlists and recursive sensitive-key plus
  recognizable secret, email, and network-value guards run before ORM insertion;
- a successful business mutation, versions, idempotency completion, and mandatory
  event commit together exactly once;
- a forced audit validation, flush, constraint, or commit failure rolls back the
  successful business mutation and every tied row;
- denied and failed paths prove protected rollback completes before the separate
  audit transaction starts;
- a failed non-success audit cannot turn the original outcome into success;
- the savepoint variant commits required non-success evidence before returning;
- deadlock/serialization retry, response loss, and unknown commit outcome do not
  duplicate or mislabel an event;
- direct event `UPDATE`, `DELETE`, and `TRUNCATE`, plus ordinary application
  `SELECT`, fail under actual runtime roles;
- no audit soft-delete or restore columns/commands exist, and partition archival
  preserves the original event rows and append-only controls;
- database-generated timestamps are timezone-aware and request IDs correlate
  response, header, operational log, and audit event; and
- representative indexed queries use stable plans without adding speculative
  JSON indexes.

Report untested isolation, grant, migration, retry, savepoint, and production
volume assumptions. Passing unit tests alone does not prove PostgreSQL transaction
or append-only behavior.
