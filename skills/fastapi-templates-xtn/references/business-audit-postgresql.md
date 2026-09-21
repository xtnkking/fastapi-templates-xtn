# Business Audit PostgreSQL

Read [Business audit module](business-audit-module.md) first. Read this reference
only when implementing or changing the PostgreSQL table, SQLAlchemy model,
catalog-backed writer, migration, caller-owned transaction, or database tests.
For read APIs, export, retention, partitioning, legal hold, alerts, backups, or
recovery, load
[Business audit operations](business-audit-operations.md) separately.

This reference owns database implementation. The core reference owns which
events exist and what they mean. Do not invent a catalog while writing a
migration.

## PostgreSQL Baseline

The single-table baseline uses application-generated random UUIDv4 event IDs.
A project with a registered prefixed-ID policy may substitute its validated
non-sequential audit ID type consistently in the model, migration, writer, and
tests. Actor and resource IDs are bounded strings so they can hold canonical
UUIDs or prefixed business IDs without storing presentation identity.

Use explicit named constraints and indexes. The `reason_code` expression below
requires 2 to 80 characters and intentionally matches the shared
`validate_audit_reason()` contract.

```sql
CREATE TABLE business_audit_events (
    id uuid PRIMARY KEY,
    domain varchar(64) NOT NULL,
    action varchar(120) NOT NULL,
    outcome varchar(16) NOT NULL,
    reason_code varchar(80) NOT NULL,
    actor_type varchar(16) NOT NULL,
    actor_id varchar(128),
    resource_type varchar(64) NOT NULL,
    resource_id varchar(128) NOT NULL,
    source varchar(16) NOT NULL,
    schema_version smallint NOT NULL,
    before_state jsonb,
    after_state jsonb,
    context jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_id varchar(128) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT ck_business_audit_id_uuid4 CHECK (
        id::text ~
        '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT ck_business_audit_domain_format CHECK (
        domain ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    CONSTRAINT ck_business_audit_action_format CHECK (
        action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$'
        AND length(action) <= 120
    ),
    CONSTRAINT ck_business_audit_action_domain CHECK (
        split_part(action, '.', 1) = domain
    ),
    CONSTRAINT ck_business_audit_outcome CHECK (
        outcome IN ('succeeded', 'failed', 'denied')
    ),
    CONSTRAINT ck_business_audit_reason_format CHECK (
        reason_code ~ '^[a-z][a-z0-9_]{1,79}$'
    ),
    CONSTRAINT ck_business_audit_actor_type CHECK (
        actor_type IN ('user', 'service', 'system', 'job', 'operator')
    ),
    CONSTRAINT ck_business_audit_actor_presence CHECK (
        (actor_type = 'system' AND actor_id IS NULL)
        OR (actor_type <> 'system' AND actor_id IS NOT NULL)
    ),
    CONSTRAINT ck_business_audit_actor_id_format CHECK (
        actor_id IS NULL OR actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'
    ),
    CONSTRAINT ck_business_audit_resource_type_format CHECK (
        resource_type ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    CONSTRAINT ck_business_audit_resource_id_format CHECK (
        resource_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'
    ),
    CONSTRAINT ck_business_audit_source CHECK (
        source IN ('http', 'service', 'job', 'operator', 'migration')
    ),
    CONSTRAINT ck_business_audit_schema_version CHECK (schema_version > 0),
    CONSTRAINT ck_business_audit_before_object CHECK (
        before_state IS NULL OR jsonb_typeof(before_state) = 'object'
    ),
    CONSTRAINT ck_business_audit_after_object CHECK (
        after_state IS NULL OR jsonb_typeof(after_state) = 'object'
    ),
    CONSTRAINT ck_business_audit_context_object CHECK (
        jsonb_typeof(context) = 'object'
    ),
    CONSTRAINT ck_business_audit_before_size CHECK (
        before_state IS NULL OR octet_length(before_state::text) <= 16384
    ),
    CONSTRAINT ck_business_audit_after_size CHECK (
        after_state IS NULL OR octet_length(after_state::text) <= 16384
    ),
    CONSTRAINT ck_business_audit_context_size CHECK (
        octet_length(context::text) <= 4096
    ),
    CONSTRAINT ck_business_audit_non_success_after CHECK (
        outcome = 'succeeded' OR after_state IS NULL
    ),
    CONSTRAINT ck_business_audit_request_id_format CHECK (
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    )
);

CREATE INDEX ix_business_audit_created
    ON business_audit_events (created_at DESC, id DESC);
CREATE INDEX ix_business_audit_domain_created
    ON business_audit_events (domain, created_at DESC, id DESC);
CREATE INDEX ix_business_audit_actor_created
    ON business_audit_events (actor_id, created_at DESC, id DESC)
    WHERE actor_id IS NOT NULL;
CREATE INDEX ix_business_audit_resource_created
    ON business_audit_events (
        resource_type, resource_id, created_at DESC, id DESC
    );
CREATE INDEX ix_business_audit_request
    ON business_audit_events (request_id);
CREATE INDEX ix_business_audit_action_outcome_created
    ON business_audit_events (action, outcome, created_at DESC, id DESC);
```

These are defense-in-depth constraints, not the event catalog. PostgreSQL cannot
prove that an action is registered, that its reason belongs to that action, or
that a JSON field is allowed for that action. The typed application writer must
enforce those catalog relationships before insertion.

Do not add an `ON DELETE CASCADE` foreign key from users or domain resources.
Audit meaning survives their lifecycle changes. The default deliberately has no
such foreign key. Add only indexes used by real review queries; arbitrary JSONB
GIN indexes add substantial write and storage cost.

## Asset Adaptation

The bundled PostgreSQL asset separates shared audit safety from RBAC and business
tables:

- `app/core/audit.py` owns `AuditSource`, JSON sanitization, bounded depth and size,
  sensitive key/value rejection, and action/reason/request-ID validators;
- `app/core/business_audit.py` owns actor/outcome types, `BusinessAuditActionSpec`,
  trusted event facts, and pure catalog/payload validation;
- `app/models/business_audit.py` owns the `BusinessAuditEvent` table and constraints;
- `app/services/business_audit.py` owns the transaction-aware `BusinessAuditWriter`;
- `alembic/env.py` imports the model so Alembic sees it on shared metadata;
- the Alembic revisions create constraints, indexes, and append-only controls;
- unit tests exercise catalog and sanitizer behavior; and
- PostgreSQL integration tests prove transaction and trigger behavior.

Copy the complete asset according to the Skill entrypoint, then adapt only the
catalog and business call sites. Do not copy the writer without its migration,
shared sanitizer, model import, and tests. Do not turn the reusable writer into
an HTTP audit-write route.

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
        resource_type="refund",
        schema_version=1,
        allowed_outcomes=frozenset(
            {
                BusinessAuditOutcome.SUCCEEDED,
                BusinessAuditOutcome.FAILED,
                BusinessAuditOutcome.DENIED,
            }
        ),
        actor_types=frozenset({BusinessAuditActorType.USER}),
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

business_audit = BusinessAuditWriter(
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
state. Do not pass a request body's user ID, resource type, action, outcome,
reason, source, or snapshots directly into the writer.

```python
facts = BusinessAuditFacts(
    event_id=uuid.uuid4(),
    action="payment.refund.approve",
    actor=BusinessAuditActor(
        actor_type=BusinessAuditActorType.USER,
        id=str(authenticated_user.id),
    ),
    resource_id=str(refund.id),
    reason_code="approval_recorded",
    source=AuditSource.HTTP,
    request_id=request_context.request_id,
    before_state=refund_audit_projection(before_refund),
    after_state=refund_audit_projection(after_refund),
    context={
        "approval_policy": policy.code,
        "channel": "admin_console",
    },
)
```

The action specification supplies `domain`, `resource_type`, allowed outcomes,
reason codes, state/context field sets, and schema version. This prevents a call
site from relabeling the same facts. The writer validates and sanitizes before
constructing the ORM row.

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
                command.actor,
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
                    actor=actor_from_authenticated_context(command.actor),
                    resource_id=str(current.id),
                    reason_code="approval_recorded",
                    source=command.audit_source,
                    request_id=command.request_id,
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

Application audit writers receive `INSERT`, not `UPDATE`, `DELETE`, or `TRUNCATE`.
Reviewers use a separate read-only role or narrowly authorized service. Add a
trigger as defense in depth:

```sql
CREATE FUNCTION reject_business_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'business audit events are append-only';
END;
$$;

CREATE TRIGGER trg_business_audit_no_update_delete
BEFORE UPDATE OR DELETE ON business_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_business_audit_mutation();

CREATE TRIGGER trg_business_audit_no_truncate
BEFORE TRUNCATE ON business_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_business_audit_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON business_audit_events FROM app_writer;
```

Use the deployment's actual role names and verify grants after migration. The
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

## Migration Sequence

Use Alembic, never runtime `create_all()`:

1. Register the business audit model on the same metadata Alembic imports.
2. Create the table with all named constraints and no sequential default.
3. Create only the baseline review indexes needed by the intended query surface.
4. Create the append-only function and update/delete plus truncate triggers.
5. Apply actual writer and reader role grants after those roles exist.
6. Seed no product events; the catalog is code, not mutable database content.
7. Run upgrade from an empty database and each supported prior revision.
8. Inspect PostgreSQL defaults to prove no sequence or identity was introduced.
9. Exercise downgrade only in a disposable database; dropping an audit table in
   production is destructive and must not be an ordinary rollback procedure.

If replacing a pre-existing business audit table, validate and quarantine legacy
rows before applying stricter constraints. Never rewrite old evidence to resemble
a new schema version. Use a new table or an explicit versioned import event when
legacy rows cannot satisfy the new contract.

Do not switch the baseline table to partitioning by adding `PARTITION BY` to this
DDL. PostgreSQL partitioned unique and primary-key constraints must include the
partition key, which changes event-ID uniqueness and lookup/index design. Read
[Business audit operations](business-audit-operations.md) and choose the
partitioned shape before production data exists.

## PostgreSQL Verification

Run these checks against PostgreSQL; SQLite cannot establish them:

- migration upgrade works from empty and every supported prior revision;
- model metadata, Alembic DDL, constraint names, types, defaults, nullability,
  indexes, triggers, and grants agree;
- IDs are UUIDv4 or the selected validated non-sequential policy and never use a
  sequence, identity, `max(id)+1`, or hidden public sequence;
- a 2-character reason passes while a 1-character reason and values over 80 fail
  in both `validate_audit_reason()` and PostgreSQL;
- invalid domain/action relationships, outcomes, actor presence, actor types,
  sources, IDs, schema versions, request IDs, non-object JSON, oversized JSON,
  and non-success `after_state` fail at the database boundary;
- action-specific allowed actor types are enforced by the catalog-backed writer;
- catalog startup rejects unregistered or internally inconsistent actions;
- actor, resource, source, and request ID are derived from trusted server state;
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
