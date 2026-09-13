# Business Audit Operations

Read this reference only when business audit events need review or export APIs,
retention, partitioning, legal hold, alerts, backups, or recovery. Read
[Business audit module](business-audit-module.md) first when the
event boundary or catalog is not already fixed. Read
[Business audit PostgreSQL](business-audit-postgresql.md) for the table, writer,
migration, append-only database controls, and transaction tests.

Operations must not weaken the core contract. `business_audit_events` remains
the append-only source of truth. Export jobs, legal-hold registries, indexes, and
alerts are supporting mechanisms, not audit evidence.

## Read And Export Access

Do not expose an audit-write API. Do not expose audit reads merely because the
table exists. When a product requires a review surface:

- expose only `GET` list, detail, and bounded export-status or download routes;
- require dedicated exact capabilities such as
  `business_audit_events:read` and `business_audit_events:export`;
- grant neither capability to ordinary users or ordinary `admin` by default;
- apply domain and resource visibility in addition to the exact capability;
- use the standard four-field response envelope and mandatory request ID;
- support bounded indexed filters for time, domain, action, outcome, actor ID,
  resource type and ID, source, and request ID;
- use deterministic descending `(created_at, id)` ordering;
- reject arbitrary JSONPath, SQL fragments, unbounded date ranges, and filters
  on fields that are not part of the stable event schema;
- cap synchronous pages and exports; use an authorized asynchronous export job
  for larger results; and
- return only fields approved for the caller's review role.

Audit visibility can reveal business volume, protected resource existence,
operator behavior, and incident activity. Capability to administer a domain does
not imply capability to read its audit history. Use non-leaking `404` behavior
when resource existence is protected.

Record a sensitive audit read or export only when the product catalog requires
it. Such an event may live in the business audit table because it describes a
distinct protected action. Do not recursively audit the audit writer, retention
job, or the internal read performed to construct that event.

For a large export, use this sequence:

1. Authorize the requested domain, time range, fields, and maximum size.
2. Create an export job and a cataloged `data.export.request` event in one
   transaction.
3. Let an idempotent worker read a fixed bounded snapshot and write encrypted
   output to the approved object store.
4. Persist only safe object metadata and a short expiry; never place a permanent
   public URL in the audit event.
5. Reauthorize download and emit the cataloged access event when required.

## Retention And Partitioning

Derive online and archive retention from legal, contractual, security, privacy,
and dispute needs. There is no universal correct number of days. If the product
has no approved policy, 365 days may be used only as a documented provisional
online-retention default that must be reviewed before production. Reaching that
age never authorizes destruction under this baseline.

Use monthly range partitions on `created_at` before volume makes conversion
expensive when at least one of these applies:

- online retention is enforced by time-based archival movement;
- expected volume is several million rows per year or more;
- review queries depend on time pruning; or
- bulk row deletion would exceed the maintenance window.

Create future partitions ahead of time. Decide explicitly whether unexpected
timestamps fail closed or enter a monitored default partition. Alert before the
next required partition boundary and on any default-partition growth.

Move closed partitions intact through a separately authorized archival workflow
to a protected archive schema, tablespace, database, or immutable export while
preserving event IDs, ordering, catalog versions, constraints, and review access.
Do not delete rows, truncate tables, drop partitions, or add a soft-delete path.
Do not put events with incompatible online retention or legal-hold requirements
in the same time partition; split domain tables or use a separately designed
archive boundary instead.

Any eventual destructive retention is a separately approved product/legal
exception outside runtime and outside this default. It requires explicit scope,
authority, legal-hold resolution, verified durable archive where required,
backup/recovery decisions, and an independent audit or deployment record. A
generic retention duration is not approval.

## Legal Hold And Privacy

Keep legal-hold state in a separately protected registry or archive workflow so
the original event stays append-only. A hold entry identifies an approved scope,
authority, start time, review time, and release decision by canonical IDs and
stable codes, without copying audit payloads.

An archival job resolves holds before moving a partition. If a held event shares
a partition with events ready to leave online storage, retain the whole
partition or copy the eligible scope to an approved immutable archive without
destroying the source evidence. Do not silently bypass retention or discard held
evidence.

Audit IDs preserve event meaning without storing presentation identity. When a
privacy erasure request affects an actor or resource, apply the product's
documented pseudonymization or access-restriction policy outside the immutable
row. Never rewrite old snapshots to pretend they were created under a newer
schema or privacy policy.

## Alerts And Review

Generate alerts only after the event commits. Build them from stable catalog
actions, outcomes, and reason codes, not free text. High-signal examples include:

- repeated denied balance adjustments, refunds, exports, or manual overrides;
- product-defined unusually large or frequent corrections;
- bulk destructive actions or restores;
- high-impact configuration changes;
- external commitments stuck in a pending or ambiguous state;
- audit insert, partition, retention, append-only control, or export failures;
  and
- unusual audit-read or export volume.

Aggregate by actor, action, resource, and time window so ordinary events do not
produce one alert each. A notification contains event IDs and request IDs only.
Do not include snapshots, direct personal data, credentials, JWT/JTI values,
exception text, or provider responses unless the destination has a separately
approved data contract.

Define an owner and response playbook for every alert. An alert with no owner,
threshold rationale, suppression rule, or recovery action is operational noise,
not an audit control.

## Backup And Recovery

Back up event tables, catalog versions, and legal-hold state.
Restrict and monitor backup access, encrypt storage, separate deletion authority,
and define recovery-point and recovery-time objectives from the actual evidence
requirement.

Test a representative restore instead of relying on backup-job success. Verify:

- event counts and deterministic `(created_at, id)` ordering;
- payload schema versions and catalog interpretation;
- append-only trigger and database grants after restore;
- partition constraints and future partition creation;
- held-event preservation; and
- correlation by request ID without exposing forbidden fields.

A trigger is only tamper resistance. It cannot prevent a database owner,
superuser, storage administrator, disabled trigger, or compromised backup
operator from changing evidence. Stronger requirements need separated
administration, monitored database auditing, signed exports, protected backups,
or object-lock storage. Do not claim cryptographic immutability unless that
separate mechanism is implemented and verified.

## Operations Verification

Exercise the selected production profile rather than claiming every optional
control. Cover at least:

- a mandatory succeeded event and its business mutation commit or roll back
  together;
- list, detail, and export enforce exact capabilities plus domain/resource
  visibility and non-leaking resource behavior;
- filters and time ranges are bounded, ordering is deterministic, and query
  plans use the intended indexes at representative volume;
- synchronous export caps and asynchronous export authorization hold;
- sensitive audit reads and exports produce any required event without
  recursive internal-read events;
- runtime writers cannot update, delete, truncate, or soft-delete event rows,
  and the approved archival path preserves every event rather than dropping
  expired partitions;
- future partitions, unexpected timestamps, default-partition alerts, and clock
  monitoring work under the deployment timezone and database settings;
- legal holds prevent archival movement when required and their release path is
  separately authorized;
- backup access is restricted and a restore preserves ordering, constraints,
  catalog versions, and holds; and
- online retention, archival, any separately approved destructive exception,
  export, backup, and alert behavior matches the policy approved for the actual
  product.

Report which database roles, retention approvals, legal-hold workflow, partition
volume, alert channel, backup system, and restore path were not exercised.
Operational logs cannot replace missing durable audit rows.
