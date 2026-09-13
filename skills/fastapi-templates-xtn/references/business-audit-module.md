# Business Audit Module

Read this reference when a product needs durable evidence for important business
actions such as refunds, balance adjustments, approvals, sensitive exports,
destructive lifecycle changes, or security-relevant configuration changes. This
module is optional. Do not add it merely because an application has CRUD routes.

Use progressive loading:

| Need | Read |
| --- | --- |
| Decide whether and what to audit; define the catalog, safe fields, outcomes, and transaction behavior | This file only |
| Implement or change the PostgreSQL model, migration, writer, or caller-owned transaction | This file, then [Business audit PostgreSQL](business-audit-postgresql.md) |
| Add an audit review API, export, retention, partitioning, legal hold, alerts, backups, or recovery | This file, then [Business audit operations](business-audit-operations.md) |
| Audit an RBAC control-plane action | [RBAC audit module](audit-module.md), not this file |
| Promise immediate authorization revocation for a protected business write | This file, [Business audit PostgreSQL](business-audit-postgresql.md), then [Atomic authorization consistency](atomic-consistency.md) |

Do not load both detailed references unless the task spans both concerns. The
PostgreSQL reference owns executable DDL and transaction implementation. The
operations reference owns optional access and lifecycle operations. This file
owns the event-selection and event-meaning contract.

## Boundaries And Defaults

Keep the three evidence channels separate:

| Channel | Purpose | Persistence contract |
| --- | --- | --- |
| Operational logs | Diagnose requests, exceptions, dependencies, and performance | Operational telemetry; not durable business evidence |
| `rbac_audit_events` | Access-control administration and relevant authorization decisions | Append-only RBAC evidence under the RBAC catalog |
| Business audit | Important domain actions and their committed or rejected outcomes | Append-only domain evidence under an explicit business catalog |

Never put business activity into `rbac_audit_events`. Never use operational logs
as a substitute for a required business audit row. A request can produce both an
RBAC event and a business event only when they describe different facts, for
example a suspicious authorization decision and a refund command. Correlate them
with the same server request ID and do not duplicate the same fact.

For a single-domain service with one access and retention boundary, use:

```text
business_audit_events
```

Keep the same contract but split into named tables such as
`payment_audit_events` or `fulfillment_audit_events` when domains have materially
different legal retention, reader populations, encryption boundaries, volumes,
or ownership. Do not create one table per resource for naming preference. See
[Business audit operations](business-audit-operations.md) before mixing retention
or legal-hold classes in one partitioned table.

Business audit also does not represent login activity or authentication state.
When account security events need different readers or retention, give them a
separate catalog and table such as `account_security_audit_events`. Do not store
authentication material in any audit table.

## Decide What To Audit

An action belongs in the event catalog when at least one of these is true:

- it moves money, credits, quota, inventory, or another valuable balance;
- it approves, rejects, overrides, or reverses a controlled workflow;
- it exports or reveals a protected data set;
- it performs a destructive, restorative, or legally meaningful state change;
- it changes a security-relevant or high-impact product configuration;
- it invokes a privileged manual correction or impersonated business action;
- it creates an external commitment whose history may be disputed; or
- policy, contract, or regulation explicitly requires evidence.

Do not audit ordinary page views, health checks, list/search requests, form
validation, autocomplete, polling, cache refreshes, harmless reads, or every
routine create/update call. High-volume analytics belongs in analytics storage.
Debug details belong in operational telemetry. Audit only sensitive reads and
exports named by product policy.

Before implementation, create a version-controlled catalog. Every entry states:

- exact `action`, owning domain, and accountable product owner;
- trigger point and canonical resource type;
- allowed outcomes and stable reason codes;
- actor rules and required authorization capability;
- safe before/after/context field allowlists;
- whether the event is mandatory for transaction success;
- retention, read, export, and alert policy; and
- current payload `schema_version` plus retained-version compatibility.

Do not let routes invent action or reason strings dynamically. Removing or
renaming an action does not rewrite historical events. Change a payload shape by
incrementing `schema_version` and keep readers able to interpret retained
versions.

## Core Event Contract

The default table exposes these logical fields. Concrete PostgreSQL types,
constraints, indexes, and migration rules live in
[Business audit PostgreSQL](business-audit-postgresql.md).

| Field | Contract |
| --- | --- |
| `id` | Non-sequential event ID; UUIDv4 in the bundled PostgreSQL profile |
| `domain` | Stable lowercase catalog domain such as `payment` |
| `action` | Stable `[domain].[resource].[verb]` catalog key |
| `outcome` | Exactly `succeeded`, `failed`, or `denied` |
| `reason_code` | Catalog-owned lowercase machine reason, 2 to 80 characters |
| `actor_type` | `user`, `service`, `system`, `job`, or `operator` |
| `actor_id` | Canonical non-PII actor ID; required except for `system` |
| `resource_type` | Stable lowercase canonical resource type |
| `resource_id` | Canonical non-sequential affected resource ID |
| `source` | `http`, `service`, `job`, `operator`, or `migration` |
| `schema_version` | Positive payload version for the action |
| `before_state` | Minimal allowlisted state before the attempt or change, or null |
| `after_state` | Minimal allowlisted state after a committed success, or null |
| `context` | Small action-specific, server-owned allowlisted object |
| `request_id` | Server request ID or safe non-HTTP operation correlation ID |
| `created_at` | Database-generated insertion time |

Actor and resource IDs can be canonical UUIDs or validated prefixed business
IDs. They identify entities without copying email, username, display name, or
other presentation identity. Do not use cascading foreign keys from live users
or business resources; audit meaning must survive their lifecycle changes.

## Outcome Semantics

Use one outcome meaning everywhere:

| Outcome | Meaning | Required ordering |
| --- | --- | --- |
| `succeeded` | The exact audited business effect committed | Mutation and mandatory audit event commit together |
| `failed` | A meaningful command was attempted, but its intended effect did not commit because of domain state or an execution failure | Roll back first, then write a required failure event |
| `denied` | Authorization, ownership, row policy, or another explicit protection rejected the action before its effect | Roll back first, then write a required denial event |

`denied` is not a synonym for malformed input, an absent route, a programming
exception, timeout, or database outage. `failed` is not a reason to make every
HTTP error durable. Validation noise and unexpected infrastructure failures
normally stay in operational logs unless the catalog identifies the attempted
command as material evidence.

An intentional partial or compensating transition is not `failed` merely because
the wider workflow remains incomplete. Record the exact committed transition as
`succeeded` under an action that describes it. Never record `succeeded` before
commit. A `failed` or `denied` event cannot have `after_state` because the intended
state did not commit.

## Starter Event Catalog

Use only rows supported by the product. Remove unused rows and define exact
reason codes, capabilities, and state allowlists before implementation.

| Action | Audit when | Resource | Safe state examples |
| --- | --- | --- | --- |
| `order.order.cancel` | A user or operator attempts a controlled cancellation | `order` | status, cancellation category, version |
| `order.order.restore` | A previously cancelled order is restored | `order` | status, version |
| `payment.refund.request` | A refund request becomes durable | `refund` | amount in minor units, currency, status |
| `payment.refund.approve` | An approver allows or denies a refund | `refund` | status, approval policy code, version |
| `payment.refund.execute` | Refund execution reaches a durable local outcome | `refund` | amount in minor units, currency, status, provider result code |
| `ledger.balance.adjust` | An authorized manual balance correction is attempted | `account` | delta in minor units, currency, adjustment category, version |
| `workflow.review.override` | An operator overrides an automated or peer review | `review` | state, override category, policy version |
| `configuration.setting.update` | A high-impact product setting changes | `setting` | allowlisted typed value or value digest, version |
| `data.export.request` | A protected export is requested or denied | `export_job` | export type, bounded scope code, status |
| `record.record.soft_delete` | A protected record is soft-deleted | Product type | deleted flag, lifecycle state, version |
| `record.record.restore` | A protected record is restored | Product type | deleted flag, lifecycle state, version |

Do not use one generic `entity.update` event. A reviewer should understand the
business intent from the catalog key without parsing an arbitrary JSON diff.
Never place IDs, route paths, free text, or localized messages in `action`.

## Example Events

A committed refund approval:

```json
{
  "id": "65205d26-c48f-4f94-9852-f83670c5d24c",
  "domain": "payment",
  "action": "payment.refund.approve",
  "outcome": "succeeded",
  "reason_code": "approval_recorded",
  "actor_type": "user",
  "actor_id": "U7Q2M9PK4DX",
  "resource_type": "refund",
  "resource_id": "RF8J6K2N5XQ",
  "source": "http",
  "schema_version": 1,
  "before_state": {
    "status": "pending_review",
    "amount_minor": 12500,
    "currency": "USD",
    "version": 3
  },
  "after_state": {
    "status": "approved",
    "amount_minor": 12500,
    "currency": "USD",
    "version": 4
  },
  "context": {
    "approval_policy": "dual_control",
    "channel": "admin_console"
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-09-10T08:30:15.321Z"
}
```

A denied adjustment contains no protected state snapshot:

```json
{
  "id": "45e0e53d-9d8c-498c-b535-f39dffb14f4f",
  "domain": "ledger",
  "action": "ledger.balance.adjust",
  "outcome": "denied",
  "reason_code": "target_outside_scope",
  "actor_type": "user",
  "actor_id": "U4W8R6K3ZQM",
  "resource_type": "account",
  "resource_id": "AC7P5J9N2VT",
  "source": "http",
  "schema_version": 1,
  "before_state": null,
  "after_state": null,
  "context": {
    "required_capability": "balances:adjust"
  },
  "request_id": "74b655f4-3926-4718-b9ec-84eb9916f00e",
  "created_at": "2026-09-10T08:34:41.902Z"
}
```

## Trusted Event Construction

Expose a typed application-owned writer, never a generic client-facing write
endpoint. Route bodies cannot submit audit fields. Construct each field from a
trusted source:

- resolve `actor_type` and `actor_id` from authenticated server context;
- select action, outcomes, reason codes, and schema version from the compiled
  catalog;
- load resource type and ID from the authoritative domain object, not only an
  unverified request body;
- derive source from the trusted HTTP, service, job, operator, or migration
  adapter;
- use the server-generated request ID, or generate an equally safe operation ID
  for non-HTTP work;
- project snapshots from post-lock authoritative state through an action-specific
  allowlist; and
- let PostgreSQL generate `created_at`.

Use enums or literal types for catalog fields and one typed constructor per event
family. A repository may accept a fully validated event object, but not an
arbitrary dictionary assembled in a route. The writer may flush; only the caller
that owns the business transaction commits.

Retries preserve the logical command and request ID. Generate the event ID once
per logical command and reuse it across fresh transaction retries. A
replay-sensitive command also needs its own transactional idempotency record;
never store a raw `Idempotency-Key` in an event or snapshot.

## Safe Snapshots And Context

Snapshots preserve the minimum fact needed to understand a change. They are not
serialized models, arbitrary diffs, request bodies, response bodies, or exception
contexts. Use per-action typed projections and allowlists.

Reasonable values include canonical resource IDs, state enums, non-secret setting
keys, booleans, version counters, quantities, currency codes, money in integer
minor units, and stable non-personal category codes.

Apply all of these defenses before insertion:

- maximum 16 KiB for each state snapshot and 4 KiB for context;
- maximum six nested levels and 100 items in any collection;
- JSON objects only at the top level;
- bounded strings and finite numbers;
- rejection, not silent truncation, when a mandatory event violates its contract;
  and
- recursive sensitive-key inspection plus recognizable secret, email, and
  network-identifier value checks after allowlist projection.

Automated guards cannot reliably recognize every name, phone number, address,
or other personal datum. The primary privacy boundary is the typed per-action
projection and its reviewed field allowlist. Never approve a generic `contact`,
`metadata`, `details`, `message`, or free-text field on the assumption that the
sanitizer will discover every unsafe value inside it.

Never store direct personal data or presentation identity such as email,
username, display name, phone number, postal address, precise location, IP
address, user agent, free-form customer text, or unbounded notes. Canonical
internal actor and resource IDs are allowed only because they preserve event
meaning; do not copy their identity attributes.

Never store passwords or hashes, authorization headers, cookies, JWTs, JTIs, any
authentication Token, API keys, private keys, signing material, database or Redis
URLs, proxy credentials or URLs, encryption keys, raw request/response bodies,
arbitrary headers or query strings, payment-card or bank-account data, or
third-party credentials. Reject secret-looking key names and values even after
the allowlist projection.

For a sensitive configuration, store its key, type, version, and a non-reversible
keyed digest only when comparison is necessary. Keep the digest key outside the
database and rotate it under a documented scheme. Otherwise record only
`changed: true`.

## Transaction Decision Table

| Situation | Required behavior |
| --- | --- |
| Successful mandatory audited mutation | Business change, versions, audit row, and idempotency completion commit once or all roll back |
| Policy denial | Roll back all protected work, then write a required denied event in a separate transaction |
| Meaningful business failure | Roll back the intended effect, then write a catalog-required failed event in a separate transaction |
| Malformed request before a meaningful attempt | Do not add a business event; use the normal API response and operational telemetry |
| Infrastructure failure with known rollback | Fail closed; add a failed event only when the catalog makes that failure material evidence |
| Commit outcome unknown | Reconcile through idempotency or authoritative state; never guess `failed` and never blindly replay |

A failed audit insert for a mandatory successful action rolls back the business
mutation. A denied or failed event written after rollback has an honest crash gap;
failure to write that event never converts the original result to success. When
every returned denial or failure must be durable, use an outer PostgreSQL
transaction and nested savepoint, commit the event, and only then return.

Do not perform Redis, HTTP, broker, email, object-store, or other network I/O in
the database transaction. PostgreSQL cannot atomically commit with an external
system. Model queued, provider-confirmed, compensated, and reconciled transitions
as distinct facts; do not call a merely queued action successful at the provider.

Read [Business audit PostgreSQL](business-audit-postgresql.md) for caller-owned
transaction code, database constraints, append-only controls, migration steps,
and PostgreSQL tests. Read
[Business audit operations](business-audit-operations.md) only when review APIs,
retention, partitioning, legal hold, alerts, backups, or recovery are in scope.

## Core Verification

Verify the policy and event construction independently of PostgreSQL details:

- the catalog includes each required high-value action and excludes routine CRUD;
- every action has one domain owner, resource meaning, trigger point, outcome set,
  reason-code set, state/context allowlist, retention class, and schema version;
- actor, resource, source, action, reason, and request ID come from trusted server
  state rather than client-supplied audit fields;
- exact action and outcome semantics hold across HTTP, service, job, operator,
  and migration entry points;
- safe projections reject fields outside their action allowlist;
- size, depth, collection, string, and finite-number boundaries are tested;
- typed projections exclude direct personal data and presentation identity;
  recursive guards additionally reject forbidden key names, recognizable email
  and network identifiers, credentials, secrets, raw bodies, JWT/JTI values, and
  Tokens;
- successful, denied, failed, retry, and commit-unknown paths cannot misstate the
  durable business result;
- RBAC and business event catalogs do not accidentally duplicate the same fact;
- retained schema versions remain readable; and
- unimplemented product catalog, retention, or durability
  assumptions are reported rather than presented as verified.

Database correctness is incomplete until the PostgreSQL checks in
[Business audit PostgreSQL](business-audit-postgresql.md) pass. Operational
access and lifecycle guarantees are incomplete until the applicable checks in
[Business audit operations](business-audit-operations.md) pass.
