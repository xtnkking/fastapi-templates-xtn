# Durable RBAC Audit Module

Read this reference when defining audit tables, privileged event coverage,
before/after snapshots, append-only controls, audit access, retention, export,
or alerts. Read
[Atomic authorization consistency](atomic-consistency.md) as well when an audit
event is tied to an authorization or protected business mutation. Use
[Operational logging](operational-logging.md) for request and failure telemetry.
Use [Business audit module](business-audit-module.md) instead for main-business
or account-security evidence.

## Audit Is Not Logging

An audit event is durable security or business evidence. It answers who or what
attempted an action, what protected target was involved, whether the action was
allowed or denied, why the policy decided that outcome, and which state changed.
It is stored under stricter write, read, retention, and integrity controls than
ordinary logs.

Do not treat an access log, analytics event, message-delivery record, distributed
trace, or JWT session record as an audit row. Do not use audit storage as a
debugging dump. Every event type needs a documented owner, trigger,
actor/target meaning, retention class, and safe field allowlist.

The fixed RBAC baseline keeps one deliberately narrow table:

```text
rbac_audit_events
```

It contains only access-control administration and decisions: role lifecycle,
role-permission/delegation changes, user-role binding, protected user status,
default-role provisioning, super-admin bootstrap or transfer, and relevant
denials. It is not a Token, login, proxy, or general application activity table.
When a product needs account-security or material business audit, follow the
separate business-audit contract. Do not silently broaden the meaning of
`rbac_audit_events`.

## `rbac_audit_events` Schema

The bundled asset uses this PostgreSQL shape:

| Column | Type | Contract |
| --- | --- | --- |
| `id` | UUID | Non-sequential event ID; application UUIDv4/default UUIDv4 |
| `actor_user_id` | UUID | Canonical actor ID; no email or username |
| `target_user_id` | UUID nullable | Affected user when applicable |
| `target_role_id` | UUID nullable | Affected role when applicable |
| `action` | varchar(120) | Stable lowercase machine event such as `role.permissions.bind` |
| `decision` | varchar(16) | Exactly `allowed` or `denied` |
| `reason_code` | varchar(80) | Stable internal lowercase reason code; not localized text |
| `source` | varchar(16) | `http`, `service`, `job`, `operator`, or `migration` |
| `schema_version` | smallint | Event payload version, currently exactly `1` |
| `before_state` | JSONB nullable | Minimal allowlisted state before an allowed change |
| `after_state` | JSONB nullable | Minimal allowlisted state after an allowed change |
| `request_id` | varchar(128) | HTTP UUIDv4 or safe non-HTTP operation correlation ID |
| `created_at` | timestamptz | Database creation time |

The actor and target UUID columns intentionally do not cascade. Audit history
must survive later lifecycle changes. If a separately approved product/legal
exception physically erases users, choose a documented pseudonymization strategy
that preserves referential audit meaning without retaining unnecessary personal
data; ordinary runtime deletion remains soft.

`request_id` equals the server-generated UUIDv4 in the response and
`X-Request-ID` for HTTP work. A CLI, job, migration, or operator action uses a
generated operation ID containing no email, username, Token/JTI, or secret.
`source` distinguishes those cases. Correlation IDs are not authentication or
idempotency credentials.

Example row:

```json
{
  "id": "fb3a4f75-399d-4460-9e7f-a97658e8e201",
  "actor_user_id": "9bb60ae3-cad9-4e07-b072-7f4336044f18",
  "target_user_id": "ea75240c-70a1-4379-813c-54ce7ad9f88e",
  "target_role_id": "4c922651-7fb8-44b4-846e-13ef3c2c963e",
  "action": "user.roles.bind",
  "decision": "allowed",
  "reason_code": "roles_bound",
  "source": "http",
  "schema_version": 1,
  "before_state": {"role_ids": ["a2a6d28b-65fb-43b7-ae3d-a3e8f37d6316"], "authz_version": 4},
  "after_state": {"role_ids": ["a2a6d28b-65fb-43b7-ae3d-a3e8f37d6316", "4c922651-7fb8-44b4-846e-13ef3c2c963e"], "authz_version": 5},
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-09-10T08:30:15.321Z"
}
```

Do not store a localized message in place of `action` or `reason_code`; those
fields are query contracts. When the payload shape changes, add a new
`schema_version` and keep readers able to interpret retained versions. Never
rewrite historical JSON to make it look as if an old event used a new schema.

## Event Construction

Construct events in an application-owned audit writer or service boundary. A
route must never accept an arbitrary audit event body from a client. The actor,
decision, source, request ID, target, reason, and snapshots come from trusted
server state after authentication and policy evaluation.

Use an explicit action catalog. The RBAC baseline includes shapes such as:

```text
user.provision
user.status.update
user.roles.bind
user.roles.unbind
role.create
role.update
role.enable
role.disable
role.delete
role.permissions.bind
role.permissions.unbind
role.delegation.bind
role.delegation.unbind
super_admin.bootstrap
super_admin.transfer
api.protected_write
```

An action describes the attempted operation; `decision` and `reason_code`
describe the outcome. Do not create different action strings by inserting IDs,
emails, route paths, or error text.

Build before/after state from an allowlist, not `model_dump()`, ORM `__dict__`, a
request body, or arbitrary exception context. Include only fields necessary to
reconstruct the security-relevant change, commonly IDs, active/deleted flags,
role keys, permission keys, tiers, and version counters. Bound each snapshot to
16 KiB, six nested levels, and 100 values per collection unless the product
deliberately adopts another tested limit.

Reject snapshots containing credential or identity-presentation fields such as:

```text
password, password_hash, secret, authorization, cookie, token, access_token,
id_token, jti, api_key, private_key, database_url, redis_url,
proxy_url, credentials, email, username
```

Also reject values with obvious Bearer credentials, credential-bearing URLs,
private-key headers, or `password`/`secret`/`token`/`api_key` assignments. This
is defense in depth; the snapshot still starts from an explicit field allowlist.

Do not merely redact an allowed mutation's audit state and continue. Rejecting
an unsafe required audit payload makes the allowed mutation roll back, exposing
the programming error before secrets enter durable history. A denied action
must remain denied even when its separate audit attempt fails; emit a safe
`audit.write.failed` operational event and alert instead.

## Transaction Outcomes

Use these defaults:

| Outcome | Required behavior |
| --- | --- |
| Allowed privileged mutation | Mutation, versions, and the allowed audit insert commit once or all roll back |
| Policy denial | Roll back protected work first, then write a denied event in a separate transaction |
| Validation failure before a meaningful privileged attempt | Do not create a domain audit row merely for malformed JSON; log/metric handles abuse |
| Infrastructure failure | Roll back/fail closed and emit operational telemetry; do not record a false policy denial |
| Read-only sensitive access | Audit only when product policy identifies the read/export as sensitive |

The separate denied-audit transaction has an honest crash gap. If the product
requires every returned denial to be durable, use the outer transaction plus
nested savepoint design in
[Atomic authorization consistency](atomic-consistency.md), test PostgreSQL and
ORM behavior, and return the denial only after the outer audit transaction
commits.

Do not send webhooks, alerts, Kafka messages, emails, or Redis writes while
holding authorization locks. External notifications are a separately designed
post-commit concern, not part of the RBAC audit transaction baseline. Denial
alerts observe a committed audit event or safe operational failure signal.

## Integrity And Database Access

Application database roles receive only the minimum required access. The audit
writer can `INSERT`; ordinary application code cannot `UPDATE`, `DELETE`, or
`TRUNCATE`.
Readers use a separate read-only role or narrowly authorized service. The asset
adds PostgreSQL triggers that reject row `UPDATE`/`DELETE` and table `TRUNCATE`
even if application code accidentally attempts them. Audit rows have no
soft-delete fields or restore operation; append-only is stronger than a
tombstone.

This is tamper resistance, not proof against a database owner or compromised
infrastructure administrator. Stronger requirements may add signed exports,
object-lock/WORM storage, separated security accounts, database audit tooling,
and monitored backups. Do not claim cryptographic immutability merely because a
trigger exists.

The baseline does not expose an audit-write API and does not expose audit rows
through the public API by default. This minimizes sensitive policy disclosure.
When the product needs an audit UI or API:

- add only `GET` list/detail/export operations;
- use a dedicated exact capability such as `access_audit_events:read`, granted
  only to `super_admin` by the fixed baseline and never delegable;
- apply the standard response envelope and simple pagination;
- support bounded indexed filters for time range, actor ID, target ID, action,
  decision, source, and request ID;
- use deterministic descending `(created_at, id)` ordering;
- cap export size or use a separately authorized asynchronous export job with
  controlled object storage;
- audit access and export according to the product's security policy; and
- never return secrets, internal stack traces, Tokens/JTIs, or fields that were
  not part of the event's safe schema.

Do not grant audit visibility to ordinary `admin` merely because it can manage
some lower users. Audit history can reveal protected identities, denied targets,
permission topology, and incident-response activity.

## Retention, Partitioning, And Recovery

Define retention from legal, security, privacy, and incident-response needs.
There is no universal correct number of days. Record the chosen period and the
owner who can approve legal hold, archive movement, and any exceptional
destructive policy. A retention period does not itself authorize deletion.

For a high-volume table, partition by `created_at` before volume makes migration
expensive. Archive old partitions intact to a protected archive schema,
tablespace, database, or immutable export while preserving event IDs, order,
payload versions, integrity controls, and review access. Do not drop, truncate,
soft-delete, or row-delete the source evidence under this baseline. Back up
audit history, test restore, protect backup access, and monitor insertion
failures, unexpected gaps, clock drift, trigger removal, and archival jobs.

Any eventual destructive retention is a separately approved product/legal
exception outside application runtime and outside this default. It requires an
explicit scope, authority, legal-hold check, verified durable archive where
required, backup/recovery decision, and independent audit or deployment record.
Never infer that authority from a generic retention duration.

Indexes must support the actual review paths without turning every possible JSON
field into an index. The baseline includes request ID, actor/time, target/time,
and `(created_at, id)`. Add JSONB indexes only for a proven query; arbitrary GIN
indexes increase write and storage cost.

## Review And Alerting

Define alerts from stable action/reason codes after events commit. High-signal
examples include:

- super-admin bootstrap or transfer;
- attempted system-role mutation;
- repeated peer/upward/self-elevation denials;
- permission or delegation changes on widely assigned roles;
- user suspension/reactivation by privileged actors;
- audit insert failure, append-only trigger changes, or archival failure; and
- unusual audit export or read volume.

Use time windows and actor/target aggregation to avoid one alert per ordinary
denial. An alert links to event IDs and request IDs but contains no before/after
payload unless the notification channel is approved for it.

## Verification

Run audit transaction and database tests against PostgreSQL. Cover:

- every privileged mutation's allowed and meaningful denied outcomes;
- exact actor, target, action, decision, reason, source, schema version, request
  ID, and timestamp semantics;
- HTTP response/header/log/audit request-ID correlation;
- allowed audit insertion failure rolling back the protected mutation;
- protected rollback completing before a denied-audit transaction begins;
- denied audit failure never converting denial into success;
- no allowed event on stale `expected_version`, validation failure, or rolled
  back mutation;
- safe snapshot allowlists, size/depth/item limits, and recursive rejection of
  secrets, JWT/JTI, credentials, email, and username;
- database constraints rejecting malformed source, action, reason, request ID,
  decision, schema version, and non-object state;
- PostgreSQL trigger rejection of direct `UPDATE`, `DELETE`, and `TRUNCATE`, and
  proof that no soft-delete path exists;
- stable indexed query plans for the product's review filters;
- runtime database roles lacking audit update/delete/truncate privileges;
- partition archival preserving every event under append-only controls, with any
  destructive exception separately approved and unreachable from runtime
  application roles; and
- backups and a representative restore preserving event ordering and payload
  versions.

Operational logs can confirm an audit write failed, but they cannot substitute
for the missing durable row. Report that residual explicitly whenever denied
auditing remains best effort.
