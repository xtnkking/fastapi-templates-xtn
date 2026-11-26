# Identifier Policy

Read this reference when adding a model, API ID, JWT subject or durable audit
record. The default project uses prefixed string IDs for business tables and
UUIDv4 for protocol identifiers. IDs are not secrets and never replace access
control.

## Default Table Contract

| Table | Format | Total length |
| --- | --- | ---: |
| `users` | `U` + 14 random uppercase letters or digits | 15 |
| `roles` | `R` + 14 random uppercase letters or digits | 15 |
| `permissions` | `P` + 14 random uppercase letters or digits | 15 |
| `user_roles` | `UR` + 13 random uppercase letters or digits | 15 |
| `role_permissions` | `RP` + 13 random uppercase letters or digits | 15 |
| `operation_audit_events` | `OA` + `YYMMDDHHMMSSmm` + 6 random characters | 22 |
| Optional `business_audit_events` | `BA` + `YYMMDDHHMMSSmm` + 6 random characters | 22 |

The random alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`, generated with
Python `secrets`, not `random`. Audit time is China local time. The last two time
digits `mm` are **hundredths of a second**, not three-digit milliseconds. For
example, `OA26092211414155317130` has prefix `OA`, time
`26092211414155`, and random suffix `317130`. The six random characters are
the default, not a claim that collisions are impossible. Use the database
primary key or unique constraint as the final guard and retry only a recognized
ID collision, at most a small fixed number of times, in a fresh savepoint or
transaction. Never pre-query a generated ID for uniqueness. A logical audit
event keeps one event ID across transaction retries so it can be recognized as
the same event. Sort by `(created_at, id)`; the ID timestamp does not replace
the database `created_at` value.

`UserService.create_user` generates new user IDs internally with
`new_entity_id("U")`; registration and administrator creation do not supply IDs.
Only a recognized `pk_users` collision regenerates the ID, for at most three
insertion attempts. Other constraint failures keep their existing error handling.

`app/core/ids.py` is the single maintenance point for ID lengths and patterns.
Its `ENTITY_ID_LENGTH` defaults to 15; `AUDIT_RANDOM_LENGTH` defaults to 6 and
`AUDIT_ID_LENGTH` derives the total audit length. The named `USER_ID_PATTERN`,
`ROLE_ID_PATTERN`, `PERMISSION_ID_PATTERN`, relationship patterns and audit
patterns, including `OPERATION_AUDIT_ID_PATTERN`, derive from these constants. Generation and exact validation,
`schemas/common.py` field types (`UserId`, `RoleId`, `PermissionId`), GET query types, ORM column lengths and
ORM CHECK expressions reference this same source. Do not repeat literal ID
regexes or lengths in these consumers. Audit time stays fixed at 14 digits;
changing its representation requires changing the time formatter too.

Incoming IDs must not
be silently uppercased. API schemas and query parameters validate the expected
entity prefix before lookup. An unknown but well-formed ID still receives the
normal authorization and non-leaking not-found treatment.

The entity length is a default, not a universal rule. If an adopter needs a
different scale, decide before creating tables and adjust `ENTITY_ID_LENGTH`
in `app/core/ids.py`. The generator, API validators, columns, foreign keys and
model check expressions derive from it when the application is imported.
This does not update an existing database: the adopter still reviews and applies
their own migrations. Existing
applications with a consistent non-sequential ID scheme need not be rewritten
just to adopt this default.

## PostgreSQL And Seed Boundary

Store business IDs as `String(15, collation="C")`, audit IDs as
`String(22, collation="C")`, with exact-format check constraints and primary
keys. Referencing business-ID columns use matching length and collation.
`user_roles` and `role_permissions` retain surrogate `UR` and `RP` IDs because
their soft-deleted relationship episodes have their own history. The default
asset supplies ORM models only; the adopter generates, reviews and applies
migrations and initial data. Historical migrations bundled as references are
not copied into generated projects and are not edited for this change.

The fixed `rbac_state.scope='global'`, optional country code, stable role keys
and stable permission keys are not generated business IDs. Do not add prefixes
to them. The first super administrator still requires the adopter's controlled
database binding; an ID generator does not create that authority.

## Protocol Boundary

- JWT `user_id` is the exact `U...` user ID. Never use a username, email, role ID or
  user-role relation ID as the subject. JWT `jti` remains a fresh UUIDv4 for
  each login and must still match the active Redis session.
- The server-generated `request_id`, CAPTCHA ID and structured-log `error_id`
  remain UUIDv4. Ordinary stdout log entries do not each get a new row ID.
- A business audit event ID is generated once for the logical operation with
  `new_audit_id("BA")`, passed in `BusinessAuditFacts.event_id`, and reused on
  any retry. The audit writer does not invent a replacement ID.
- Do not accept sequential integer IDs as primary, foreign or public lookup
  IDs. Version, retry count, tier and ordering fields are counters or
  values, not identifiers.

## Focused Verification

Verify exact prefix, length and alphabet for all six default ID-bearing tables and any optional business table, including a
fixed-time test for the 14-digit audit time segment. Verify model columns,
constraints and foreign keys, request validators, JWT subject and Redis active
JTI handling. Keep UUIDv4 checks for the four protocol IDs. Verify malformed,
wrong-prefix, wrong-length and lowercase inputs are rejected. A generated
project must contain the same ID contract as the canonical asset. A default
project generation task does not authorize access to PostgreSQL or Redis.
