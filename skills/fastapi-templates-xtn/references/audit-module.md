# Durable Operation Audit Module

Read for account/permission audit models, safe input/result summaries, action
coverage and append-only requirements. Add [Atomic consistency](atomic-consistency.md)
for authorization transactions. [Operational logging](operational-logging.md)
owns ordinary request telemetry and the shared redaction implementation.
[Business audit](business-audit-module.md) is an opt-in product extension.

## Default Owners And Coverage

The default combines account-security and permission audit into one table and
one writer:

```text
operation_audit_events
app/models/postgres/operation_audit.py :: OperationAuditEvent
app/services/audit_service.py :: AuditService
```

Account operations cover registration, administrator creation, own-password
change and administrator reset. Permission operations cover user status/session
administration, role lifecycle, role-permission/user-role bindings and meaningful
denials. Registration and administrator creation each write one account event
covering the created user and default-role binding; shared creation does not
write a second permission event. Ordinary queries only write file logs.
Login/session state and arbitrary CRUD are not automatically audit events.

Audit is durable business/security evidence. Operational logs help diagnose
requests and exceptions; they do not replace a required audit insert. Optional
product events such as refunds have their own reviewed catalog and transaction
boundary. Their source resources remain in the Skill, excluded from default
model registration and project export.

## `operation_audit_events` Schema

| Column | Type | Contract |
| --- | --- | --- |
| `id` | varchar(22) | `OA` + `YYMMDDHHMMSSmm` China time + 6 random characters |
| `category` | varchar(16) | `account` or `permission`; business ownership, not a second table |
| `action` | varchar(120) | Stable machine action such as `role.permissions.bind` |
| `outcome` | varchar(16) | Exactly `succeeded`, `failed` or `denied` |
| `reason_code` | varchar(80) nullable | Stable internal reason; null when unnecessary; never localized text |
| `user_id` | varchar(15) nullable | Operation user's `U...` ID; null for anonymous or offline work |
| `target_user_id` | varchar(15) nullable | Affected user; may equal `user_id` for own-password changes |
| `target_role_id` | varchar(15) nullable | Affected role; null when no role is targeted |
| `source` | varchar(16) | `http`, `service`, `job`, `operator`, or `migration` |
| `request_data` | JSONB nullable | Bounded recursively redacted query/body summary |
| `response_data` | JSONB nullable | Safe business response snapshot, not delivery confirmation |
| `password_fingerprint` | varchar(32) nullable | New-password comparison fingerprint; never plaintext/database hash |
| `before_state` | JSONB nullable | Minimal allowlisted business state before a change |
| `after_state` | JSONB nullable | Minimal state staged for successful change; null on failure/denial |
| `request_id` | varchar(128) | Existing HTTP request or non-HTTP operation correlation ID |
| `created_at` | timestamptz | Database insertion time |

These are the 16 default fields. Do not add `schema_version`, `operator_type`,
service name or environment fields. Do not cascade live-user/role deletion into
audit history. Runtime user deletion remains soft. Historical published migrations
stay unchanged; the user reviews and executes any schema/data migration.

The writer reads the no-argument `core/audit.py::get_audit_request_id()`;
routes and Services do not forward an ID through every method. HTTP middleware
binds the server-generated UUIDv4 once, matching the response and `X-Request-ID`.
A CLI/job binds one safe operation ID and clears its context in `finally`.
Missing or inactive context raises `RuntimeError`, never a new unrelated ID.
Correlation IDs contain no username, email, Token/JTI or secret.

## Redacted Request And Response Summaries

Reuse the file logger's recursive allowlist and redaction owner rather than
introducing another sanitizer. Capture at most 16 KiB per request/response side;
safe summaries are limited to 4 KiB each. Non-JSON, incomplete or oversized
content records its omission reason. Preserve query/body separation, nesting
and safe identifiers/status/filter values. Unknown fields and free text are
hidden by default. Passwords, CAPTCHA answers, credentials, Tokens/JTIs,
Authorization and Cookie values never enter durable storage. The outer response
`message` may retain ordinary bounded business text under credential filtering;
nested/request free text remains hidden. These summary fields may contain the
safe `[REDACTED]` placeholder, never the original secret.

State snapshots retain their stricter reject-on-secret contract. Do not pass
request summaries through `sanitize_audit_state` or relax snapshot checks to
make raw request bodies fit. The writer only accepts shared-owner safe summaries
and validates their persistence shape and size.

For registration, administrator creation, administrator password reset and own
password change, reuse the independent `LOG_HMAC_KEY` new-password fingerprint:

```python
HMAC-SHA256(key, b"password\x00" + password_utf8).hexdigest()[:32]
```

Login/current passwords have no fingerprint. Fingerprints are irreversible
comparison data, not encryption or database password hashes. Identical input
under one key produces the same fingerprint; key rotation changes comparability.

`response_data` is the business result known before commit. It is not the exact
later HTTP envelope or proof that a client received it. Do not add a second
UPDATE or background response writer; file logs capture actual HTTP completion
and send failure. Non-HTTP operations keep request/result/fingerprint fields null
unless an approved adapter provides equivalent safe data. Unavailable request
bodies remain absent; audit capture does not actively read protected input ahead
of its dependencies.

Example administrator reset event (JSONC comments explain the stored fields):

```jsonc
{
  "id": "OA26101614302538172904", // 审计 ID：OA + 北京时间百分秒 + 六位随机字符。
  "category": "account", // 账号安全业务。
  "action": "account_security.password.admin_reset", // 稳定动作标识，不翻译。
  "outcome": "succeeded", // 与业务修改同事务保存，回滚则该行也不存在。
  "reason_code": null, // 成功无额外原因时为空。
  "user_id": "U7MQ2J9R4AV8K6N", // 操作管理员。
  "target_user_id": "U5N9B2LK7QR4X6D", // 被重置密码的用户。
  "target_role_id": null, // 没有操作角色。
  "source": "http", // HTTP 入口。
  "request_data": {
    "query": {},
    "body": {
      "user_id": "U5N9B2LK7QR4X6D",
      "new_password": "[REDACTED]",
      "captcha_id": "[REDACTED]",
      "captcha_answer": "[REDACTED]"
    }
  },
  "response_data": { // 提交前的业务响应，不是实际送达凭据。
    "code": 20000,
    "message": "密码重置成功",
    "data": null, // 密码重置成功，不返回密码或额外的修改标记。
    "request_id": "fc67559b-44db-472b-a718-99160e46b663"
  },
  "password_fingerprint": "9c04e72baf8136d025784a1ef930bc62", // 只比较新密码是否相同。
  "before_state": null, // 不保存密码或数据库密码哈希。
  "after_state": null,
  "request_id": "fc67559b-44db-472b-a718-99160e46b663", // 关联文件请求日志。
  "created_at": "2026-10-16T14:30:25.380+08:00" // 北京时间展示。
}
```

The response code/text above illustrates shape; persisted snapshots use the
actual operation's business result and locale, without claiming final delivery.

## Event Construction

Construct fields from trusted server context, authenticated identity, policy
results and post-lock state. There is no client-facing arbitrary audit-write API.
Fixed permission actions remain grouped as `RbacAuditAction`, account actions
as `AccountAuditAction`, in `app/core/audit.py`, with Chinese explanations.
Callers pass the named enum member itself; `AuditService` derives its category
and persists the existing string value. Stored action/reason values remain stable.
Dynamic `api.<route_name>` permission denials keep their existing validated
fallbacks. Offline commands remain excluded from generated projects.

Only two public writer methods are needed:

- `audit_success(session, action=..., context=..., ...)` stages a successful
  record in the caller's active transaction. The action enum determines
  `account`/`permission`; the trusted context determines the operation user and
  source. Anonymous registration has no operation user. Input summaries,
  new-password fingerprints and request ID are collected automatically.
  `message_key`/`data`/`code` supply the safe business response snapshot; the
  method neither commits nor sends an HTTP response.
- `await audit_denied(error=error, action=..., context=..., ...)` runs after business
  rollback. It derives the reason, failure/denial outcome and safe response from
  the original exception, uses a separate transaction and preserves that error
  if auditing fails. Server errors (`>=500`) do not become policy denials.

For example, code previously repeated construction and transport metadata:

```python
session.add(AuditService.build_event(
    category="account",
    action=AccountAuditAction.ADMIN_RESET_PASSWORD.value,
    user_id=context.login_info.user_id,
    source=context.audit_source,
    target_user_id=target_user_id,
    response_data=AuditService.response_snapshot(message_key=MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED),
))
```

The equivalent new caller supplies the business fact directly (existing imports
and the surrounding locked password mutation are omitted):

```python
self._audit.audit_success(
    session,
    action=AccountAuditAction.ADMIN_RESET_PASSWORD,
    context=context,
    target_user_id=target_user_id,
    message_key=MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED,
)
```

`user_role_transaction` yields only `session`; each business Service calls
`audit_success` after its mutation/result is known, before leaving that
transaction. The wrapper does not write success audits automatically or provide
an audit object to fill field by field. Its optional `target_user_id` and
`target_role_id` default to `None`; callers pass only actual targets.
Keep the outer session context around the inner transaction context so session
cleanup still runs if commit or rollback raises. The wrapper attempts the denied
audit only after the business session exits, in a separate transaction; failure
to write that audit preserves the original error.
Construction and response-summary helpers are private implementation details;
do not expose old wrappers or add a second action-to-metadata registry.

Use `outcome` to describe success/failure/denial, not a new action string for each
result. Use only reviewed minimal state projections: IDs, active/deleted flags,
role/permission keys, tiers and necessary versions. Do not serialize an ORM object,
request or exception wholesale. State limits remain 16 KiB, six nesting levels
and 100 collection entries. Reject credential/presentation fields and recognizable
credential values in state. An unsafe mandatory success payload rolls back the
mutation; replacing it with a silently incomplete state would hide the defect.

## Transaction Outcomes

| Outcome | Required behavior |
| --- | --- |
| Successful account/permission mutation | Mutation, versions and `succeeded` audit commit together or all roll back; staging the row alone is not success |
| Policy denial | Roll back protected work before writing a best-effort `denied` event in a separate transaction |
| Meaningful failed account command | Roll back first; use a safe error snapshot and `failed`; no `after_state` |
| Malformed input/ordinary query | File logs handle it; do not create domain evidence for every request |
| Infrastructure failure | Roll back/fail closed and emit safe operational telemetry; never invent a policy denial |

Denied/failure audit write errors emit safe `audit.write.failed` telemetry and
preserve the original rejection. Their separate transaction has an honest crash
gap. Stronger durability requires a separately approved outer transaction and
savepoint design, not a false claim about this baseline. Never perform Redis,
webhook, mail or other external I/O while holding authorization locks.

## Integrity And Database Access

The writer receives `INSERT`, not `UPDATE`, `DELETE` or `TRUNCATE`. The user
installs database guards rejecting row mutation and table truncation; ORM
metadata does not create those triggers. Audit rows have no soft-delete field.
This resists accidental application tampering, not a compromised database owner.

No default public audit read/write API is exposed. An explicitly requested review
API needs exact dedicated permission, indexed bounded filters, deterministic
`(created_at, id)` ordering, limited exports and reviewed visibility. Ordinary
administrators do not automatically receive audit access.

## Retention, Partitioning, And Recovery

Retention, archive, legal hold and optional stronger integrity controls belong
to the adopter's policy. A duration does not authorize deletion. Preserve event
IDs, interpretation and append-only controls in archives; exceptional destructive
retention requires separate explicit authority. Do not add archive workers or
operational infrastructure to this coding baseline.

Indexes support time/ID, request ID, operation-user/time and target/time lookups.
Add JSONB indexes only for demonstrated queries. Protect backups and make restore
checks part of the owner's operational process.

## Verification

Use focused offline tests for exactly 16 model fields, OA IDs, enum/category/
outcome validation, nullable reasons and identities, bounded recursive redaction,
new-password fingerprint restrictions and automatic request-ID correlation.
Verify one account creation event and absence of optional business audit from
the default registry/export. Test business mutation/audit transaction coupling,
rollback-before-denial and preservation of original errors on audit failure.
Database append-only/constraint checks require a user-prepared disposable
PostgreSQL environment; never create or migrate a database merely to obtain
ordinary task evidence. Report unavailable service checks separately.
