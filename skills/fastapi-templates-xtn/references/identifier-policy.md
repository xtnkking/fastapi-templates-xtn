# Non-Sequential Identifier Policy

Read this reference when defining a table, API identifier, JWT subject, RBAC
entity, session, audit record, seed, or migration from integer IDs. The default is
fixed so a greenfield implementation does not need an ID-strategy discussion.

## Fixed Baseline

Use a random UUIDv4 as the primary key and public API identifier for every user,
tenant, membership, role, authentication session, audit event, and business
entity. Generate it before dependent writes need the value. PostgreSQL stores it
as native `uuid`; Python uses `uuid.UUID`; JSON and JWT use its canonical
lowercase hyphenated string.

Do not use:

- `SMALLSERIAL`, `SERIAL`, `BIGSERIAL`, `GENERATED ... AS IDENTITY`, a
  sequence-backed integer primary key, or SQLAlchemy integer autoincrement;
- `max(id) + 1`, timestamps, short random numbers, array positions, row counts,
  or another predictable value as an identifier;
- a hidden sequential internal key exposed through a UUID alias, or an integer
  compatibility ID that remains accepted by a public lookup;
- a UUID deterministically derived from an old integer, email, username, phone,
  tenant slug, or other guessable/private source.

Integer `management_tier`, `version`, `epoch`, retry count, quantity, and display
ordering fields are counters or values, not identifiers, and remain integers. A
legally required invoice or order number may be sequential only as a separately
named, tenant-scoped display field with its own uniqueness rule. It is never the
primary key, foreign key, JWT subject, or sole authorization lookup.

Human-readable tenant slugs and permission keys such as `projects:read` are
intentional public names, not secrets. The included permission seed uses UUIDv5
derived from its public permission key for deterministic migration data. That
narrow non-sequential exception is acceptable only while the UUID is not exposed
as a security secret; use UUIDv4 for all user-controlled, tenant, session, audit,
and business rows.

## SQLAlchemy And PostgreSQL Shape

Use both an application default and a database default when rows may be inserted
outside SQLAlchemy. PostgreSQL's `gen_random_uuid()` is available in current
supported PostgreSQL versions; on an older supported version, enable `pgcrypto`
explicitly in a migration.

```python
import uuid

from sqlalchemy import ForeignKey, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
```

The equivalent Alembic column is explicit and has no integer sequence:

```python
sa.Column(
    "id",
    postgresql.UUID(as_uuid=True),
    server_default=sa.text("gen_random_uuid()"),
    nullable=False,
)
```

For pure association tables, prefer the meaningful composite UUID key rather
than adding a surrogate:

```python
sa.PrimaryKeyConstraint(
    "tenant_id", "membership_id", "role_id", name="pk_membership_roles"
)
```

If an association row later needs its own lifecycle or external reference, give
it a UUIDv4 ID; do not switch to an integer. Name foreign keys and add tenant-safe
composite constraints where the relationship must not cross tenants.

Create indexes for real access paths. Tenant-owned detail queries normally need
`(tenant_id, id)` support, and tenant lists need deterministic ordering such as
`(tenant_id, created_at, id)`. Do not sort by UUID and pretend it is creation
order. UUIDv4 index locality is the accepted security/default tradeoff; consider
another scheme only after measured database evidence and a documented leakage
review. UUIDv7 is not the default because it exposes approximate creation order.

## JWT And API Boundary

`sub` is exactly `str(users.id)` and never a membership ID, email, username, or
legacy integer. Parse path/body identifiers directly as `uuid.UUID`; reject
malformed values through normal validation. Do not reveal whether a syntactically
valid UUID exists before authentication, tenant resolution, capability checks,
and the tenant-scoped query.

UUIDs reduce trivial neighbor guessing, but they are not authorization. A leaked
UUID remains usable by an attacker unless every endpoint enforces tenant and
object policy. Preserve generic `404` behavior for missing and cross-tenant IDs,
rate-limit abuse, audit sensitive enumeration patterns, and test IDOR across
detail, list, search, count, export, bulk, and nested endpoints.

## Migration From Integer Identifiers

Do not replace a deployed primary key in one blocking step. Use an expand,
backfill, compatible-read/write, and contract migration:

1. Add nullable UUID columns to the parent and every referencing table. Give new
   parent writes UUIDv4 values; keep old and new applications compatible.
2. Backfill parent UUIDs in bounded batches with `gen_random_uuid()`. Add and
   validate uniqueness before using them as references.
3. Backfill child UUID foreign keys by joining to the parent's old key. Include
   `tenant_id` in the join and constraint wherever tenant ownership applies.
4. Add new UUID foreign keys as `NOT VALID`, validate them, dual-write during the
   compatibility window, and verify no null or orphaned mapping remains.
5. Switch internal queries, events, URLs, schemas, logs, JWT `sub`, and external
   integrations to UUID. Reject rather than silently truncate malformed values.
6. Stop returning and accepting the old integer. Make UUID columns non-null and
   move primary/foreign-key ownership in a planned maintenance or online schema
   procedure appropriate to table size.
7. Remove old integer keys, sequences, compatibility routes, and mapping columns
   only after the rollback window and all old workers, jobs, and tokens are gone.

Keep an explicit old-to-new mapping until migration verification completes. Do
not encode the old integer into the UUID; that preserves enumeration. Treat JWT
subject migration as a credential migration: expire or revoke old-subject tokens
rather than accepting both indefinitely.

## Required Verification

- Introspect every application-owned PostgreSQL table and fail if a primary key
  has an integer type, an identity property, or a `nextval(...)` default. Also
  inspect unique public aliases so a sequence is not hidden beside a UUID key.
- Create rows through both SQLAlchemy and direct SQL where supported, and prove
  generated identifiers are UUIDv4, unique, non-null, and round-trip as
  `uuid.UUID`.
- Assert every user, tenant, membership, role, session, audit, and business model
  uses native UUID columns; association keys and foreign keys use matching types.
- Test malformed UUIDs, random unknown UUIDs, another tenant's valid UUID, leaked
  UUIDs without permission, and every list/bulk/nested variant. Cross-tenant and
  missing objects must have the same observable response where concealment is
  required.
- For an integer-to-UUID migration, test empty upgrade, production-shaped
  backfill, mixed-version dual writes, constraint validation, rollback policy,
  old-token expiry, and removal of old integer lookup paths.

A PostgreSQL inspection query can detect the most common forbidden generators:

```sql
SELECT table_schema, table_name, column_name, data_type,
       is_identity, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND (
      is_identity = 'YES'
      OR column_default LIKE 'nextval(%'
  );
```

Combine this with primary-key metadata; the query alone does not find an integer
key populated manually or an application-generated sequence.
