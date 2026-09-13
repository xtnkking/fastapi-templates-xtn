# Non-Sequential Identifier Policy

Read this reference when defining a table, public identifier, JWT subject,
RBAC entity, audit record, seed, or migration from sequential IDs. The policy
prevents enumerable identifiers without forcing an established project to
replace one safe non-sequential scheme with another.

## Decision Rule

Use this order:

1. Preserve an existing, consistently enforced non-sequential identifier scheme
   unless the user requests a migration or repository evidence shows it is
   unsafe.
2. For a new project with no established scheme, prefer a typed business ID made
   from an entity prefix and a cryptographically random uppercase suffix.
3. Random UUIDv4 remains fully compliant. The bundled PostgreSQL asset uses
   native UUIDv4 entity IDs because changing a published schema, URLs, JWT
   subjects, Redis records, resource-version contracts, and foreign keys requires a coordinated
   versioned migration.

Do not tell a user that UUID is mandatory. Prefix IDs improve recognition in
logs and support work; UUIDv4 offers broad library and native PostgreSQL support.
Both are identifiers, not authorization secrets.

## Preferred Prefix Format

For a new business namespace, use:

```text
<registered uppercase prefix><random uppercase suffix>
```

Use the Crockford Base32 suffix alphabet:

```text
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

It contains digits and unambiguous uppercase letters. Generate the suffix with
a CSPRNG such as Python `secrets.choice`. Never derive it from a counter,
timestamp, email, username, phone number, old integer ID, or another business
value. The prefix identifies the entity type and contributes no random entropy.

Keep a central prefix registry. A reasonable starting registry is:

| Entity | Prefix | Example profile |
| --- | --- | --- |
| User | `U` | `U` plus the selected suffix length |
| Role | `R` | `R` plus the selected suffix length |
| Permission | `P` | `P` plus the selected suffix length |
| RBAC audit event | `A` | `A` plus the selected suffix length |

Add a distinct stable prefix for each business entity, such as `O` for an order.
Do not reuse one prefix for unrelated types merely because they share a table.
Keep prefixes short, uppercase, and immutable after public IDs exist.

### Choose Length From Lifetime Volume

Size each namespace by the total number of IDs expected to be generated over
the product's lifetime, including deleted rows. Do not size it from the current
row count. Use these defaults so the adopter normally does not need to design a
scheme:

| Expected lifetime IDs in one prefix namespace | Random suffix | Example user shape |
| ---: | ---: | --- |
| Up to `100,000` | `10` characters | `U` + 10 characters |
| Up to `1,000,000` | `12` characters | `U` + 12 characters |
| Up to `100,000,000` | `16` characters | `U` + 16 characters |
| Above `100,000,000` or very high-volume events | `20` characters | `U` + 20 characters |

When volume is unknown, default to a 16-character suffix. A user ID shaped as
`U` plus 10 random characters is a valid low-volume example, not a universal
default. The database uniqueness constraint and bounded collision retry remain
required at every length.

JWT `jti`, request IDs, and other protocol identifiers do not need a business
prefix. A fresh random UUIDv4 remains the baseline for Access Token JTI values.

## Reusable Python Shape

Centralize generation and validation instead of scattering string construction:

```python
import re
import secrets
from dataclasses import dataclass

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@dataclass(frozen=True, slots=True)
class BusinessIdSpec:
    prefix: str
    suffix_length: int

    def __post_init__(self) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9]{0,3}", self.prefix) is None:
            raise ValueError("prefix must start with A-Z and be 1-4 alphanumerics")
        if self.suffix_length not in {10, 12, 16, 20}:
            raise ValueError("suffix length must use an approved volume tier")

    @property
    def pattern(self) -> re.Pattern[str]:
        alphabet = re.escape(ALPHABET)
        return re.compile(
            rf"{re.escape(self.prefix)}[{alphabet}]{{{self.suffix_length}}}"
        )


USER_ID = BusinessIdSpec(prefix="U", suffix_length=16)
ROLE_ID = BusinessIdSpec(prefix="R", suffix_length=12)
PERMISSION_ID = BusinessIdSpec(prefix="P", suffix_length=12)
AUDIT_ID = BusinessIdSpec(prefix="A", suffix_length=20)


def new_business_id(spec: BusinessIdSpec) -> str:
    suffix = "".join(secrets.choice(ALPHABET) for _ in range(spec.suffix_length))
    return f"{spec.prefix}{suffix}"


def parse_business_id(value: str, spec: BusinessIdSpec) -> str:
    if spec.pattern.fullmatch(value) is None:
        raise ValueError("identifier has the wrong prefix, alphabet, or length")
    return value
```

Do not silently uppercase or otherwise normalize an incoming ID. Reject a
non-canonical value so caches, signatures, database lookups, logs, and equality
checks all use one representation. Use entity-specific types or validators so a
role ID cannot accidentally be passed where a user ID is required.

## PostgreSQL Shape

Store a prefixed ID as a constrained string with the exact entity format, a
primary key or unique constraint, and byte-stable collation. For a 16-character
user suffix:

```python
from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "id ~ '^U[0-9A-HJKMNP-TV-Z]{16}$'",
            name="user_id_format",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(17, collation="C"),
        primary_key=True,
        default=lambda: new_business_id(USER_ID),
    )
```

All foreign-key columns use the same type, length, and collation. Give every
constraint a stable name. An application default is appropriate because a
business prefix registry belongs to application policy; direct SQL writers must
either call an approved database generator or provide an already valid ID.

Generate and insert directly. Do not perform a race-prone "check then insert".
On a collision, retry only when the database error names the expected primary
key or ID uniqueness constraint, and stop after a small fixed number such as
three attempts. Re-raise every other integrity failure unchanged.

For pure association tables, prefer a meaningful composite key such as
`(user_id, role_id)` rather than adding a surrogate ID. If an association later
needs its own lifecycle or public reference, give it a non-sequential ID under
the same policy.

Chronological lists need deterministic ordering such as `(created_at, id)`.
Never treat a random suffix or UUID as creation order. Keep one canonical byte
order for lock sorting in both Python and PostgreSQL; uppercase ASCII with `C`
collation makes prefixed-string ordering predictable.

## UUIDv4 Compatibility Profile

When UUIDv4 is selected or already established, use native PostgreSQL `uuid`,
Python `uuid.UUID`, canonical lowercase hyphenated JSON strings, application
`uuid.uuid4()` generation, and `gen_random_uuid()` for approved direct database
writes. Deterministic UUIDv5 is acceptable only for a version-controlled seed
whose stable source key is already public. It must never encode a private or
sequential source.

The bundled `assets/postgresql-rbac` implementation intentionally remains on
this valid UUIDv4 profile. Do not rewrite its published `0001` or `0002`
migrations merely to adopt prefixes. A deployed conversion requires a new
versioned migration and coordinated handling of foreign keys, URLs, JWT `sub`,
Redis active-JTI values, resource-version values, events, logs, and external
integrations.

## Forbidden Identifier Designs

Do not use:

- `SMALLSERIAL`, `SERIAL`, `BIGSERIAL`, `GENERATED ... AS IDENTITY`, a
  sequence-backed integer primary key, or application integer autoincrement;
- `max(id) + 1`, timestamps, short random numbers, array positions, row counts,
  or another predictable value as an identifier;
- a hidden sequential internal key exposed through a random alias while the
  integer remains accepted by a public lookup;
- an ID derived from an email, username, phone number, business secret, or old
  integer; or
- a prefix with an undersized suffix justified only by the presence of a unique
  constraint.

Integer `management_tier`, `version`, `epoch`, retry count, quantity, and display
ordering fields are values or counters, not identifiers. A legally required
invoice number may be sequential only as a separately named display field. It
must not be the primary key, foreign key, JWT subject, or sole authorization
lookup.

## JWT And API Boundary

JWT `sub` is the canonical string form of the immutable `users.id` selected by
the project. For a prefixed profile it is the exact validated `U...` value; for
the bundled UUID profile it is the canonical UUIDv4 string. Never use email,
username, a role-assignment ID, or a legacy integer as `sub`.

Validate path, body, event, and token IDs with the entity-specific parser before
lookup. Do not reveal whether a syntactically valid ID exists before
authentication, capability checks, and row policy. Non-sequential IDs reduce
casual enumeration; they do not replace authorization. Preserve non-leaking
`404` behavior where required, rate limits, audit signals, and IDOR tests across
detail, list, search, count, export, bulk, and nested operations.

## Migration From Sequential IDs

Do not replace a deployed primary key in one blocking step. Use an expand,
backfill, compatible-read/write, and contract migration:

1. Select and document the target prefix or UUIDv4 profile. Freeze its format
   before generating any externally visible value.
2. Add nullable new-ID columns to every parent and referencing table. Generate
   new parent values under the target policy while old and new applications
   coexist.
3. Backfill parents in bounded batches, add uniqueness, and backfill children by
   joining through the old key. Verify the mapping is complete and unambiguous.
4. Add new foreign keys as `NOT VALID`, validate them, dual-write during the
   compatibility window, and prove no null or orphaned mapping remains.
5. Switch queries, events, URLs, schemas, logs, JWT `sub`, Redis values, and
   external integrations. Reject malformed values rather than truncating or
   normalizing them.
6. Stop returning and accepting the old integer. Make new columns non-null and
   move primary/foreign-key ownership using a procedure appropriate to table
   size.
7. Remove old keys, sequences, compatibility routes, and mapping columns only
   after the rollback window and all old workers, jobs, caches, and tokens are
   gone.

Keep an explicit old-to-new mapping until verification completes. Treat JWT
subject conversion as a credential migration: expire or revoke old-subject
tokens instead of accepting both formats indefinitely.

## Required Verification

- Inspect every application-owned PostgreSQL table and reject integer primary
  keys, identity properties, `nextval(...)` defaults, and sequential public
  aliases.
- For each prefixed namespace, test the exact prefix, alphabet, length,
  uppercase-only rule, application generation, direct-SQL constraint, foreign
  keys, uniqueness, and bounded retry on only the named ID constraint.
- For UUIDv4 namespaces, test version, canonical serialization, database type,
  uniqueness, and direct-database generation where supported.
- Test malformed, wrong-prefix, wrong-length, lowercase, random unknown, leaked,
  concealed, and unauthorized IDs through every lookup variant.
- For a migration, test empty upgrade, production-shaped backfill, mixed-version
  writes, constraint validation, rollback policy, old-token expiry, and removal
  of all old integer lookup paths.

Use both column and key metadata; checking sequence defaults alone does not find
an integer key populated manually.
