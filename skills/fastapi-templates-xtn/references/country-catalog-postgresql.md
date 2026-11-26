# Country Catalog PostgreSQL Implementation

Read [Optional country catalog](country-catalog.md) first. Use this reference only
when the requested deliverable includes a SQLAlchemy model, database handoff,
CSV import feature, read API, or tests. Adapt package imports and existing
components without weakening the contract. The user generates, reviews and
executes migrations, creates the schema, and initializes data themselves.

This is an integration shape, not another default module inside the bundled RBAC
asset. Do not wire it into an application that did not request a country catalog.

## SQLAlchemy Model

Use the application's declarative `Base` and naming convention. The model has no
synthetic ID and no relationship that can cascade-delete business data:

```python
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.postgres.base import Base


class Country(Base):
    __tablename__ = "countries"
    __table_args__ = (
        CheckConstraint(
            "country_code ~ '^[A-Z]{2}$'",
            name="ck_countries_country_code",
        ),
        CheckConstraint(
            "calling_code ~ '^[1-9][0-9]{0,2}$'",
            name="ck_countries_calling_code",
        ),
        CheckConstraint(
            "btrim(name_zh) <> '' AND btrim(name_en) <> ''",
            name="ck_countries_names_nonempty",
        ),
        CheckConstraint("version >= 0", name="ck_countries_version_nonnegative"),
        CheckConstraint(
            "flag_url IS NULL OR flag_url ~ '^https://'",
            name="ck_countries_flag_https",
        ),
        CheckConstraint(
            "deleted_at IS NULL OR is_active = false",
            name="ck_countries_deleted_inactive",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="ck_countries_timestamp_order",
        ),
        Index(
            "ix_countries_active_code",
            "country_code",
            postgresql_where=text("deleted_at IS NULL AND is_active"),
        ),
        Index(
            "ix_countries_live_calling_code",
            "calling_code",
            "country_code",
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    country_code: Mapped[str] = mapped_column(String(2), primary_key=True)
    calling_code: Mapped[str] = mapped_column(String(3), nullable=False)
    name_zh: Mapped[str] = mapped_column(String(128), nullable=False)
    name_en: Mapped[str] = mapped_column(String(128), nullable=False)
    flag_url: Mapped[str | None] = mapped_column(String(2048))
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.statement_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.statement_timestamp(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
```

The simple HTTPS database check is defense in depth. The importer must still use
a structured URL parser, require the default HTTPS port, reject credentials,
queries, and fragments, and enforce the configured host allowlist. Do not add
unique constraints to `calling_code`,
`name_zh`, or `name_en`.

If country changes must identify the operator, use the business audit event as
the durable operator record. Add `deleted_by_user_id` only when the product has a
separate query need for it and can use exactly the established `users.user_id` type;
do not introduce a loosely typed duplicate identity column.

## User-Owned Database Setup

Deliver the `Country` model and its named constraints/indexes above. The user
generates, reviews, and executes their own migration using the project's chosen
tool. Do not generate or copy an Alembic revision, create the table, initialize
country rows, or call `create_all()` from startup or ordinary fixtures.
The model is the schema specification; duplicate DDL examples are unnecessary.

The handoff asks the user to verify the natural `varchar(2)` primary key,
typed timestamps, partial live indexes, and every check in the model. Their
setup must preserve existing references and tombstones. Initial data is their
responsibility; a CSV import feature is implemented only when separately
requested as product functionality, and is never run automatically.

When another model stores a country code, use the same type and collation with
a restrictive foreign key:

```python
ForeignKey("countries.country_code", ondelete="RESTRICT", onupdate="RESTRICT")
```

Do not use `CASCADE` or `SET NULL` to simulate soft deletion. Any later physical
schema removal and its data impact remain the user's reviewed migration work.

## Read Schemas And Queries

Use strict, immutable response models and the shared page envelope:

```python
from pydantic import ConfigDict, Field

from app.core.response import ResponseBase
from app.schemas.common import RequestBase


class CountryRead(ResponseBase):
    model_config = ConfigDict(from_attributes=True)

    country_code: str = Field(pattern=r"^[A-Z]{2}$")
    calling_code: str = Field(pattern=r"^[1-9][0-9]{0,2}$")
    name_zh: str
    name_en: str
    flag_url: str | None


class CountryListQuery(RequestBase):
    q: str | None = Field(default=None, max_length=128)
    calling_code: str | None = Field(
        default=None,
        pattern=r"^[1-9][0-9]{0,2}$",
    )
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=200)
```

Normalize `q` with `strip()` and return a validation error when it becomes empty.
Build one shared predicate for both the count and item statements:

```python
predicates = [Country.deleted_at.is_(None), Country.is_active.is_(True)]
if query.calling_code is not None:
    predicates.append(Country.calling_code == query.calling_code)
if query.q is not None:
    term = query.q.strip()
    predicates.append(
        or_(
            Country.country_code == term.upper(),
            Country.name_zh.icontains(term, autoescape=True),
            Country.name_en.icontains(term, autoescape=True),
        )
    )

total = await session.scalar(
    select(func.count()).select_from(Country).where(*predicates)
)
items = list(
    (
        await session.scalars(
            select(Country)
            .where(*predicates)
            .order_by(Country.country_code)
            .offset((query.page - 1) * query.page_size)
            .limit(query.page_size)
        )
    ).all()
)
```

Use the same live-and-active predicate for detail. Normalize a typed query code to
uppercase, but do not map aliases such as `UK` to `GB` unless the product owns a
separate explicit alias table. Return `40401` for missing, inactive, or deleted
ordinary results.

Adapt the router to the existing response helpers and authentication
dependencies. This endpoint excerpt assumes the application's existing
`country_service`, schemas and session dependency; it does not create a public
country directory or an extra forwarding service:

```python
from app.core.i18n.messages import MessageKey
from app.core.access.authorization import AuthorizationContext
from app.dependencies.auth import get_current_user

router = APIRouter(prefix="/countries")


@router.get("/list", response_model=ApiResponse[PageResponse[CountryRead]])
async def list_countries(
    request: Request, query: Annotated[CountryListQuery, Query()],
    db: Annotated[AsyncSession, Depends(get_postgres_session)],
    context: AuthorizationContext = Depends(get_current_user),
) -> ApiResponse[PageResponse[CountryRead]]:
    """
        为已登录用户查询当前可选的国家/地区，返回筛选后的分页结果。

    :param request: 当前请求，用于生成统一响应与请求 ID。
    :param query: 已校验的搜索条件与分页参数。
    :param context: 已完成登录身份和当前业务限流检查的上下文。
    :param db: FastAPI 为本次查询注入的 PostgreSQL 会话；请求结束自动关闭。
    :return: 仅包含启用且未软删除国家/地区的分页响应。
    """
    # Service/Repository 对列表和总数使用同一组可见性与搜索条件。
    items, total = await country_service.list_active(db, query)
    country_items = list(map(CountryRead.model_validate, items))
    page = PageResponse(items=country_items, page=query.page, page_size=query.page_size, total=total)
    return api_response(request, code=BusinessCode.OK, message_key=MessageKey.COMMON_QUERY_SUCCESS, data=page)
```

Add `/detail` with required Query `country_code`, using the same login, automatic
GET quota and envelope contracts. Register the router in the v1 assembler only
when the product needs HTTP reads. Do not mount a write or import router as part
of this baseline.

## Optional Import Feature

Implement the following business operation only when the user requested an
import feature. It is not a schema initializer or a reason to run imports while
generating the project. The user first completes their own database setup.

The command that writes rows must parse and validate the exact bytes it imports;
a prior CLI validation alone is susceptible to a file-change race. Reuse the
validator rules in the command or bind validation and import to the same file
hash and in-memory row set.

After validation, use one caller-owned transaction. Every country-catalog writer,
including any later runtime manager, takes the same advisory lock before row
locks so an import cannot race an administrative change:

```python
from collections.abc import Sequence
from typing import TypedDict

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession


class CountrySeedRow(TypedDict):
    country_code: str
    calling_code: str
    name_zh: str
    name_en: str
    flag_url: str | None


class DeletedCountryConflict(Exception):
    def __init__(self, country_codes: Sequence[str]) -> None:
        self.country_codes = tuple(sorted(country_codes))
        super().__init__("country import conflicts with soft-deleted rows")


async def upsert_country_catalog(
    session: AsyncSession,
    rows: Sequence[CountrySeedRow],
) -> None:
    if not rows:
        raise ValueError("country import requires at least one validated row")

    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtextextended('country_catalog_write', 0))"
        )
    )

    incoming_codes = [row["country_code"] for row in rows]
    deleted_codes = list(
        (
            await session.scalars(
                select(Country.country_code)
                .where(
                    Country.country_code.in_(incoming_codes),
                    Country.deleted_at.is_not(None),
                )
                .order_by(Country.country_code)
                .with_for_update()
            )
        ).all()
    )
    if deleted_codes:
        raise DeletedCountryConflict(deleted_codes)

    insert_statement = pg_insert(Country).values(list(rows))
    excluded = insert_statement.excluded
    changed = or_(
        Country.calling_code.is_distinct_from(excluded.calling_code),
        Country.name_zh.is_distinct_from(excluded.name_zh),
        Country.name_en.is_distinct_from(excluded.name_en),
        Country.flag_url.is_distinct_from(excluded.flag_url),
    )
    statement = insert_statement.on_conflict_do_update(
        index_elements=[Country.country_code],
        set_={
            "calling_code": excluded.calling_code,
            "name_zh": excluded.name_zh,
            "name_en": excluded.name_en,
            "flag_url": excluded.flag_url,
            "version": Country.version + 1,
            "updated_at": func.statement_timestamp(),
        },
        where=and_(Country.deleted_at.is_(None), changed),
    )
    await session.execute(statement)
```

Call it only after complete in-memory validation:

```python
async with session_factory() as session:
    async with session.begin():
        await upsert_country_catalog(session, validated_rows)
```

The import intentionally does not update `is_active`, so it cannot re-enable a
country. It never compares the database with absent file rows, so it cannot delete
or disable them. Duplicate incoming codes must already have failed validation.
An empty incoming set is an error, not a successful zero-row replacement.

Do not run one transaction per row. Do not commit inside the service, catch a
database error and continue, or call a flag CDN or country API while holding the
transaction. If the product needs durable evidence for an operator import, stage
one bounded business-audit summary containing the source identifier, approved
file hash, inserted/changed counts, and outcome; do not copy all country names or
the entire CSV into audit state.

## Optional Runtime Maintenance

Add runtime maintenance only for an explicit product need. All writers take the
country advisory lock, reload the target with `FOR UPDATE`, authorize before
revealing version state, and compare a strict integer `expected_version` before
changing it. The supported actions are create, update display fields, disable,
enable, soft-delete, and explicit restore. Use only neutral `GET` and `POST`
routes, for example `POST /api/v1/countries/disable` with `country_code` and
`expected_version` in a Pydantic JSON body whose extra fields are forbidden.

Soft-delete sets `is_active=false`, `deleted_at=statement_timestamp()`, increments
`version`, and commits the matching business audit in the same transaction.
Restore clears `deleted_at` but remains inactive; a separate enable action makes
it selectable. This two-step rule prevents accidental reintroduction. Never let
the CSV upsert invoke restore or enable.

## PostgreSQL And API Tests

Use isolated validator/model/API tests for Skill delivery. The user verifies
the actual PostgreSQL boundaries after completing their own schema. Do not
create tables, migrate or seed inside new-project fixtures. The applicable
acceptance matrix is:

```text
schema:       no serial/identity; varchar(2) PK; timestamptz fields; named checks
constraints:  lowercase/long code rejected; +86/leading-zero/4-digit calling rejected
uniqueness:   duplicate country code rejected; shared calling code accepted
source:       strict UTF-8; size/row limits; nonempty; exact header and approved code set
import:       all-or-nothing; unchanged retry is a no-op; changed row increments version
tombstone:    import collision fails; missing file row stays untouched; no silent enable
reads:        active live only; deterministic pagination; lowercase query code normalized
history:      inactive/deleted country remains referenced by existing business rows
deletion:     runtime removal writes a tombstone; no hard-delete HTTP path
flags:        invalid host/port/credentials/query/fragment rejected; reads never fetch
optional API: permission, hierarchy, stale-version, rollback, and business-audit behavior
absence:      an ordinary RBAC project receives no country model or route
```

Run the standalone CSV validator tests as part of the Skill release checks:

```powershell
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
```

Do not use SQLite to claim the regular-expression checks, partial indexes,
advisory locking, timestamp behavior, or PostgreSQL upsert contract passed.
