# Modern FastAPI Baseline

Read this reference when starting a project or replacing legacy FastAPI,
Pydantic, SQLAlchemy, or HTTPX patterns. Prefer the versions already pinned by an
existing repository when they are supported and intentional.

## Choose The Stack Deliberately

- Record a supported Python version and compatible dependency ranges in
  `pyproject.toml`; commit the repository's lockfile when its workflow uses one.
- Prefer Pydantic 2 and `pydantic-settings` 2 for a new service.
- Prefer SQLAlchemy 2 typed mappings and `async_sessionmaker` for an async SQL
  service. Use the async driver required by the selected database.
- Use Alembic or the repository's migration system for persistent SQL schemas.
- Prefer an application factory when tests or deployment require multiple app
  configurations. Otherwise a clear module-level app is acceptable.
- Add repository and service layers only where they own meaningful query or
  business behavior. For shared functions, repeated flows, or new layers, follow
  [Reuse and abstraction](reuse-and-abstraction.md).

## Settings

Use typed settings and fail at startup when required production values are
missing. Keep secret values out of source control and exception output.

```python
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str
    secret_key: str
    allowed_origins: list[str] = Field(default_factory=list)
    sql_echo: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- Do not give secrets a realistic-looking default.
- Do not use wildcard CORS together with credentialed browser requests. Parse and
  validate an explicit origin allowlist per environment.
- Keep debug mode and SQL echo disabled by default.
- Override the settings dependency or construct an app with test settings before
  importing modules that eagerly read required environment variables.

## Database Sessions

Use SQLAlchemy 2 APIs for new code:

```python
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


engine = create_async_engine(settings.database_url, echo=settings.sql_echo)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
```

- Choose one visible transaction boundary. A service may use
  `async with session.begin()`, or a request dependency may commit after a
  successful mutation. Do not mix both approaches accidentally.
- Avoid committing inside generic repositories; callers need to compose several
  writes atomically.
- Roll back failed transactions and dispose the engine during application
  shutdown when the process owns it.
- Use `Mapped`, `mapped_column`, explicit relationships, named constraints, and
  deterministic indexes. Avoid legacy `declarative_base()` in new templates.

## Schemas And Endpoints

- For JSON envelopes, numeric business codes, server-generated request IDs,
  simple page-number pagination, and error handlers, read
  [API response standard](api-response-standard.md). Do not invent a competing
  response shape in this general stack layer.
- Use `model_config = ConfigDict(from_attributes=True)` for output models that
  validate ORM objects.
- Use `model_dump()` instead of the Pydantic 1 `dict()` API.
- Set `extra="forbid"` on privileged mutation inputs where silent extra fields
  could hide an attempted privilege escalation.
- Separate create, update, internal persistence, and response schemas. Password
  hashes and authorization state never belong in public response models.
- Prefer `Annotated[T, Depends(...)]` aliases for shared dependencies when that
  improves signatures.
- Validate pagination bounds and make ordering deterministic. Under the XTN
  baseline, page data contains only `items`, `page`, `page_size`, and `total`.
- Use `200` with the standard envelope for an ordinary JSON command such as
  logout. A true `204`, `304`, file, or stream has no JSON envelope and carries
  its mandatory request ID in `X-Request-ID` only.
- Translate known domain failures to stable error codes at the HTTP boundary;
  do not expose raw exception strings or database details.

## Authentication

- Use a maintained password hashing implementation with a memory-hard default
  such as Argon2 when local passwords are required.
- For JWT claims, opaque subjects, signing, Redis active-JTI validation, login,
  logout, and revocation, read
  [JWT access-token security](jwt-session-security.md). Its minimal payload and
  server-side authority rules replace generic JWT examples.
- After cryptographic validation, require the exact Redis active-JTI record, then
  load the existing current active PostgreSQL user and RBAC authority and compare
  the Redis-bound user version. A correctly signed Token with a missing JTI or a
  disabled user is not an authenticated application principal. Do not add a
  PostgreSQL Token table or another per-request query for an individual Token.

## Application Lifecycle And Operations

- Use FastAPI lifespan context for resources the process owns. Do not call
  imaginary `connect()` or `disconnect()` functions on an engine abstraction.
- Provide separate liveness and readiness behavior when deployment needs them;
  readiness may check critical dependencies without leaking their details.
- Configure structured logs and request correlation at the application boundary.
  Never log authorization headers, cookies, passwords, or secret settings. Read
  [Operational logging](operational-logging.md) when implementing this boundary.
- Put trusted-proxy, host, HTTPS, payload-limit, timeout, and CORS configuration
  under deployment-aware policy instead of pretending one default fits all.
