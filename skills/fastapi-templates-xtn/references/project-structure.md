# Project Structure

Read when generating a project, adding modules, or explicitly reorganizing its
layout. This responsibility-first tree is the optional greenfield default.
It is not a migration instruction for an existing application. Folder placement
does not require a forwarding function for every operation; follow
[Reuse and abstraction](reuse-and-abstraction.md).

## Select The Project Context First

Inspect the repository root, local instructions, settings and a representative
route-to-data flow. An empty subdirectory inside an existing repository still
belongs to that project.

| Context | Action |
| --- | --- |
| Empty project or explicitly requested independent new service | Use this default unless the owner chose another architecture |
| Existing application, including a partially built scaffold | Follow its modules, names, injection, queries and transaction ownership |
| Explicit request to reorganize architecture | Apply the agreed scope, preserving unrelated code and behavior; do not request the same authorization again |

Calling this Skill or requesting a feature, fix or optimization does not
authorize framework replacement. For example, add orders to an existing
`features/orders/` and DAO structure instead of installing a competing
Service/Repository tree. If a necessary change exceeds the task, explain its
need and scope and obtain direction while continuing independent in-scope work.
A preferred layout alone is not such a need.

## Business Names Within Responsibility Directories

Only `main.py` and `__init__.py` live directly under `app/`. This sketch omits
package `__init__.py` files and shows representative businesses, not a mandatory
file per operation:

```text
app/
  __init__.py
  main.py
  api/
    v1/
      router.py
      route_validation.py
      endpoints/
        auth.py
        me.py
        users.py
        roles.py
        permissions.py
  core/
    config.py
    codes.py
    exceptions.py
    exception_handlers.py
    response.py
    route_validation.py
    audit.py
    access/
      permissions.py
      roles.py
      authorization.py
      authorization_policy.py
      role_policy.py
      user_policy.py
    i18n/
      messages.py
      language.py
      validation_messages.py
    rate_limit/
      limiter.py
    logging/
      events.py
      context.py
      output.py
    middleware/
      request_body_limit.py
      request_logging.py
      security_headers.py
    security/
      user_name.py
      passwords.py
      jwt_tokens.py
  db/
    postgres_db.py
    redis_db.py
  dependencies/
    auth.py
    permission.py
    captcha.py
    rate_limit.py
  models/
    postgres/
      base.py
      user.py
      role.py
      permission.py
      rbac_state.py
      operation_audit.py
  repositories/
    postgres/
      user_repository.py
      role_repository.py
      permission_repository.py
    redis/
      login_session_repository.py
  schemas/
    common.py
    captcha.py
    auth.py
    user.py
    role.py
    permission.py
  services/
    audit_service.py
    auth_service.py
    captcha_service.py
    user_service.py
    role_service.py
    permission_service.py
```

| Location | Naming and responsibility |
| --- | --- |
| `api/v1/endpoints/<business>.py` | HTTP inputs, dependencies, explicit business calls, response/status/header composition; no SQL or multi-query business orchestration |
| `api/v1/router.py` | Only assemble business routers by domain and declare the `/api/v1` prefix; keep startup security rules out of this file |
| `api/v1/route_validation.py` | Declare version-specific public/special authentication routes and call the shared startup validator |
| `services/<business>_service.py` | Business decisions, orchestration, transaction ownership and authoritative response snapshots |
| `repositories/<database>/<business>_repository.py` | Database-specific queries, filters, batching and lock/load operations; no independent commits or business-policy decisions |
| `repositories/postgres/user_repository.py` | `UserRepository` owns parameterized user lookup, account/permission loading, visible-user queries and page-only `UserDetails`; current-account validation reuses `check_current_user` |
| `repositories/postgres/role_repository.py` | `RoleRepository` owns role lookup, visible-role list/detail SQL and role grants |
| `repositories/redis/login_session_repository.py` | `LoginSessionRepository` owns Redis login keys, atomic registration, validation, deletion, listing, expiry cleanup and login-order maintenance; it does not sign Tokens |
| `models/<database>/<business>.py` | Entities, constraints and relationships; PostgreSQL uses `models/postgres/base.py` |
| `schemas/<business>.py` | API data contracts and pure validation; no database queries or service calls |
| `schemas/common.py` | `RequestBase`, username validation and shared `Password`/`NewPassword` field types |
| `schemas/captcha.py` | CAPTCHA answer, issuance request and image response; imports the purpose enum from `core/captcha.py` |
| `db/<database>_db.py` | Default engine/session/client construction and lifecycle, not business queries; PostgreSQL connection-pool configuration and failure classification stay together in `postgres_db.py` |
| `dependencies/auth.py` | `check_token` validates JWT/Redis and directly supports current-session logout without a quota or PostgreSQL read; `get_current_user` and `get_captcha_user` each count their quota and load current account authority once; `_load_current_user` is shared with permission checks |
| `dependencies/permission.py` | The callback returned by `require_permission` receives `Depends(check_token)`, applies the route-selected quota (ordinary user by default; management only with explicit `management=True`), calls the shared account loader and checks the exact capability; target visibility stays with the business Service, denied POST audit uses the shared transaction Service |
| `dependencies/` | CAPTCHA, rate-limit and other request injection adapters besides authentication and permission |
| `core/` | Settings, response/errors, audit rules and generic route validation; cohesive access, language, rate-limit, logging, security and middleware packages below it |
| `core/access/` | Permission and system-role definitions, authority snapshots and pure administrative policies; not password/JWT processing |
| `core/rate_limit/` | Redis 固定窗口原子计数；业务窗口及请求主体直接写在 `dependencies/rate_limit.py` |
| `core/logging/` | Safe events, request context and output setup; request-completion middleware stays in `core/middleware/` |
| `core/access/permissions.py` | Business-grouped permission keys, description message-key catalog and description lookup |
| `core/access/roles.py` | System-role keys, specifications, fixed tiers, role limits and explicit grant allowlists |
| `core/codes.py` | Five-digit success/error business codes and fallback mapping for unlisted HTTP errors |
| `core/exceptions.py` | Named business-error constructors and shared application exception types, including the fixed login-credential error |
| `core/response.py` | `ResponseBase`, four-field response and pagination models plus JSON content assembly |
| `core/exception_handlers.py` | Framework exception registration and conversion to HTTP responses |
| `core/i18n/messages.py` | Message keys, catalog loading and translation lookup |
| `core/i18n/language.py` | Request language negotiation and language response headers |
| `core/i18n/validation_messages.py` | Localized, non-reflective parameter errors and safe field hints |

Use full business names when a short name is ambiguous, for example
`product_user_balance_service.py`,
`repositories/postgres/product_user_balance_repository.py`,
`models/postgres/product_user_balance.py` and
`api/v1/endpoints/product_user_balances.py`. Prefixes such as `center_` and
`product_` belong only to projects with those business distinctions.

Use the same business word across related layers: `auth.py`, `auth_service.py`
and `AuthService` describe this one username/password authentication surface.
Do not use several near-synonyms for the same flow.
Use `LoginInfo` for verified Token/session facts and
`AuthorizationContext.login_info` for those facts inside a loaded account context.
`AuthorizationContext.user_info` holds the current account state, roles, role
level and permissions loaded from PostgreSQL.
Ordinary account routes show `context: AuthorizationContext = Depends(get_current_user)`
directly; this returns login and database authority context, not an ORM `User`.
`require_permission` internally receives `Depends(check_token)`, calls
`rate_limit_user(..., management=management)` and `_load_current_user`, then checks
the exact permission. The factory defaults to ordinary user quotas; business
management routes explicitly use `require_permission(key, management=True)`.
A permission check does not identify an administrator. It does not call
`get_current_user` and count again or add a
management-context layer. Private CAPTCHA uses `get_captcha_user`, and
current-session logout uses `check_token` directly
without a quota, database read or business-permission check; do not add
`CurrentPrincipal`/`MyAccountContext`/`MyCaptchaContext` aliases or forwarding layers.
Use the route's action word in request-model names when it is unambiguous:
`register` uses `RegisterRequest`, and `login` uses `LoginRequest`.
Keep a business-object prefix when it distinguishes operations, such as
`RoleCreateRequest` versus `UserCreateRequest`; do not rename merely to reorder words.
`user_service.py::UserService.create_user` owns shared account creation,
including initial password storage, default-role binding and creation audit.
Registration and the
administrator flow `UserService.admin_create_user` reuse this method while
keeping their own permission/password checks and outer transactions. Keep this
rule with the other user operations; no separate account-creation Service or
`with_default_role` method-name suffix is needed.
`captcha_service.py` owns Redis-backed CAPTCHA creation plus verification and
immediate one-time invalidation. `dependencies/rate_limit.py` directly declares
business quotas and trusted IP/current-user dimensions from Settings.
`core/rate_limit/limiter.py` owns atomic Redis counting;
`core/exception_handlers.py` formats 429 response headers.
`dependencies/captcha.py` exposes `require_captcha(CaptchaScene)` and only reads
the challenge fields and previously authenticated user before verifying its
one-use challenge. It does not call limiters/permission dependencies or validate
complete business models. Routes declare the limit or authorization parameter
before this CAPTCHA dependency, and keep business calls and complete success
responses in their own bodies. Other business-field errors may be reported after
CAPTCHA consumption; do not introduce a dispatcher to avoid this timing.
Authentication establishes
identity; `core/access/authorization.py` defines identity and authority data
types. `authorization_policy.py` owns only shared authorization conditions;
`role_policy.py` owns role-management decisions, while `user_policy.py` owns
user management and user-role assignments. `jwt_tokens.py` signs and verifies
JWTs without Redis I/O. `AuthService.issue_access_token` coordinates signing and
confirmed registration through `login_session_repository`; the Repository owns
the Redis records and Lua scripts, without issuing Tokens.
`core/access/permissions.py` groups `PermissionKey` and `PERMISSION_CATALOG` by business;
`core/access/roles.py` keeps system-role configuration separate from that catalog.
System-role display names and descriptions are database role data, not fields in
the security specification; choose their stored text when preparing the initial roles.
Catalog values are `MessageKey` values, not descriptions to copy into the
database. Initial descriptions use `get_permission_description(key)`, defaulting
to Chinese. New permissions need description text in both locale catalogs;
custom database descriptions remain as stored. Renames update real callers, generation,
tests and current guidance together without unused old-path forwarding modules.

The default `repositories/redis/` owns login-session persistence. Add other
Redis repositories only for actual business data, and create
`repositories/mongo/` plus `models/mongo/` only when MongoDB is adopted.
Do not invent Redis ORM tables, Mongo connections or empty directories. Atomic
security scripts may stay with their algorithm owner; moving one `eval()` into
a forwarding Repository does not improve separation. The default remains one
PostgreSQL and one shared Redis.

Group models by the business a developer will search for: `user.py` also owns
user-role assignments; `role.py` also owns role-permission assignments.
`permission.py`, `rbac_state.py` and `operation_audit.py` name their separate
responsibilities. Do not require one file per table or collect unrelated
identity/access entities under a broad `access.py`. Register every model through
`models/postgres/__init__.py` so metadata discovery stays complete without DDL.
Group API schemas by their real consumers: `auth.py` owns registration, login,
own-password-change requests and access-token data; `captcha.py` owns CAPTCHA
contracts; `user.py` owns user management and its `ActiveSessionsResponse` response.
`common.py` holds common API definitions: `RequestBase`, `UsernameRequest`,
`Password` and `NewPassword`. Operations with no resource result return `data: null` without
an extra boolean-only response model.
Login `password` and self-change `current_password` import `Password`:
`SecretStr` with direct `Field` constraints for nonempty input and the independent
`MAX_PASSWORD_INPUT_CHARACTERS` ceiling (default 1024). Fields that set a password
import `NewPassword`: `SecretStr` with direct `Field` constraints from
`MIN_PASSWORD_CHARACTERS` and `MAX_PASSWORD_CHARACTERS` (default 8..32).
An out-of-range HTTP input returns request-validation code `42201`. Setting a
password additionally applies the business password policy. Login and
current-password verification check input type, nonempty value, valid UTF-8 and
the input ceiling, then verify the stored hash without applying new-password
length or strength rules. Keep the input ceiling stable when tightening policy
so existing valid passwords still work. Do not add `AfterValidator`, a third
`ExistingPassword` alias, a length-validator wrapper or a password-only module.
Consumers import directly; moving a definition must
preserve its field order, extra-field rejection, frozen state and validation.
Do not add re-export modules, copied validators or a file for every field.

Every HTTP request model inherits `RequestBase`; every HTTP response model,
including nested objects, `ApiResponse[T]` and `PageResponse[T]`, inherits
`ResponseBase`. Existing shared request models may supply indirect inheritance.
Keep business models in their current owner and retain local schema metadata and
validators. The [API model-base contract](api-response-standard.md#request-and-response-bases)
owns shared configuration and its limits; do not add a separate base-model module.

Name interface inputs `<Business>Request` and interface outputs
`<Business>Response`, including the objects placed inside `ApiResponse.data`.
For example, CAPTCHA uses `CaptchaCreateRequest` and `CaptchaResponse`;
login returns `AccessTokenResponse`; shared pagination is `PageResponse[T]`.
Do not use a `Data` suffix for response models or keep old-name aliases.
The JSON envelope field remains `data`: `ApiResponse[CaptchaResponse]` still
serializes as `{"code": ..., "message": ..., "data": {...}, "request_id": ...}`.
Internal calculation results and database/library types keep names reflecting
their own responsibilities; this API naming rule does not rename SQLAlchemy
`MetaData` or an internal authentication `Result`.

The asset groups endpoints into five business modules:

| Endpoint file | Related operations |
| --- | --- |
| `auth.py` | Public CAPTCHA, registration, login and current-login logout |
| `me.py` | Current identity and permissions, authenticated CAPTCHA and own password change |
| `users.py` | Administrator user list/detail/create, visible-user login-session list, password reset, account status, role assignment and forced logout of all target sessions |
| `roles.py` | Role list/detail/create, information, lifecycle and permission assignment |
| `permissions.py` | Permission catalog list and detail |

Keep a business's related routes together so a maintainer can find its flow in
one place. Do not create separate endpoint files just because an operation uses
CAPTCHA, passwords or sessions; those are shared implementation concerns, with
their own reusable dependencies and Services where needed. For example,
administrator password reset belongs to `users.py`, and own password change
belongs to `me.py`; neither requires a standalone endpoint module. Default
projects do not add documentation-only route tags. Different authentication or CAPTCHA dependencies
remain explicit on each route; sharing a file must not broaden access.

Permission, role and user queries and commands have their own Services; database
queries have named role, user, permission, assignment and state repositories.
User account/permission reads stay in `UserRepository`; visible-role queries
stay in `RoleRepository`, without a separate cross-table authority Repository.
Split at real business boundaries, not at an arbitrary number of lines or one
file per endpoint. One shared permission calculation or lock protocol stays in
one owner rather than being copied into every business.

Follow [API response standard](api-response-standard.md#methods-paths-and-request-parameters)
for new business routes: only `GET`/`POST`, `/list` and `/detail` read suffixes,
GET target IDs in Query, and POST target IDs in a closed JSON request model.
For an existing application, follow its established grouping and public
contracts; this default does not authorize a framework or route migration.

Keep used directories such as `assets/locales/`. Operator `commands/` are not
part of the default new-project export; add only for an explicitly requested
application workflow, never to initialize its database. Add `workers/`
only for implemented background jobs and `utils/` only for concrete shared
behavior with no clearer owner. Do not copy `__pycache__`, `.pyc`, unused database
packages or placeholder modules from an example tree.

## Calls Follow Actual Responsibility

Preserve an existing framework's equivalent boundaries rather than introducing
a competing architecture:

- The default business chain is endpoint → business Service → named Repository.
  A permission catalog Service owns pagination, the missing-detail business
  error and public response construction; its endpoint only adapts HTTP inputs
  and the response envelope. Role/user Services additionally own visibility
  and batch-loaded authority. Give each Service these actual responsibilities;
  never add a facade that merely calls another Service with identical arguments.
- Mutations with business rules, locks, multiple writes or audits belong in a
  Service that owns one transaction. Repositories own SQL, filter/count rules
  and meaningful persistence operations; Services decide when to call them.
  Assigning an already-locked ORM field may stay in that transaction; do not
  create a setter per column. Repositories and audit writers never commit the
  business transaction. Keep password hashing and external I/O outside held
  database connections/locks exactly as the original operation requires.
- Request authentication dependencies may call repositories directly; resource
  probes and pure infrastructure are not business workflows. Preserve an
  existing host framework's intentional direct-read convention. These are
  concrete exceptions, not a reason to bypass the default business Service.
- `UserRepository.get_user_permissions(session, users=users)` reuses loaded
  users and always returns a user-ID mapping. For one user, pass `users=(user,)`
  and read the result by `user.user_id`; one and many use the same entrypoint.
  Each `UserPermissions` value has `user_info` containing only enabled roles, while
  `user_info_with_disabled_roles` includes disabled roles for management restrictions
  and must not grant access. One role read
  builds both sets, without querying the same user again. The shared role query
  and assembly live together in `_load_user_permissions` and also serve
  `get_users_info`, which adds usernames, bound roles and permitted permissions
  to already loaded users and returns `dict[str, UserDetails]`.
  `UserDetails.user_info` contains only the roles visible to the viewer. Never use that filtered page
  result to authorize an operation. Keep SQL visibility and the current-user
  rechecks before and after role locks.
- `UserRepository.get_user` shares ordinary single-user reads through explicit
  `user_id`, normalized `user_name`, `is_active` and `is_deleted` filters. Supply
  at least one identifier; when both are supplied they must match the same row.
  `is_active=None` includes enabled and disabled accounts. `is_deleted=False`
  reads live users by default, `True` reads deleted users only, and `None` reads
  either. Login and password-state reads deliberately pass `is_deleted=None`;
  the existing username-existence query also includes deleted rows. Deleted
  accounts still cannot log in and their names remain reserved. Keep separate
  locking, batch and SQL visibility operations:
  they cannot be safely replaced by flags that skip checks. Current-account
  authentication uses `check_current_user` to check state and `token_version`
  before querying current roles and permissions.
- Models and schemas never import Services. Put shared value types and pure
  validation in `core/`. Response builders depending on repository visibility
  belong with Services, not in schemas that then perform database queries.
- Services return business data or `<Business>Response` models. Business routes
  wrap them in the complete `ApiResponse`; dependencies do not assemble success
  envelopes. Shared response utilities, exception handlers and middleware keep
  their existing HTTP-response responsibilities. Do not extract a short envelope
  constructor just because two routes use it.
- `main.py` assembles lifespan, middleware, handlers and `api/v1/router.py`.
  Only add infrastructure health probes at the adopter's explicit request,
  restricted to an internal network or trusted probes. Keep requested probes
  unversioned; adding a `v1` directory does not rename existing HTTP contracts.

## Make The Code Navigable

### Application Entry

Read `main.py` from top to bottom as lifecycle and application assembly. Keep
resource setup and cleanup together in a visible `lifespan`, then construct
FastAPI, register exception handlers, add middleware and include routers.
The maintained asset uses these owners:

- `core/exception_handlers.py`: exception-to-response conversion and one explicit
  `register_exception_handlers(app)` registry.
- `core/route_validation.py`: generic startup checks for business routes using
  the version-specific rules supplied by `api/v1/route_validation.py`.
- `core/logging/context.py`: request-ID context binding, clearing, and detached-task isolation.
- `core/logging/events.py`: safe event emission, redaction, exception metadata, and JSON formatting.
- `core/logging/details.py`: bounded, redacted request/response summaries,
  affected users/roles and independent-key new-password fingerprints; passive
  observation only, with no additional request-body reads.
- `core/logging/output.py`: bounded single-line JSON output to stdout and
  `logs/YYYY-MM-DD/app.log`, daily switching and numbered segments controlled by
  `LOG_FILE_MAX_MB`, handler lifetime, and logger setup; no background queue in
  the default project.
- `core/middleware/request_logging.py`: request IDs, language headers and
  actual request-completion logging, including cancellation and streamed failures.
- `core/middleware/request_body_limit.py`: the configured byte limit, checked
  against both `Content-Length` and the actual received request chunks before a
  route executes.
- `core/middleware/security_headers.py`: mandatory baseline browser security
  headers for HTTP responses, without a per-business toggle.
- `core/config.py`: application, single-endpoint PostgreSQL, standalone Redis,
  logging, security and rate-limit settings. `db/redis_db.py` owns the Redis
  client and request dependencies; no topology configuration module is generated.

The default asset includes no `api/health.py`, `/health/live` or `/health/ready`.
If the adopter explicitly requests probes, place their implementation in a
dedicated API module, restrict access to an internal network or trusted probes,
and keep them outside versioned business routes; no forwarding Service is needed.

Use `AsyncExitStack` when several acquired resources need cleanup: register each
successful acquisition immediately, and explain the reverse release order.
Keep the logging lifetime outside the resources it observes. Partial startup or
a failing cleanup must not skip the remaining releases. Do not copy automatic
database initialization or other unrelated behavior from a style reference.

Clarity comes from visible responsibilities, not a line-count threshold. Do not
move an entire crowded entrypoint into `bootstrap.py`, introduce an application
builder framework, or wrap each library registration in a one-line helper.

### Business Flow

For a new business Service or Repository, default to a descriptive `RoleService` or
`RoleRepository` class with explicitly named methods and a module-level
`role_service` / `role_repository` instance. These objects contain no current
request, current user, live database session, or transaction. Pass those values to the
operation. A Service may retain immutable configuration or a session factory
when it owns session lifetime. Import an ordinary shared Service instance
directly from its owning module; do not add a dependency getter or typed alias
that only returns the same object. Tests can construct the Service with a test
factory or replace the instance imported by its consumer. Services that actually
need request-specific construction or resource acquisition/cleanup retain that
lifetime, as do authentication, permission and other real request dependencies.
Do not change transaction ownership just to imitate an example project's syntax.
Pure functions, route handlers and small shared
algorithms do not need artificial classes. Put related database operations and
business workflows on their owning class instead of accumulating module-level
functions in a `*_service.py` or `*_repository.py` file. A shared context manager
that owns a real transaction lifetime may remain a function. A simple lookup
becomes a method on its business Repository, not a new class per query.

Prefer `role_service.create_role(...)` and
`role_repository.get_role_permissions(session, roles=(role,))` to a generic
`service.execute(action, ...)`. Role-permission reads always return a role-ID
mapping; read a single result by `role.id` instead of using a separate method.
Names distinguish lookup, mutation and locking. Use explicit keyword arguments
for long calls, domain names for intermediate results, and early returns for
invalid states. Put the public operation before its local implementation details
when practical. Do not hide normal business steps in nested functions, dynamic
`getattr`, callback registries, inheritance chains, or configurable skip flags.
A context manager may centralize the real transaction/audit lifetime while the
business method visibly performs its checks and changes inside that block.
When a shared lock helper returns several different facts (such as current user,
target, rows and state), give the result named fields instead of making callers
remember positions in a long tuple. Keep a simple one- or two-value return as
is; do not add a data class for every query.
Framework dependency callbacks and security callbacks that must run a CAPTCHA
check only after the rate-limit check remain valid; preserve their
ordering instead of rewriting them to satisfy a stylistic rule.

Keep SQL construction, execution and result conversion readable as separate
steps (`statement`, `result`, then the returned records). Reuse the same filter
builder for list and count; do not create a QueryBuilder or BaseRepository to
save a few expressions. Preserve SQL visibility filtering, stable ordering,
soft-delete scope and batch loading instead of filtering all records in Python.
Business-owned response builders use already-loaded data and perform no I/O.
Use one POST request model per operation; do not pass its target ID or version
again as a second argument. Keep the version prefix in `api/v1/router.py`, and
name distinct concepts explicitly (`role_policy.py` and `user_policy.py`)
rather than relying on singular/plural spelling.
Within a POST request model, place a locally declared target ID first, an
expected version next when required, and then the fields describing this
operation. Inherited shared fields may still appear first in Pydantic's
serialized field order. This is for source readability, not permission checking.

When extending an existing project, inspect a nearby complete API → Service →
Repository flow and match its conventions. For a new project, inspect the same
chain in the asset. A file rename and added docstrings alone do not constitute
a successful architecture cleanup: follow one list, detail and mutation through
the code and check that each layer has a clear job.

Every function and method follows [Python comments](python-comments.md),
including helpers, validators, Repository queries and endpoint handlers.
Use its aligned, individually wrapped parameters for multi-input class methods
and extra-indented docstring prose. Keep multi-argument business calls readable
on separate lines; do not collapse them solely to fit a line-length target.
Directory and class names alone do not establish the requested code style.
Follow the same comment reference for readable long endpoint signatures,
response/audit field mappings and public Chinese `Field`/`Query` descriptions.
Explain a callback at its actual invocation point; do not make the reader infer
that defining a nested function has already performed its business checks.

## Keep Generated Caches Out Of The Project

`.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `__pycache__` and `.pyc` are
tool-generated caches, not architecture layers. Never copy them into a new
project or a Skill package. `.gitignore` prevents commits but does not stop their
creation. Use `ruff check --no-cache` and the asset's cache-free pytest settings, run Python commands
with `-B`, and point `MYPY_CACHE_DIR` or `mypy --cache-dir` to an OS temporary
directory. The asset also gives bare Ruff/mypy commands a user-cache location
outside the project. See the asset README for PowerShell and POSIX commands.
An IDE or a command run without these settings can generate caches again.
Do not recursively clean an application tree; remove only positively identified
generated cache directories in the authorized target, never `.venv`, uploads,
logs, data or source files.

For a new service, follow [New project delivery](new-project-delivery.md) to
export a curated tree. Deliver models and a database handoff; the user generates
and executes their migration files. Do not copy the asset's entire test suite,
SQL, historical migrations, load tools or development-service orchestration.

When reorganizing, update imports, model metadata discovery, CLI entry points,
package resources, tests and current documentation together. Remove obsolete
paths rather than adding unused forwarding modules. Moving files must not
change schema, published migrations, URLs, authorization or transaction behavior.
