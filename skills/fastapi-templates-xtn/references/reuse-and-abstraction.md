# Reuse And Abstraction

Read when introducing shared functions or layers, adding a variant of an
existing flow, or reviewing duplication. Apply these decisions to the changed
surface; do not turn an ordinary feature into a repository-wide rewrite.
Follow the host project's established abstractions and naming. A different
preferred layout is not evidence that its framework needs replacing; only an
explicitly requested reorganization changes that scope.

## Decide By Behavior

Before adding a function, use `rg` to find the equivalent operation, its callers,
and tests. Extend the existing owner when it already implements the required
behavior. Compare inputs, outputs, permission checks, transaction ownership,
error handling, audit actions, and resource lifetime before consolidating code.

| Situation | Decision |
| --- | --- |
| Two real scenarios implement one rule that must change together; differences fit a few meaningful parameters | Share a core in the existing domain/service module |
| One short expression or a simple one-use sequence | Keep it inline unless it defines a useful boundary |
| One caller, but a distinct transaction, security check, resource cleanup, framework callback, or complex algorithm | A named function can be justified; explain the boundary when it is not obvious |
| Similar syntax but different permissions, failure semantics, side effects, or consistency guarantees | Keep independent flows, or share only the proven common part |
| An existing function already does the work and a wrapper just forwards arguments | Call the existing function directly unless the wrapper owns a stable contract or framework adaptation |
| A hypothetical future consumer | Do not introduce an abstraction solely for that consumer |

Two callers are evidence of reuse, not an automatic extraction threshold. Do not
deduplicate ordinary assignments, short constructors, or isolated library calls
just because they repeat. Conversely, a complex one-use operation may deserve a
name to make its intent, failure handling, or algorithm understandable. Neither
line count nor a similarity percentage makes the decision.

## Share The Rule, Preserve Its Boundaries

- For enable/disable or bind/unbind, keep separate public routes where their
  permissions, schemas, audit actions, or responses differ. Call one existing
  service command with the selected state or operation. Do not insert a second
  helper that only forwards those arguments to that command.
- Share identical response projections between reads and writes in their owning
  business Service or a pure Schema constructor. Do not create a generic
  projection Service for two unrelated business conversions. A projection must not start a query,
  change visibility rules, or open a transaction. Reads supply already-filtered
  data; writes construct their response while the authoritative locks are held
  and return it only after commit.
- A private common authorization decision may receive the required capability
  from explicit policy entry points. Each entry point fixes its own capability;
  neither request data nor a generic caller-selected permission may weaken it.
  Preserve capability-before-visibility ordering, complete multi-role authority,
  self/protected-target denial, and operation-specific checks.
- Keep public CAPTCHA and authenticated CAPTCHA dependency adapters separate
  when FastAPI must resolve different identities. Share their actual parsing
  work. A framework adapter has a purpose even if its body is short.
- Share resource acquisition and cleanup together, including in tests. For
  example, two SQL query-capture tests can use the same context manager whose
  `finally` removes its listener; do not share a mutable listener or Session
  across tests.

Do not merge whole workflows merely because both use validation, locking, and
audit. Registration, password changes, and permission changes can have different
targets and failure semantics. Extract only a common rule with compatible
contracts. Do not move commit, rollback, audit, or external I/O across an
existing boundary just to reduce duplication.

In the bundled PostgreSQL asset, `db/postgres_db.py::get_constraint_name` shares
only the SQLAlchemy/asyncpg constraint-name extraction. User creation, default-role
binding and role creation keep their exact primary-key allowlists, savepoints
and maximum three attempts at the business call site. `UserService.create_user`
generates the user ID internally; callers cannot supply it.
`UserService.create_user` also owns username-conflict handling: both its
pre-check and the exact `uq_users_user_name` failure at insertion raise the
existing `username_exists_error`. Registration and administrator creation use
that shared result without another conflict helper or duplicate outer
`IntegrityError` catches. Other constraint failures retain their original
meaning. Do not parse exception messages or add a generic retry executor to
shorten these separate flows.

`UserService.create_user` owns shared user insertion with the required initial
password hash and database password timestamp, default-role binding and creation
audit. `AuthService.register` and `UserService.admin_create_user` calculate the
hash outside locks and pass it to this method while retaining their distinct
password/permission checks and outer transaction ownership. Default-role binding
is explained in comments, not added
to the method name as `with_default_role`. Do not create a separate account-creation
Service merely to hold this shared rule.

Request correlation is execution context, not a business parameter.
`AuthService.register`, shared user creation and audit constructors do not accept
or forward `request_id`. HTTP middleware binds the ID once, and audit construction
uses the existing no-argument `core/audit.py::get_audit_request_id()` reader.
Non-HTTP entrypoints generate and bind one operation ID and deactivate/reset it
in `finally`, including cleanup failures. Missing or inactive context raises
`RuntimeError`; do not add per-Service wrappers or silently generate another ID.

## Keep Parameters And Layers Small

### Shared Business Definitions

When an existing finite business concept is used by request validation,
dependencies and Services, put its named values in one business-owned enum.
Derive allowed-value sets and classifications from that definition instead of
hand-maintaining matching literals or lists in each layer. CAPTCHA purposes and
their login requirements are a concrete example: `core/captcha.py` owns the
enum and classification, while consumers import the generated sets.

Keep stable wire values explicit with `.value` at string-based boundaries.
Preserve unknown-value rejection, localized errors, authorization requirements
and persisted-value checks when consolidating. A model-local `Literal` can
still be appropriate when its values have no other business consumers; a local
string choice does not need an enum just for a nicer type hint.

When learning from a reference project, trace the requested business from its
API through dependencies, Service and Repository as applicable. Identify where
its definitions, rules and defaults are maintained and how directly callers
express their intent. Apply those useful ownership and naming decisions within
the requested scope, alongside its comments and layout. Review the number of
places an ordinary business change requires editing and whether the main flow
remains readable; matching filenames alone does not establish equivalent clarity.

Prefer inputs with domain meaning: `is_active: bool` represents a real state;
`operation: str` can select binding or unbinding, with accepted values explained
beside the actual check. Avoid
boolean combinations such as `skip_permission`, `skip_audit`, `commit`, or
`is_admin` that turn one function into unrelated workflows or allow a bypass.
Use explicit keyword arguments where call sites would otherwise be ambiguous.

The bundled `UserRepository.get_user` combines single-user reads by ID and/or
normalized username with optional active/soft-delete filters. At least one
identifier is required, and supplied filters are combined with AND. Its live-user
default is explicit; login selects `is_deleted=None` when it needs to inspect
deleted rows. The lightweight username-existence query also includes deleted
rows so their names remain reserved. Keep user permission loading and visible
user SQL in that same business Repository; visible role SQL belongs to
`RoleRepository`. A shared file does not mean one query with flags for locking,
permission checks and pagination: preserve those distinct contracts.

Do not create a separate named `Literal` catalog only to repeat ordinary string
options that the runtime check or mapping already owns. Use plain `str` and
adjacent comments. Pydantic model `Literal` fields validate values, and FastAPI
`Annotated` dependencies execute real work; preserve those runtime contracts.
A command callable outside Pydantic must reject unknown operation values before
lookup or side effects; never treat every value other than `"bind"` as `"unbind"`.

Remove unused parameters, unused wrappers, and redundant forwarding when changing
their owning API. Preserve genuinely supported callers and versioned public
contracts; do not invent compatibility wrappers when there is no such consumer.

Keep a shared helper beside its actual domain within the relevant responsibility
directory; follow [Project structure](project-structure.md) for new-project
placement. The new-project business default is endpoint → Service → Repository:
the Service owns page organization, missing-object semantics and public result
construction even for a small catalog. Keep SQL in named repositories and give
the Service those actual jobs, not an extra call to an existing workflow.
Already-locked ORM fields can be assigned in the business transaction without
per-column forwarding setters. Authentication dependencies and infrastructure
probes keep their direct resource access; existing frameworks retain their own
intentional boundaries.
When a lock result contains the target ORM object, use a direct local such as
`role = locked_role.role` for repeated reads and writes. A local such as
`permissions_before` keeps the original immutable permission set clear during
change calculation. Group the operation's required permission and audit-action
selection together; retain the explicit authorization, mutation and audit stages.
Do not create a generic `utils`
module, base repository, service hierarchy, strategy registry, or callback
framework solely to anticipate reuse. Add a new layer only when its query,
business rule, or lifecycle responsibility improves the real call sites. Check
the call graph after extraction: fewer repeated rules should not require more
steps to understand an otherwise simple operation.

Keep the primary Service flow visible in execution order: obtain the transaction,
load/lock, check the rule, change state, record audit, return after commit. Share
the transaction/audit lifetime with a named context manager when several actual
commands require it; do not wrap every command body in a nested callback merely
to call a generic executor. Do not generalize commands into action strings,
`getattr` dispatch, a generic CRUD framework, or inheritance that forces the
reader to reconstruct where a business rule runs. Framework-required dependency
callbacks and an existing security-check callback with real ordering
semantics are separate cases; do not remove them blindly.

Business classes group related operations for navigation. They do not justify
request state on a global instance, empty constructors, one-method wrappers, or
duplicating a shared rule in several classes. Prefer the same domain vocabulary
in filenames, class names, method names and callers.

For an ordinary Service with no per-request state or resource acquisition and
cleanup, import its module-level instance directly, for example
`from app.services.auth_service import auth_service`. A `get_auth_service`
dependency that only returns this same object adds no request work; do not wrap
it in a `ServiceDependency` alias. The Service may retain its session factory
while each operation still owns its documented session and transaction lifetime.
Tests can construct it with a test factory or replace the instance imported by
the consumer. Authentication, permissions, CAPTCHA, rate limiting and resource
acquisition/cleanup remain real dependencies; this rule does not remove them.

For bundled login, `AuthService.login` shows loading account fields into `user_info`, password
verification, locked rechecks, database transaction exit, then Token issuance
and Redis session registration in order. It returns `LoginResult` only after
registration succeeds; the route only calls this complete login operation and
builds the HTTP response. A second method that only forwards this whole
operation adds no boundary. Keep shared helpers for password errors and state
comparison. `AuthService.issue_access_token` owns signing and registration
coordination; it calls the JWT codec and `login_session_repository` rather than
duplicating their implementations. Keep Redis keys, record conversion and Lua
scripts together in the Repository, and do not hold database locks during issuance.
The local-password and JWT references own the security details.

## Verify The Result

For a behavior-preserving refactor, compare observable outputs, error precedence,
side effects, and transaction boundaries for every affected variant. Use
parameterized tests for shared rules, including invalid operations and the
distinct permission required by each entry point. Keep route-level negative
tests so an unchanged shared core cannot hide an incorrectly wired route.

Run the relevant rollback/concurrency tests when moving authorization or
transaction code. Keep tests focused on outcomes rather than asserting that a
specific helper was called or copying production branches into the test. A
source scan can find possible clones or unused symbols, but similarity and call
counts must not become automatic CI pass/fail rules.

In review, identify the rule now maintained in one place and any deliberately
retained adapter or one-use function whose purpose is non-obvious. Report the
behavior tested and any untested database/Redis boundary.
