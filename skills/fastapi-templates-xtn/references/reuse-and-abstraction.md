# Reuse And Abstraction

Read when introducing shared functions or layers, adding a variant of an
existing flow, or reviewing duplication. Apply these decisions to the changed
surface; do not turn an ordinary feature into a repository-wide rewrite.

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
  permissions, schemas, operation IDs, or responses differ. Call one existing
  service command with the selected state or operation. Do not insert a second
  helper that only forwards those arguments to that command.
- Share identical response projections between reads and writes in a small
  domain-owned module when both need them. A projection must not start a query,
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

## Keep Parameters And Layers Small

Prefer inputs with domain meaning: `is_active: bool` represents a real state;
`operation: Literal["bind", "unbind"]` represents two closed operations. Avoid
boolean combinations such as `skip_permission`, `skip_audit`, `commit`, or
`is_admin` that turn one function into unrelated workflows or allow a bypass.
Use explicit keyword arguments where call sites would otherwise be ambiguous.

`Literal` and annotations are not runtime validation. A command callable outside
Pydantic must reject unknown operation values before lookup or side effects;
never treat every value other than `"bind"` as `"unbind"`.

Remove unused parameters, unused wrappers, and redundant forwarding when changing
their owning API. Preserve genuinely supported callers and versioned public
contracts; do not invent compatibility wrappers when there is no such consumer.

Keep a shared helper beside its actual domain. Do not create a generic `utils`
module, base repository, service hierarchy, strategy registry, or callback
framework solely to anticipate reuse. Add a new layer only when its query,
business rule, or lifecycle responsibility improves the real call sites. Check
the call graph after extraction: fewer repeated rules should not require more
steps to understand an otherwise simple operation.

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
