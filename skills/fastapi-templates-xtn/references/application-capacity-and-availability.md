# Application Capacity And Availability

Read only when changing connection pools, timeouts, shared process state, or
investigating a measured application bottleneck. This Skill owns code conventions
and correctness. Production sizing, zero-downtime releases, cluster deployment,
monitoring platforms, and recovery drills belong to the project owner and
operations; they are not default feature work or completion gates.

## Dependency Integration Boundary

New projects use one standalone PostgreSQL instance and one standalone Redis
instance. `DATABASE_URL` and `REDIS_URL` are sufficient connection settings;
login state, CAPTCHA, and quotas share Redis. The Skill does not bundle cluster
clients or a cluster-selection step. Preserve an existing project's topology.

`DATABASE_URL` names one writable PostgreSQL endpoint by default. The bundled
code bounds waits and retires failed connections; it does not discover nodes,
promote a primary, or configure failover. A project may explicitly request
multiple connection entrances without adopting a full cluster client, but that
requires supplied endpoints and project-specific connection/failure testing.

Do not add read/write splitting by default. If the owner explicitly requests it,
adapt to the supplied routing design. Authentication, current account status,
`token_version`, and RBAC authority must read the primary, including behind a
proxy. Never route every `SELECT` or `GET` to a replica. Only selected business
reads may tolerate lag; transactions stay on their intended connection.

The bundled Redis factory supports a standalone URL only. Sessions, CAPTCHA,
and quotas retain their Redis atomic scripts. A second standalone rate-limit URL
is optional; Sentinel, Cluster and proxy-specific behavior are not implemented
or certified by this Skill.

Redis outages fail closed; never accept signature-only JWTs or reconstruct JTI
state. Infrastructure recovery may lose recent writes or restore revoked keys.
Do not promise stronger consistency than the supplied infrastructure provides.

## Connection And Timeout Settings

The configuration owner is `app/core/config.py`; settings are exposed through
`.env.example`. These are editable starting values, not a throughput promise.

| Setting | Default | Meaning |
| --- | ---: | --- |
| `DATABASE_POOL_SIZE` | 5 | Retained PostgreSQL connections per process |
| `DATABASE_MAX_OVERFLOW` | 5 | Extra PostgreSQL connections per process |
| `DATABASE_POOL_TIMEOUT_SECONDS` | 5 | Maximum pool checkout wait |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | 5 | Maximum new-connection wait |
| `DATABASE_COMMAND_TIMEOUT_SECONDS` | 20 | Client limit per asyncpg command, including the built-in checkout ping |
| `DATABASE_STATEMENT_TIMEOUT_MS` | 15000 | PostgreSQL statement limit |
| `DATABASE_LOCK_TIMEOUT_MS` | 3000 | PostgreSQL lock-wait limit |
| `REDIS_MAX_CONNECTIONS` | 50 | Maximum connections per client, per node, per process |

PostgreSQL's application ceiling is
`instances * workers * (pool_size + max_overflow)`; two instances with four
workers at these defaults can use 80 connections. Allow room for other database
clients. By default the asset reuses one Redis client per process for active
sessions, CAPTCHA, and rate limiting. It creates a second client only when an
independent standalone rate-limit URL is configured. Worker count also multiplies
password-hashing memory and concurrency.
Increasing pools is not automatically a performance improvement.

Keep lock timeout no larger than statement timeout. Server limits cannot bound
client waits when network replies disappear; the separate driver-command limit
covers that wait. It is not a total HTTP-request deadline: prepare/execute and
multiple commands can consume separate budgets. A total deadline is a
project-specific policy; preserve an existing one and add or alter it only
within the requested scope.

## Password Calculation Capacity

Password work uses the existing `PasswordManager` and these restart-applied
settings from `app/core/config.py` and `.env.example`:

| Setting | Default | Meaning |
| --- | ---: | --- |
| `PASSWORD_MAX_RUNNING` | 2 | Native password calculations running per worker; integer 1..32 |
| `PASSWORD_MAX_WAITING` | 4 | Additional waiting callers per worker; zero disables waiting |
| `PASSWORD_WAIT_TIMEOUT_SECONDS` | 0.5 | Finite positive maximum wait for a calculation slot, in seconds |

A free slot starts immediately. A full queue or elapsed waiting deadline returns
safe HTTP `503` / `50301` with the bilingual busy message before starting native
work. The deadline does not stop a calculation already running. Cancellation
removes a waiting caller, while a started calculation retains its running slot
until its native thread finishes. This keeps actual CPU and memory usage bounded.

Each worker owns its running slots and waiting callers. Total deployment ceilings
are `instances * workers * PASSWORD_MAX_RUNNING` calculations and
`instances * workers * PASSWORD_MAX_WAITING` waiting callers for uniform settings.
Workers do not transfer waiting requests or borrow slots. With two workers on
one server, the defaults permit four simultaneous Argon2 calculations, using
about 256 MiB of Argon2 working memory at 64 MiB each, plus application overhead.
Choose worker count and these limits together based on the server's CPU, memory
and measured concurrent latency. The local resource guard is separate from
Redis-backed business request counts; it adds no distributed queue.

CAPTCHA verification runs before password admission and has already consumed
the challenge if admission later returns busy. Do not return the CAPTCHA or
automatically replay the submission; require a fresh CAPTCHA for another attempt.

## Resource And Transaction Correctness

- Release authentication's database connection after copying its immutable
  authority snapshot, before a Redis rate-limit check or a separate business transaction.
  Protected writes still recheck authority under their own transaction locks.
- Keep password hashing bounded per process. Cancelling its caller must not free
  a slot while the underlying native work still runs.
- Keep external I/O outside authorization locks. The global `rbac_state` lock
  deliberately serializes its protected writes; unrelated business writes must
  not acquire it by default. Preserve the correctness rules in
  [Atomic consistency](atomic-consistency.md).
- Shared PostgreSQL/Redis state, keys, namespaces, session policy, trusted-IP
  interpretation, and clocks must agree across app processes. Never substitute
  process-local positive-JTI caches or counters for authoritative shared state.
- Dispose resources owned by the process during lifespan shutdown. Use the
  existing project lifecycle rather than introducing a deployment controller.

The asset keeps engine, session and narrow connection-failure hooks together in
`app/db/postgres_db.py`. SQLAlchemy's `pool_pre_ping` checks an existing pooled
connection when it is borrowed and reconnects to the configured endpoint when
it detects a disconnect. The driver command timeout bounds the individual ping;
there is no separate whole-checkout deadline or custom one-replacement counter.
It never replays business SQL or commits.

Classified database connection/pool/server-timeout/client-deadline failures
return safe `50301`. A driver command timeout marks only the affected connection
invalid; local asyncpg `terminate()` prevents cleanup from waiting on a broken
network. Cancellation propagates.
Unrelated business timeouts, programming failures, and integrity errors retain
their ordinary response handling instead of being mislabeled database outages.

A lost commit response may mean the write succeeded. Reconcile authoritative
business state before retrying; `503` does not prove rollback. Add duplicate
prevention for concrete replay-sensitive business commands, using the project's
existing mechanisms when available; do not add generic tables to every service.

The default project has no readiness endpoint. Add dependency probes only when
the adopter explicitly requests them, and restrict access to an internal network
or trusted probes. Use bounded timeouts and safe overall results. A readiness
result does not promise uninterrupted schema upgrades or automatic failover.
Those deployment choices are outside the default Skill deliverable.

## Focused Verification

Run tests for the code boundary being changed. Database timeout changes also
need real-PostgreSQL network-stall tests before claiming the timeout/recovery
behavior is verified; changes to shared session/quota
behavior need independent-process checks. See [Testing](testing.md). Routine
feature work does not require a production load run or a cluster exercise.

For an actual performance task, measure representative queries, lock/pool waits,
and CPU/memory before changing code. Keep normal authorization and quotas intact.
The existing GET-only `scripts/load_test.py` is optional; commands and count/time
modes are documented in the [asset README](../assets/postgresql-rbac/README.md).
Its results describe the tested workload, not universal capacity or HA.

Do not add caches, queues, sharding, monitoring systems, rolling-release
machinery, or a cluster-validation backlog merely because the owner requests
clean or efficient code. Missing optional deployment features are not baseline
code defects. Report actual correctness failures separately from user-owned
deployment choices and unmeasured performance assumptions.
