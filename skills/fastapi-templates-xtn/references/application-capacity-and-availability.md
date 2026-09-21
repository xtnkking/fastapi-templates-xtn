# Application Capacity And Availability

Read only when changing connection pools, timeouts, shared process state, or
investigating a measured application bottleneck. This Skill owns code conventions
and correctness. Production sizing, zero-downtime releases, cluster deployment,
monitoring platforms, and recovery drills belong to the project owner and
operations; they are not default feature work or completion gates.

## Dependency Integration Boundary

New projects default to one standalone PostgreSQL instance and one standalone
Redis instance. `DATABASE_URL` and `REDIS_URL` are sufficient connection settings;
login state, CAPTCHA, and quotas share Redis. Preserve existing topology and do
not add a cluster-selection step to ordinary project setup.

Only when a PostgreSQL cluster is requested, point `DATABASE_URL` at its supplied
writable endpoint. Operations owns replication, primary promotion, and endpoint
switching. Application code owns bounded waits,
bad-connection cleanup, reconnection through that endpoint, and transaction
failure handling. It does not elect nodes or manage cluster infrastructure.

Do not add read/write splitting by default. If the owner explicitly requests it,
adapt to the supplied routing design. Authentication, current account status,
`token_version`, and RBAC authority must read the primary, including behind a
proxy. Never route every `SELECT` or `GET` to a replica. Only selected business
reads may tolerate lag; transactions stay on their intended connection.

The bundled Redis factory supports standalone, Sentinel master discovery, and
native Cluster routing. Keep standalone as the default; read
[Redis connections](redis-connections.md) when configuring another supplied
topology. Sessions use fixed same-slot keys per user; quota scripts use one key.
CAPTCHA refresh keeps its namespace in one slot to preserve atomic replacement.
A supplied proxy must support the driver's connection options and script
behavior; a changed URL alone is not proof of compatibility.

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
| `DATABASE_COMMAND_TIMEOUT_SECONDS` | 20 | Client limit per asyncpg command and complete checkout probe |
| `DATABASE_STATEMENT_TIMEOUT_MS` | 15000 | PostgreSQL statement limit |
| `DATABASE_LOCK_TIMEOUT_MS` | 3000 | PostgreSQL lock-wait limit |
| `REDIS_MAX_CONNECTIONS` | 50 | Maximum connections per client, per node, per process |

PostgreSQL's application ceiling is
`instances * workers * (pool_size + max_overflow)`; two instances with four
workers at these defaults can use 80 connections. Allow room for other database
clients. The asset has two Redis clients per process, even when both target
one server. Cluster has a pool per discovered node; Sentinel also has discovery
pools. Worker count also multiplies password-hashing memory and concurrency.
Increasing pools is not automatically a performance improvement.

Keep lock timeout no larger than statement timeout. Server limits cannot bound
client waits when network replies disappear; the separate driver-command limit
covers that wait. It is not a total HTTP-request deadline: prepare/execute and
multiple commands can consume separate budgets. A total deadline is a
project-specific policy; preserve an existing one and add or alter it only
within the requested scope.

## Resource And Transaction Correctness

- Release authentication's database connection after copying its immutable
  authority snapshot, before Redis admission or a separate business transaction.
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

The asset uses a bounded, transaction-free asyncpg checkout `SELECT 1` instead
of SQLAlchemy's built-in `pool_pre_ping`. A confirmed preflight disconnect may
replace the connection once before business SQL starts; a timeout or exhausted
preflight returns unavailable. It never replays business SQL or commits.

Classified database connection/pool/server-timeout/client-deadline failures
return safe `503001`. Only the affected timed-out connection is retired through
local asyncpg `terminate()`; healthy peers are preserved. Cancellation propagates.
Unrelated business timeouts, programming failures, and integrity errors retain
their ordinary response handling instead of being mislabeled database outages.

A lost commit response may mean the write succeeded. Reconcile authoritative
business state before retrying; `503` does not prove rollback. Add duplicate
prevention for concrete replay-sensitive business commands, using the project's
existing mechanisms when available; do not add generic tables to every service.

Readiness checks a writable primary, the expected schema and authorization row,
and usable Redis. It does not promise uninterrupted schema upgrades or automatic
failover. Those deployment choices are outside the default Skill deliverable.

## Focused Verification

Run tests for the code boundary being changed. Database timeout changes need the
existing real-PostgreSQL network-stall tests; changes to shared session/quota
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
