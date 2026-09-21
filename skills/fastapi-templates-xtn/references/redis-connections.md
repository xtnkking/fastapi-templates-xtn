# Redis Connection Modes

Read for explicitly requested or existing Sentinel/Cluster, separate backends,
custom TLS, or changes to Redis clients/keys/scripts. Ordinary new projects use
one standalone Redis via `REDIS_URL`; no cluster choice or second Redis is
required. The application connects to an existing service. Operations supplies reachable
addresses, accounts, certificates, and the Sentinel service name; deploying
nodes, replication, elections, routing, and backups is outside this Skill.

The runnable implementation is
[`app/db/redis.py`](../assets/postgresql-rbac/app/db/redis.py), with validated
[`Settings` and `RedisEndpoint`](../assets/postgresql-rbac/app/core/config.py).
It uses redis-py 5.3.1 or newer within major version 5.

## Choose One Connection Form

The default is one standalone Redis shared by login state, CAPTCHA, and quotas:

```dotenv
REDIS_URL=redis://127.0.0.1:6379/0
```

Only when native Sentinel discovery is needed, replace `REDIS_URL` with:

```dotenv
REDIS_CONNECTION__MODE=sentinel
REDIS_CONNECTION__NODES='[{"host":"sentinel-a.example.test","port":26379},{"host":"sentinel-b.example.test","port":26379}]'
REDIS_CONNECTION__SENTINEL_MASTER=auth-primary
```

Only when native Cluster is needed, replace `REDIS_URL` with:

```dotenv
REDIS_CONNECTION__MODE=cluster
REDIS_CONNECTION__NODES='[{"host":"redis-a.example.test","port":6379},{"host":"redis-b.example.test","port":6379}]'
```

Node lists are JSON arrays of `host`/integer `port` objects. Hosts contain no
scheme or credentials; use an unbracketed IPv6 address where applicable. Cluster
nodes are discovery seeds: the application must also reach every address
advertised by the cluster. An inaccessible advertised address requires a
corrected infrastructure endpoint, not a fallback to local or standalone Redis.

`REDIS_URL` and `REDIS_CONNECTION` are mutually exclusive. A nested standalone
form is also supported with `REDIS_CONNECTION__MODE=standalone` and
`REDIS_CONNECTION__URL=redis://.../0`. Standalone credentials and database number
belong in that URL; percent-encode reserved characters in credentials. Redis
URLs cannot contain query parameters that override the bounded client settings.

## Accounts, TLS, And Separate Backends

These fields are optional when the supplied service does not require them:

| Nested suffix after `REDIS_CONNECTION__` | Purpose |
| --- | --- |
| `USERNAME`, `PASSWORD` | Data-node ACL account for Sentinel or Cluster |
| `DB` | Sentinel database number, default `0`; Cluster accepts only `0` |
| `SENTINEL_USERNAME`, `SENTINEL_PASSWORD` | Separate Sentinel discovery account |
| `TLS` | Enable TLS for Sentinel data nodes or Cluster nodes |
| `CA_FILE` | Optional trust certificate file for data connections |
| `CERT_FILE`, `KEY_FILE` | Optional client certificate and key, configured together |
| `SENTINEL_TLS` | Independently enable TLS for Sentinel discovery connections |
| `SENTINEL_CA_FILE` | Optional trust certificate file for Sentinel discovery |
| `SENTINEL_CERT_FILE`, `SENTINEL_KEY_FILE` | Optional discovery client certificate/key pair |

Standalone TLS uses `rediss://` and the same nested `CA_FILE`, `CERT_FILE`, and
`KEY_FILE` options when custom files are needed. TLS always verifies the server
certificate and hostname; there is no disable-verification setting. TLS file
settings require TLS, existing files, and a complete client certificate/key pair.
Provide credentials through the project's secret configuration; never print
connection URLs, passwords, or complete settings in application logs.

Active login and CAPTCHA state share the main Redis client; rate-limit counters
may use a different service and connection mode. The rate-limit backend accepts either
`RATE_LIMIT_REDIS_URL` or the same nested fields under
`RATE_LIMIT_REDIS_CONNECTION__`, never both. For example, a standalone active-JTI
backend can coexist with a Cluster rate-limit backend.

If both rate-limit connection forms are absent, it inherits the **complete**
active-JTI connection: mode, nodes, accounts, database, TLS, and Sentinel service.
It does not inherit just a URL or merge a partial second connection. The example
leaves the separate rate-limit URL commented out, so sharing works by default.
Remove any existing override to return to sharing; do not assign an empty string.
Shared infrastructure means shared
failure and capacity boundaries. The application still creates two clients.

## Client Correctness

- `REDIS_CONNECT_TIMEOUT_SECONDS` and `REDIS_SOCKET_TIMEOUT_SECONDS` default to
  `0.5` seconds and must be finite positive values. Adapt them to the supplied
  network. `REDIS_MAX_CONNECTIONS=50` bounds each client pool per process. In
  Cluster it is **per node**, and Sentinel discovery clients also own bounded
  pools. It is not one total limit across the cluster or all application workers.
- Sentinel data commands target the discovered primary. Cluster reads also use
  primaries; replica reads are disabled for security state. Cluster requires all
  slots to be covered and does not support nonzero logical databases.
- Network/timeout command retries are disabled. A lost reply may follow a
  successful login, CAPTCHA consumption, or limiter increment; replaying its
  Lua script could duplicate a mutation. Normal `MOVED`/`ASK` redirection remains
  enabled because those replies identify a different command destination.
- Session Lua keys use a per-user hash tag so every key touched by one script
  occupies one Cluster slot. Preserve this invariant when changing scripts;
  unrelated users must not all be assigned one shared slot. Quota scripts touch
  one key, so their keys can distribute across slots. CAPTCHA keys deliberately
  share their namespace slot to preserve atomic challenge replacement; Cluster
  does not distribute that particular write path across nodes. Other multi-key
  features must group by slot or use a supported non-atomic scatter operation.
- Connection failure returns the normal safe unavailable response. Later
  requests can discover the new primary/topology; the application does not elect
  nodes, silently accept signature-only JWTs, or reconstruct missing active JTI
  records. A network error is not proof that the previous command did nothing.
- Use `close_redis_client` in the existing application lifespan. Sentinel clients
  close both data connections and the separate discovery connections they own.

Connection support does not promise lossless failover. The supplied Redis
service's persistence and replication determine whether recent writes survive.
The isolated tests cover real standalone, Sentinel, and Cluster connections;
TLS configuration is tested separately from those plaintext topology tests.
Changing from the earlier quota-key format starts new counters; old quota keys
expire under their existing short TTLs. It does not preserve a partially used
window across this update.
