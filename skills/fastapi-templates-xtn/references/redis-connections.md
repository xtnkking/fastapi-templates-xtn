# Redis Standalone Connections

The bundled application connects only to a standalone Redis endpoint. It does
not configure Sentinel, Cluster, replication, node discovery, or failover.
Adopters needing those capabilities must implement and verify them in their own
project; do not imply that changing a URL enables cluster support.

## Default

```dotenv
REDIS_URL=redis://127.0.0.1:6379/0
```

The same client and connection pool serve active login JTI, graphical CAPTCHA,
and per-business quotas. `REDIS_MAX_CONNECTIONS=50` bounds connections per
process; `REDIS_CONNECT_TIMEOUT_SECONDS` and `REDIS_SOCKET_TIMEOUT_SECONDS`
default to `0.5`. Tune these values for the adopter's network. Redis outages
fail closed for authentication and rate limiting.

When an explicitly separate **standalone** rate-limit service is needed, set
`RATE_LIMIT_REDIS_URL=redis://host:port/db`. Otherwise leave it unset so the
application reuses the main Redis client. Both URLs accept `redis://` or
`rediss://`, a host, optional credentials and an optional database number.
Percent-encode reserved characters in credentials. Query strings and fragments
are rejected so a URL cannot override bounded client options.

`rediss://` enables TLS with server-certificate and hostname verification.
The bundled configuration has no switch to disable those checks or to load a
project-specific CA/client certificate. Implement and verify such an extension
only for a concrete service that requires it; never put passwords or complete
URLs in logs.

The client deliberately does not retry a command whose reply was lost: the
server may already have consumed a CAPTCHA, registered a session, or increased
a quota. `app/db/redis_db.py` owns construction, request access and closing;
`app/main.py` creates the second client only when its URL is present and closes
each created client once.
