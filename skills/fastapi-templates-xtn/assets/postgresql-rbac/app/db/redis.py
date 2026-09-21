import asyncio
from pathlib import Path
from typing import Any, cast

from fastapi import Request
from redis.asyncio import Redis, RedisCluster
from redis.asyncio.cluster import ClusterNode
from redis.asyncio.retry import Retry
from redis.asyncio.sentinel import Sentinel, SentinelConnectionPool
from redis.backoff import NoBackoff

from app.core.config import RedisEndpoint, Settings
from app.core.errors import unavailable

type RedisClient = Redis | RedisCluster


def create_redis_client(settings: Settings) -> RedisClient:
    return _create_client(settings.effective_redis_connection, settings)


def create_rate_limit_redis_client(settings: Settings) -> RedisClient:
    return _create_client(settings.effective_rate_limit_redis_connection, settings)


class _SentinelRedis(Redis):
    """Own both the data pool and Sentinel's separate discovery clients."""

    def __init__(self, manager: Sentinel, pool: SentinelConnectionPool) -> None:
        super().__init__(connection_pool=pool)
        self.auto_close_connection_pool = True
        self._sentinel_manager = manager

    async def aclose(self, close_connection_pool: bool | None = None) -> None:
        # Attempt every close even if one connection close raises.
        results = await asyncio.gather(
            super().aclose(close_connection_pool),
            *(client.aclose() for client in self._sentinel_manager.sentinels),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result


def _tls_options(
    enabled: bool,
    ca_file: Path | None,
    cert_file: Path | None,
    key_file: Path | None,
) -> dict[str, Any]:
    if not enabled:
        return {}
    return {
        "ssl": True,
        "ssl_cert_reqs": "required",
        "ssl_check_hostname": True,
        "ssl_ca_certs": str(ca_file) if ca_file else None,
        "ssl_certfile": str(cert_file) if cert_file else None,
        "ssl_keyfile": str(key_file) if key_file else None,
    }


def _create_client(endpoint: RedisEndpoint, settings: Settings) -> RedisClient:
    options: dict[str, Any] = {
        "decode_responses": True,
        "socket_connect_timeout": settings.redis_connect_timeout_seconds,
        "socket_timeout": settings.redis_socket_timeout_seconds,
        "max_connections": settings.redis_max_connections,
        # A lost response may follow a successful Lua write. Never replay it.
        "retry": Retry(NoBackoff(), 0),
        "retry_on_error": [],
    }
    data_options = {
        **options,
        **_tls_options(
            endpoint.tls or bool(endpoint.url and endpoint.url.startswith("rediss://")),
            endpoint.ca_file,
            endpoint.cert_file,
            endpoint.key_file,
        ),
    }
    if endpoint.mode == "standalone":
        assert endpoint.url is not None  # Validated during settings startup.
        # from_url selects SSLConnection itself; that class has no 'ssl' argument.
        data_options.pop("ssl", None)
        return cast(Redis, Redis.from_url(endpoint.url, **data_options))

    data_options.update(
        username=endpoint.username,
        password=endpoint.password.get_secret_value() if endpoint.password else None,
        db=endpoint.db,
    )
    if endpoint.mode == "cluster":
        return cast(
            RedisCluster,
            RedisCluster(
                startup_nodes=[
                    ClusterNode(node.host, node.port) for node in endpoint.nodes
                ],
                require_full_coverage=True,
                cluster_error_retry_attempts=0,
                connection_error_retry_attempts=0,
                **data_options,
            ),
        )

    sentinel_options = {
        **options,
        **_tls_options(
            endpoint.sentinel_tls,
            endpoint.sentinel_ca_file,
            endpoint.sentinel_cert_file,
            endpoint.sentinel_key_file,
        ),
        "username": endpoint.sentinel_username,
        "password": (
            endpoint.sentinel_password.get_secret_value()
            if endpoint.sentinel_password
            else None
        ),
    }
    manager = Sentinel(  # type: ignore[no-untyped-call]
        [(node.host, node.port) for node in endpoint.nodes],
        sentinel_kwargs=sentinel_options,
    )
    pool = SentinelConnectionPool(  # type: ignore[no-untyped-call]
        endpoint.sentinel_master,
        manager,
        is_master=True,
        **data_options,
    )
    return _SentinelRedis(manager, pool)


async def close_redis_client(client: RedisClient) -> None:
    await client.aclose()


def get_redis(request: Request) -> RedisClient:
    client = getattr(request.app.state, "redis", None)
    if client is None:
        raise unavailable("active_token_registry_unavailable")
    return cast(RedisClient, client)


def get_rate_limit_redis(request: Request) -> RedisClient:
    client = getattr(request.app.state, "rate_limit_redis", None)
    if client is None:
        raise unavailable("rate_limit_registry_unavailable")
    return cast(RedisClient, client)
