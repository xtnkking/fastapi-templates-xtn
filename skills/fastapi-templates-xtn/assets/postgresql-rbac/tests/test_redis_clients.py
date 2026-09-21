from typing import Any
from unittest.mock import AsyncMock

import pytest
from redis.asyncio import Redis, RedisCluster
from redis.asyncio.connection import SSLConnection
from redis.asyncio.sentinel import SentinelConnectionPool, SentinelManagedSSLConnection
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.config import RedisEndpoint, Settings
from app.db.redis import (
    RedisClient,
    close_redis_client,
    create_rate_limit_redis_client,
    create_redis_client,
)


def connection_settings(**overrides: Any) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        redis_url=None,
        rate_limit_redis_url=None,
        redis_connection=RedisEndpoint.model_validate(overrides),
        redis_max_connections=7,
        redis_connect_timeout_seconds=0.4,
        redis_socket_timeout_seconds=0.6,
    )


async def test_legacy_standalone_url_keeps_bounded_connections_and_closes() -> None:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        redis_url="redis://data-user:private-data-password@localhost:6379/2",
        rate_limit_redis_url=None,
        redis_max_connections=7,
        redis_connect_timeout_seconds=0.4,
        redis_socket_timeout_seconds=0.6,
    )
    client = create_redis_client(settings)
    assert isinstance(client, Redis)
    options = client.connection_pool.connection_kwargs
    assert options["username"] == "data-user"
    assert options["password"] == "private-data-password"
    assert options["db"] == 2
    assert client.connection_pool.max_connections == 7
    assert options["socket_connect_timeout"] == 0.4
    assert options["socket_timeout"] == 0.6
    assert options["decode_responses"] is True
    await close_redis_client(client)


async def test_rediss_url_enforces_certificate_and_hostname_verification() -> None:
    client = create_redis_client(
        connection_settings(mode="standalone", url="rediss://redis.example.test/0")
    )
    assert isinstance(client, Redis)
    assert client.connection_pool.connection_class is SSLConnection
    options = client.connection_pool.connection_kwargs
    assert options["ssl_cert_reqs"] == "required"
    assert options["ssl_check_hostname"] is True
    # Exercise pool construction as well: 'ssl' is not an SSLConnection keyword.
    connection = client.connection_pool.make_connection()  # type: ignore[no-untyped-call]
    assert isinstance(connection, SSLConnection)
    await close_redis_client(client)


async def test_sentinel_separates_discovery_auth_tls_and_data_auth_tls() -> None:
    settings = connection_settings(
        mode="sentinel",
        nodes=[{"host": "sentinel.example.test", "port": 26379}],
        sentinel_master="auth-primary",
        username="data-user",
        password="private-data-password",
        db=2,
        tls=True,
        sentinel_username="discovery-user",
        sentinel_password="private-discovery-password",
        sentinel_tls=True,
    )
    client = create_redis_client(settings)
    assert isinstance(client, Redis)
    pool = client.connection_pool
    assert isinstance(pool, SentinelConnectionPool)
    assert pool.is_master is True
    assert pool.service_name == "auth-primary"
    assert pool.max_connections == 7
    assert pool.connection_class is SentinelManagedSSLConnection
    data_options = pool.connection_kwargs
    assert data_options["username"] == "data-user"
    assert data_options["password"] == "private-data-password"
    assert data_options["db"] == 2
    assert data_options["ssl_check_hostname"] is True
    assert data_options["ssl_cert_reqs"] == "required"
    discovery = pool.sentinel_manager.sentinels[0]
    discovery_pool = discovery.connection_pool
    assert discovery_pool.max_connections == 7
    assert discovery_pool.connection_class is SSLConnection
    discovery_options = discovery_pool.connection_kwargs
    assert discovery_options["username"] == "discovery-user"
    assert discovery_options["password"] == "private-discovery-password"
    assert discovery_options["db"] == 0
    assert discovery_options["socket_timeout"] == 0.6
    assert discovery_options["ssl_check_hostname"] is True
    assert discovery_options["ssl_cert_reqs"] == "required"
    await close_redis_client(client)


async def test_cluster_uses_primary_reads_and_bounded_per_node_pools() -> None:
    client = create_redis_client(
        connection_settings(
            mode="cluster",
            nodes=[
                {"host": "redis-a.example.test", "port": 6379},
                {"host": "redis-b.example.test", "port": 6379},
            ],
            username="data-user",
            password="private-data-password",
            tls=True,
        )
    )
    assert isinstance(client, RedisCluster)
    assert client.read_from_replicas is False
    assert client.load_balancing_strategy is None
    assert client.cluster_error_retry_attempts == 0
    assert client.connection_error_retry_attempts == 0
    assert len(client.nodes_manager.startup_nodes) == 2
    for node in client.nodes_manager.startup_nodes.values():
        assert node.max_connections == 7
        assert node.connection_class is SSLConnection
        assert node.connection_kwargs["username"] == "data-user"
        assert node.connection_kwargs["password"] == "private-data-password"
        assert node.connection_kwargs["socket_timeout"] == 0.6
        assert node.connection_kwargs["ssl_check_hostname"] is True
        assert node.connection_kwargs["ssl_cert_reqs"] == "required"
    await close_redis_client(client)


@pytest.mark.parametrize("mode", ["standalone", "sentinel", "cluster"])
async def test_lost_response_never_replays_a_client_command(mode: str) -> None:
    endpoint: dict[str, Any] = {"mode": mode}
    if mode == "standalone":
        endpoint["url"] = "redis://redis.example.test/0"
    else:
        endpoint["nodes"] = [{"host": "redis.example.test", "port": 6379}]
        if mode == "sentinel":
            endpoint["sentinel_master"] = "auth-primary"
    client = create_redis_client(connection_settings(**endpoint))
    if isinstance(client, RedisCluster):
        retries = [client.retry]
    else:
        retries = [client.connection_pool.connection_kwargs["retry"]]
        if isinstance(client.connection_pool, SentinelConnectionPool):
            retries.extend(
                node.connection_pool.connection_kwargs["retry"]
                for node in client.connection_pool.sentinel_manager.sentinels
            )
    try:
        for retry in retries:
            execute = AsyncMock(side_effect=RedisTimeoutError("reply lost"))
            disconnect = AsyncMock()
            with pytest.raises(RedisTimeoutError):
                await retry.call_with_retry(execute, disconnect)
            assert execute.await_count == 1
            assert disconnect.await_count == 1
    finally:
        await close_redis_client(client)


async def test_sentinel_shutdown_closes_discovery_even_if_data_pool_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = create_redis_client(
        connection_settings(
            mode="sentinel",
            nodes=[
                {"host": "sentinel-a.example.test", "port": 26379},
                {"host": "sentinel-b.example.test", "port": 26379},
            ],
            sentinel_master="auth-primary",
        )
    )
    assert isinstance(client, Redis)
    pool = client.connection_pool
    assert isinstance(pool, SentinelConnectionPool)
    data_close = AsyncMock(side_effect=RuntimeError("data close failed"))
    node_closes = [AsyncMock(), AsyncMock()]
    monkeypatch.setattr(pool, "disconnect", data_close)
    for node, close in zip(pool.sentinel_manager.sentinels, node_closes, strict=True):
        monkeypatch.setattr(node, "aclose", close)
    with pytest.raises(RuntimeError, match="data close failed"):
        await close_redis_client(client)
    assert data_close.await_count == 1
    assert all(close.await_count == 1 for close in node_closes)


async def test_rate_limit_factory_inherits_cluster_or_connects_independently() -> None:
    shared = connection_settings(
        mode="cluster", nodes=[{"host": "redis.example.test", "port": 6379}]
    )
    clients: list[RedisClient] = []
    try:
        shared_client = create_rate_limit_redis_client(shared)
        clients.append(shared_client)
        assert isinstance(shared_client, RedisCluster)
        independent = shared.model_copy(
            update={"rate_limit_redis_url": "redis://limiter.example.test:6380/1"}
        )
        independent_client = create_rate_limit_redis_client(independent)
        clients.append(independent_client)
        assert isinstance(independent_client, Redis)
        assert independent_client.connection_pool.connection_kwargs["host"] == (
            "limiter.example.test"
        )
    finally:
        for client in clients:
            await close_redis_client(client)
