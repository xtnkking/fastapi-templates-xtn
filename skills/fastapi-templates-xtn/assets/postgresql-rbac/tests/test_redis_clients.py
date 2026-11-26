#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证单机 Redis 客户端的连接池、TLS、重试与独立限流入口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        移除集群模式测试并保留单机安全边界
# --------------------------------------------------------------------------------------------------

from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest
from redis.asyncio import Redis
from redis.asyncio.connection import SSLConnection
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.config import get_settings
from app.db.redis_db import close_redis_client, create_rate_limit_redis_client, create_redis_client


async def test_standalone_url_keeps_bounded_connections_and_closes() -> None:
    """
        确认单机连接地址和超时参数进入 Redis 连接池，并可正常关闭。

    :return: 无返回值；连接池配置符合设置时测试通过。
    """
    settings = get_settings().model_copy(update={
        "redis_url": "redis://data-user:private-data-password@localhost:6379/2",
        "redis_max_connections": 7,
        "redis_connect_timeout_seconds": 0.4,
        "redis_socket_timeout_seconds": 0.6,
    })
    client = create_redis_client(settings)
    options = client.connection_pool.connection_kwargs
    assert options["username"] == "data-user"
    assert options["password"] == "private-data-password"
    assert options["db"] == 2
    assert client.connection_pool.max_connections == 7
    assert options["socket_connect_timeout"] == 0.4
    assert options["socket_timeout"] == 0.6
    assert options["decode_responses"] is True
    await close_redis_client(client)


async def test_rediss_url_verifies_certificate_and_hostname() -> None:
    """
        确认单机加密 URL 启用证书和主机名校验。

    :return: 无返回值；TLS 连接参数完整时测试通过。
    """
    settings = get_settings().model_copy(update={"redis_url": "rediss://redis.example.test/0"})
    client = create_redis_client(settings)
    assert client.connection_pool.connection_class is SSLConnection
    options = client.connection_pool.connection_kwargs
    assert options["ssl_cert_reqs"] == "required"
    assert options["ssl_check_hostname"] is True
    connection = client.connection_pool.make_connection()  # type: ignore[no-untyped-call]
    assert isinstance(connection, SSLConnection)
    await close_redis_client(client)


async def test_lost_response_does_not_replay_a_client_command() -> None:
    """
        确认 Redis 响应丢失时不会重放可能已经执行的写命令。

    :return: 无返回值；底层重试器只尝试一次时测试通过。
    """
    client = create_redis_client(get_settings())
    retry = client.connection_pool.connection_kwargs["retry"]
    execute = AsyncMock(side_effect=RedisTimeoutError("reply lost"))
    disconnect = AsyncMock()
    try:
        with pytest.raises(RedisTimeoutError):
            await retry.call_with_retry(execute, disconnect)
        assert execute.await_count == 1
        assert disconnect.await_count == 1
    finally:
        await close_redis_client(client)


async def test_rate_limit_client_uses_separate_url_when_configured() -> None:
    """
        确认独立限流 URL 只创建单机客户端，未配置时使用主 URL。

    :return: 无返回值；两个入口地址按设置选择时测试通过。
    """
    settings = get_settings()
    shared = create_rate_limit_redis_client(settings)
    independent_settings = settings.model_copy(update={
        "rate_limit_redis_url": "redis://limiter.example.test:6380/1",
    })
    independent = create_rate_limit_redis_client(independent_settings)
    try:
        assert isinstance(shared, Redis)
        assert shared.connection_pool.connection_kwargs["host"] == urlsplit(settings.redis_url).hostname
        assert isinstance(independent, Redis)
        assert independent.connection_pool.connection_kwargs["host"] == "limiter.example.test"
    finally:
        await close_redis_client(shared)
        await close_redis_client(independent)
