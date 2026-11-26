#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    创建默认单机 Redis 客户端，提供请求依赖并管理连接关闭。
#    限流默认共用该客户端；仅明确提供第二个单机 URL 时新建客户端。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释共享客户端、发现连接与禁止重放写入的原因
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/26    XTN       V1.003        对齐 Redis Cluster 客户端参数与类型标注
# 2026/09/27    XTN       V1.004        Redis 拓扑模型改由独立配置模块负责
# 2026/09/29    XTN       V1.005        Redis 客户端类型别名改用普通赋值形式
# 2026/09/30    XTN       V1.006        分离按需拓扑客户端，突出默认单机连接与依赖
# 2026/09/30    XTN       V1.007        删除集群模式，只保留单机 Redis URL
# 2026/10/13    XTN       V1.008        通俗说明客户端创建、请求共用及关闭步骤
# 2026/10/16    XTN       V1.009        异常构造器名称统一标明固定 HTTP 状态
# --------------------------------------------------------------------------------------------------


from typing import Any, cast

from fastapi import Request
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff

from app.core.config import Settings
from app.core.exceptions import unavailable_503

# 业务、验证码和限流使用同一类异步 Redis 客户端。
RedisClient = Redis


def create_redis_client(settings: Settings) -> RedisClient:
    """
        创建业务 Redis 客户端；默认由 REDIS_URL 连接单机服务。

    :param settings: 含业务 Redis 入口、连接数和超时的应用配置。
    :return: 应用生命周期负责关闭的 Redis 客户端。
    """
    # 用业务 REDIS_URL 和连接参数准备客户端；真正连接发生在后续发送 Redis 命令时。
    return _create_client(settings.redis_url, settings)


def create_rate_limit_redis_client(settings: Settings) -> RedisClient:
    """
        创建显式配置的限流客户端；未配置时入口与主 Redis 相同。

        默认复用同一实例的判断由应用 lifespan 负责，不在此重复创建连接池。

    :param settings: 含限流 Redis 入口、连接数和超时的应用配置。
    :return: 应用生命周期负责关闭的 Redis 客户端。
    """
    # 取配置确定的限流地址再创建客户端；是否直接复用业务客户端，由启动入口先判断。
    return _create_client(settings.effective_rate_limit_redis_url, settings)


def _create_client(url: str, settings: Settings) -> RedisClient:
    """
        由已校验的单机 URL 创建带连接池和超时上限的客户端。

        关闭自动命令重试，避免丢失回包后重复消费验证码或重复扣限流次数。

    :param url: 已校验的 redis:// 或 rediss:// 单机地址。
    :param settings: 连接数与网络等待上限。
    :return: 尚未发起网络请求的单机 Redis 客户端。
    """
    # 1. 指定解码为文字、连接数和等待时间；重试次数设为0，避免一次命令意外执行两次。
    options: dict[str, Any] = {
        "decode_responses": True,
        "socket_connect_timeout": settings.redis_connect_timeout_seconds,
        "socket_timeout": settings.redis_socket_timeout_seconds,
        "max_connections": settings.redis_max_connections,
        "retry": Retry(NoBackoff(), 0),
        "retry_on_error": [],
    }
    if url.startswith("rediss://"):
        # 2. rediss 是加密连接，必须检查证书和主机名，确认连到的是预期 Redis。
        options.update(ssl_cert_reqs="required", ssl_check_hostname=True)
    # 3. 返回带连接池的客户端；此时不发送命令，也不为每次请求新建客户端。
    return cast(Redis, Redis.from_url(url, **options))


async def close_redis_client(client: RedisClient) -> None:
    """
        关闭单机 Redis 客户端及其拥有的连接池。

    :param client: 应用停止使用的业务或限流 Redis 客户端。
    :return: 无返回值；连接关闭完成后返回。
    """
    # 应用退出时关闭这个客户端及其连接池，让连接资源及时释放。
    await client.aclose()


def get_redis(request: Request) -> RedisClient:
    """
        从应用状态读取共享的业务 Redis 客户端，不为请求新建连接池。

    :param request: 当前请求，用于读取应用生命周期状态。
    :return: 已初始化的业务 Redis 客户端。
    :raises AppError: 生命周期尚未提供业务 Redis 客户端。
    """
    # 从启动入口保存的应用状态取出同一个客户端；没准备好就拒绝，不能临时绕过存储检查。
    client = getattr(request.app.state, "redis", None)
    if client is None:
        raise unavailable_503("active_token_registry_unavailable")
    return cast(RedisClient, client)


def get_rate_limit_redis(request: Request) -> RedisClient:
    """
        从应用状态读取限流客户端，默认与业务 Redis 共用实例。

    :param request: 当前请求，用于读取应用生命周期状态。
    :return: 已初始化的限流 Redis 客户端。
    :raises AppError: 生命周期尚未提供限流 Redis 客户端。
    """
    # 取启动时准备好的限流客户端，通常就是业务客户端；缺失时拒绝，不能跳过限流。
    client = getattr(request.app.state, "rate_limit_redis", None)
    if client is None:
        raise unavailable_503("rate_limit_registry_unavailable")
    return cast(RedisClient, client)
