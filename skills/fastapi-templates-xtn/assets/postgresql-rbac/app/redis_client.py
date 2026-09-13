from typing import cast

from fastapi import Request
from redis.asyncio import Redis

from app.rbac.errors import unavailable
from app.settings import Settings


def create_redis_client(settings: Settings) -> Redis:
    return _create_client(settings.redis_url, settings)


def create_rate_limit_redis_client(settings: Settings) -> Redis:
    return _create_client(settings.effective_rate_limit_redis_url, settings)


def _create_client(url: str, settings: Settings) -> Redis:
    return cast(
        Redis,
        Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            socket_timeout=settings.redis_socket_timeout_seconds,
            retry_on_timeout=False,
        ),
    )


def get_redis(request: Request) -> Redis:
    client = getattr(request.app.state, "redis", None)
    if client is None:
        raise unavailable("active_token_registry_unavailable")
    return cast(Redis, client)


def get_rate_limit_redis(request: Request) -> Redis:
    client = getattr(request.app.state, "rate_limit_redis", None)
    if client is None:
        raise unavailable("rate_limit_registry_unavailable")
    return cast(Redis, client)
