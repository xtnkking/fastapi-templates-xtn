import asyncio
import json
import uuid
from collections.abc import Awaitable
from typing import cast

import pytest
from httpx import AsyncClient

from app.core.config import Settings, get_settings
from app.core.errors import RbacError
from app.core.security.tokens import (
    _ACTIVATE_JTI,
    AccessTokenClaims,
    _active_jti_field,
    _active_jti_value,
    _user_session_keys,
    list_active_sessions,
    require_active_jti,
    revoke_active_jti,
)
from app.db.redis import RedisClient
from app.main import app

pytestmark = pytest.mark.postgresql


async def activate(
    redis: RedisClient,
    claims: AccessTokenClaims,
    settings: Settings,
    *,
    version: int = 1,
) -> object:
    return await cast(
        Awaitable[object],
        redis.eval(
            _ACTIVATE_JTI,
            3,
            *_user_session_keys(settings=settings, user_id=claims.user_id),
            _active_jti_field(settings=settings, token_id=claims.token_id),
            _active_jti_value(claims, user_token_version=version),
            str(claims.expires_at),
            str(version),
            str(settings.max_active_sessions_per_user),
        ),
    )


async def test_shorter_login_never_shortens_existing_session_deadline(
    client: AsyncClient,
) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = uuid.uuid4()
    now, _ = await redis.time()
    long = AccessTokenClaims(user_id, uuid.uuid4(), now - 5, now + 300)
    short = AccessTokenClaims(user_id, uuid.uuid4(), now - 3, now + 30)

    assert await activate(redis, long, settings) == 1
    assert await activate(redis, short, settings) == 1
    keys = _user_session_keys(settings=settings, user_id=user_id)
    deadlines = [await cast(Awaitable[int], redis.pexpiretime(key)) for key in keys]
    assert deadlines == [long.expires_at * 1000] * 3
    assert await require_active_jti(redis, claims=long, settings=settings) == 1
    assert await require_active_jti(redis, claims=short, settings=settings) == 1
    assert await list_active_sessions(
        redis, user_id=user_id, token_version=1, settings=settings
    ) == (long.issued_at, short.issued_at)
    assert [
        await cast(Awaitable[int], redis.pexpiretime(key)) for key in keys
    ] == deadlines


@pytest.mark.parametrize("operation", ["read", "list", "activate"])
async def test_expired_hash_fields_are_rejected_and_do_not_consume_login_slots(
    client: AsyncClient, operation: str
) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
    user_id = uuid.uuid4()
    now, _ = await redis.time()
    live = AccessTokenClaims(user_id, uuid.uuid4(), now - 10, now + 300)
    expired = AccessTokenClaims(user_id, uuid.uuid4(), now - 20, now - 1)
    assert await activate(redis, live, settings) == 1
    records, order, expires = _user_session_keys(settings=settings, user_id=user_id)
    expired_field = _active_jti_field(settings=settings, token_id=expired.token_id)
    # Model time having passed for one field while the other session keeps its
    # shared container alive. No clock sleeps or Redis server-clock mutations.
    await cast(
        Awaitable[int],
        redis.hset(
            records, expired_field, _active_jti_value(expired, user_token_version=1)
        ),
    )
    await redis.zadd(order, {expired_field: 0})
    await redis.zadd(expires, {expired_field: expired.expires_at})

    if operation == "read":
        with pytest.raises(RbacError) as caught:
            await require_active_jti(redis, claims=expired, settings=settings)
        assert caught.value.status_code == 401
    elif operation == "list":
        assert await list_active_sessions(
            redis, user_id=user_id, token_version=1, settings=settings
        ) == (live.issued_at,)
    else:
        new = AccessTokenClaims(user_id, uuid.uuid4(), now, now + 60)
        assert await activate(redis, new, settings) == 1
        assert await require_active_jti(redis, claims=new, settings=settings) == 1

    assert await require_active_jti(redis, claims=live, settings=settings) == 1
    assert not await cast(Awaitable[bool], redis.hexists(records, expired_field))
    assert await redis.zscore(order, expired_field) is None
    assert await redis.zscore(expires, expired_field) is None


async def test_version_watermark_survives_shorter_replacement_and_final_logout(
    client: AsyncClient,
) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = uuid.uuid4()
    now, _ = await redis.time()
    old = AccessTokenClaims(user_id, uuid.uuid4(), now - 5, now + 300)
    new = AccessTokenClaims(user_id, uuid.uuid4(), now - 3, now + 30)
    assert await activate(redis, old, settings, version=1) == 1
    assert await activate(redis, new, settings, version=2) == 1
    records, order, expires = _user_session_keys(settings=settings, user_id=user_id)
    assert await cast(Awaitable[int], redis.pexpiretime(records)) == (
        old.expires_at * 1000
    )
    with pytest.raises(RbacError) as caught:
        await require_active_jti(redis, claims=old, settings=settings)
    assert caught.value.status_code == 401

    await revoke_active_jti(redis, claims=new, user_token_version=2, settings=settings)
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == {
        "_version": "2"
    }
    assert not await redis.exists(order)
    assert not await redis.exists(expires)
    stale = AccessTokenClaims(user_id, uuid.uuid4(), now, now + 200)
    assert await activate(redis, stale, settings, version=1) == -2
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == {
        "_version": "2"
    }
    assert await cast(Awaitable[int], redis.pexpiretime(records)) == (
        old.expires_at * 1000
    )
    assert await activate(redis, stale, settings, version=2) == 1


async def test_concurrent_logins_keep_exact_latest_limit_and_matching_indexes(
    client: AsyncClient,
) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 5})
    user_id = uuid.uuid4()
    now, _ = await redis.time()
    claims = [
        AccessTokenClaims(user_id, uuid.uuid4(), now, now + 300) for _ in range(20)
    ]
    results = await asyncio.gather(
        *(activate(redis, item, settings) for item in claims)
    )
    assert results == [1] * 20
    records, order, expires = _user_session_keys(settings=settings, user_id=user_id)
    active_fields = await redis.zrange(order, 0, -1)
    assert len(active_fields) == 5
    assert set(await cast(Awaitable[list[str]], redis.hkeys(records))) == set(
        active_fields
    ) | {"_version"}
    assert set(await redis.zrange(expires, 0, -1)) == set(active_fields)
    checks = await asyncio.gather(
        *(require_active_jti(redis, claims=item, settings=settings) for item in claims),
        return_exceptions=True,
    )
    assert sum(result == 1 for result in checks) == 5
    assert sum(isinstance(result, RbacError) for result in checks) == 15
    # Request completion order is not Redis serialization order. A later
    # sequential login deterministically evicts the actual oldest Redis entry.
    newest = AccessTokenClaims(user_id, uuid.uuid4(), now, now + 300)
    assert await activate(redis, newest, settings) == 1
    final_fields = await redis.zrange(order, 0, -1)
    assert final_fields == active_fields[1:] + [
        _active_jti_field(settings=settings, token_id=newest.token_id)
    ]


async def test_duplicate_expired_activation_and_mismatched_logout_preserve_state(
    client: AsyncClient,
) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = uuid.uuid4()
    now, _ = await redis.time()
    claims = AccessTokenClaims(user_id, uuid.uuid4(), now, now + 300)
    assert await activate(redis, claims, settings) == 1
    records, order, expires = _user_session_keys(settings=settings, user_id=user_id)
    original = await cast(Awaitable[dict[str, str]], redis.hgetall(records))
    assert await activate(redis, claims, settings) == 0
    past = AccessTokenClaims(user_id, uuid.uuid4(), now - 10, now - 1)
    assert await activate(redis, past, settings) == -1
    with pytest.raises(RbacError) as caught:
        await revoke_active_jti(
            redis, claims=claims, user_token_version=2, settings=settings
        )
    assert caught.value.status_code == 401
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == original
    assert await require_active_jti(redis, claims=claims, settings=settings) == 1
    assert await redis.zcard(order) == await redis.zcard(expires) == 1
    stored = json.loads(
        original[_active_jti_field(settings=settings, token_id=claims.token_id)]
    )
    assert set(stored) == {"exp", "iat", "sub", "token_version", "typ"}
