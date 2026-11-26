#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在已准备的一次性 Redis 中验证会话有效期、索引、登录上限及原子撤销。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        会话键与活跃检查移除配置输入并补充维护记录
# 2026/10/13    XTN       V1.001        覆盖记录过期清理与登录顺序二键登记淘汰
# 2026/10/20    XTN       V1.002        同步登录会话检查与删除入口，保留原有行为断言
# --------------------------------------------------------------------------------------------------

import asyncio
import json
import uuid
from collections.abc import Awaitable
from typing import cast

import pytest
from httpx import AsyncClient

from app.core.config import Settings, get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import AccessTokenInfo
from app.db.redis_db import RedisClient
from app.main import app
from app.repositories.redis.login_session_repository import (
    _ACTIVATE_JTI,
    _build_session_record,
    _user_session_keys,
    login_session_repository,
)

pytestmark = pytest.mark.postgresql


async def activate(redis: RedisClient, token_info: AccessTokenInfo, settings: Settings, *, version: int = 1) -> object:
    """
        使用生产 Lua 登记已构造的会话，便于验证不同有效期与版本的原子边界。

    :param redis: 已验证隔离的一次性 Redis 客户端。
    :param token_info: 测试构造的用户、JTI 和 UTC 秒级时间。
    :param settings: 提供每用户同时在线上限的配置。
    :param version: 本次登记使用的非负用户版本，默认 1。
    :return: 生产登记脚本的原始结果码。
    """
    # 显式声明记录和顺序二键；过期时间只存放在会话 JSON 内。
    return await cast(
        Awaitable[object],
        redis.eval(
            _ACTIVATE_JTI,
            2,
            *_user_session_keys(user_id=token_info.user_id),
            token_info.token_id.hex,
            _build_session_record(token_info, user_token_version=version),
            str(token_info.expires_at),
            str(version),
            str(settings.max_active_sessions_per_user),
        ),
    )


async def test_shorter_login_never_shortens_existing_session_deadline(client: AsyncClient) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    long = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    short = AccessTokenInfo(user_id, uuid.uuid4(), now - 3, now + 30)

    assert await activate(redis, long, settings) == 1
    assert await activate(redis, short, settings) == 1
    keys = _user_session_keys(user_id=user_id)
    deadlines = [await cast(Awaitable[int], redis.pexpiretime(key)) for key in keys]
    assert deadlines == [long.expires_at * 1000] * 2
    assert await login_session_repository.check_login_session(redis, token_info=long) == 1
    assert await login_session_repository.check_login_session(redis, token_info=short) == 1
    assert await login_session_repository.list_active_sessions(
        redis, user_id=user_id, token_version=1
    ) == (long.issued_at, short.issued_at)
    assert [
        await cast(Awaitable[int], redis.pexpiretime(key)) for key in keys
    ] == deadlines


@pytest.mark.parametrize("operation", ["read", "list", "activate"])
@pytest.mark.parametrize("expired_is_newest", [False, True])
async def test_expired_hash_fields_are_rejected_and_do_not_consume_login_slots(client: AsyncClient,
                                                                               operation: str,
                                                                               expired_is_newest: bool) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    live = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now + 300)
    expired = AccessTokenInfo(user_id, uuid.uuid4(), now - 20, now - 1)
    assert await activate(redis, live, settings) == 1
    records, order = _user_session_keys(user_id=user_id)
    expired_field = expired.token_id.hex
    # Model time having passed for one field while the other session keeps its
    # shared container alive. No clock sleeps or Redis server-clock mutations.
    await cast(
        Awaitable[int],
        redis.hset(
            records, expired_field, _build_session_record(expired, user_token_version=1)
        ),
    )
    live_score = await redis.zscore(order, live.token_id.hex)
    assert live_score is not None
    await redis.zadd(order, {expired_field: live_score + (1 if expired_is_newest else -1)})

    if operation == "read":
        with pytest.raises(AppError) as caught:
            await login_session_repository.check_login_session(redis, token_info=expired)
        assert caught.value.status_code == 401
    elif operation == "list":
        assert await login_session_repository.list_active_sessions(
            redis, user_id=user_id, token_version=1
        ) == (live.issued_at,)
    else:
        new = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 60)
        assert await activate(redis, new, settings) == 1
        assert await login_session_repository.check_login_session(redis, token_info=new) == 1

    assert await login_session_repository.check_login_session(redis, token_info=live) == 1
    assert not await cast(Awaitable[bool], redis.hexists(records, expired_field))
    assert await redis.zscore(order, expired_field) is None


async def test_oldest_login_is_evicted_even_when_it_expires_after_later_logins(client: AsyncClient) -> None:
    """
        先登录且较晚到期的会话仍先被淘汰，证明顺序索引没有改为到期时间排序。

    :param client: 使已准备的一次性 Redis 处于应用生命周期内的测试客户端。
    :return: 无返回值；最早登录失效且后来两个登录保留时通过。
    """
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    oldest = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now + 300)
    later = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 60)
    latest = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 30)

    for token_info in (oldest, later, latest):
        assert await activate(redis, token_info, settings) == 1

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=oldest)
    assert caught.value.status_code == 401
    assert await login_session_repository.check_login_session(redis, token_info=later) == 1
    assert await login_session_repository.check_login_session(redis, token_info=latest) == 1
    assert await login_session_repository.list_active_sessions(
        redis, user_id=user_id, token_version=1
    ) == (later.issued_at, latest.issued_at)
    records, order = _user_session_keys(user_id=user_id)
    assert await redis.zrange(order, 0, -1) == [
        later.token_id.hex,
        latest.token_id.hex,
    ]
    assert not await cast(Awaitable[bool], redis.hexists(records, oldest.token_id.hex))


async def test_version_watermark_survives_shorter_replacement_and_final_logout(client: AsyncClient) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    old = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    new = AccessTokenInfo(user_id, uuid.uuid4(), now - 3, now + 30)
    assert await activate(redis, old, settings, version=1) == 1
    assert await activate(redis, new, settings, version=2) == 1
    records, order = _user_session_keys(user_id=user_id)
    assert await cast(Awaitable[int], redis.pexpiretime(records)) == (
        old.expires_at * 1000
    )
    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(redis, token_info=old)
    assert caught.value.status_code == 401

    await login_session_repository.delete_login_session(redis, token_info=new, user_token_version=2)
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == {
        "_version": "2"
    }
    assert not await redis.exists(order)
    stale = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 200)
    assert await activate(redis, stale, settings, version=1) == -2
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == {
        "_version": "2"
    }
    assert await cast(Awaitable[int], redis.pexpiretime(records)) == (
        old.expires_at * 1000
    )
    assert await activate(redis, stale, settings, version=2) == 1


async def test_concurrent_logins_keep_exact_latest_limit_and_matching_indexes(client: AsyncClient) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 5})
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    token_info = [
        AccessTokenInfo(user_id, uuid.uuid4(), now, now + 300) for _ in range(20)
    ]
    results = await asyncio.gather(
        *(activate(redis, item, settings) for item in token_info)
    )
    assert results == [1] * 20
    records, order = _user_session_keys(user_id=user_id)
    active_fields = await redis.zrange(order, 0, -1)
    assert len(active_fields) == 5
    assert set(await cast(Awaitable[list[str]], redis.hkeys(records))) == set(
        active_fields
    ) | {"_version"}
    checks = await asyncio.gather(
        *(login_session_repository.check_login_session(redis, token_info=item) for item in token_info),
        return_exceptions=True,
    )
    assert sum(result == 1 for result in checks) == 5
    assert sum(isinstance(result, AppError) for result in checks) == 15
    # Request completion order is not Redis serialization order. A later
    # sequential login deterministically evicts the actual oldest Redis entry.
    newest = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 300)
    assert await activate(redis, newest, settings) == 1
    final_fields = await redis.zrange(order, 0, -1)
    assert final_fields == active_fields[1:] + [
        newest.token_id.hex
    ]


async def test_duplicate_expired_activation_and_mismatched_logout_preserve_state(client: AsyncClient) -> None:
    redis = cast(RedisClient, app.state.redis)
    settings = get_settings()
    user_id = new_entity_id("U")
    now, _ = await redis.time()
    token_info = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 300)
    assert await activate(redis, token_info, settings) == 1
    records, order = _user_session_keys(user_id=user_id)
    original = await cast(Awaitable[dict[str, str]], redis.hgetall(records))
    assert await activate(redis, token_info, settings) == 0
    past = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now - 1)
    assert await activate(redis, past, settings) == -1
    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(
            redis, token_info=token_info, user_token_version=2
        )
    assert caught.value.status_code == 401
    assert await cast(Awaitable[dict[str, str]], redis.hgetall(records)) == original
    assert await login_session_repository.check_login_session(redis, token_info=token_info) == 1
    assert await redis.zcard(order) == 1
    stored = json.loads(
        original[token_info.token_id.hex]
    )
    assert set(stored) == {"exp", "iat", "user_id", "token_version", "typ"}
