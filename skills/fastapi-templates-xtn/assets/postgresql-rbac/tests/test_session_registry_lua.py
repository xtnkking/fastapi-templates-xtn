#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    使用内存 Redis 后端直接执行生产 Lua，离线验证二键会话登记、过期及精准退出。
#    不启动 Redis 进程，也不连接 PostgreSQL 或外部 Redis。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        新建
# 2026/10/13    XTN       V1.001        直接验证用户 ID 键名和短 UUID 字段的 Lua 存储结果
# 2026/10/20    XTN       V1.002        对齐登录会话命名，保留冲突登记和精确退出的 Lua 行为验证
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import cast

import pytest
import pytest_asyncio

from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import AccessTokenInfo
from app.db.redis_db import RedisClient
from app.repositories.redis.login_session_repository import (
    _ACTIVATE_JTI,
    _build_session_record,
    _eval_session_script,
    _user_session_keys,
    login_session_repository,
)


@pytest_asyncio.fixture
async def memory_redis() -> AsyncIterator[RedisClient]:
    """
        为每个测试创建独立的内存 Redis 7 后端，以实际 Lua 执行替代结果模拟。

    :yield: 本次测试独享的内存客户端；退出时关闭，不访问外部服务。
    """
    # 这两个可选维护依赖缺失时明确跳过；测试自身不安装包或创建真实服务。
    pytest.importorskip("lupa")
    fakeredis_asyncio = pytest.importorskip("fakeredis.aioredis")
    async with fakeredis_asyncio.FakeRedis(version=(7, 0), decode_responses=True) as redis:
        yield cast(RedisClient, redis)


async def activate(redis: RedisClient, token_info: AccessTokenInfo, *,
                   version: int = 1, maximum: int = 2) -> object:
    """
        将测试构造的完整会话交给生产登记脚本，不在测试中复制登记或淘汰算法。

    :param redis: 本次测试独享的内存 Redis 客户端。
    :param token_info: 用户、JTI 和 UTC 秒级签发及到期时间。
    :param version: 本次登记使用的非负用户版本，默认 1。
    :param maximum: 该用户同时在线会话上限，默认 2。
    :return: 生产登记脚本的原始结果码。
    """
    # 使用生产调用边界声明二键，使参数数量和真实 Lua 语义一同得到覆盖。
    return await _eval_session_script(
        redis,
        script=_ACTIVATE_JTI,
        session_keys=_user_session_keys(user_id=token_info.user_id),
        arguments=(
            token_info.token_id.hex,
            _build_session_record(token_info, user_token_version=version),
            str(token_info.expires_at),
            str(version),
            str(maximum),
        ),
        operation="register_active_jti",
    )


async def test_activation_creates_only_session_hash_and_login_order(memory_redis: RedisClient) -> None:
    """
        首次登记只创建会话 Hash 与登录顺序 Sorted Set，并保留规范记录及版本。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；键集合、数据类型和完整记录符合二键契约时通过。
    """
    now, _ = await memory_redis.time()
    token_info = AccessTokenInfo(new_entity_id("U"), uuid.uuid4(), now, now + 300)
    assert await activate(memory_redis, token_info, version=3) == 1
    records, order = _user_session_keys(user_id=token_info.user_id)
    field = token_info.token_id.hex

    assert (records, order) == (f"login:sessions:{token_info.user_id}", f"login:sequence:{token_info.user_id}")
    assert set(await memory_redis.keys("*")) == {records, order}
    assert await memory_redis.type(records) == "hash"
    assert await memory_redis.type(order) == "zset"
    assert await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records)) == {
        "_version": "3",
        field: _build_session_record(token_info, user_token_version=3),
    }
    assert await memory_redis.zrange(order, 0, -1) == [field]
    assert await login_session_repository.check_login_session(memory_redis, token_info=token_info) == 3


async def test_earlier_login_is_evicted_even_with_a_later_expiration(memory_redis: RedisClient) -> None:
    """
        先登录但晚到期的会话仍先被淘汰；登录顺序和到期时间不能混用。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；最早登录失效且最近两个登录保留时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    oldest = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now + 300)
    later = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 60)
    latest = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 30)
    for token_info in (oldest, later, latest):
        assert await activate(memory_redis, token_info) == 1

    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(memory_redis, token_info=oldest)
    assert caught.value.status_code == 401
    assert await login_session_repository.check_login_session(memory_redis, token_info=later) == 1
    assert await login_session_repository.check_login_session(memory_redis, token_info=latest) == 1
    assert await login_session_repository.list_active_sessions(
        memory_redis, user_id=user_id, token_version=1
    ) == (later.issued_at, latest.issued_at)
    records, order = _user_session_keys(user_id=user_id)
    assert await memory_redis.zrange(order, 0, -1) == [
        later.token_id.hex,
        latest.token_id.hex,
    ]
    assert not await cast(
        Awaitable[bool], memory_redis.hexists(records, oldest.token_id.hex)
    )


@pytest.mark.parametrize("operation", ["read", "list", "activate"])
@pytest.mark.parametrize("expired_is_newest", [False, True])
async def test_record_expiration_is_pruned_without_consuming_a_login_slot(memory_redis: RedisClient,
                                                                          operation: str,
                                                                          expired_is_newest: bool) -> None:
    """
        过期记录位于顺序索引任意一端时，读取、列表和登记都按 JSON 的 exp 清理。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :param operation: 触发清理的生产入口：单会话读取、会话列表或新登录登记。
    :param expired_is_newest: 是否将过期会话放在现有登录之后，以覆盖完整索引遍历。
    :return: 无返回值；过期项被清理且有效登录没有被误淘汰时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    live = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now + 300)
    expired = AccessTokenInfo(user_id, uuid.uuid4(), now - 20, now - 1)
    assert await activate(memory_redis, live) == 1
    records, order = _user_session_keys(user_id=user_id)
    expired_field = expired.token_id.hex
    live_score = await memory_redis.zscore(order, live.token_id.hex)
    assert live_score is not None
    # 模拟一份会话先到期而容器仍由长期会话保留；不等待真实时间或修改生产算法。
    await cast(
        Awaitable[int],
        memory_redis.hset(records, expired_field, _build_session_record(expired, user_token_version=1)),
    )
    await memory_redis.zadd(order, {expired_field: live_score + (1 if expired_is_newest else -1)})

    if operation == "read":
        with pytest.raises(AppError) as caught:
            await login_session_repository.check_login_session(memory_redis, token_info=expired)
        assert caught.value.status_code == 401
    elif operation == "list":
        assert await login_session_repository.list_active_sessions(
            memory_redis, user_id=user_id, token_version=1
        ) == (live.issued_at,)
    else:
        new = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 60)
        assert await activate(memory_redis, new) == 1
        assert await login_session_repository.check_login_session(memory_redis, token_info=new) == 1

    assert await login_session_repository.check_login_session(memory_redis, token_info=live) == 1
    assert not await cast(Awaitable[bool], memory_redis.hexists(records, expired_field))
    assert await memory_redis.zscore(order, expired_field) is None


async def test_read_checks_only_the_requested_session(memory_redis: RedisClient) -> None:
    """
        核对一个有效登录不会顺带遍历或清理其他登录；全量清理由列表和登记负责。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；有效登录可用且不相关的过期项仍待全量清理时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    live = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 300)
    expired = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now - 1)
    assert await activate(memory_redis, live) == 1
    records, order = _user_session_keys(user_id=user_id)
    field = expired.token_id.hex
    await cast(
        Awaitable[int], memory_redis.hset(records, field, _build_session_record(expired, user_token_version=1))
    )
    await memory_redis.zadd(order, {field: 0})

    assert await login_session_repository.check_login_session(memory_redis, token_info=live) == 1
    assert await cast(Awaitable[bool], memory_redis.hexists(records, field))
    assert await memory_redis.zscore(order, field) == 0


async def test_short_login_keeps_both_key_deadlines_and_read_does_not_extend_them(memory_redis: RedisClient) -> None:
    """
        较短的新登录保留两个容器的最长截止时间；读取和列表不能续期。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；两个登录均有效且两把键的绝对到期时间保持不变时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    long = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    short = AccessTokenInfo(user_id, uuid.uuid4(), now - 3, now + 30)
    assert await activate(memory_redis, long) == 1
    assert await activate(memory_redis, short) == 1
    keys = _user_session_keys(user_id=user_id)
    assert [await cast(Awaitable[int], memory_redis.pexpiretime(key)) for key in keys] == [
        long.expires_at * 1000
    ] * 2

    assert await login_session_repository.check_login_session(memory_redis, token_info=long) == 1
    assert await login_session_repository.check_login_session(memory_redis, token_info=short) == 1
    assert await login_session_repository.list_active_sessions(
        memory_redis, user_id=user_id, token_version=1
    ) == (long.issued_at, short.issued_at)
    assert [await cast(Awaitable[int], memory_redis.pexpiretime(key)) for key in keys] == [
        long.expires_at * 1000
    ] * 2


async def test_version_watermark_survives_replacement_and_last_logout(memory_redis: RedisClient) -> None:
    """
        较短的新版本替换和最后一次退出都保留旧最长截止时间，拒绝延迟旧版本登记。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；旧版本不能倒退且同版本仍可登记时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    old = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    current = AccessTokenInfo(user_id, uuid.uuid4(), now - 3, now + 30)
    assert await activate(memory_redis, old) == 1
    assert await activate(memory_redis, current, version=2) == 1
    with pytest.raises(AppError) as caught:
        await login_session_repository.check_login_session(memory_redis, token_info=old)
    assert caught.value.status_code == 401
    await login_session_repository.delete_login_session(memory_redis, token_info=current, user_token_version=2)
    records, order = _user_session_keys(user_id=user_id)
    assert await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records)) == {"_version": "2"}
    assert not await memory_redis.exists(order)
    assert await cast(Awaitable[int], memory_redis.pexpiretime(records)) == old.expires_at * 1000

    delayed = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 200)
    assert await activate(memory_redis, delayed, version=1) == -2
    assert await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records)) == {"_version": "2"}
    assert await activate(memory_redis, delayed, version=2) == 1
    assert [await cast(Awaitable[int], memory_redis.pexpiretime(key)) for key in (records, order)] == [
        old.expires_at * 1000
    ] * 2


async def test_duplicate_and_mismatched_logout_preserve_state_then_exact_logout_removes_only_target(
    memory_redis: RedisClient,
) -> None:
    """
        冲突登记和错误版本退出不修改会话；精确退出只删除当前 JTI 并保留其他登录。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；失败时原状态保留且成功退出只影响指定登录时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    target = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    other = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 60)
    assert await activate(memory_redis, target) == 1
    assert await activate(memory_redis, other) == 1
    records, order = _user_session_keys(user_id=user_id)
    snapshot = await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records))
    index = await memory_redis.zrange(order, 0, -1, withscores=True)
    assert await activate(memory_redis, target) == 0
    expired = AccessTokenInfo(user_id, uuid.uuid4(), now - 10, now - 1)
    assert await activate(memory_redis, expired) == -1
    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(memory_redis, token_info=target, user_token_version=2)
    assert caught.value.status_code == 401
    assert await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records)) == snapshot
    assert await memory_redis.zrange(order, 0, -1, withscores=True) == index

    await login_session_repository.delete_login_session(memory_redis, token_info=target, user_token_version=1)
    assert await login_session_repository.check_login_session(memory_redis, token_info=other) == 1
    assert await memory_redis.zrange(order, 0, -1) == [other.token_id.hex]
    with pytest.raises(AppError) as caught:
        await login_session_repository.delete_login_session(memory_redis, token_info=target, user_token_version=1)
    assert caught.value.status_code == 401


async def test_new_version_replaces_damaged_old_record_and_keeps_long_deadline(memory_redis: RedisClient) -> None:
    """
        版本提升先替换旧代，旧 JSON 损坏不能阻止改密后的新登录或缩短版本保护时间。

    :param memory_redis: 本次测试独享的内存 Redis 客户端。
    :return: 无返回值；损坏旧代被清除、新版本活跃且两键保留最长截止时间时通过。
    """
    user_id = new_entity_id("U")
    now, _ = await memory_redis.time()
    old = AccessTokenInfo(user_id, uuid.uuid4(), now - 5, now + 300)
    current = AccessTokenInfo(user_id, uuid.uuid4(), now, now + 30)
    assert await activate(memory_redis, old) == 1
    records, order = _user_session_keys(user_id=user_id)
    # 模拟旧代存储损坏，同时保留已设置的最长容器截止时间。
    await cast(
        Awaitable[int], memory_redis.hset(records, old.token_id.hex, "{invalid")
    )

    assert await activate(memory_redis, current, version=2) == 1
    assert await login_session_repository.check_login_session(memory_redis, token_info=current) == 2
    assert await cast(Awaitable[dict[str, str]], memory_redis.hgetall(records)) == {
        "_version": "2",
        current.token_id.hex: _build_session_record(current, user_token_version=2),
    }
    assert await memory_redis.zrange(order, 0, -1) == [current.token_id.hex]
    assert [await cast(Awaitable[int], memory_redis.pexpiretime(key)) for key in (records, order)] == [
        old.expires_at * 1000
    ] * 2
