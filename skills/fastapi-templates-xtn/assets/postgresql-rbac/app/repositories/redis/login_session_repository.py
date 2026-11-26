#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在 Redis 中保存登录记录，检查登录是否有效，并限制同时登录数量。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释令牌身份、单次登录标识与时间字段的业务含义
# 2026/09/29    XTN       V1.002        将纯 JWT 编解码独立，保留 Redis 会话登记与签发编排
# 2026/09/29    XTN       V1.003        说明会话脚本参数并统一 Redis 调用故障边界
# 2026/09/30    XTN       V1.004        会话键说明改为单机 Redis 语义
# 2026/10/02    XTN       V1.005        区分会话确实失效与 Redis 脚本异常结果
# 2026/10/02    XTN       V1.006        说明 Lua 会话登记、校验和淘汰的关键阶段
# 2026/10/02    XTN       V1.007        在 Redis 会话故障边界直接分类已使用的异常
# 2026/10/10    XTN       V1.008        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.009        补全会话函数契约及登记核对撤销的业务阶段
# 2026/10/13    XTN       V1.010        会话键和摘要移除服务与环境标识，删除无用配置参数
# 2026/10/13    XTN       V1.011        会话只保留登录记录与登录顺序两键，到期时间直接读取记录
# 2026/10/13    XTN       V1.012        会话键直接使用用户 ID，登录字段使用短 UUID，顺序键改名 sequence
# 2026/10/16    XTN       V1.013        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/19    XTN       V1.014        精简登录记录注释，改用简短的大白话说明
# 2026/10/20    XTN       V1.015        Token 参数统一命名为 token_info，保持 Redis 登录记录格式
# 2026/10/20    XTN       V1.016        登录检查和退出直接命名，删除简单包装与重复检查
# 2026/10/23    XTN       V1.017        Redis 登录记录移入仓储，Token 签发流程归认证服务
# --------------------------------------------------------------------------------------------------


import json
import logging
from collections.abc import Awaitable
from typing import cast

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.exceptions import unauthenticated_401, unavailable_503
from app.core.ids import require_entity_id
from app.core.logging.events import (
    safe_exception_metadata,
    safe_log,
)
from app.core.security.jwt_tokens import (
    AccessTokenInfo,
    integer_numeric_date,
)
from app.db.redis_db import RedisClient

# 会话操作共用 Redis 时间，避免多实例各自计时导致到期判断不同。
# 两个 KEYS 依次是登录记录、登录顺序，必须来自同一用户。
# 到期时间保存在登录记录的 exp 中，不再另建到期索引；删除时同时维护两份结构。
_SESSION_FUNCTIONS = """
-- 多个应用实例共用 Redis 时间判断到期，不依赖各自机器的系统时间。
local redis_time = redis.call('TIME')
local now = tonumber(redis_time[1])
-- 删除这次登录时，一起删除记录和顺序中的对应项，避免留下错误的在线数量。
local function remove_session(field)
    redis.call('HDEL', KEYS[1], field)
    redis.call('ZREM', KEYS[2], field)
end
-- 读取一条登录记录，直接从 exp 取得到期秒数；损坏记录与不存在分别交给调用方处理。
local function read_session(field)
    local raw = redis.call('HGET', KEYS[1], field)
    if not raw then return nil, nil end
    local ok, record = pcall(cjson.decode, raw)
    if not ok or type(record) ~= 'table' or type(record.exp) ~= 'number'
        or record.exp ~= math.floor(record.exp) or record.exp < 0 then
        return nil, raw
    end
    return record, raw
end
-- 新登录时遍历这个用户的旧登录，清理过期项；普通鉴权不调用这里，也不遍历全部登录。
local function prune_expired()
    local entries = redis.call('ZRANGE', KEYS[2], 0, -1)
    for _, field in ipairs(entries) do
        local record, raw = read_session(field)
        if raw and not record then error('invalid active session') end
        if not record or record.exp <= now then remove_session(field) end
    end
end
"""
# 一次完成新登录登记、过期清理和超限淘汰；旧版本不能覆盖改密后的新版本。
# KEYS[1] 是登录记录哈希，KEYS[2] 是登录先后顺序。
# ARGV[1] 是 32 位登录编号，ARGV[2] 是会话 JSON，ARGV[3] 是到期 UTC 秒数，
# ARGV[4] 是用户令牌版本，ARGV[5] 是该用户允许同时在线的会话数。
# 两个键按最晚到期的登录设置过期时间，不能被短期登录提前缩短。
# 返回 1 表示成功，0 表示 JTI 冲突，-1 表示参数/状态无效，-2 表示调用方版本已经过时。
_ACTIVATE_JTI = (
    _SESSION_FUNCTIONS
    + """
local expires_at = tonumber(ARGV[3])
local maximum = tonumber(ARGV[5])
local incoming_version = tonumber(ARGV[4])
-- 1. 先检查参数和版本；过期登录、无效参数或旧版本都不能登记。
if not expires_at or expires_at ~= math.floor(expires_at) then
    return -1
end
if not maximum or maximum < 1 or maximum ~= math.floor(maximum) then return -1 end
if not incoming_version or incoming_version < 0 or
    incoming_version ~= math.floor(incoming_version) then return -1 end
if expires_at <= now then return -1 end
local current_version = redis.call('HGET', KEYS[1], '_version')
if current_version then
    local parsed_version = tonumber(current_version)
    if not parsed_version or parsed_version < 0 or
        parsed_version ~= math.floor(parsed_version) then return -1 end
    if parsed_version > incoming_version then return -2 end
end
-- 2. 记住最长到期时间，再清理旧登录；短期登录不能提前清空其他登录。
local deadline_ms = expires_at * 1000
local previous_deadline = redis.call('PEXPIRETIME', KEYS[1])
if previous_deadline > deadline_ms then deadline_ms = previous_deadline end
if current_version ~= ARGV[4] then
    -- 改密或强制退出后版本已变化，直接清空旧登录；旧记录损坏也不能阻止新版本登录。
    redis.call('DEL', KEYS[1], KEYS[2])
else
    -- 同版本才逐条检查旧登录的到期时间，清理后再判断本次 JTI 是否重复。
    prune_expired()
end
-- 3. 保存本次登录；HSETNX 只在编号不存在时写入，重复编号直接返回 0。
if redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2]) ~= 1 then return 0 end
redis.call('HSET', KEYS[1], '_version', ARGV[4])
-- 4. 记下登录先后顺序；同一时刻的登录也要排出先后。
local score = now * 1000000 + tonumber(redis_time[2])
local most_recent = redis.call('ZREVRANGE', KEYS[2], 0, 0, 'WITHSCORES')
if #most_recent == 2 and tonumber(most_recent[2]) >= score then
    score = tonumber(most_recent[2]) + 1
end
redis.call('ZADD', KEYS[2], score, ARGV[1])
-- 5. 超出允许的同时登录数时，踢掉最早的登录。
while redis.call('ZCARD', KEYS[2]) > maximum do
    local oldest = redis.call('ZRANGE', KEYS[2], 0, 0)[1]
    remove_session(oldest)
end
-- 6. 两个键使用同一个最长到期时间，保留现有登录和版本保护。
for _, key in ipairs(KEYS) do redis.call('PEXPIREAT', key, deadline_ms) end
return 1
"""
)
# 只退出本次登录；完整记录匹配后才删除，避免旧请求误删新记录。
# ARGV[1] 是 32 位登录编号，ARGV[2] 是登录记录 JSON；两者都匹配才删除。
# 返回 1 表示已删除，0 表示会话不存在或到期，-1 表示记录与请求预期不匹配。
_COMPARE_AND_DELETE = (
    _SESSION_FUNCTIONS
    + """
-- 退出只读取这次登录，先确认记录存在且可以读取，再检查记录里的到期时间。
local record, current = read_session(ARGV[1])
if not current then return 0 end
if not record then return -1 end
if record.exp <= now then
    remove_session(ARGV[1])
    return 0
end
if current ~= ARGV[2] then
    return -1
end
-- 记录必须与调用方预期完全一致，避免旧请求删除后来更新的登录。
remove_session(ARGV[1])
return 1
"""
)
# 鉴权只读取当前这次登录，核对记录里的到期时间、用户版本及登录顺序中是否仍有它。
# ARGV[1] 是待核验的 32 位登录编号；脚本只返回会话记录，不在此处信任其用户身份字段。
_READ_ACTIVE_JTI = (
    _SESSION_FUNCTIONS
    + """
-- 只读取待核验的 JTI，不扫描其他登录；不存在或记录损坏时不能确认登录有效。
local record, value = read_session(ARGV[1])
if not record then return false end
-- 到期时间直接保存在记录中，过期后同时清除这次登录的记录和顺序项。
if record.exp <= now then
    remove_session(ARGV[1])
    return false
end
-- 版本必须仍是当前版本，并且登录尚未被超限淘汰或退出，才把记录交回 Python 精确比对。
if type(record.token_version) ~= 'number' then return false end
if redis.call('HGET', KEYS[1], '_version') ~= tostring(record.token_version)
    then return false end
if not redis.call('ZSCORE', KEYS[2], ARGV[1]) then return false end
return value
"""
)
# 列出当前版本的有效登录时间；登录次数不等于设备数量。
# ARGV[1] 是数据库读取的用户令牌版本；旧版本会话不进入当前在线列表。
# 记录损坏就报错，不能把漏查的结果当成真实在线数量。
_LIST_USER_SESSIONS = (
    _SESSION_FUNCTIONS
    + """
-- 只列出数据库当前版本的有效登录；旧版本不显示为在线。
if redis.call('HGET', KEYS[1], '_version') ~= ARGV[1] then return {} end
local entries = redis.call('ZRANGE', KEYS[2], 0, -1)
local result = {}
for _, field in ipairs(entries) do
    local record, raw = read_session(field)
    if raw then
        -- 存储损坏时直接报错，不返回看似正常但不完整的在线数据。
        if not record or type(record.iat) ~= 'number'
            or record.iat ~= math.floor(record.iat) or record.iat < 0
            or tostring(record.token_version) ~= ARGV[1] then
            return redis.error_reply('invalid active session')
        end
        -- 一边遍历一边清理过期登录；只把仍有效的登录时间加入在线列表。
        if record.exp <= now then
            remove_session(field)
        else
            result[#result + 1] = record.iat
        end
    else
        remove_session(field)
    end
end
return result
"""
)
logger = logging.getLogger(__name__)


def _user_session_keys(*, user_id: str) -> tuple[str, str]:
    """
        生成这个用户的登录记录键和登录顺序键。

    :param user_id: 要管理登录的用户 ID。
    :return: login:sessions 登录记录哈希键、login:sequence 登录顺序有序集合键。
    """
    # 用用户 ID 区分数据；sequence 保存登录先后顺序。
    return f"login:sessions:{user_id}", f"login:sequence:{user_id}"


def _build_session_record(token_info: AccessTokenInfo, *, user_token_version: int) -> str:
    """
        把 Token 的用户、时间和登录版本整理成 Redis 登录记录。

    :param token_info: Token 中的用户和时间信息。
    :param user_token_version: 本次登录的版本，此处不检查取值范围。
    :return: 字段顺序固定的 JSON 字符串，不含密码或 Token 签名。
    """
    # 固定 JSON 格式，让登记、检查和退出登录时能直接比较整段内容。
    return json.dumps(
        {
            "exp": token_info.expires_at,
            "iat": token_info.issued_at,
            "user_id": str(token_info.user_id),
            "token_version": user_token_version,
            "typ": "access",
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _parse_session_record(record_json: str) -> tuple[str, int, int, int]:
    """
        读取 Redis 登录记录，检查字段和格式。

    :param record_json: 从 Redis 登录记录中读取的 JSON 字符串。
    :return: 用户 ID、登录版本、签发时间和到期时间；时间单位为秒。
    :raises ValueError: 记录内容、用户 ID、版本或时间格式不正确。
    """
    # 1. 检查 JSON 字段和 Token 类型，多字段或少字段都拒绝。
    session_record = json.loads(record_json)
    if not isinstance(session_record, dict) or set(session_record) != {
        "exp",
        "iat",
        "user_id",
        "token_version",
        "typ",
    }:
        raise ValueError("invalid active JTI record")
    if session_record["typ"] != "access":
        raise ValueError("invalid active JTI type")
    # 2. 版本必须是非负整数，True、False 也不能当版本使用。
    token_version = session_record["token_version"]
    if (
        isinstance(token_version, bool)
        or not isinstance(token_version, int)
        or token_version < 0
    ):
        raise ValueError("invalid active JTI token version")
    # 3. 检查时间和用户 ID 格式；是否已到期由后续登录检查判断。
    expires_at = integer_numeric_date(session_record["exp"])
    issued_at = integer_numeric_date(session_record["iat"])
    return require_entity_id(session_record["user_id"], "U"), token_version, issued_at, expires_at


async def _eval_session_script(redis: RedisClient, *, script: str,
                               session_keys: tuple[str, str],
                               arguments: tuple[str, ...],
                               operation: str) -> object:
    """
        执行 Redis 登录脚本，失败时记录故障并报服务不可用。

    :param redis: 执行 Lua 脚本的 Redis 客户端。
    :param script: 本模块定义的会话登记、读取、撤销或列表脚本。
    :param session_keys: 同一用户的登录记录哈希键及登录顺序键。
    :param arguments: 该脚本需要的字符串参数，按其 ARGV 顺序传入。
    :param operation: 日志中的操作名，不包含 Token 或 Redis 键值。
    :return: 脚本原始结果，由调用方判断成功或失败。
    :raises AppError: Redis 执行失败时返回统一服务不可用错误。
    """
    # 1. 一次执行脚本，同时处理这个用户的两份登录数据。
    try:
        # cast 仅用于类型检查，不改变 Redis 返回值。
        return await cast(
            Awaitable[object],
            redis.eval(script, 2, *session_keys, *arguments),
        )
    except RedisError as exc:
        # 2. 失败时区分超时、断连和其他错误，方便排查。
        if isinstance(exc, RedisTimeoutError):
            error_category = "timeout"
        elif isinstance(exc, RedisConnectionError):
            error_category = "connection"
        else:
            error_category = "unknown"
        # 3. 只记录故障类别和代码位置，不记录 Token 或登录内容。
        safe_log(
            logger,
            logging.ERROR,
            "dependency.redis.unavailable",
            extra={
                "dependency": "redis",
                "dependency_operation": operation,
                "error_category": error_category,
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable_503("active_token_registry_unavailable") from exc


class LoginSessionRepository:
    """
        读写 Redis 登录记录和登录顺序，不生成 Token，也不保存请求状态。
    """

    async def register_login_session(self, redis: RedisClient, *,
                                     token_info: AccessTokenInfo,
                                     user_token_version: int,
                                     max_active_sessions: int
                                     ) -> bool:
        """
            登记已经生成的 Token，并一起清理过期登录和处理登录数量上限。

        :param redis: 应用共用的 Redis 客户端。
        :param token_info: 已生成 Token 的用户、登录编号和有效期，不包含 Token 签名。
        :param user_token_version: 数据库刚确认的登录撤销版本。
        :param max_active_sessions: 每个用户允许同时保留的登录数量。
        :return: True 表示登记成功；False 表示登录编号重复，由业务层决定是否换编号。
        :raises AppError: 登录版本已过时，或 Redis 故障、参数及回包异常。
        """
        # 1. 一次写入登录记录和顺序；过期清理及超限淘汰也在同一个脚本内完成。
        register_result = await _eval_session_script(
            redis,
            script=_ACTIVATE_JTI,
            session_keys=_user_session_keys(user_id=token_info.user_id),
            arguments=(
                token_info.token_id.hex,
                _build_session_record(token_info, user_token_version=user_token_version),
                str(token_info.expires_at),
                str(user_token_version),
                str(max_active_sessions),
            ),
            operation="register_active_jti",
        )
        # 2. 只接受脚本约定的整数：1 成功，0 编号重复，-2 登录版本已过时。
        # 参数无效或其他回包都按服务故障处理，不能当成登记成功或盲目重试。
        if type(register_result) is not int or register_result not in {1, 0, -2}:
            raise unavailable_503("active_token_registry_unavailable")
        if register_result == -2:
            raise unauthenticated_401("token_version_changed")
        return register_result == 1

    async def check_login_session(self, redis: RedisClient, *, token_info: AccessTokenInfo) -> int:
        """
            检查 Token 对应的登录是否仍有效，已退出或被踢出的登录不能继续使用。

        :param redis: 读取当前登录记录及登录顺序的 Redis 客户端。
        :param token_info: 已完成 JWT 验签和字段校验的访问令牌信息。
        :return: 这次登录的版本，后续还需与数据库中的版本比较。
        :raises AppError: 会话失效、记录不匹配或 Redis 无法完成验证。
        """
        # 1. 按用户 ID 和登录编号查 Redis，同时检查到期时间、版本和登录顺序记录。
        session_keys = _user_session_keys(user_id=token_info.user_id)
        record_json = await _eval_session_script(
            redis,
            script=_READ_ACTIVE_JTI,
            session_keys=session_keys,
            arguments=(token_info.token_id.hex,),
            operation="read_active_jti",
        )
        # 2. None 表示登录无效，可能已到期、被删除或版本不符。
        if record_json is None:
            raise unauthenticated_401("inactive_access_token")
        # 正常只会返回记录字符串或 None，其他类型按服务故障处理。
        if not isinstance(record_json, str):
            raise unavailable_503("active_token_registry_unavailable")

        # 3. 检查记录格式，再与当前 Token 对应的完整记录比较；匹配后返回登录版本。
        try:
            # 这里只取登录版本；其余字段仍会在解析时检查，并通过下面的完整比较核对。
            _, token_version, _, _ = _parse_session_record(record_json)
            if record_json != _build_session_record(
                token_info,
                user_token_version=token_version,
            ):
                raise ValueError("active JTI record is not canonical")
        except (KeyError, TypeError, ValueError) as exc:
            raise unauthenticated_401("active_token_record_mismatch") from exc
        return token_version

    async def delete_login_session(self, redis: RedisClient, *,
                                   token_info: AccessTokenInfo,
                                   user_token_version: int
                                   ) -> None:
        """
            核对完整记录后删除本次登录，不影响这个用户的其他登录。

        :param redis: 保存登录记录和登录顺序的 Redis 客户端。
        :param token_info: 当前准备退出的已校验访问令牌信息。
        :param user_token_version: 与当前登录记录匹配的用户令牌版本。
        :return: 无返回值，当前会话成功删除后正常结束。
        :raises AppError: 会话已失效、记录不匹配或 Redis 操作失败。
        """
        # 1. 核对并删除本次登录，同时删除它的登录顺序记录。
        session_keys = _user_session_keys(user_id=token_info.user_id)
        deleted = await _eval_session_script(
            redis,
            script=_COMPARE_AND_DELETE,
            session_keys=session_keys,
            arguments=(
                token_info.token_id.hex,
                _build_session_record(
                    token_info,
                    user_token_version=user_token_version,
                ),
            ),
            operation="revoke_active_jti",
        )
        # 2. 1 表示已删除，0 表示不存在或到期，-1 表示记录不匹配；其他结果按故障处理。
        if type(deleted) is not int or deleted not in {1, 0, -1}:
            raise unavailable_503("active_token_registry_unavailable")
        if deleted != 1:
            raise unauthenticated_401("inactive_access_token")

    async def list_active_sessions(self, redis: RedisClient, *, user_id: str, token_version: int) -> tuple[int, ...]:
        """
            清理过期记录，查询用户当前有效的各次登录时间。

        :param redis: 读取用户会话和索引的 Redis 客户端。
        :param user_id: 调用方已校验的 U 开头用户 ID，用于定位其在线登录。
        :param token_version: 调用方从数据库取得的当前有效令牌版本，旧版本会话不纳入结果。
        :return: 按登录顺序排列的 UTC 时间戳，单位为秒；没有有效登录时为空元组。
        :raises AppError: Redis 不可用或会话时间记录格式不合法。
        """
        # 1. 只查当前版本的登录，并顺便清理过期记录。
        session_keys = _user_session_keys(user_id=user_id)
        values = await _eval_session_script(
            redis,
            script=_LIST_USER_SESSIONS,
            session_keys=session_keys,
            arguments=(str(token_version),),
            operation="list_active_sessions",
        )
        # 2. 时间戳必须是非负整数；数据损坏就报错，不能当成正常登录数量。
        if not isinstance(values, list) or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            raise unavailable_503("active_token_registry_unavailable")
        return tuple(values)


# 仓储不保存当前用户或 Redis 连接，操作时由调用方传入。
login_session_repository = LoginSessionRepository()
