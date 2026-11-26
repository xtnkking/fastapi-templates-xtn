#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    提供单业务、单主体的 Redis 原子计数固定窗口限流。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        解释限流规则与判定结果字段，区分次数、时间和业务名
# 2026/09/29    XTN       V1.002        共用 Redis 回包结构校验，保留扣次与预检的独立边界
# 2026/10/02    XTN       V1.003        补充 Lua 固定窗口和预检查的中文阶段说明
# 2026/10/02    XTN       V1.004        让启动路由校验直接复用固定标识规则
# 2026/10/08    XTN       V1.005        注释直接说明实际计数对象和窗口次数
# 2026/10/10    XTN       V1.006        删除只读预查，仅保留单次原子计数和窗口结果校验
# 2026/10/13    XTN       V1.007        补充限流参数边界及校验计数解析的业务阶段
# 2026/10/13    XTN       V1.008        简化限流键，摘要只绑定业务、主体类型及实际对象
# --------------------------------------------------------------------------------------------------


import hashlib
import hmac
import re
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from typing import Final, cast

from redis.exceptions import RedisError

from app.db.redis_db import RedisClient

# 限流记录统一以 rate_limit 开头；Redis 专供本服务使用，不再附加服务名或格式版本。
RATE_LIMIT_KEY_PREFIX: Final = "rate_limit"
# 这些是配置输入的保护边界，不是业务默认额度；实际次数和窗口由 Settings 及业务策略给出。
_MAX_LIMIT: Final = 1_000_000  # 单窗口次数的配置上限，必须为正整数。
_MAX_WINDOW_SECONDS: Final = 30 * 86_400  # 窗口最多 30 天，单位秒，防止误配长期占用存储。
_MAX_SUBJECT_BYTES: Final = 1_024  # 主体原值 UTF-8 编码上限，单位字节；最终 Redis 键只保留摘要。
# 业务名等标识限为 1～64 位小写 ASCII 字符，并以字母开头，禁止把任意请求内容作为策略名。
_IDENTIFIER_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

# 单键原子计数：只在窗口第一条请求设置到期时间，后续请求不能不断延长封锁窗口。
# KEYS[1] 为业务+主体的限流键；ARGV 是次数上限和窗口秒数，返回计数与剩余毫秒数。
# 无到期时间或损坏的窗口必须报错，不能把不可信状态解释成可以放行。
FIXED_WINDOW_SCRIPT: Final = r"""
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
if not limit or not window or limit < 1 or window < 1
    or limit ~= math.floor(limit) or window ~= math.floor(window) then
    return redis.error_reply('invalid rate limit policy')
end

-- 已有计数键却没有过期时间属于损坏，不能当作正常窗口继续放行。
if redis.call('PTTL', KEYS[1]) == -1 then
    return redis.error_reply('rate limit key has no expiry')
end
-- 第一次计数才设置有效期，后续请求不会不断延长这个窗口。
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], window)
end
local remaining_ms = redis.call('PTTL', KEYS[1])
if remaining_ms <= 0 then
    return redis.error_reply('rate limit key has invalid expiry')
end
return {count, remaining_ms}
"""


class RateLimitUnavailable(RuntimeError):
    """
        表示 Redis 不可用或窗口损坏，调用方应返回服务暂不可用，不能误报为超过额度。
    """


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """
        描述一个业务对一个 IP 或操作者的固定窗口次数限制。
    """

    name: str  # 策略档位名称，例如 login；实际业务隔离维度还会由接口依赖传入。
    limit: int  # 窗口内最多放行的请求数，达到此值后下一次请求被拒绝。
    window_seconds: int  # 第一次请求起计时的窗口长度，单位秒，不是自然整点窗口。

    def __post_init__(self) -> None:
        """
            在策略创建后检查业务名称和数值边界，禁止无效配置进入 Redis 脚本。

        :return: 无返回值，策略字段全部有效时正常结束。
        :raises ValueError: 名称格式非法，或次数、窗口不在允许范围内。
        """
        # 步骤：创建策略时一次校验名称、次数和秒数上限，避免错误配置等到请求扣次才暴露。
        require_rate_limit_identifier(self.name, field_name="policy name")
        _require_positive_integer(self.limit, field_name="limit", maximum=_MAX_LIMIT)
        _require_positive_integer(
            self.window_seconds,
            field_name="window_seconds",
            maximum=_MAX_WINDOW_SECONDS,
        )


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """
        保存本次原子计数后的放行结果，供响应头和统一错误响应使用。
    """

    allowed: bool  # True 表示本次可继续处理，False 表示应返回 429。
    limit: int  # 当前业务针对这个 IP 或操作者，在一个窗口内允许的请求次数。
    remaining: int  # 本次计数后窗口还可使用的次数，最少为 0。
    retry_after_ms: int  # 被拒绝时建议等待的毫秒数，允许请求时为 0。
    reset_after_ms: int  # 当前窗口距离重置的毫秒数，不代表 UTC 时间戳。


@dataclass(frozen=True, slots=True)
class RateLimitExceeded(Exception):
    """
        携带确已超额的策略和窗口结果，由接口层转换为 HTTP 429。
    """

    policy_name: str  # 哪个业务策略判定超额，供日志和响应头解释使用。
    result: RateLimitResult  # 本次真实超额结果，含额度和建议等待时间；不重新读取计数。


def _require_positive_integer(value: object, *, field_name: str, maximum: int) -> None:
    """
        校验有限范围内的正整数，显式拒绝 Python 中可被当作整数的布尔值。

    :param value: 待检查的策略数值。
    :param field_name: 用于配置异常说明的字段名称。
    :param maximum: 当前字段允许的最大整数，包含该值。
    :return: 无返回值，输入是允许范围内的正整数时通过。
    :raises ValueError: 类型错误，或数值小于 1、超过上限。
    """
    # 步骤：排除布尔值并检查包含两端的整数范围，True 不能冒充一次请求额度。
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ValueError(f"{field_name} must be an integer between 1 and {maximum}")


def require_rate_limit_identifier(value: object, *, field_name: str) -> str:
    """
        校验服务端定义的固定标识，包括策略名和使用它的路由函数名。
        限制长度和字符，避免任意请求内容进入限流键结构。

    :param value: 待校验的业务名或主体类型。
    :param field_name: 用于异常说明的字段名称。
    :return: 通过小写 ASCII 标识规则的原字符串。
    :raises ValueError: 输入不是字符串或不匹配固定标识规则。
    """
    # 步骤：按完整固定标识规则检查原字符串，不裁剪或改写服务端定义的业务名称。
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a static lowercase ASCII identifier")
    return value


def _subject_bytes(subject: object) -> bytes:
    """
        将可信限流主体编码为有长度上限的 UTF-8 数据，避免空主体共用额度。

    :param subject: 服务端确认的 IP 或已认证用户标识。
    :return: 非空且不超过主体字节上限的 UTF-8 数据。
    :raises ValueError: 主体类型错误、编码无效、为空或过长。
    """
    # 步骤 1：确认主体是可编码的字符串；编码错误统一转换为调用方可处理的输入异常。
    if not isinstance(subject, str):
        raise ValueError("subject must be a non-empty bounded string")
    try:
        encoded = subject.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("subject must be a non-empty bounded string") from exc
    # 步骤 2：按实际 UTF-8 字节数拒绝空值和超长主体，之后才可用于计算限流键摘要。
    if not encoded or len(encoded) > _MAX_SUBJECT_BYTES:
        raise ValueError("subject must be a non-empty bounded string")
    return encoded


def build_rate_limit_key(*, policy: RateLimitPolicy, subject_type: str, subject: str,
                         key_secret: bytes) -> str:
    """
        构造按业务和主体隔离的限流键，仅保存主体 HMAC 摘要而非原始 IP 或用户 ID。

    :param policy: 已校验的业务窗口策略。
    :param subject_type: 服务端选定的主体类型标识。
    :param subject: 本次限流的可信主体原值，仅参与摘要计算。
    :param key_secret: 至少 32 字节的主体摘要密钥。
    :return: 带策略名称、主体类型及摘要的完整 Redis 键。
    :raises ValueError: 主体、策略或密钥不符合约束。
    """
    # 步骤 1：检查固定业务标识、主体输入、策略对象和摘要密钥，尚不访问 Redis 或消耗额度。
    safe_subject_type = require_rate_limit_identifier(subject_type, field_name="subject type")
    subject_bytes = _subject_bytes(subject)
    if not isinstance(policy, RateLimitPolicy):
        raise ValueError("rate-limit policy must be validated")
    if not isinstance(key_secret, bytes) or len(key_secret) < 32:
        raise ValueError("rate-limit key secret must contain at least 32 bytes")
    # 步骤 2：摘要只使用三项：业务名、主体类型、实际 IP 或当前用户 ID。
    # 零字节用于分清三项的边界；同一密钥和输入得到同一摘要，后续请求才能累计到同一个计数器。
    # HMAC-SHA256 是带服务端密钥的摘要计算；Redis key 不直接暴露 IP 或用户 ID。
    message = b"\0".join(
        (
            policy.name.encode("ascii"),
            safe_subject_type.encode("ascii"),
            subject_bytes,
        )
    )
    digest = hmac.new(key_secret, message, hashlib.sha256).hexdigest()
    # 步骤 3：按“限流前缀:业务名:主体类型:摘要”拼接记录名，方便按业务查看计数。
    return f"{RATE_LIMIT_KEY_PREFIX}:{policy.name}:{safe_subject_type}:{digest}"


def _parse_result(raw: object, *, policy: RateLimitPolicy) -> RateLimitResult:
    """
        解析已计入本次请求后的 Redis 计数和剩余时间，拒绝不可信脚本结果。

    :param raw: Redis 脚本返回的计数与剩余毫秒数二元序列。
    :param policy: 本次请求使用的业务窗口策略。
    :return: 本次是否放行、剩余额度及重试等待时间。
    :raises RateLimitUnavailable: 返回类型、计数或窗口剩余时间不合法。
    """
    # 步骤 1：核对回包是两个非布尔整数，避免把损坏数据当成已验证的剩余额度。
    if (
        not isinstance(raw, Sequence)
        or isinstance(raw, (str, bytes))
        or len(raw) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) for value in raw)
    ):
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    count, ttl_ms = cast(tuple[int, int], tuple(raw))
    # 步骤 2：验证计数和剩余毫秒数，再按已包含本次请求的计数计算放行及等待时间。
    if count < 1 or not 0 < ttl_ms <= policy.window_seconds * 1000:
        raise RateLimitUnavailable("rate-limit store returned an invalid result")
    allowed = count <= policy.limit
    return RateLimitResult(
        allowed=allowed,
        limit=policy.limit,
        remaining=max(0, policy.limit - count),
        retry_after_ms=0 if allowed else ttl_ms,
        reset_after_ms=ttl_ms,
    )


async def check_rate_limit(redis: RedisClient, *, policy: RateLimitPolicy, subject_type: str,
                           subject: str, key_secret: bytes) -> RateLimitResult:
    """
        原子增加一个业务和主体的计数，保留首次请求设置的窗口过期时间。

    :param redis: 执行单键 Lua 脚本的 Redis 客户端。
    :param policy: 当前业务允许次数及窗口时长。
    :param subject_type: 服务端选定的 IP 或已认证用户等主体类型。
    :param subject: 要消耗额度的可信主体标识。
    :param key_secret: 计算主体 HMAC 摘要的服务端密钥。
    :return: 已包含本次请求的放行决定、剩余额度及重试时间。
    :raises ValueError: 主体、策略对象或摘要密钥不符合构键要求。
    :raises RateLimitUnavailable: Redis 不可用或无法返回可信的窗口数据。
    """
    # 步骤 1：为本业务和可信主体构造独立计数键，输入非法时不会向 Redis 扣次。
    key = build_rate_limit_key(
        policy=policy,
        subject_type=subject_type,
        subject=subject,
        key_secret=key_secret,
    )
    # 步骤 2：通过单次 Lua 调用增加计数并读取窗口余时；超额请求同样计数，不延长已有窗口。
    try:
        raw = await cast(
            Awaitable[object],
            redis.eval(
                FIXED_WINDOW_SCRIPT,
                1,
                key,
                str(policy.limit),
                str(policy.window_seconds),
            ),
        )
    except RedisError as exc:
        # 存储失败无法确定可信额度，交给上层按服务不可用处理，不能按普通超额放行或拒绝。
        raise RateLimitUnavailable("rate-limit store is unavailable") from exc
    # 步骤 3：检查脚本回包并给出允许或超额的结果；此函数本身不抛出 RateLimitExceeded。
    return _parse_result(raw, policy=policy)
