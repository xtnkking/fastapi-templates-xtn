#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    签名并解析精简 Access Token；不读写 Redis 或数据库。
#    验签后的身份仍须由会话登记和当前数据库用户状态继续核对。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从会话登记中独立 JWT 字段、编码和验签规则
# 2026/10/02    XTN       V1.001        在验签入口直接展示可选字段与签发方受众校验
# 2026/10/10    XTN       V1.002        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.003        补全令牌函数契约及验签签发阶段说明
# 2026/10/16    XTN       V1.004        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/20    XTN       V1.005        Token 信息与允许字段改用直观名称，保留 JWT 协议内容
# 2026/10/20    XTN       V1.006        Token 字段字典采用 token_fields 名称，区分原始字段和解析结果
# --------------------------------------------------------------------------------------------------


import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt

from app.core.config import Settings
from app.core.exceptions import unauthenticated_401
from app.core.ids import require_entity_id

# Bearer 令牌本体最多 4096 字节，签发和请求解析共同限制，避免超长认证头占用资源。
MAX_BEARER_TOKEN_BYTES = 4096
# JWT 时间校验允许 30 秒时钟偏差；Redis 仍按自己的时间严格检查会话到期，不延长在线会话。
JWT_CLOCK_LEEWAY_SECONDS = 30
# 必填字段依次表示用户、该次登录标识、签发秒数、到期秒数和令牌类型；权限不写入 JWT。
# JTI 是一次登录令牌的唯一标识；同一用户的不同登录必须分别登记，才能单独退出。
REQUIRED_ACCESS_TOKEN_FIELDS = frozenset({"user_id", "jti", "iat", "exp", "token_type"})
# iss 是签发者，aud 是使用方；只有使用者选择并配置这两个范围字段时才成对启用。
OPTIONAL_ACCESS_TOKEN_FIELDS = frozenset({"iss", "aud"})


@dataclass(frozen=True, slots=True)
class AccessTokenInfo:
    """
        保存通过 JWT 验签后的最小身份和 UTC Unix 秒数，不代表已完成 Redis 会话校验。
    """

    user_id: str  # JWT 的 user_id，U 开头的不可变用户 ID；不代表当前权限。
    token_id: uuid.UUID  # JWT 的 jti，只标记这一次登录；Redis 必须保留它才认可该 Token。
    issued_at: int  # JWT 的 iat，签发时刻的 UTC Unix 秒数。
    expires_at: int  # JWT 的 exp，到期时刻的 UTC Unix 整数秒，不是剩余有效秒数。


def canonical_uuid4(value: object) -> uuid.UUID:
    """
        校验 JTI 采用规范 UUIDv4 字符串。

    :param value: 从令牌读出的 JTI 原值。
    :return: 已解析并验证版本、规范文本格式的 UUID 对象。
    :raises ValueError: 输入不是字符串、不是 UUIDv4 或字符串表示不规范。
    """
    # 步骤：同时检查 UUID 的随机版本和标准小写文本，确保同一次登录标识只有一种表示。
    if not isinstance(value, str):
        raise ValueError("claim must be a canonical UUIDv4 string")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("claim must be a canonical UUIDv4 string")
    return parsed


def integer_numeric_date(value: object) -> int:
    """
        校验 JWT 或会话中的时间字段为整数秒，显式拒绝布尔值及浮点数。

    :param value: 待检查的签发或过期时间字段。
    :return: 通过类型检查的整数时间值。
    :raises ValueError: 时间字段不是有效整数类型。
    """
    # 步骤：只接受整数秒；此处不判断是否已到期，到期检查由 JWT 解码和会话脚本完成。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("NumericDate claims must be integers")
    return value


def decode_access_token(token: str, settings: Settings) -> AccessTokenInfo:
    """
        校验 HS256 签名、时间、类型和精确字段集合，解析访问令牌的最小身份信息。

        此处不访问 Redis；调用方仍须检查活跃 JTI 和用户状态，不能仅凭验签放行。

    :param token: 从请求中取得的访问令牌字符串。
    :param settings: 签名密钥、最大有效期及可选签发者和受众配置。
    :return: 不可变的用户 ID、JTI、签发时间及过期时间快照，尚未确认登录仍有效。
    :raises AppError: 签名、字段、令牌类型或有效期检查失败。
    """
    try:
        # 步骤 1：按服务端配置选择允许字段，并检查签名、时间和可选的签发者及受众。
        # 默认只接收五个基础字段；配置已保证 iss 和 aud 同时存在或同时省略。
        expected_fields = REQUIRED_ACCESS_TOKEN_FIELDS
        if settings.jwt_issuer is not None:
            expected_fields |= OPTIONAL_ACCESS_TOKEN_FIELDS
        # 算法由服务端固定，不能信任请求中令牌头自行声明的算法。
        token_fields: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            leeway=JWT_CLOCK_LEEWAY_SECONDS,
            options={
                "require": sorted(expected_fields),
                "strict_aud": True,
            },
        )
        # 步骤 2：核对精确字段集合、访问令牌类型和有效期长度，拒绝额外字段或过长有效期。
        # 避免调用方把角色、权限或其他未约定字段误当作可信授权信息。
        if set(token_fields) != expected_fields:
            raise ValueError("access token must contain only the configured claims")
        if token_fields["token_type"] != "access":
            raise ValueError("wrong token type")

        issued_at = integer_numeric_date(token_fields["iat"])
        expires_at = integer_numeric_date(token_fields["exp"])
        if (
            expires_at <= issued_at
            or expires_at - issued_at > settings.jwt_access_token_ttl_seconds
        ):
            raise ValueError("invalid access token lifetime")

        # 步骤 3：校验用户 ID 和本次登录标识，组装后续 Redis 会话核对所需的最小身份。
        return AccessTokenInfo(
            user_id=require_entity_id(token_fields["user_id"], "U"),
            token_id=canonical_uuid4(token_fields["jti"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (jwt.PyJWTError, KeyError, OverflowError, TypeError, ValueError) as exc:
        # 对外统一为令牌无效，原始解析细节只保留在异常链中供内部排查。
        raise unauthenticated_401("invalid_access_token") from exc


def encode_access_token(*, user_id: str, token_id: uuid.UUID,
                        settings: Settings) -> tuple[str, AccessTokenInfo]:
    """
        生成当前时间起生效的精简 HS256 访问令牌，但尚不将其登记为活跃登录。

    :param user_id: 令牌所属用户的唯一 ID，写入同名 user_id 字段。
    :param token_id: 调用方为本次登录随机生成的 UUIDv4 标识；此函数只编码，不重新生成。
    :param settings: 签名密钥、有效期及按需启用的 iss、aud 配置。
    :return: 已签名令牌字符串及对应的身份和时间信息。
    :raises ValueError: 用户 ID 不符合 U 开头的业务标识规则，或编码令牌超过请求头大小上限。
    """
    # 步骤 1：检查用户标识，以当前 UTC 整数秒计算签发时刻和配置的到期时刻。
    require_entity_id(user_id, "U")
    now = int(datetime.now(UTC).timestamp())
    token_info = AccessTokenInfo(
        user_id=user_id,
        token_id=token_id,
        issued_at=now,
        expires_at=now + settings.jwt_access_token_ttl_seconds,
    )
    # 步骤 2：只写入身份、登录标识和时间；配置启用范围校验时才加入签发者与受众。
    token_fields: dict[str, object] = {
        "user_id": str(token_info.user_id),
        "jti": str(token_info.token_id),
        "iat": token_info.issued_at,
        "exp": token_info.expires_at,
        "token_type": "access",
    }
    if settings.jwt_issuer is not None and settings.jwt_audience is not None:
        token_fields.update(iss=settings.jwt_issuer, aud=settings.jwt_audience)
    # 步骤 3：使用服务端固定算法签名并检查大小；活跃登录登记仍由调用方完成。
    token = jwt.encode(
        token_fields,
        settings.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )
    if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
        raise ValueError("encoded access token exceeds the bearer token size limit")
    return token, token_info
