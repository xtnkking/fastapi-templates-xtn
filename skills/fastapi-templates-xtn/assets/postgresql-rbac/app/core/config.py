#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    应用连接、安全及业务参数配置；校验必填密钥、限流参数和单机连接地址。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        补齐初学者可读的配置用途、单位和修改位置
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/27    XTN       V1.003        拆分 Redis 高级配置并补齐强制安全配置
# 2026/09/29    XTN       V1.004        删除默认健康探针的专属超时配置
# 2026/09/29    XTN       V1.005        将通用 Redis 连接参数移回 Redis 配置组
# 2026/09/30    XTN       V1.006        删除默认日志队列和关闭等待配置
# 2026/09/30    XTN       V1.007        Redis 只保留单机 URL，移除拓扑配置入口
# 2026/09/30    XTN       V1.008        删除管理员密码模式及临时完成限流配置
# 2026/10/02    XTN       V1.009        用直观循环表达弱密钥重复检测并校正数值校验命名
# 2026/10/02    XTN       V1.010        修正限流窗口规则的模块位置说明
# 2026/10/08    XTN       V1.011        注册限流配置字段统一使用 register 命名
# 2026/10/09    XTN       V1.012        按业务分组限流配置，说明主体、窗口、次数和生效方式
# 2026/10/09    XTN       V1.013        说明验证码无效用途申请使用的次数配置
# 2026/10/13    XTN       V1.014        补充配置校验、密钥强度和连接地址检查的通俗步骤
# 2026/10/13    XTN       V1.015        修正环境配置说明，验证码键不再使用环境标识
# 2026/10/13    XTN       V1.016        删除限流命名空间配置，限流键只包含业务和计数主体
# 2026/10/13    XTN       V1.017        环境与服务名只用于日志和应用信息，不参与 Redis 键
# 2026/10/14    XTN       V1.018        增加单个日志文件大小配置，默认 100 MB
# 2026/10/14    XTN       V1.019        删除日志专用环境配置，应用名称和版本仅用于 FastAPI 信息
# 2026/10/14    XTN       V1.020        增加日志密码指纹专用强密钥并禁止与登录及限流密钥复用
# 2026/10/20    XTN       V1.021        增加本进程密码计算和排队限制，拒绝无效人数或等待秒数
# 2026/10/22    XTN       V1.022        本人和管理接口限流配置统一使用简短名称
# 2026/10/22    XTN       V1.023        说明普通权限接口默认额度与显式管理业务额度的区别
# --------------------------------------------------------------------------------------------------

import unicodedata
from functools import lru_cache
from typing import Self
from urllib.parse import urlsplit

from pydantic import (
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# 这些公开示例即使长度够也不安全；启动时拒绝它们，实际密钥在私有 .env 中随机生成。
_PUBLIC_JWT_SECRET_PLACEHOLDERS = frozenset(
    {
        "change-me-change-me-change-me-change-me",
        "replace-this-with-at-least-32-random-bytes",
        "super-secret-super-secret-super-secret",
        "your-secret-key-your-secret-key-your-secret-key",
    }
)
# 限流和日志指纹用的 HMAC 密钥也不能使用文档示例；三种用途必须分别生成密钥。
_PUBLIC_SECURITY_SECRET_PLACEHOLDERS = _PUBLIC_JWT_SECRET_PLACEHOLDERS | {
    "replace-this-with-a-rate-limit-hmac-secret",
    "replace-this-with-a-verification-hmac-secret",
    "replace-this-with-a-log-hmac-secret",
}
_MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS = 8  # 至少包含 8 种不同字符；只是弱值检查，不代表随机性达标。
_MAXIMUM_SECURITY_SECRET_UTF8_BYTES = 4_096  # 密钥编码后最多 4096 字节，拒绝误填的大段内容。
MAX_OPTIONAL_JWT_SCOPE_CHARACTERS = 256  # 可选签发者/接收方标识的字符上限，不是 Token 有效期。


def _is_repeated_pattern(value: str) -> bool:
    """
        判断密钥是否由较短片段重复构成，用于识别明显弱密钥。

    :param value: 待检查的密钥文本。
    :return: 非空文本由重复片段构成时为 True，否则为 False。
    """
    if not value:
        return False
    length = len(value)
    # 重复单元最多占整段的一半；长度不能整除时不可能拼出原密钥。
    for pattern_length in range(1, length // 2 + 1):
        if length % pattern_length:
            continue
        if value[:pattern_length] * (length // pattern_length) == value:
            return True
    return False


class Settings(BaseSettings):
    """
        应用参数统一入口；优先从环境变量读取，其次读取项目 .env，未填写项使用下方默认值。
        调整参数通常改 .env 中的大写同名项并重启，例如 JWT_ACCESS_TOKEN_TTL_SECONDS。
        Redis 使用 REDIS_URL；只有明确需要独立限流服务时才填写 RATE_LIMIT_REDIS_URL。
    """

    # .env 使用 UTF-8；环境变量大小写不敏感；忽略其他工具的无关配置。
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    # -------------------------------- 应用身份与 HTTP --------------------------------
    # FastAPI 的应用显示名称；不写入日志或参与 Redis 键。
    service_name: str = Field(
        default="fastapi-access-service",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$",
    )
    # FastAPI 的应用版本信息；不会自动修改 Skill 或数据库版本，不写入日志。
    service_version: str = Field(default="unreleased", min_length=1, max_length=64)
    # 单个 HTTP 请求体最大字节数；默认 1 MiB，超出时在进入业务代码前返回 413。
    request_body_max_bytes: int = Field(
        default=1024 * 1024,
        ge=1,
        le=100 * 1024 * 1024,
    )

    # -------------------------------- PostgreSQL --------------------------------
    # 必填的单机 PostgreSQL 异步连接串；不在业务代码中选择节点。
    database_url: str = Field(repr=False)
    # 每进程连接池可保留的常规连接上限，连接按需创建；多进程分别计数。
    database_pool_size: int = Field(default=5, ge=1)
    # 池满后额外允许的临时连接数；单进程最多 pool_size + max_overflow。
    database_max_overflow: int = Field(default=5, ge=0)
    # 从连接池等待空闲连接的秒数，超时会失败，避免请求无限排队。
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0, allow_inf_nan=False)
    # 新建一条 PostgreSQL 网络连接的最长等待秒数。
    database_connect_timeout_seconds: float = Field(
        default=5.0, gt=0, allow_inf_nan=False
    )
    # 驱动等待单条命令完成的秒数，不是整个 HTTP 请求的总时限。
    database_command_timeout_seconds: float = Field(
        default=20.0, gt=0, allow_inf_nan=False
    )
    # 数据库端单条 SQL 的最长执行毫秒数，防止慢查询长期占用资源。
    database_statement_timeout_ms: int = Field(default=15_000, ge=1, le=2_147_483_647)
    # 数据库等待其他事务释放锁的毫秒数；3000 毫秒就是 3 秒。
    database_lock_timeout_ms: int = Field(default=3_000, ge=1, le=2_147_483_647)

    # -------------------------------- Redis --------------------------------
    # 必填单机 Redis 地址；默认由登录状态、验证码和限流共用。
    redis_url: str = Field(repr=False)
    # 新建 Redis 连接的最长秒数；服务不可用时及时返回，不让请求一直等待。
    redis_connect_timeout_seconds: float = Field(default=0.5, gt=0, allow_inf_nan=False)
    # 等待 Redis 网络响应的最长秒数，不自动重放结果未知的写入。
    redis_socket_timeout_seconds: float = Field(default=0.5, gt=0, allow_inf_nan=False)
    # 单个 Redis 客户端的连接池上限；进程多时分别计数。
    redis_max_connections: int = Field(default=50, ge=1)

    # -------------------------------- 日志 --------------------------------
    log_level: str = "INFO"  # 最低输出等级，例如 INFO、WARNING、ERROR。
    # 默认不打印异常细节，避免驱动异常带出连接或输入信息；开启前检查日志读取者。
    log_include_exception_details: bool = False
    # 单个文件最多多少 MB，1 MB = 1024 × 1024 字节；下一条放不下时切换新序号，旧日志保留。
    # 在 .env 修改 LOG_FILE_MAX_MB 并重启服务生效，默认每个文件最多 100 MB。
    log_file_max_mb: int = Field(default=100, ge=1)
    # 必填的独立随机密钥；只给设置新密码请求生成不可还原的日志指纹，不记录密码原文。
    # 在 .env 单独生成 LOG_HMAC_KEY；更换后，相同密码的指纹也会变化，不能跨密钥直接比较。
    log_hmac_key: SecretStr

    # -------------------------------- 安全与登录会话 --------------------------------
    jwt_secret: SecretStr  # 必填随机签名密钥，防止他人随意签发 Token；仍须验证 Redis 活跃记录。
    rate_limit_hmac_key: SecretStr  # 独立随机密钥，用于限流/CAPTCHA 摘要，禁止与 JWT 密钥相同。
    # 必须先与使用者确认；记录登录会话数量，不识别物理设备，超出会踢掉最早的旧登录。
    max_active_sessions_per_user: int = Field(ge=1)
    jwt_issuer: str | None = None  # 谁签发的 Token；仅使用者同意后与 audience 一起设置。
    jwt_audience: str | None = None  # Token 给哪个服务用；默认 None，不强制跨服务标识。
    # 默认 86400 秒即 24 小时；按业务风险调整，高风险管理场景通常缩短。
    jwt_access_token_ttl_seconds: int = Field(default=86_400, ge=1)

    # -------------------------------- 密码计算保护 --------------------------------
    # 每个 worker 各自执行以下限制；修改部署 .env 的 PASSWORD_* 同名项后重启生效。
    # 注册、登录、改密、重置共用本进程的计算名额，空闲时立即执行，不固定等待。
    password_max_running: int = Field(default=2, ge=1, le=32)  # 同时计算的任务数，每项约需 64 MiB。
    password_max_waiting: int = Field(default=4, ge=0)  # 另外允许等候的任务数；0 表示没有空位就拒绝。
    # 只限制等候名额的最长秒数；排队满或超时返回 50301，已经开始的计算仍需结束后归还名额。
    password_wait_timeout_seconds: float = Field(default=0.5, gt=0, allow_inf_nan=False)

    # -------------------------------- 业务限流 --------------------------------
    # 修改次数：在部署的 .env 中填写对应 RATE_LIMIT_* 参数，保存后重启服务。
    # 窗口秒数在 app/dependencies/rate_limit.py；例如 300 秒是 5 分钟，3600 秒是 1 小时。
    # 进入正式计数步骤的请求占用一次，业务失败不返还次数；不是只统计成功操作。

    # 通用连接：供下面各业务的限流检查使用。
    # 可选独立单机限流 Redis URL；不填时复用主 Redis 客户端。
    rate_limit_redis_url: str | None = Field(default=None, repr=False)

    # 登录提交（不要求先登录）
    # POST /api/v1/auth/login：每个来源 IP，每 5 分钟最多提交 20 次。
    # 同一 IP 更换用户名仍继续累计；验证码或密码错误也占用本次提交次数。
    rate_limit_login_ip_per_five_minutes: int = Field(default=20, ge=1, le=1_000_000)

    # 注册提交（不要求先登录）
    # POST /api/v1/auth/register：每个来源 IP，每小时最多提交 5 次。
    # 这是注册请求次数，不是成功新增 5 个账号；与登录提交分别计数。
    rate_limit_register_ip_per_hour: int = Field(default=5, ge=1, le=1_000_000)

    # 验证码领取：每种用途分别计数，默认每 5 分钟最多申请 10 次。
    # 未登录：POST /api/v1/auth/captcha，按登录或注册用途 + 来源 IP 计数。
    # 已登录：POST /api/v1/me/captcha，按新增用户、重置密码或本人改密用途 + 操作者 ID 计数。
    # 本项限制领图片的请求；后续登录、注册、改密等提交仍使用各自的限流配置。
    # 用途无效的申请（captcha_invalid_scene）也使用本项次数，按来源 IP 或当前用户 ID 单独计数。
    rate_limit_captcha_create_per_five_minutes: int = Field(default=10, ge=1, le=1_000_000)

    # 普通用户接口：包括本人接口、默认的权限接口，按每个接口、每个当前用户的 60 秒窗口分别计数。
    # GET 查询，例如查看本人权限；默认最多 600 次。
    rate_limit_user_read: int = Field(default=600, ge=1, le=1_000_000)
    # POST 修改，例如本人改密；默认最多 120 次。退出登录不使用限流。
    rate_limit_user_write: int = Field(default=120, ge=1, le=1_000_000)

    # 管理业务：只有 require_permission(..., management=True) 才选择下面两项。
    # 有接口权限不代表是管理员；不根据用户角色或是否检查权限自动选择管理额度。
    # 以下两项同样按每个接口、每个当前用户的 60 秒窗口分别计数。
    # GET 查询，例如用户、角色、权限列表及详情；默认最多 300 次。
    rate_limit_admin_read: int = Field(default=300, ge=1, le=1_000_000)
    # POST 修改，例如新增用户、重置密码、角色授权；默认最多 60 次。
    rate_limit_admin_write: int = Field(default=60, ge=1, le=1_000_000)

    # -------------------------------- SQL 调试 --------------------------------
    sql_echo: bool = False  # SQL 调试输出；正常保持 False，开启前检查 SQL 文本中的敏感信息。

    @field_validator(
        "database_pool_size",
        "database_max_overflow",
        "database_pool_timeout_seconds",
        "database_connect_timeout_seconds",
        "database_command_timeout_seconds",
        "database_statement_timeout_ms",
        "database_lock_timeout_ms",
        "request_body_max_bytes",
        "log_file_max_mb",
        "password_max_running",
        "password_max_waiting",
        "password_wait_timeout_seconds",
        "redis_max_connections",
        "redis_connect_timeout_seconds",
        "redis_socket_timeout_seconds",
        mode="before",
    )
    @classmethod
    def reject_boolean_numeric_settings(cls, value: object) -> object:
        """
            拒绝将布尔值用作连接容量、密码任务人数、超时或请求体大小。

        :param value: 尚未完成类型转换的容量、超时或大小配置。
        :return: 原输入值，供后续数值校验使用。
        :raises ValueError: 输入是布尔值。
        """
        # Python 会把 True/False 当成 1/0，先明确拒绝，避免把开关误填成容量或超时。
        if isinstance(value, bool):
            raise ValueError("capacity, timeout and request size settings must be numbers")
        return value

    @model_validator(mode="after")
    def require_ordered_database_timeouts(self) -> Self:
        """
            确保数据库等待锁的超时不超过单条 SQL 的执行超时。

        :return: 超时关系合法的当前配置对象。
        :raises ValueError: 等待锁的时间上限高于语句执行上限。
        """
        # 等待锁不能比整条 SQL 的执行上限还长，否则锁超时设置没有机会先发挥作用。
        if self.database_lock_timeout_ms > self.database_statement_timeout_ms:
            raise ValueError(
                "database_lock_timeout_ms must not exceed database_statement_timeout_ms"
            )
        return self

    @field_validator("database_url")
    @classmethod
    def require_postgresql_asyncpg(cls, value: str) -> str:
        """
            限定数据库连接使用 PostgreSQL 的 asyncpg 异步驱动。

        :param value: SQLAlchemy 数据库连接 URL。
        :return: 校验通过的原连接 URL。
        :raises ValueError: URL 不以 postgresql+asyncpg:// 开头。
        """
        # 这里只核对连接串的驱动前缀，不连接数据库，也不验证账号密码能否登录。
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg")
        return value

    @field_validator("redis_url", "rate_limit_redis_url")
    @classmethod
    def require_redis_url(cls, value: str | None,
                          info: ValidationInfo
                          ) -> str | None:
        """
            校验默认或独立限流 Redis 的单机连接 URL。

        :param value: 待校验的连接 URL，未配置时为 None。
        :param info: Pydantic 字段信息，用于标明无效配置项。
        :return: 校验通过的原 URL，或未配置时的 None。
        :raises ValueError: URL 协议或结构不符合 Redis 连接规范。
        """
        # 1. 未提供独立限流地址时允许 None；已提供的地址只能使用 Redis 或加密 Redis 协议。
        if value is None:
            return None
        if not value.startswith(("redis://", "rediss://")):
            raise ValueError(f"{info.field_name} must use redis or rediss")
        # 2. 检查主机、端口、数据库序号和非法空白；查询参数与片段不允许混入连接配置。
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme in {"redis", "rediss"}
                and bool(parsed.hostname)
                and (parsed.port is None or 1 <= parsed.port <= 65535)
                and not parsed.query
                and not parsed.fragment
                and (parsed.path in {"", "/"} or parsed.path[1:].isdigit())
                and not any(c.isspace() or ord(c) < 32 for c in value)
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(f"{info.field_name} must be a Redis URL without query or fragment")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        """
            去除日志级别首尾空白并转大写，限定为标准 Python 日志级别。

        :param value: 使用者配置的日志级别文本。
        :return: DEBUG、INFO、WARNING、ERROR 或 CRITICAL。
        :raises ValueError: 文本不属于允许的日志级别。
        """
        # 统一空白和大小写后只接受标准级别，拼错配置时启动即报错。
        normalized = value.strip().upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard Python logging level")
        return normalized

    @field_validator("jwt_secret", "rate_limit_hmac_key", "log_hmac_key")
    @classmethod
    def require_strong_security_secret(cls, value: SecretStr,
                                       info: ValidationInfo
                                       ) -> SecretStr:
        """
            对 JWT、限流和日志指纹的三种密钥应用同一强度检查。

        :param value: 由 SecretStr 包装的密钥，避免常规输出显示明文。
        :param info: 当前校验字段的信息，用于生成不含密钥的错误说明。
        :return: 校验通过的原密钥对象。
        :raises ValueError: 密钥是公开占位值、长度不合适或存在明显弱模式。
        """
        # 三种用途共用基础弱值检查，错误只说明哪个配置项，不回显密钥内容。
        return cls._validate_security_secret(
            value,
            field_name=info.field_name or "security_secret",
        )

    @staticmethod
    def _validate_security_secret(value: SecretStr, *,
                                  field_name: str
                                  ) -> SecretStr:
        """
            检查安全密钥的 UTF-8 字节长度、公开占位值及明显弱模式。
            仅做启动前基本检查，随机性仍应由密码学安全随机生成器保证。

        :param value: 待检查的密钥对象。
        :param field_name: 错误说明中的配置字段名，不包含密钥内容。
        :return: 校验通过的原密钥对象。
        :raises ValueError: 编码、长度、字符分布或重复模式不符合基本要求。
        """
        # 1. 只在校验内部取密钥原文，确认能编码为 UTF-8；报错不携带原文。
        secret = value.get_secret_value()
        try:
            encoded_secret = secret.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(f"{field_name} must contain valid UTF-8 text") from None
        # 2. 拒绝公开示例并检查实际字节长度，中文字符的字节数不能按字符数计算。
        normalized = secret.strip().casefold()
        if normalized in _PUBLIC_SECURITY_SECRET_PLACEHOLDERS:
            raise ValueError(
                f"{field_name} must not use the public example placeholder; "
                "generate a unique random secret before startup"
            )
        if len(encoded_secret) < 32:
            raise ValueError(f"{field_name} must contain at least 32 UTF-8 bytes")
        if len(encoded_secret) > _MAXIMUM_SECURITY_SECRET_UTF8_BYTES:
            raise ValueError(
                f"{field_name} must contain at most "
                f"{_MAXIMUM_SECURITY_SECRET_UTF8_BYTES} UTF-8 bytes"
            )
        # 3. 空白、控制字符、字符种类过少或重复短片段都表示明显弱值；通过不代表随机性合格。
        if (
            not normalized
            or secret != secret.strip()
            or any(
                character.isspace() or unicodedata.category(character) == "Cc"
                for character in secret
            )
            or len(set(secret)) < _MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS
            or _is_repeated_pattern(secret)
        ):
            raise ValueError(
                f"{field_name} is obviously weak; generate it with a cryptographically "
                "secure random generator"
            )
        return value

    @field_validator("jwt_issuer", "jwt_audience")
    @classmethod
    def normalize_optional_token_scope(cls, value: str | None) -> str | None:
        """
            规范化按需启用的 JWT 签发方或接收方标识。
            去掉首尾空白后只允许有长度上限且不含空白的可见 ASCII 文本。

        :param value: 可选的 issuer 或 audience 标识，未启用时为 None。
        :return: 规范化后的标识，或未启用时的 None。
        :raises ValueError: 标识为空、超长或包含不允许的字符。
        """
        # 未启用就保留 None；启用时去掉两端空白，再限制可见字符和长度，不接受空标识。
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("optional JWT issuer and audience must not be blank")
        if not normalized.isascii() or any(
            character.isspace() or not 32 <= ord(character) <= 126
            for character in normalized
        ):
            raise ValueError(
                "optional JWT issuer and audience must use visible ASCII "
                "characters without whitespace"
            )
        if len(normalized) > MAX_OPTIONAL_JWT_SCOPE_CHARACTERS:
            raise ValueError(
                "optional JWT issuer and audience must contain at most "
                f"{MAX_OPTIONAL_JWT_SCOPE_CHARACTERS} characters"
            )
        return normalized

    @model_validator(mode="after")
    def require_safe_security_relationships(self) -> Self:
        """
            校验 JWT 可选范围字段必须成对启用，并禁止不同用途复用同一密钥。

        :return: 满足跨字段安全约束的当前配置对象。
        :raises ValueError: JWT 范围配对或密钥独立性不符合要求。
        """
        # 1. 签发方与接收方必须一起启用，不能只启用其中一个。
        if (self.jwt_issuer is None) != (self.jwt_audience is None):
            raise ValueError(
                "jwt_issuer and jwt_audience must be configured together or omitted"
            )
        # 2. 签名和限流摘要必须分别生成密钥，避免不同用途共用秘密。
        if (
            self.jwt_secret.get_secret_value()
            == self.rate_limit_hmac_key.get_secret_value()
        ):
            raise ValueError("JWT and rate-limit secrets must use different values")
        # 3. 日志密码指纹再使用一份独立密钥；获取日志密钥不能影响 Token 或限流。
        if self.log_hmac_key.get_secret_value() in {
            self.jwt_secret.get_secret_value(),
            self.rate_limit_hmac_key.get_secret_value(),
        }:
            raise ValueError("log HMAC secret and JWT/rate-limit secrets must use different values")
        return self

    @property
    def effective_rate_limit_redis_url(self) -> str:
        """
            获取独立限流 Redis URL；未配置时使用主 Redis URL。

        :return: 当前限流 Redis 的单机 URL。
        """
        # 配了独立地址就使用它，否则复用主地址；这里只选择地址，不新建 Redis 连接。
        return self.rate_limit_redis_url or self.redis_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
        从环境变量与 .env 加载配置，并在当前进程内缓存校验后的结果。

    :return: 已通过 Pydantic 校验的应用配置对象。
    :raises ValueError: 必填配置缺失或配置值未通过模型校验。
    """
    # 首次读取时加载并校验配置，后续调用由缓存返回同一对象；配置变化需重启或显式清缓存。
    return Settings()  # type: ignore[call-arg]
