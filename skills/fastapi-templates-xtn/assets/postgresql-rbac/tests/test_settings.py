#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证应用、数据库、Redis 和业务安全设置的默认值及边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        删除默认健康探针移除后不再提供的就绪超时配置断言
# 2026/09/30    XTN       V1.001        删除已移除日志队列配置的断言
# 2026/09/30    XTN       V1.002        删除管理员密码模式及临时完成额度断言
# 2026/10/02    XTN       V1.003        覆盖请求体大小布尔输入并对齐数值校验称呼
# 2026/10/08    XTN       V1.004        验证注册限流配置字段使用 register
# 2026/10/13    XTN       V1.005        移除已删除的限流命名空间环境变量测试准备
# 2026/10/14    XTN       V1.006        验证日志文件 100 MB 默认值、环境配置和正整数约束
# 2026/10/14    XTN       V1.007        运行配置不再要求环境标识，保留测试配置隔离
# 2026/10/14    XTN       V1.008        验证日志指纹密钥必填、强度、环境读取和三项密钥独立
# 2026/10/20    XTN       V1.009        验证密码计算和排队默认值、环境覆盖及无效配置拒绝
# 2026/10/22    XTN       V1.010        对齐简短限流配置名称，验证环境文件覆盖生效
# --------------------------------------------------------------------------------------------------

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings

EXAMPLE_ENV = Path(__file__).parents[1] / ".env.example"
VALID_TEST_SECRET = "D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz"
VALID_RATE_LIMIT_SECRET = "R8qM4vK2zT7pN5xC9sW1dF6hJ3yB0uGa"
VALID_LOG_SECRET = "N6wR2tY9qH4kF7vD1sL8cB3mJ5xP0uGa"
SETTINGS_ENV_NAMES = (
    "DATABASE_URL",
    "DATABASE_POOL_SIZE",
    "DATABASE_MAX_OVERFLOW",
    "DATABASE_POOL_TIMEOUT_SECONDS",
    "DATABASE_CONNECT_TIMEOUT_SECONDS",
    "DATABASE_COMMAND_TIMEOUT_SECONDS",
    "DATABASE_STATEMENT_TIMEOUT_MS",
    "DATABASE_LOCK_TIMEOUT_MS",
    "REDIS_URL",
    "RATE_LIMIT_REDIS_URL",
    "APP_ENVIRONMENT",
    "SERVICE_NAME",
    "SERVICE_VERSION",
    "REQUEST_BODY_MAX_BYTES",
    "LOG_LEVEL",
    "LOG_INCLUDE_EXCEPTION_DETAILS",
    "LOG_FILE_MAX_MB",
    "LOG_HMAC_KEY",
    "JWT_SECRET",
    "RATE_LIMIT_HMAC_KEY",
    "MAX_ACTIVE_SESSIONS_PER_USER",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "JWT_ACCESS_TOKEN_TTL_SECONDS",
    "REDIS_CONNECT_TIMEOUT_SECONDS",
    "REDIS_SOCKET_TIMEOUT_SECONDS",
    "REDIS_MAX_CONNECTIONS",
    "SQL_ECHO",
    "PASSWORD_MAX_RUNNING",
    "PASSWORD_MAX_WAITING",
    "PASSWORD_WAIT_TIMEOUT_SECONDS",
)


def settings_for_test(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql+asyncpg://postgres:postgres@localhost/example",
        "redis_url": "redis://localhost:6379/0",
        "rate_limit_redis_url": "redis://127.0.0.1:6380/0",
        "jwt_secret": SecretStr(VALID_TEST_SECRET),
        "rate_limit_hmac_key": SecretStr(VALID_RATE_LIMIT_SECRET),
        "log_hmac_key": SecretStr(VALID_LOG_SECRET),
        "max_active_sessions_per_user": 2,
    }
    values.update(overrides)
    return Settings.model_validate(values)


def settings_with_secret(secret: str) -> Settings:
    return settings_for_test(jwt_secret=SecretStr(secret))


def test_database_url_is_hidden_from_settings_representation() -> None:
    database_url = "postgresql+asyncpg://private-user:private-password@db/example"

    settings = settings_for_test(database_url=database_url)

    assert database_url not in repr(settings)
    assert "private-password" not in repr(settings)


def test_request_body_limit_defaults_to_one_mebibyte_and_is_configurable() -> None:
    default_settings = settings_for_test()
    custom_settings = settings_for_test(request_body_max_bytes=2 * 1024 * 1024)

    assert default_settings.request_body_max_bytes == 1024 * 1024
    assert custom_settings.request_body_max_bytes == 2 * 1024 * 1024


@pytest.mark.parametrize(
    "invalid_value",
    [0, True, 100 * 1024 * 1024 + 1],
)
def test_request_body_limit_rejects_invalid_values(invalid_value: object) -> None:
    with pytest.raises(ValidationError, match="request_body_max_bytes"):
        settings_for_test(request_body_max_bytes=invalid_value)


def test_app_environment_is_not_a_runtime_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENVIRONMENT", raising=False)
    settings = settings_for_test()
    assert "app_environment" not in Settings.model_fields
    assert not hasattr(settings, "app_environment")
    assert "APP_ENVIRONMENT" not in EXAMPLE_ENV.read_text(encoding="utf-8")


def test_example_env_cannot_start_with_public_jwt_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SETTINGS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(
        ValidationError,
        match="jwt_secret must not use the public example placeholder",
    ):
        Settings(_env_file=EXAMPLE_ENV)  # type: ignore[call-arg]


def test_public_jwt_placeholder_rejection_ignores_case_and_outer_whitespace() -> None:
    placeholder = "  REPLACE-THIS-WITH-AT-LEAST-32-RANDOM-BYTES  "

    with pytest.raises(
        ValidationError,
        match="jwt_secret must not use the public example placeholder",
    ):
        settings_with_secret(placeholder)


def test_jwt_secret_length_is_measured_in_utf8_bytes() -> None:
    with pytest.raises(
        ValidationError,
        match="jwt_secret must contain at least 32 UTF-8 bytes",
    ):
        settings_with_secret("\u5bc6" * 10)

    settings = settings_with_secret(
        "\u5bc6\u94a5\u5b89\u5168\u7532\u4e59\u4e19\u4e01\u620a\u5df1\u5e9a\u8f9bAB"
    )

    assert len(settings.jwt_secret.get_secret_value().encode("utf-8")) >= 32


def test_security_secret_rejects_invalid_unicode_without_encoding_error() -> None:
    with pytest.raises(ValidationError, match="valid UTF-8 text"):
        settings_with_secret("D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz\ud800")


def test_security_secret_has_a_bounded_utf8_size() -> None:
    with pytest.raises(ValidationError, match="at most 4096 UTF-8 bytes"):
        settings_with_secret("Ab3!" * 1_025)


@pytest.mark.parametrize(
    "secret",
    [
        " " * 32,
        "a" * 32,
        "abcd" * 8,
        "change-me-change-me-change-me-change-me",
        " valid-looking-secret-with-outer-space-123456789 ",
    ],
)
def test_jwt_secret_rejects_obviously_weak_shapes(secret: str) -> None:
    with pytest.raises(ValidationError, match="jwt_secret") as caught:
        settings_with_secret(secret)

    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    ("pattern", "repetitions"),
    [
        ("Ab3$Cd5!E", 4),
        ("Q7!wE2@rT9", 4),
        ("N4#vP8@xL2!sD6$q", 2),
    ],
)
def test_jwt_secret_rejects_repeated_patterns_wider_than_eight_characters(pattern: str, repetitions: int) -> None:
    secret = pattern * repetitions

    with pytest.raises(ValidationError, match="jwt_secret") as caught:
        settings_with_secret(secret)

    assert len(pattern) in {9, 10, 16}
    assert secret not in str(caught.value)


def test_jwt_secret_accepts_nonperiodic_random_value_with_repeated_substrings() -> None:
    secret = "D7vL3qN9-D7vL3qN9-xR2mK8pT5sW1cF6hJ4yB0uGz"

    settings = settings_with_secret(secret)

    assert settings.jwt_secret.get_secret_value() == secret


@pytest.mark.parametrize("control_character", ["\x7f", "\x80"])
def test_jwt_secret_rejects_unicode_control_characters(control_character: str) -> None:
    secret = VALID_TEST_SECRET + control_character

    with pytest.raises(ValidationError, match="jwt_secret") as caught:
        settings_with_secret(secret)

    assert secret not in str(caught.value)


def test_access_token_lifetime_defaults_to_twenty_four_hours_and_is_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("JWT_ACCESS_TOKEN_TTL_SECONDS", raising=False)
    default_settings = settings_with_secret(VALID_TEST_SECRET)
    custom_settings = settings_for_test(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        redis_url="redis://localhost:6379/0",
        jwt_secret=SecretStr(VALID_TEST_SECRET),
        jwt_access_token_ttl_seconds=900,
    )

    assert default_settings.jwt_access_token_ttl_seconds == 86_400
    assert custom_settings.jwt_access_token_ttl_seconds == 900


def test_redis_url_requires_redis_protocol() -> None:
    with pytest.raises(ValidationError, match="redis_url must use redis or rediss"):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="http://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
        )


def test_rate_limit_defaults_are_explicit_and_configurable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fields = ("rate_limit_user_read", "rate_limit_user_write", "rate_limit_admin_read", "rate_limit_admin_write")
    for field in fields:
        monkeypatch.delenv(field.upper(), raising=False)
    settings = settings_with_secret(VALID_TEST_SECRET)

    assert settings.rate_limit_captcha_create_per_five_minutes == 10
    assert settings.rate_limit_user_read == 600
    assert settings.rate_limit_user_write == 120
    assert settings.rate_limit_admin_read == 300
    assert settings.rate_limit_admin_write == 60
    assert settings.rate_limit_login_ip_per_five_minutes == 20
    assert settings.rate_limit_register_ip_per_hour == 5
    assert settings.max_active_sessions_per_user == 2

    env_file = tmp_path / "rate-limit.env"
    env_file.write_text(
        "RATE_LIMIT_USER_READ=45\nRATE_LIMIT_USER_WRITE=23\n"
        "RATE_LIMIT_ADMIN_READ=17\nRATE_LIMIT_ADMIN_WRITE=9\n",
        encoding="utf-8",
    )
    values = settings.model_dump()
    for field in fields:
        values.pop(field)
    configured = Settings(_env_file=env_file, **values)  # type: ignore[call-arg]
    assert tuple(getattr(configured, field) for field in fields) == (45, 23, 17, 9)


def test_password_capacity_defaults_and_env_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    names = ("PASSWORD_MAX_RUNNING", "PASSWORD_MAX_WAITING", "PASSWORD_WAIT_TIMEOUT_SECONDS")
    for name in names:
        monkeypatch.delenv(name, raising=False)
    default = settings_for_test()
    assert (default.password_max_running, default.password_max_waiting, default.password_wait_timeout_seconds) == (
        2, 4, 0.5,
    )

    env_file = tmp_path / "password-capacity.env"
    env_file.write_text(
        "PASSWORD_MAX_RUNNING=1\nPASSWORD_MAX_WAITING=0\nPASSWORD_WAIT_TIMEOUT_SECONDS=0.25\n",
        encoding="utf-8",
    )
    values = default.model_dump()
    for name in names:
        values.pop(name.lower())
    configured = Settings(_env_file=env_file, **values)  # type: ignore[call-arg]
    assert (configured.password_max_running, configured.password_max_waiting,
            configured.password_wait_timeout_seconds) == (1, 0, 0.25)


@pytest.mark.parametrize(
    ("name", "invalid_value"),
    [
        ("database_pool_size", 0),
        ("database_pool_size", True),
        ("database_max_overflow", -1),
        ("database_pool_timeout_seconds", 0),
        ("database_pool_timeout_seconds", float("inf")),
        ("database_connect_timeout_seconds", float("nan")),
        ("database_connect_timeout_seconds", False),
        ("database_command_timeout_seconds", 0),
        ("database_command_timeout_seconds", -1),
        ("database_command_timeout_seconds", float("nan")),
        ("database_command_timeout_seconds", float("inf")),
        ("database_command_timeout_seconds", True),
        ("database_statement_timeout_ms", 0),
        ("database_statement_timeout_ms", 2_147_483_648),
        ("database_lock_timeout_ms", 0),
        ("database_lock_timeout_ms", 1.5),
        ("redis_max_connections", 0),
        ("redis_max_connections", True),
        ("request_body_max_bytes", True),
        ("password_max_running", 0),
        ("password_max_running", 33),
        ("password_max_running", True),
        ("password_max_running", 1.5),
        ("password_max_waiting", -1),
        ("password_max_waiting", True),
        ("password_max_waiting", 1.5),
        ("password_wait_timeout_seconds", 0),
        ("password_wait_timeout_seconds", -1),
        ("password_wait_timeout_seconds", True),
        ("password_wait_timeout_seconds", float("nan")),
        ("password_wait_timeout_seconds", float("inf")),
    ],
)
def test_numeric_limits_reject_unbounded_or_invalid_values(name: str, invalid_value: object) -> None:
    with pytest.raises(ValidationError, match=name):
        settings_for_test(**{name: invalid_value})


def test_connection_limits_are_configurable_without_unlimited_pool_modes() -> None:
    settings = settings_for_test(
        database_pool_size=3,
        database_max_overflow=0,
        database_pool_timeout_seconds=0.25,
        database_connect_timeout_seconds=1.5,
        database_command_timeout_seconds=4.0,
        database_statement_timeout_ms=2_000,
        database_lock_timeout_ms=500,
        redis_max_connections=7,
    )

    assert settings.database_pool_size == 3
    assert settings.database_max_overflow == 0
    assert settings.database_pool_timeout_seconds == 0.25
    assert settings.database_connect_timeout_seconds == 1.5
    assert settings.database_command_timeout_seconds == 4.0
    assert settings.database_statement_timeout_ms == 2_000
    assert settings.database_lock_timeout_ms == 500
    assert settings.redis_max_connections == 7

    with pytest.raises(ValidationError, match="must not exceed"):
        settings_for_test(database_statement_timeout_ms=1_000)


def test_session_limit_must_be_positive_and_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MAX_ACTIVE_SESSIONS_PER_USER", raising=False)
    with pytest.raises(ValidationError, match="max_active_sessions_per_user"):
        Settings.model_validate(
            {
                "database_url": "postgresql+asyncpg://postgres:postgres@localhost/example",
                "redis_url": "redis://localhost:6379/0",
                "jwt_secret": SecretStr(VALID_TEST_SECRET),
                "rate_limit_hmac_key": SecretStr(VALID_RATE_LIMIT_SECRET),
                "log_hmac_key": SecretStr(VALID_LOG_SECRET),
            }
        )
    with pytest.raises(ValidationError, match="max_active_sessions_per_user"):
        settings_for_test(max_active_sessions_per_user=0)


def test_rate_limit_policy_bounds_can_be_validated_at_startup() -> None:
    with pytest.raises(ValidationError, match="rate_limit_login_ip_per_five_minutes"):
        settings_for_test(rate_limit_login_ip_per_five_minutes=1_000_001)


def test_rate_limit_redis_can_be_isolated_or_explicitly_shared() -> None:
    isolated = settings_with_secret(VALID_TEST_SECRET)
    shared = settings_for_test(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        redis_url="redis://localhost:6379/0",
        rate_limit_redis_url=None,
        jwt_secret=SecretStr(VALID_TEST_SECRET),
    )

    assert isolated.effective_rate_limit_redis_url == "redis://127.0.0.1:6380/0"
    assert shared.effective_rate_limit_redis_url == shared.redis_url


def test_rate_limit_hmac_secret_rejects_weak_values() -> None:
    with pytest.raises(ValidationError, match="rate_limit_hmac_key"):
        settings_for_test(rate_limit_hmac_key=SecretStr("a" * 32))


def test_security_secrets_must_not_be_reused() -> None:
    with pytest.raises(ValidationError, match="must use different values"):
        settings_for_test(
            rate_limit_hmac_key=SecretStr(VALID_TEST_SECRET),
        )


def test_log_hmac_key_is_required_and_reads_its_env_name(monkeypatch: pytest.MonkeyPatch) -> None:
    values = settings_for_test().model_dump()
    values.pop("log_hmac_key")
    monkeypatch.delenv("LOG_HMAC_KEY", raising=False)
    with pytest.raises(ValidationError, match="log_hmac_key"):
        Settings(_env_file=None, **values)  # type: ignore[call-arg]

    monkeypatch.setenv("LOG_HMAC_KEY", VALID_LOG_SECRET)
    settings = Settings(_env_file=None, **values)  # type: ignore[call-arg]
    assert settings.log_hmac_key.get_secret_value() == VALID_LOG_SECRET
    assert VALID_LOG_SECRET not in repr(settings)


@pytest.mark.parametrize("secret", ["short", "a" * 32, "replace-this-with-a-log-hmac-secret"])
def test_log_hmac_key_rejects_weak_or_example_values_without_leaking(secret: str) -> None:
    with pytest.raises(ValidationError, match="log_hmac_key") as caught:
        settings_for_test(log_hmac_key=SecretStr(secret))
    assert secret not in str(caught.value)


@pytest.mark.parametrize("secret", [VALID_TEST_SECRET, VALID_RATE_LIMIT_SECRET])
def test_log_hmac_key_must_not_reuse_jwt_or_rate_limit_secret(secret: str) -> None:
    with pytest.raises(ValidationError, match="must use different values"):
        settings_for_test(log_hmac_key=SecretStr(secret))


def test_log_level_is_normalized_and_rejects_unknown_levels() -> None:
    settings = settings_for_test(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        redis_url="redis://localhost:6379/0",
        jwt_secret=SecretStr(VALID_TEST_SECRET),
        log_level="warning",
    )

    assert settings.log_level == "WARNING"
    assert settings.log_include_exception_details is False

    with pytest.raises(ValidationError, match="standard Python logging level"):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="redis://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
            log_level="verbose",
        )


def test_log_file_size_defaults_to_100_mb_and_reads_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.delenv("LOG_FILE_MAX_MB", raising=False)
    default_settings = settings_for_test()
    assert default_settings.log_file_max_mb == 100

    env_file = tmp_path / "logging.env"
    env_file.write_text("LOG_FILE_MAX_MB=2\n", encoding="utf-8")
    values = default_settings.model_dump()
    values.pop("log_file_max_mb")
    configured = Settings(_env_file=env_file, **values)  # type: ignore[call-arg]
    assert configured.log_file_max_mb == 2


@pytest.mark.parametrize("invalid_value", [0, -1, 1.5, True])
def test_log_file_size_requires_a_positive_integer(invalid_value: object) -> None:
    with pytest.raises(ValidationError, match="log_file_max_mb"):
        settings_for_test(log_file_max_mb=invalid_value)


def test_issuer_and_audience_are_disabled_by_default() -> None:
    settings = settings_with_secret(VALID_TEST_SECRET)

    assert settings.jwt_issuer is None
    assert settings.jwt_audience is None


def test_issuer_and_audience_can_be_enabled_together() -> None:
    settings = settings_for_test(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        redis_url="redis://localhost:6379/0",
        jwt_secret=SecretStr(VALID_TEST_SECRET),
        jwt_issuer="  https://identity.example.test  ",
        jwt_audience="  example-api  ",
    )

    assert settings.jwt_issuer == "https://identity.example.test"
    assert settings.jwt_audience == "example-api"


@pytest.mark.parametrize(
    "value",
    ["api audience", "\u670d\u52a1-audience", "api\nservice", "api\x7fservice"],
)
def test_issuer_and_audience_reject_non_ascii_or_whitespace(value: str) -> None:
    with pytest.raises(ValidationError, match="visible ASCII"):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="redis://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
            jwt_issuer="https://identity.example.test",
            jwt_audience=value,
        )


@pytest.mark.parametrize(
    ("issuer", "audience"),
    [
        ("https://identity.example.test", None),
        (None, "example-api"),
        ("   ", "example-api"),
        ("https://identity.example.test", "   "),
    ],
)
def test_issuer_and_audience_must_be_a_complete_nonblank_pair(issuer: str | None, audience: str | None) -> None:
    with pytest.raises(ValidationError):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="redis://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
            jwt_issuer=issuer,
            jwt_audience=audience,
        )


@pytest.mark.parametrize("field", ["jwt_issuer", "jwt_audience"])
def test_optional_token_scope_has_a_bounded_length(field: str) -> None:
    issuer = "x" * 257 if field == "jwt_issuer" else "https://identity.example.test"
    audience = "x" * 257 if field == "jwt_audience" else "example-api"

    with pytest.raises(ValidationError, match="at most 256 characters"):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="redis://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
            jwt_issuer=issuer,
            jwt_audience=audience,
        )


@pytest.mark.parametrize(
    "url",
    [
        "redis://user:private-password@node/0?socket_timeout=0",
        "redis://user:private-password@node/0?retry_on_timeout=True",
        "redis://user:private-password@node/0?ssl_cert_reqs=none",
        "redis://user:private-password@node/invalid",
        "redis://user:private-password@node:99999/0",
    ],
)
def test_redis_url_cannot_override_client_safety_options_or_leak_secrets(url: str) -> None:
    with pytest.raises(ValidationError) as caught:
        settings_for_test(redis_url=url)
    assert "private-password" not in str(caught.value)


@pytest.mark.parametrize("value", [float("inf"), float("nan"), True, 0])
@pytest.mark.parametrize(
    "field", ["redis_connect_timeout_seconds", "redis_socket_timeout_seconds"]
)
def test_redis_timeouts_are_finite_positive_numbers(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        settings_for_test(**{field: value})
