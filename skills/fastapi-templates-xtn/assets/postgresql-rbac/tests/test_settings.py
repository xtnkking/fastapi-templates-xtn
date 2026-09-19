from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.security_policies import SecurityPolicies
from app.settings import Settings

EXAMPLE_ENV = Path(__file__).parents[1] / ".env.example"
VALID_TEST_SECRET = "D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz"
VALID_RATE_LIMIT_SECRET = "R8qM4vK2zT7pN5xC9sW1dF6hJ3yB0uGa"
SETTINGS_ENV_NAMES = (
    "DATABASE_URL",
    "REDIS_URL",
    "RATE_LIMIT_REDIS_URL",
    "APP_ENVIRONMENT",
    "SERVICE_NAME",
    "SERVICE_VERSION",
    "LOG_LEVEL",
    "LOG_INCLUDE_EXCEPTION_DETAILS",
    "JWT_SECRET",
    "RATE_LIMIT_HMAC_KEY",
    "MAX_ACTIVE_SESSIONS_PER_USER",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "JWT_ACCESS_TOKEN_TTL_SECONDS",
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_NAMESPACE",
    "REDIS_CONNECT_TIMEOUT_SECONDS",
    "REDIS_SOCKET_TIMEOUT_SECONDS",
    "READINESS_TIMEOUT_SECONDS",
    "SQL_ECHO",
)


def settings_for_test(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql+asyncpg://postgres:postgres@localhost/example",
        "redis_url": "redis://localhost:6379/0",
        "rate_limit_redis_url": "redis://127.0.0.1:6380/0",
        "app_environment": "test",
        "rate_limit_enabled": False,
        "jwt_secret": SecretStr(VALID_TEST_SECRET),
        "rate_limit_hmac_key": SecretStr(VALID_RATE_LIMIT_SECRET),
        "max_active_sessions_per_user": 2,
    }
    values.update(overrides)
    return Settings.model_validate(values)


def settings_with_secret(secret: str) -> Settings:
    return settings_for_test(jwt_secret=SecretStr(secret))


@pytest.mark.parametrize("rate_limit_enabled", [True, False])
def test_app_environment_is_required_for_every_rate_limit_mode(
    monkeypatch: pytest.MonkeyPatch,
    rate_limit_enabled: bool,
) -> None:
    monkeypatch.delenv("APP_ENVIRONMENT", raising=False)

    with pytest.raises(ValidationError) as caught:
        Settings.model_validate(
            {
                "database_url": (
                    "postgresql+asyncpg://postgres:postgres@localhost/example"
                ),
                "redis_url": "redis://localhost:6379/0",
                "rate_limit_enabled": rate_limit_enabled,
                "jwt_secret": SecretStr(VALID_TEST_SECRET),
                "rate_limit_hmac_key": SecretStr(VALID_RATE_LIMIT_SECRET),
            }
        )

    assert Settings.model_fields["app_environment"].is_required()
    assert any(
        error["loc"] == ("app_environment",) and error["type"] == "missing"
        for error in caught.value.errors()
    )


@pytest.mark.parametrize("environment", ["prod", "production", "staging", "qa"])
def test_deployable_environments_cannot_disable_rate_limiting(
    environment: str,
) -> None:
    with pytest.raises(
        ValidationError,
        match="only in an explicit local or test environment",
    ):
        settings_for_test(app_environment=environment, rate_limit_enabled=False)


@pytest.mark.parametrize(
    "environment",
    ["dev", "development", "local", "test", "testing"],
)
def test_local_and_test_environments_may_explicitly_disable_rate_limiting(
    environment: str,
) -> None:
    settings = settings_for_test(
        app_environment=environment,
        rate_limit_enabled=False,
    )

    assert settings.rate_limit_enabled is False


def test_example_env_cannot_start_with_public_jwt_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
def test_jwt_secret_rejects_repeated_patterns_wider_than_eight_characters(
    pattern: str,
    repetitions: int,
) -> None:
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
def test_jwt_secret_rejects_unicode_control_characters(
    control_character: str,
) -> None:
    secret = VALID_TEST_SECRET + control_character

    with pytest.raises(ValidationError, match="jwt_secret") as caught:
        settings_with_secret(secret)

    assert secret not in str(caught.value)


def test_access_token_lifetime_defaults_to_one_hour_and_is_configurable() -> None:
    default_settings = settings_with_secret(VALID_TEST_SECRET)
    custom_settings = settings_for_test(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        redis_url="redis://localhost:6379/0",
        jwt_secret=SecretStr(VALID_TEST_SECRET),
        jwt_access_token_ttl_seconds=900,
    )

    assert default_settings.jwt_access_token_ttl_seconds == 3600
    assert custom_settings.jwt_access_token_ttl_seconds == 900


def test_redis_url_requires_redis_protocol() -> None:
    with pytest.raises(ValidationError, match="redis_url must use redis or rediss"):
        settings_for_test(
            database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
            redis_url="http://localhost:6379/0",
            jwt_secret=SecretStr(VALID_TEST_SECRET),
        )


def test_rate_limit_defaults_are_explicit_and_configurable() -> None:
    settings = settings_with_secret(VALID_TEST_SECRET)

    assert settings.rate_limit_enabled is False  # Isolated unit tests opt out.
    assert settings.rate_limit_captcha_create_per_five_minutes == 10
    assert settings.rate_limit_authenticated_read_per_minute == 600
    assert settings.rate_limit_ordinary_write_per_minute == 120
    assert settings.rate_limit_management_read_per_minute == 300
    assert settings.rate_limit_authorization_write_per_minute == 60
    assert settings.rate_limit_login_ip_per_five_minutes == 20
    assert settings.rate_limit_registration_ip_per_hour == 5
    assert settings.rate_limit_temporary_complete_ip_per_five_minutes == 20
    assert settings.max_active_sessions_per_user == 2
    assert settings.readiness_timeout_seconds == 1.0


def test_readiness_timeout_is_short_bounded_and_configurable() -> None:
    settings = settings_for_test(readiness_timeout_seconds=2.5)

    assert settings.readiness_timeout_seconds == 2.5
    with pytest.raises(ValidationError, match="readiness_timeout_seconds"):
        settings_for_test(readiness_timeout_seconds=0)
    with pytest.raises(ValidationError, match="readiness_timeout_seconds"):
        settings_for_test(readiness_timeout_seconds=10.1)


def test_session_limit_must_be_positive_and_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MAX_ACTIVE_SESSIONS_PER_USER", raising=False)
    with pytest.raises(ValidationError, match="max_active_sessions_per_user"):
        Settings.model_validate(
            {
                "database_url": "postgresql+asyncpg://postgres:postgres@localhost/example",
                "redis_url": "redis://localhost:6379/0",
                "app_environment": "test",
                "jwt_secret": SecretStr(VALID_TEST_SECRET),
                "rate_limit_hmac_key": SecretStr(VALID_RATE_LIMIT_SECRET),
            }
        )
    with pytest.raises(ValidationError, match="max_active_sessions_per_user"):
        settings_for_test(max_active_sessions_per_user=0)


def test_rate_limit_policy_bounds_can_be_validated_at_startup() -> None:
    settings = settings_with_secret(VALID_TEST_SECRET).model_copy(
        update={"rate_limit_login_ip_per_five_minutes": 1_000_001}
    )

    with pytest.raises(ValueError, match="limit"):
        SecurityPolicies.from_settings(settings)


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
def test_issuer_and_audience_must_be_a_complete_nonblank_pair(
    issuer: str | None,
    audience: str | None,
) -> None:
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
