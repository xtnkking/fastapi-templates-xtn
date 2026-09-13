import unicodedata
from functools import lru_cache
from typing import Self

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PUBLIC_JWT_SECRET_PLACEHOLDERS = frozenset(
    {
        "change-me-change-me-change-me-change-me",
        "replace-this-with-at-least-32-random-bytes",
        "super-secret-super-secret-super-secret",
        "your-secret-key-your-secret-key-your-secret-key",
    }
)
_PUBLIC_SECURITY_SECRET_PLACEHOLDERS = _PUBLIC_JWT_SECRET_PLACEHOLDERS | {
    "replace-this-with-a-rate-limit-hmac-secret",
    "replace-this-with-a-verification-hmac-secret",
}
_MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS = 8
_MAXIMUM_SECURITY_SECRET_UTF8_BYTES = 4_096
MAX_OPTIONAL_JWT_SCOPE_CHARACTERS = 256
_RATE_LIMIT_DISABLE_ENVIRONMENTS = frozenset(
    {"dev", "development", "local", "test", "testing"}
)
_VERIFICATION_PURPOSE_NAMES = frozenset(
    {
        "registration",
        "login",
        "password_reset",
        "email_change",
        "phone_change",
        "sensitive_action",
    }
)
_VERIFICATION_CHANNEL_NAMES = frozenset({"email", "sms"})


def _is_repeated_pattern(value: str) -> bool:
    if not value:
        return False
    return (value + value).find(value, 1) != len(value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str
    redis_url: str
    app_environment: str = Field(
        pattern=r"^[a-z0-9][a-z0-9_-]{0,31}$",
    )
    service_name: str = Field(
        default="fastapi-postgresql-rbac-example",
        pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$",
    )
    service_version: str = Field(default="unreleased", min_length=1, max_length=64)
    log_level: str = "INFO"
    log_include_exception_details: bool = False
    jwt_secret: SecretStr
    rate_limit_hmac_key: SecretStr
    public_registration_enabled: bool = False
    verification_enabled: bool = False
    verification_code_hmac_key: SecretStr | None = None
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_access_token_ttl_seconds: int = Field(default=3600, ge=1)
    rate_limit_enabled: bool = True
    rate_limit_redis_url: str | None = None
    rate_limit_namespace: str = Field(
        default="fastapi_rbac",
        pattern=r"^[a-z0-9][a-z0-9_-]{0,47}$",
    )
    rate_limit_global_per_minute: int = Field(default=6000, ge=1)
    rate_limit_global_burst: int = Field(default=1000, ge=1)
    rate_limit_api_ip_per_minute: int = Field(default=1200, ge=1)
    rate_limit_api_ip_burst: int = Field(default=200, ge=1)
    rate_limit_anonymous_read_per_minute: int = Field(default=120, ge=1)
    rate_limit_authenticated_read_per_minute: int = Field(default=300, ge=1)
    rate_limit_management_read_per_minute: int = Field(default=120, ge=1)
    rate_limit_ordinary_write_per_minute: int = Field(default=60, ge=1)
    rate_limit_authorization_write_per_minute: int = Field(default=30, ge=1)
    rate_limit_super_admin_transfer_per_hour: int = Field(default=3, ge=1)
    rate_limit_logout_all_per_ten_minutes: int = Field(default=5, ge=1)
    rate_limit_login_ip_per_five_minutes: int = Field(default=20, ge=1)
    rate_limit_login_pair_per_fifteen_minutes: int = Field(default=5, ge=1)
    rate_limit_login_global_per_five_minutes: int = Field(default=1000, ge=1)
    rate_limit_login_global_burst: int = Field(default=200, ge=1)
    rate_limit_registration_ip_per_hour: int = Field(default=5, ge=1)
    rate_limit_registration_target_per_hour: int = Field(default=3, ge=1)
    rate_limit_registration_pair_per_hour: int = Field(default=3, ge=1)
    rate_limit_registration_global_per_hour: int = Field(default=500, ge=1)
    rate_limit_registration_global_burst: int = Field(default=100, ge=1)
    rate_limit_verification_target_average_per_day: int = Field(default=5, ge=1)
    rate_limit_verification_ip_per_hour: int = Field(default=20, ge=1)
    rate_limit_verification_pair_per_hour: int = Field(default=5, ge=1)
    rate_limit_verification_global_per_minute: int = Field(default=300, ge=1)
    rate_limit_verification_global_burst: int = Field(default=50, ge=1)
    rate_limit_verification_channel_per_minute: int = Field(default=200, ge=1)
    rate_limit_verification_channel_burst: int = Field(default=40, ge=1)
    rate_limit_verification_submit_ip_per_hour: int = Field(default=120, ge=1)
    rate_limit_verification_submit_target_per_hour: int = Field(default=20, ge=1)
    rate_limit_verification_submit_pair_per_hour: int = Field(default=10, ge=1)
    rate_limit_verification_submit_global_per_minute: int = Field(default=3000, ge=1)
    rate_limit_verification_submit_global_burst: int = Field(default=500, ge=1)
    verification_send_cooldown_seconds: int = Field(default=60, ge=1)
    verification_code_ttl_seconds: int = Field(default=300, ge=30, le=1800)
    verification_code_length: int = Field(default=6, ge=4, le=10)
    verification_max_attempts: int = Field(default=5, ge=1, le=10)
    verification_enabled_purposes: str = ""
    verification_enabled_channels: str = ""
    login_failure_state_retention_seconds: int = Field(default=86400, ge=900)
    redis_connect_timeout_seconds: float = Field(default=0.5, gt=0)
    redis_socket_timeout_seconds: float = Field(default=0.5, gt=0)
    sql_echo: bool = False

    @field_validator("database_url")
    @classmethod
    def require_postgresql_asyncpg(cls, value: str) -> str:
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg")
        return value

    @field_validator("redis_url", "rate_limit_redis_url")
    @classmethod
    def require_redis_url(
        cls,
        value: str | None,
        info: ValidationInfo,
    ) -> str | None:
        if value is None:
            return None
        if not value.startswith(("redis://", "rediss://")):
            raise ValueError(f"{info.field_name} must use redis or rediss")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard Python logging level")
        return normalized

    @field_validator("jwt_secret", "rate_limit_hmac_key")
    @classmethod
    def require_strong_security_secret(
        cls,
        value: SecretStr,
        info: ValidationInfo,
    ) -> SecretStr:
        return cls._validate_security_secret(
            value,
            field_name=info.field_name or "security_secret",
        )

    @field_validator("verification_code_hmac_key")
    @classmethod
    def require_strong_optional_verification_secret(
        cls,
        value: SecretStr | None,
        info: ValidationInfo,
    ) -> SecretStr | None:
        if value is None:
            return None
        return cls._validate_security_secret(
            value,
            field_name=info.field_name or "verification_code_hmac_key",
        )

    @staticmethod
    def _validate_security_secret(value: SecretStr, *, field_name: str) -> SecretStr:
        secret = value.get_secret_value()
        try:
            encoded_secret = secret.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(f"{field_name} must contain valid UTF-8 text") from None
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

    @field_validator("verification_enabled_purposes")
    @classmethod
    def normalize_verification_purposes(cls, value: str) -> str:
        return cls._normalize_csv_allowlist(
            value,
            allowed=_VERIFICATION_PURPOSE_NAMES,
            field_name="verification_enabled_purposes",
            allow_empty=True,
        )

    @field_validator("verification_enabled_channels")
    @classmethod
    def normalize_verification_channels(cls, value: str) -> str:
        return cls._normalize_csv_allowlist(
            value,
            allowed=_VERIFICATION_CHANNEL_NAMES,
            field_name="verification_enabled_channels",
            allow_empty=True,
        )

    @model_validator(mode="after")
    def require_complete_optional_token_scope(self) -> Self:
        if (
            not self.rate_limit_enabled
            and self.app_environment not in _RATE_LIMIT_DISABLE_ENVIRONMENTS
        ):
            raise ValueError(
                "rate limiting can be disabled only in an explicit local or test "
                "environment"
            )
        if (self.jwt_issuer is None) != (self.jwt_audience is None):
            raise ValueError(
                "jwt_issuer and jwt_audience must be configured together or omitted"
            )
        enabled_purposes = frozenset(
            item for item in self.verification_enabled_purposes.split(",") if item
        )
        enabled_channels = frozenset(
            item for item in self.verification_enabled_channels.split(",") if item
        )
        verification_configured = bool(
            self.verification_code_hmac_key or enabled_purposes or enabled_channels
        )
        if self.verification_enabled:
            if self.verification_code_hmac_key is None:
                raise ValueError(
                    "verification_code_hmac_key is required when verification is "
                    "enabled"
                )
            if not enabled_purposes:
                raise ValueError(
                    "verification_enabled_purposes is required when verification is "
                    "enabled"
                )
            if not enabled_channels:
                raise ValueError(
                    "verification_enabled_channels is required when verification is "
                    "enabled"
                )
            if (
                "email_change" in enabled_purposes and "email" not in enabled_channels
            ) or ("phone_change" in enabled_purposes and "sms" not in enabled_channels):
                raise ValueError(
                    "enabled verification purposes require their matching channel"
                )
        elif verification_configured:
            raise ValueError(
                "verification-specific settings must be omitted when verification is "
                "disabled"
            )

        security_secrets = [
            self.jwt_secret.get_secret_value(),
            self.rate_limit_hmac_key.get_secret_value(),
        ]
        if self.verification_code_hmac_key is not None:
            security_secrets.append(self.verification_code_hmac_key.get_secret_value())
        if len(set(security_secrets)) != len(security_secrets):
            raise ValueError(
                "JWT, rate-limit, and enabled verification secrets must use "
                "different values"
            )
        return self

    @property
    def effective_rate_limit_redis_url(self) -> str:
        """Allow an explicit small-project fallback while preferring isolation."""
        return self.rate_limit_redis_url or self.redis_url

    @staticmethod
    def _normalize_csv_allowlist(
        value: str,
        *,
        allowed: frozenset[str],
        field_name: str,
        allow_empty: bool = False,
    ) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a comma-separated string")
        if allow_empty and not value.strip():
            return ""
        items = tuple(item.strip() for item in value.split(","))
        if (
            not items
            or any(not item for item in items)
            or len(set(items)) != len(items)
            or any(item not in allowed for item in items)
        ):
            expected = ", ".join(sorted(allowed))
            raise ValueError(
                f"{field_name} must contain unique values selected from: {expected}"
            )
        return ",".join(items)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
