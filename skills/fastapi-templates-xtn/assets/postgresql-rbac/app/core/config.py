import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
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


def _is_repeated_pattern(value: str) -> bool:
    if not value:
        return False
    return (value + value).find(value, 1) != len(value)


class RedisNode(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535, strict=True)

    @field_validator("host")
    @classmethod
    def require_host_without_credentials(cls, value: str) -> str:
        if any(c.isspace() or c in "/@?#[]" or ord(c) < 32 for c in value):
            raise ValueError("node host must contain only a hostname or unbracketed IP")
        return value


class RedisEndpoint(BaseModel):
    """A complete connection choice; rate limiting inherits this whole object."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    mode: Literal["standalone", "sentinel", "cluster"] = "standalone"
    url: str | None = Field(default=None, repr=False)
    nodes: list[RedisNode] = Field(default_factory=list, max_length=32)
    username: str | None = Field(default=None, min_length=1, repr=False)
    password: SecretStr | None = None
    db: int = Field(default=0, ge=0)
    tls: bool = False
    ca_file: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None
    sentinel_master: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]+$")
    sentinel_username: str | None = Field(default=None, min_length=1, repr=False)
    sentinel_password: SecretStr | None = None
    sentinel_tls: bool = False
    sentinel_ca_file: Path | None = None
    sentinel_cert_file: Path | None = None
    sentinel_key_file: Path | None = None

    @field_validator("url")
    @classmethod
    def require_bounded_redis_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
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
            raise ValueError(
                "Redis URL must use redis or rediss with a host and optional /db; "
                "query parameters and fragments are not allowed"
            )
        return value

    @field_validator("db", mode="before")
    @classmethod
    def reject_boolean_database(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("Redis db must be a nonnegative integer")
        return value

    @model_validator(mode="after")
    def require_complete_endpoint(self) -> Self:
        if self.mode == "standalone":
            if not self.url or self.nodes:
                raise ValueError("standalone requires url and does not accept nodes")
            if self.username is not None or self.password is not None or self.db:
                raise ValueError("standalone credentials and db belong in url")
            if self.tls and not self.url.startswith("rediss://"):
                raise ValueError("standalone TLS requires a rediss URL")
        else:
            if self.url is not None or not self.nodes:
                raise ValueError("sentinel and cluster require nodes instead of url")
            addresses = {(node.host, node.port) for node in self.nodes}
            if len(addresses) != len(self.nodes):
                raise ValueError("Redis discovery nodes must not contain duplicates")
        if self.mode == "sentinel":
            if self.sentinel_master is None:
                raise ValueError("sentinel requires sentinel_master")
        elif any(
            value is not None and value is not False
            for value in (
                self.sentinel_master,
                self.sentinel_username,
                self.sentinel_password,
                self.sentinel_tls,
                self.sentinel_ca_file,
                self.sentinel_cert_file,
                self.sentinel_key_file,
            )
        ):
            raise ValueError("sentinel settings require sentinel mode")
        if self.mode == "cluster" and self.db != 0:
            raise ValueError("Redis Cluster supports only db 0")
        data_tls = self.tls or bool(self.url and self.url.startswith("rediss://"))
        for enabled, ca_file, cert_file, key_file in (
            (data_tls, self.ca_file, self.cert_file, self.key_file),
            (
                self.sentinel_tls,
                self.sentinel_ca_file,
                self.sentinel_cert_file,
                self.sentinel_key_file,
            ),
        ):
            if (cert_file is None) != (key_file is None):
                raise ValueError(
                    "TLS cert_file and key_file must be configured together"
                )
            for path in (ca_file, cert_file, key_file):
                if path is not None:
                    if not enabled:
                        raise ValueError("TLS file settings require TLS to be enabled")
                    if not path.is_file():
                        raise ValueError(
                            "Redis TLS certificate/key file does not exist"
                        )
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_nested_delimiter="__",
        hide_input_in_errors=True,
    )

    database_url: str
    database_pool_size: int = Field(default=5, ge=1)
    database_max_overflow: int = Field(default=5, ge=0)
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0, allow_inf_nan=False)
    database_connect_timeout_seconds: float = Field(
        default=5.0, gt=0, allow_inf_nan=False
    )
    database_command_timeout_seconds: float = Field(
        default=20.0, gt=0, allow_inf_nan=False
    )
    database_statement_timeout_ms: int = Field(default=15_000, ge=1, le=2_147_483_647)
    database_lock_timeout_ms: int = Field(default=3_000, ge=1, le=2_147_483_647)
    redis_url: str | None = Field(default=None, repr=False)
    redis_connection: RedisEndpoint | None = None
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
    log_queue_capacity: int = Field(default=1_000, ge=1, le=10_000)
    log_shutdown_timeout_seconds: float = Field(
        default=2.0, ge=0, le=30, allow_inf_nan=False
    )
    jwt_secret: SecretStr
    rate_limit_hmac_key: SecretStr
    max_active_sessions_per_user: int = Field(ge=1)
    admin_password_reset_mode: Literal["direct", "temporary"] = "direct"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_access_token_ttl_seconds: int = Field(default=86_400, ge=1)
    rate_limit_enabled: bool = True
    rate_limit_redis_url: str | None = Field(default=None, repr=False)
    rate_limit_redis_connection: RedisEndpoint | None = None
    rate_limit_namespace: str = Field(
        default="fastapi_rbac",
        pattern=r"^[a-z0-9][a-z0-9_-]{0,47}$",
    )
    rate_limit_captcha_create_per_five_minutes: int = Field(default=10, ge=1)
    rate_limit_authenticated_read_per_minute: int = Field(default=600, ge=1)
    rate_limit_management_read_per_minute: int = Field(default=300, ge=1)
    rate_limit_ordinary_write_per_minute: int = Field(default=120, ge=1)
    rate_limit_authorization_write_per_minute: int = Field(default=60, ge=1)
    rate_limit_login_ip_per_five_minutes: int = Field(default=20, ge=1)
    rate_limit_registration_ip_per_hour: int = Field(default=5, ge=1)
    rate_limit_temporary_complete_ip_per_five_minutes: int = Field(default=20, ge=1)
    redis_connect_timeout_seconds: float = Field(default=0.5, gt=0, allow_inf_nan=False)
    redis_socket_timeout_seconds: float = Field(default=0.5, gt=0, allow_inf_nan=False)
    redis_max_connections: int = Field(default=50, ge=1)
    readiness_timeout_seconds: float = Field(default=1.0, gt=0, le=10)
    sql_echo: bool = False

    @field_validator(
        "database_pool_size",
        "database_max_overflow",
        "database_pool_timeout_seconds",
        "database_connect_timeout_seconds",
        "database_command_timeout_seconds",
        "database_statement_timeout_ms",
        "database_lock_timeout_ms",
        "redis_max_connections",
        "redis_connect_timeout_seconds",
        "redis_socket_timeout_seconds",
        mode="before",
    )
    @classmethod
    def reject_boolean_connection_limits(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("connection capacity and timeout settings must be numbers")
        return value

    @model_validator(mode="after")
    def require_ordered_database_timeouts(self) -> Self:
        if self.database_lock_timeout_ms > self.database_statement_timeout_ms:
            raise ValueError(
                "database_lock_timeout_ms must not exceed database_statement_timeout_ms"
            )
        return self

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
        return RedisEndpoint.require_bounded_redis_url(value)

    @model_validator(mode="after")
    def require_complete_redis_connections(self) -> Self:
        if (self.redis_url is None) == (self.redis_connection is None):
            raise ValueError("configure exactly one of redis_url or redis_connection")
        if (
            self.rate_limit_redis_url is not None
            and self.rate_limit_redis_connection is not None
        ):
            raise ValueError(
                "configure rate_limit_redis_url or rate_limit_redis_connection, "
                "not both"
            )
        return self

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
        if (
            self.jwt_secret.get_secret_value()
            == self.rate_limit_hmac_key.get_secret_value()
        ):
            raise ValueError("JWT and rate-limit secrets must use different values")
        return self

    @property
    def effective_redis_connection(self) -> RedisEndpoint:
        if self.redis_connection is not None:
            return self.redis_connection
        return RedisEndpoint(url=self.redis_url)

    @property
    def effective_rate_limit_redis_connection(self) -> RedisEndpoint:
        if self.rate_limit_redis_connection is not None:
            return self.rate_limit_redis_connection
        if self.rate_limit_redis_url is not None:
            return RedisEndpoint(url=self.rate_limit_redis_url)
        return self.effective_redis_connection

    @property
    def effective_rate_limit_redis_url(self) -> str:
        """Legacy single-node configuration accessor; factories use the endpoint."""
        url = self.effective_rate_limit_redis_connection.url
        if url is None:
            raise ValueError(
                "the rate-limit Redis connection does not use a single URL"
            )
        return url


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
