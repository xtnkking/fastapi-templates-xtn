from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PUBLIC_JWT_SECRET_PLACEHOLDERS = frozenset(
    {
        "replace-this-with-at-least-32-random-bytes",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str
    jwt_secret: SecretStr
    jwt_issuer: str
    jwt_audience: str
    sql_echo: bool = False

    @field_validator("database_url")
    @classmethod
    def require_postgresql_asyncpg(cls, value: str) -> str:
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg")
        return value

    @field_validator("jwt_secret")
    @classmethod
    def require_strong_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if secret.strip().casefold() in _PUBLIC_JWT_SECRET_PLACEHOLDERS:
            raise ValueError(
                "jwt_secret must not use the public example placeholder; "
                "generate a unique random secret before startup"
            )
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("jwt_secret must contain at least 32 UTF-8 bytes")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
