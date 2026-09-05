from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.settings import Settings

EXAMPLE_ENV = Path(__file__).parents[1] / ".env.example"
REQUIRED_ENV_NAMES = (
    "DATABASE_URL",
    "JWT_SECRET",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "SQL_ECHO",
)


def settings_with_secret(secret: str) -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/example",
        jwt_secret=SecretStr(secret),
        jwt_issuer="https://identity.example.test",
        jwt_audience="fastapi-rbac-example",
    )


def test_example_env_cannot_start_with_public_jwt_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in REQUIRED_ENV_NAMES:
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

    settings = settings_with_secret(("\u5bc6" * 10) + "ab")

    assert len(settings.jwt_secret.get_secret_value().encode("utf-8")) == 32
