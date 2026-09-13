import os

from sqlalchemy.engine import make_url

test_database_url = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/rbac_example_test",
)
parsed_test_url = make_url(test_database_url)
if (
    parsed_test_url.drivername != "postgresql+asyncpg"
    or parsed_test_url.database is None
    or not parsed_test_url.database.endswith("_test")
):
    raise RuntimeError(
        "TEST_DATABASE_URL must use postgresql+asyncpg and a database name "
        "ending in '_test'"
    )

# Tests never inherit the application's DATABASE_URL.
os.environ["DATABASE_URL"] = test_database_url
os.environ["REDIS_URL"] = os.environ.get(
    "TEST_REDIS_URL",
    "redis://127.0.0.1:6379/15",
)
os.environ["RATE_LIMIT_REDIS_URL"] = os.environ.get(
    "TEST_RATE_LIMIT_REDIS_URL",
    "redis://127.0.0.1:6380/0",
)
os.environ["APP_ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz"
os.environ["RATE_LIMIT_HMAC_KEY"] = "vM8qD2kR7pX4cN9sH5wF1jL6tG3yB0uZ"
os.environ["MAX_ACTIVE_SESSIONS_PER_USER"] = "2"
os.environ["PUBLIC_REGISTRATION_ENABLED"] = "true"
os.environ["VERIFICATION_ENABLED"] = "false"
os.environ.pop("VERIFICATION_CODE_HMAC_KEY", None)
os.environ.pop("VERIFICATION_ENABLED_PURPOSES", None)
os.environ.pop("VERIFICATION_ENABLED_CHANNELS", None)
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ.pop("JWT_ISSUER", None)
os.environ.pop("JWT_AUDIENCE", None)
os.environ["JWT_ACCESS_TOKEN_TTL_SECONDS"] = "3600"
