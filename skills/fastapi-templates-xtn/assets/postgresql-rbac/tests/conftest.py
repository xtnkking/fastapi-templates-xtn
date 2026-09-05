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
os.environ["JWT_SECRET"] = "test-secret-with-at-least-thirty-two-characters"
os.environ["JWT_ISSUER"] = "https://identity.example.test"
os.environ["JWT_AUDIENCE"] = "fastapi-rbac-example"
