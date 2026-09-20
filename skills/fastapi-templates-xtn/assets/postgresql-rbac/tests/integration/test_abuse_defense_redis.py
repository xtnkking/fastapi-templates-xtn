import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.rate_limit import RateLimitPolicy, build_rate_limit_key
from app.rate_limit_dependencies import RateLimitExceeded
from app.settings import get_settings

pytestmark = pytest.mark.postgresql


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """No PostgreSQL writes in this Redis-only test module."""


@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncIterator[None]:
    yield


async def test_login_uses_only_per_business_ip_key() -> None:
    settings = get_settings().model_copy(
        update={
            "rate_limit_namespace": f"test_{uuid.uuid4().hex}",
            "rate_limit_login_ip_per_five_minutes": 1,
        }
    )
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url, decode_responses=True
    )
    service = AbuseDefenseService(redis, settings)
    key = build_rate_limit_key(
        namespace=settings.rate_limit_namespace,
        policy=RateLimitPolicy("login", 1, 300),
        subject_type="ip",
        subject="203.0.113.9",
        key_secret=settings.rate_limit_hmac_key.get_secret_value().encode(),
    )
    try:
        await service.check_login_attempt(client_ip="203.0.113.9")
        with pytest.raises(RateLimitExceeded):
            await service.check_login_attempt(client_ip="203.0.113.9")
        assert int(await redis.get(key)) == 2
        assert 0 < await redis.ttl(key) <= 300
    finally:
        await redis.delete(key)
        await redis.aclose()


async def test_captcha_scenes_and_subjects_do_not_share_quota() -> None:
    settings = get_settings().model_copy(
        update={
            "rate_limit_namespace": f"test_{uuid.uuid4().hex}",
            "rate_limit_captcha_create_per_five_minutes": 1,
        }
    )
    redis = Redis.from_url(
        settings.effective_rate_limit_redis_url, decode_responses=True
    )
    service = AbuseDefenseService(redis, settings)
    policies = [
        ("captcha_create_login", "ip", "203.0.113.9"),
        ("captcha_create_register", "ip", "203.0.113.9"),
        ("captcha_create_admin_create", "actor", "U1234567890"),
    ]
    keys = [
        build_rate_limit_key(
            namespace=settings.rate_limit_namespace,
            policy=RateLimitPolicy(name, 1, 300),
            subject_type=subject_type,
            subject=subject,
            key_secret=settings.rate_limit_hmac_key.get_secret_value().encode(),
        )
        for name, subject_type, subject in policies
    ]
    try:
        await service.check_captcha_create(scene="login", client_ip="203.0.113.9")
        await service.check_captcha_create(scene="register", client_ip="203.0.113.9")
        await service.check_captcha_create(scene="admin_create", user_id="U1234567890")
        assert [int(await redis.get(key)) for key in keys] == [1, 1, 1]
        with pytest.raises(RateLimitExceeded):
            await service.check_captcha_create(scene="login", client_ip="203.0.113.9")
    finally:
        await redis.delete(*keys)
        await redis.aclose()
