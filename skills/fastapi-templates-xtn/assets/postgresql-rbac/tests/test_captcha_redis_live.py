"""Redis-only checks; run only against a confirmed disposable empty instance."""

import asyncio
import os
import secrets
import uuid

import pytest
from redis.asyncio import Redis

from app.abuse_defense import AbuseDefenseService
from app.captcha import CaptchaService
from app.rate_limit_dependencies import RateLimitExceeded
from app.rbac.errors import RbacError
from app.rbac.security import (
    decode_access_token,
    issue_access_token,
    list_active_sessions,
    require_active_jti,
)
from app.settings import get_settings
from tests.integration.safety import confirmed_redis_only_target


async def test_atomic_captcha_and_session_limit_against_isolated_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get("TEST_REDIS_ISOLATION_CONFIRMED") != "yes":
        pytest.skip("requires an explicitly confirmed disposable Redis instance")
    if not os.environ.get("TEST_CAPTCHA_REDIS_URL"):
        pytest.skip("requires a separate disposable TEST_CAPTCHA_REDIS_URL")
    url = confirmed_redis_only_target()
    redis = Redis.from_url(url, decode_responses=True)
    try:
        assert await redis.dbsize() == 0, "refusing a nonempty Redis target"
        monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
        settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
        service = CaptchaService(redis, settings)
        owner = uuid.uuid4()
        initial, _image = await service.issue(scene="admin_reset", owner_id=owner)

        def fail_render(_answer: str) -> str:
            raise RuntimeError("image renderer failed")

        with monkeypatch.context() as patch:
            patch.setattr("app.captcha._captcha_image", fail_render)
            with pytest.raises(RuntimeError, match="image renderer failed"):
                await service.issue(
                    scene="admin_reset", owner_id=owner, previous_captcha_id=initial
                )

        await service.consume(
            captcha_id=initial, answer="AAAAA", scene="admin_reset", owner_id=owner
        )
        initial, _image = await service.issue(scene="admin_reset", owner_id=owner)
        refreshed, _image = await service.issue(
            scene="admin_reset", owner_id=owner, previous_captcha_id=initial
        )
        with pytest.raises(RbacError):
            await service.consume(
                captcha_id=initial, answer="AAAAA", scene="admin_reset", owner_id=owner
            )
        decisions = await asyncio.gather(
            *(
                service.consume(
                    captcha_id=refreshed,
                    answer="AAAAA",
                    scene="admin_reset",
                    owner_id=owner,
                )
                for _ in range(2)
            ),
            return_exceptions=True,
        )
        assert sum(result is None for result in decisions) == 1
        assert sum(isinstance(result, RbacError) for result in decisions) == 1

        user_id = uuid.uuid4()
        claims = [
            decode_access_token(
                await issue_access_token(
                    redis,
                    user_id=user_id,
                    user_token_version=0,
                    settings=settings,
                ),
                settings,
            )
            for _ in range(3)
        ]
        with pytest.raises(RbacError):
            await require_active_jti(redis, claims=claims[0], settings=settings)
        assert await require_active_jti(redis, claims=claims[1], settings=settings) == 0
        assert await require_active_jti(redis, claims=claims[2], settings=settings) == 0
        assert (
            len(
                await list_active_sessions(
                    redis, user_id=user_id, token_version=0, settings=settings
                )
            )
            == 2
        )

        newer_token = decode_access_token(
            await issue_access_token(
                redis, user_id=user_id, user_token_version=1, settings=settings
            ),
            settings,
        )
        with pytest.raises(RbacError) as stale:
            await issue_access_token(
                redis, user_id=user_id, user_token_version=0, settings=settings
            )
        assert stale.value.status_code == 401
        assert (
            await require_active_jti(redis, claims=newer_token, settings=settings) == 1
        )
        assert (
            len(
                await list_active_sessions(
                    redis, user_id=user_id, token_version=1, settings=settings
                )
            )
            == 1
        )

        defense = AbuseDefenseService(redis, settings)
        for _ in range(10):
            await defense.check_rejected_captcha_scene(client_ip="203.0.113.8")
        with pytest.raises(RateLimitExceeded):
            await defense.check_rejected_captcha_scene(client_ip="203.0.113.8")
        await defense.check_rejected_captcha_scene(user_id=str(owner))
        await defense.check_captcha_create(scene="login", client_ip="203.0.113.8")
    finally:
        await redis.aclose()
