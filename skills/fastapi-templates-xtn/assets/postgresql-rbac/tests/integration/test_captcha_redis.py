import asyncio
import secrets
import uuid
from typing import cast

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

from app import captcha
from app.main import app
from app.rbac.errors import RbacError
from app.rbac.security import (
    decode_access_token,
    issue_access_token,
    list_active_sessions,
    require_active_jti,
    revoke_active_jti,
)
from app.settings import get_settings

pytestmark = pytest.mark.postgresql


async def test_captcha_is_single_use_for_success_failure_and_scene_mismatch(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    service = captcha.CaptchaService(cast(Redis, app.state.redis), get_settings())

    challenge, _image = await service.issue(scene="login", owner_id=None)
    attempts = await asyncio.gather(
        service.consume(
            captcha_id=challenge, answer="AAAAA", scene="login", owner_id=None
        ),
        service.consume(
            captcha_id=challenge, answer="AAAAA", scene="login", owner_id=None
        ),
        return_exceptions=True,
    )
    assert sum(item is None for item in attempts) == 1
    assert sum(isinstance(item, RbacError) for item in attempts) == 1

    challenge, _image = await service.issue(scene="register", owner_id=None)
    with pytest.raises(RbacError):
        await service.consume(
            captcha_id=challenge, answer="WRONG", scene="register", owner_id=None
        )
    with pytest.raises(RbacError):
        await service.consume(
            captcha_id=challenge, answer="AAAAA", scene="register", owner_id=None
        )

    challenge, _image = await service.issue(scene="login", owner_id=None)
    with pytest.raises(RbacError):
        await service.consume(
            captcha_id=challenge, answer="AAAAA", scene="register", owner_id=None
        )
    with pytest.raises(RbacError):
        await service.consume(
            captcha_id=challenge, answer="AAAAA", scene="login", owner_id=None
        )


async def test_refresh_invalidates_old_and_concurrent_refresh_has_one_winner(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    service = captcha.CaptchaService(cast(Redis, app.state.redis), get_settings())
    owner = uuid.uuid4()
    old, _image = await service.issue(scene="self_change", owner_id=owner)
    results = await asyncio.gather(
        service.issue(scene="self_change", owner_id=owner, previous_captcha_id=old),
        service.issue(scene="self_change", owner_id=owner, previous_captcha_id=old),
        return_exceptions=True,
    )
    winners = [item for item in results if isinstance(item, tuple)]
    assert len(winners) == 1
    assert sum(isinstance(item, RbacError) for item in results) == 1
    with pytest.raises(RbacError):
        await service.consume(
            captcha_id=old, answer="AAAAA", scene="self_change", owner_id=owner
        )
    await service.consume(
        captcha_id=winners[0][0], answer="AAAAA", scene="self_change", owner_id=owner
    )


async def test_active_sessions_limit_and_version_change_do_not_count_old_tokens(
    client: AsyncClient,
) -> None:
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
    redis = cast(Redis, app.state.redis)
    user_id = uuid.uuid4()
    issued = [
        decode_access_token(
            await issue_access_token(
                redis, user_id=user_id, user_token_version=1, settings=settings
            ),
            settings,
        )
        for _ in range(3)
    ]
    with pytest.raises(RbacError) as old:
        await require_active_jti(redis, claims=issued[0], settings=settings)
    assert old.value.status_code == 401
    assert await require_active_jti(redis, claims=issued[1], settings=settings) == 1
    assert await require_active_jti(redis, claims=issued[2], settings=settings) == 1
    assert (
        len(
            await list_active_sessions(
                redis, user_id=user_id, token_version=1, settings=settings
            )
        )
        == 2
    )

    await revoke_active_jti(
        redis, claims=issued[1], user_token_version=1, settings=settings
    )
    assert (
        len(
            await list_active_sessions(
                redis, user_id=user_id, token_version=1, settings=settings
            )
        )
        == 1
    )

    newest = decode_access_token(
        await issue_access_token(
            redis, user_id=user_id, user_token_version=2, settings=settings
        ),
        settings,
    )
    assert await require_active_jti(redis, claims=newest, settings=settings) == 2
    with pytest.raises(RbacError):
        await require_active_jti(redis, claims=issued[2], settings=settings)
    assert (
        len(
            await list_active_sessions(
                redis, user_id=user_id, token_version=2, settings=settings
            )
        )
        == 1
    )
