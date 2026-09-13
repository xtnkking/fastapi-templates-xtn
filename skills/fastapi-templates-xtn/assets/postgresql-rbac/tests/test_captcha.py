import base64
import secrets
import uuid
from typing import cast
from unittest.mock import AsyncMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app import captcha
from app.rbac.errors import RbacError
from app.settings import get_settings


def mock_service() -> tuple[captcha.CaptchaService, AsyncMock]:
    client = AsyncMock()
    return captcha.CaptchaService(cast(Redis, client), get_settings()), client


async def test_issue_returns_png_and_never_stores_plaintext_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, redis = mock_service()
    redis.eval.return_value = 1
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")

    challenge_id, image = await service.issue(scene="login", owner_id=None)

    assert challenge_id.version == 4
    assert base64.b64decode(image.removeprefix("data:image/png;base64,")).startswith(
        b"\x89PNG\r\n\x1a\n"
    )
    args = redis.eval.await_args.args
    assert args[1] == 3
    assert '"scene":"login"' in args[9]
    assert "AAAAA" not in args[9]


async def test_render_failure_does_not_replace_existing_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, redis = mock_service()
    previous = uuid.uuid4()

    def fail_render(_answer: str) -> str:
        raise RuntimeError("image renderer failed")

    monkeypatch.setattr(captcha, "_captcha_image", fail_render)
    with pytest.raises(RuntimeError, match="image renderer failed"):
        await service.issue(
            scene="self_change", owner_id=uuid.uuid4(), previous_captcha_id=previous
        )
    redis.eval.assert_not_awaited()


async def test_challenge_is_required_and_wrong_answer_is_rejected() -> None:
    service, redis = mock_service()
    redis.eval.return_value = 0
    with pytest.raises(RbacError) as caught:
        await service.consume(
            captcha_id=uuid.uuid4(), answer="wrong", scene="register", owner_id=None
        )
    assert caught.value.status_code == 400


async def test_invalid_unicode_answer_still_reaches_one_use_consume_script() -> None:
    service, redis = mock_service()
    redis.eval.return_value = 0
    with pytest.raises(RbacError) as caught:
        await service.consume(
            captcha_id=uuid.uuid4(),
            answer="\ud800",
            scene="login",
            owner_id=None,
        )
    assert caught.value.status_code == 400
    redis.eval.assert_awaited_once()


async def test_private_scene_requires_authenticated_owner() -> None:
    service, redis = mock_service()
    with pytest.raises(RbacError):
        await service.issue(scene="admin_reset", owner_id=None)
    redis.eval.assert_not_awaited()


async def test_redis_error_fails_closed_before_verifying_business_operation() -> None:
    service, redis = mock_service()
    redis.eval.side_effect = RedisConnectionError("not-available")
    with pytest.raises(RbacError) as caught:
        await service.consume(
            captcha_id=uuid.uuid4(), answer="AB234", scene="login", owner_id=None
        )
    assert caught.value.status_code == 503


async def test_private_owner_and_scene_are_passed_to_atomic_consumer() -> None:
    service, redis = mock_service()
    redis.eval.return_value = 1
    owner_id = uuid.uuid4()
    await service.consume(
        captcha_id=uuid.uuid4(),
        answer="aB234",
        scene="self_change",
        owner_id=owner_id,
    )
    args = redis.eval.await_args.args
    assert args[1] == 1
    assert args[-3:-1] == ("self_change", str(owner_id))
