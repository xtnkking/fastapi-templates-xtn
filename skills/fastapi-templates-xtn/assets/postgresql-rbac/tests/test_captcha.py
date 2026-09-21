import base64
import json
import secrets
import uuid
from typing import cast
from unittest.mock import AsyncMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import get_settings
from app.core.errors import RbacError
from app.core.security import captcha


def mock_service() -> tuple[captcha.CaptchaService, AsyncMock]:
    client = AsyncMock()
    client.get.return_value = json.dumps(
        {"scene": "login", "owner": "", "digest": "a" * 64, "index": ""}
    )
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
    assert args[1] == 4
    assert '"scene":"login"' in args[10]
    assert "AAAAA" not in args[10]


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
    assert args[1] == 2
    assert args[-4:-2] == ("self_change", str(owner_id))


async def test_private_issue_retries_changed_pointer_without_regenerating_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, redis = mock_service()
    owner = uuid.uuid4()
    old, competing = uuid.uuid4(), uuid.uuid4()
    redis.get.side_effect = [str(old), str(competing)]
    redis.eval.side_effect = [2, 1]
    render_calls: list[str] = []

    def render(answer: str) -> str:
        render_calls.append(answer)
        return "test-image"

    monkeypatch.setattr(captcha, "_captcha_image", render)
    issued, image = await service.issue(scene="self_change", owner_id=owner)
    assert image == "test-image"
    assert len(render_calls) == 1
    assert redis.get.await_count == redis.eval.await_count == 2
    for attempt, previous in zip(
        redis.eval.await_args_list, (old, competing), strict=True
    ):
        args = attempt.args
        assert args[1] == 4
        assert args[2] == service._key(issued)
        assert args[4] == service._index("self_change", owner)
        assert args[5] == service._key(previous)
        assert args[-1] == str(previous)


async def test_private_issue_pointer_contention_has_bounded_retry() -> None:
    service, redis = mock_service()
    redis.get.return_value = None
    redis.eval.return_value = 2
    with pytest.raises(RbacError) as caught:
        await service.issue(scene="admin_reset", owner_id=uuid.uuid4())
    assert caught.value.status_code == 503
    assert redis.get.await_count == redis.eval.await_count == 3


@pytest.mark.parametrize("pointer", ["invalid", str(uuid.uuid1()), b"invalid", 7])
async def test_private_issue_rejects_corrupted_pointer_before_mutation(
    pointer: object,
) -> None:
    service, redis = mock_service()
    redis.get.return_value = pointer
    with pytest.raises(RbacError) as caught:
        await service.issue(scene="self_change", owner_id=uuid.uuid4())
    assert caught.value.status_code == 503
    redis.eval.assert_not_awaited()


async def test_wrong_binding_consume_uses_real_owner_pointer() -> None:
    service, redis = mock_service()
    stored_owner = uuid.uuid4()
    real_index = service._index("admin_reset", stored_owner)
    raw = json.dumps(
        {
            "scene": "admin_reset",
            "owner": str(stored_owner),
            "digest": "a" * 64,
            "index": real_index,
        }
    )
    redis.get.return_value = raw
    redis.eval.return_value = 0
    presented_id = uuid.uuid4()
    with pytest.raises(RbacError) as caught:
        await service.consume(
            captcha_id=presented_id,
            answer="wrong",
            scene="self_change",
            owner_id=uuid.uuid4(),
        )
    assert caught.value.status_code == 400
    args = redis.eval.await_args.args
    assert args[1:4] == (2, service._key(presented_id), real_index)
    assert args[-1] == raw


@pytest.mark.parametrize(
    "change",
    [
        {"index": "some-unrelated-key"},
        {"index": ""},
        {"owner": []},
        {"scene": "login"},
        {"digest": "invalid"},
        {"extra": "invalid"},
    ],
)
async def test_consume_rejects_corrupted_record_without_accessing_untrusted_key(
    change: dict[str, object],
) -> None:
    service, redis = mock_service()
    owner = uuid.uuid4()
    record = {
        "scene": "admin_reset",
        "owner": str(owner),
        "digest": "a" * 64,
        "index": service._index("admin_reset", owner),
        **change,
    }
    redis.get.return_value = json.dumps(record)
    with pytest.raises(RbacError) as caught:
        await service.consume(
            captcha_id=uuid.uuid4(),
            answer="AAAAA",
            scene="admin_reset",
            owner_id=owner,
        )
    assert caught.value.status_code == 503
    redis.eval.assert_not_awaited()
