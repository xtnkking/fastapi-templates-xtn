from typing import cast
from unittest.mock import AsyncMock

import pytest

import app.abuse_defense as abuse_module
from app.abuse_defense import AbuseDefenseService, canonical_client_ip
from app.rate_limit import RateLimitPolicy, RateLimitResult, RateLimitUnavailable
from app.rate_limit_dependencies import RateLimitExceeded
from app.settings import get_settings


def service() -> AbuseDefenseService:
    return AbuseDefenseService(AsyncMock(), get_settings())


@pytest.mark.asyncio
async def test_anonymous_quota_does_not_use_user_supplied_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checks: list[tuple[str, str, str]] = []

    async def check(_redis: object, **kwargs: object) -> RateLimitResult:
        policy = cast(RateLimitPolicy, kwargs["policy"])
        checks.append(
            (policy.name, str(kwargs["subject_type"]), str(kwargs["subject"]))
        )
        return RateLimitResult(True, policy.limit, policy.limit - 1, 0, 300000)

    monkeypatch.setattr(abuse_module, "check_rate_limit", check)
    defense = service()
    await defense.check_login_attempt(
        client_ip="203.0.113.8", normalized_identifier="alice"
    )
    await defense.check_login_attempt(
        client_ip="203.0.113.8", normalized_identifier="bob"
    )
    await defense.check_registration_attempt(
        client_ip="203.0.113.8", normalized_identifier="alice"
    )
    await defense.check_temporary_password_completion(client_ip="203.0.113.8")
    assert checks == [
        ("login", "ip", "203.0.113.8"),
        ("login", "ip", "203.0.113.8"),
        ("register", "ip", "203.0.113.8"),
        ("temporary_complete", "ip", "203.0.113.8"),
    ]


@pytest.mark.parametrize(
    "address", ["", "unknown", "not-an-ip", "127.0.0.1, 127.0.0.2"]
)
@pytest.mark.asyncio
async def test_missing_trusted_ip_never_enters_a_shared_bucket(address: str) -> None:
    with pytest.raises(RateLimitUnavailable):
        await service().check_login_attempt(
            client_ip=address, normalized_identifier="alice"
        )


@pytest.mark.asyncio
async def test_captcha_scene_is_independent_and_private_subject_is_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checks: list[tuple[str, str, str, int, int]] = []

    async def check(_redis: object, **kwargs: object) -> RateLimitResult:
        policy = cast(RateLimitPolicy, kwargs["policy"])
        checks.append(
            (
                policy.name,
                str(kwargs["subject_type"]),
                str(kwargs["subject"]),
                policy.limit,
                policy.window_seconds,
            )
        )
        return RateLimitResult(True, policy.limit, policy.limit - 1, 0, 300000)

    monkeypatch.setattr(abuse_module, "check_rate_limit", check)
    defense = service()
    await defense.check_captcha_create(scene="login", client_ip="203.0.113.8")
    await defense.check_captcha_create(scene="register", client_ip="203.0.113.8")
    await defense.check_captcha_create(scene="admin_create", user_id="UABC123")
    await defense.check_captcha_create(scene="admin_reset", user_id="UABC123")
    await defense.check_captcha_create(scene="self_change", user_id="UABC123")
    assert checks == [
        ("captcha_create_login", "ip", "203.0.113.8", 10, 300),
        ("captcha_create_register", "ip", "203.0.113.8", 10, 300),
        ("captcha_create_admin_create", "actor", "UABC123", 10, 300),
        ("captcha_create_admin_reset", "actor", "UABC123", 10, 300),
        ("captcha_create_self_change", "actor", "UABC123", 10, 300),
    ]


@pytest.mark.asyncio
async def test_captcha_rejects_unknown_scene_or_client_selected_actor() -> None:
    defense = service()
    with pytest.raises(ValueError):
        await defense.check_captcha_create(scene="reset", client_ip="203.0.113.8")
    with pytest.raises(ValueError):
        await defense.check_captcha_create(scene="admin_reset", client_ip="203.0.113.8")
    with pytest.raises(ValueError):
        await defense.check_captcha_create(scene="login", user_id="UABC123")


@pytest.mark.asyncio
async def test_rejected_captcha_scene_uses_one_private_key_per_subject_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checks: list[tuple[str, str, str, int, int]] = []

    async def check(_redis: object, **kwargs: object) -> RateLimitResult:
        policy = cast(RateLimitPolicy, kwargs["policy"])
        checks.append(
            (
                policy.name,
                str(kwargs["subject_type"]),
                str(kwargs["subject"]),
                policy.limit,
                policy.window_seconds,
            )
        )
        return RateLimitResult(True, policy.limit, policy.limit - 1, 0, 300000)

    monkeypatch.setattr(abuse_module, "check_rate_limit", check)
    defense = service()
    await defense.check_rejected_captcha_scene(client_ip="2001:0db8::1")
    await defense.check_rejected_captcha_scene(user_id="UABC123")

    assert checks == [
        ("captcha_rejected_scene", "ip", "2001:db8::1", 10, 300),
        ("captcha_rejected_scene", "actor", "UABC123", 10, 300),
    ]


@pytest.mark.asyncio
async def test_rejected_captcha_scene_requires_exactly_one_trusted_subject() -> None:
    defense = service()
    with pytest.raises(RateLimitUnavailable):
        await defense.check_rejected_captcha_scene(client_ip="unknown")
    with pytest.raises(ValueError):
        await defense.check_rejected_captcha_scene()
    with pytest.raises(ValueError):
        await defense.check_rejected_captcha_scene(
            client_ip="203.0.113.8", user_id="UABC123"
        )


@pytest.mark.asyncio
async def test_denial_raises_429_with_the_one_business_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def denied(_redis: object, **_kwargs: object) -> RateLimitResult:
        return RateLimitResult(False, 20, 0, 1300, 1300)

    monkeypatch.setattr(abuse_module, "check_rate_limit", denied)
    with pytest.raises(RateLimitExceeded) as caught:
        await service().check_login_attempt(
            client_ip="203.0.113.8", normalized_identifier="alice"
        )
    assert caught.value.policy_name == "login"
    assert caught.value.result.retry_after_ms == 1300


def test_trusted_client_ip_canonicalization() -> None:
    assert canonical_client_ip("2001:0db8::1") == "2001:db8::1"
