from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

import app.abuse_defense as abuse_module
from app.abuse_defense import (
    AbuseDefenseService,
    canonical_client_ip,
    require_canonical_identity,
)
from app.rate_limit import (
    RateLimitBatchDecision,
    RateLimitResult,
    RateLimitUnavailable,
)
from app.rate_limit_dependencies import RateLimitExceeded
from app.settings import get_settings
from app.verification import VerificationChannel


def service_with_eval(*results: object) -> tuple[AbuseDefenseService, MagicMock]:
    redis = MagicMock(spec=Redis)
    redis.eval = AsyncMock(side_effect=results)
    redis.delete = AsyncMock(return_value=1)
    return AbuseDefenseService(cast(Redis, redis), get_settings()), redis


def allowed_decision(count: int) -> RateLimitBatchDecision:
    results = tuple(
        RateLimitResult(
            allowed=True,
            limit=100,
            remaining=99,
            retry_after_ms=0,
            reset_after_ms=1000,
        )
        for _ in range(count)
    )
    return RateLimitBatchDecision(allowed=True, results=results, retry_after_ms=0)


async def test_login_checks_only_ip_pair_and_global(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, redis = service_with_eval(
        RedisConnectionError("account failure state must not be read")
    )
    batch = AsyncMock(return_value=allowed_decision(3))
    monkeypatch.setattr(abuse_module, "check_rate_limits", batch)

    await service.check_login_attempt(
        client_ip="2001:0db8::1",
        normalized_identifier="person@example.test",
    )

    redis.eval.assert_not_awaited()
    assert batch.await_args is not None
    checks = batch.await_args.kwargs["checks"]
    assert [check.policy.name for check in checks] == [
        "login_ip",
        "login_pair",
        "login_global",
    ]
    assert checks[0].subject == "2001:db8::1"
    assert checks[1].subject == "2001:db8::1\0person@example.test"


async def test_registration_checks_every_configured_dimension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _redis = service_with_eval()
    batch = AsyncMock(return_value=allowed_decision(4))
    monkeypatch.setattr(abuse_module, "check_rate_limits", batch)

    await service.check_registration_attempt(
        client_ip="198.51.100.9",
        normalized_identifier="new_user",
    )

    assert batch.await_args is not None
    checks = batch.await_args.kwargs["checks"]
    assert [check.policy.name for check in checks] == [
        "registration_ip",
        "registration_target",
        "registration_pair",
        "registration_global",
    ]


async def test_verification_send_normalizes_target_and_checks_six_dimensions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _redis = service_with_eval()
    batch = AsyncMock(return_value=allowed_decision(6))
    monkeypatch.setattr(abuse_module, "check_rate_limits", batch)

    normalized = await service.check_verification_send(
        client_ip="198.51.100.10",
        channel=VerificationChannel.EMAIL,
        target=" Person@Example.Test ",
    )

    assert normalized == "person@example.test"
    assert batch.await_args is not None
    checks = batch.await_args.kwargs["checks"]
    assert [check.policy.name for check in checks] == [
        "verification_target_cooldown",
        "verification_target_average",
        "verification_ip",
        "verification_pair",
        "verification_channel",
        "verification_global",
    ]


async def test_verification_submission_has_independent_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _redis = service_with_eval()
    batch = AsyncMock(return_value=allowed_decision(4))
    monkeypatch.setattr(abuse_module, "check_rate_limits", batch)

    await service.check_verification_attempt(
        client_ip="198.51.100.11",
        channel=VerificationChannel.SMS,
        target="+15551234567",
    )

    assert batch.await_args is not None
    checks = batch.await_args.kwargs["checks"]
    assert [check.policy.name for check in checks] == [
        "verification_submit_ip",
        "verification_submit_target",
        "verification_submit_pair",
        "verification_submit_global",
    ]


async def test_batch_denial_uses_longest_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _redis = service_with_eval()
    allowed = RateLimitResult(True, 5, 4, 0, 1000)
    short = RateLimitResult(False, 5, 0, 1000, 5000)
    long = RateLimitResult(False, 5, 0, 3000, 5000)
    monkeypatch.setattr(
        abuse_module,
        "check_rate_limits",
        AsyncMock(
            return_value=RateLimitBatchDecision(
                allowed=False,
                results=(allowed, short, long, allowed),
                retry_after_ms=3000,
            )
        ),
    )

    with pytest.raises(RateLimitExceeded) as caught:
        await service.check_registration_attempt(
            client_ip="198.51.100.12",
            normalized_identifier="new_user",
        )

    assert caught.value.policy_name == "registration_pair"
    assert caught.value.result.retry_after_ms == 3000


async def test_failure_state_and_success_use_only_hmac_key() -> None:
    service, redis = service_with_eval(10)
    identifier = "private@example.test"

    state = await service.record_login_failure(identifier)
    await service.record_login_success(identifier)

    assert state.consecutive_failures == 10
    eval_key = str(redis.eval.await_args.args[2])
    delete_key = str(redis.delete.await_args.args[0])
    assert eval_key == delete_key
    assert identifier not in eval_key
    assert eval_key.startswith("abuse:v1:")


async def test_failure_counter_uses_configured_finite_retention() -> None:
    service, redis = service_with_eval(1)

    await service.record_login_failure("person@example.test")

    assert redis.eval.await_args.args[3] == 86_400


async def test_failure_store_errors_fail_closed_without_details() -> None:
    service, _redis = service_with_eval(
        RedisConnectionError("redis://user:password@private.example")
    )

    with pytest.raises(RateLimitUnavailable) as caught:
        await service.login_failure_state("person@example.test")

    assert "password" not in str(caught.value)
    assert "private.example" not in str(caught.value)


def test_identity_and_ip_inputs_are_canonical_and_bounded() -> None:
    assert canonical_client_ip("2001:0db8::1") == "2001:db8::1"
    assert canonical_client_ip("unknown") == "unknown"
    assert require_canonical_identity("user_name") == "user_name"
    with pytest.raises(ValueError):
        canonical_client_ip("forwarded-for-value")
    with pytest.raises(ValueError):
        require_canonical_identity(" user_name ")
    with pytest.raises(
        ValueError,
        match="normalized identity must be a bounded non-empty string",
    ):
        require_canonical_identity("user_\ud800")
