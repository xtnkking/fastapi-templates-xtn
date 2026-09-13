from typing import cast
from unittest.mock import AsyncMock

import pytest

from app.abuse_defense import AbuseDefenseService
from app.abuse_flow import IdentityAbuseFlow, InvalidLoginCredentialsError
from app.rate_limit import RateLimitResult
from app.rate_limit_dependencies import RateLimitExceeded


def make_flow() -> tuple[IdentityAbuseFlow, AsyncMock]:
    defense = AsyncMock(spec=AbuseDefenseService)
    return IdentityAbuseFlow(cast(AbuseDefenseService, defense)), defense


async def test_invalid_or_unknown_login_runs_hash_then_records_risk_signal() -> None:
    flow, defense = make_flow()
    calls: list[str] = []

    async def real_or_dummy_credentials() -> None:
        calls.append("real_or_dummy_hash")

    defense.check_login_attempt.side_effect = lambda **_kwargs: calls.append(
        "admission"
    )
    defense.record_login_failure.side_effect = lambda *_args: calls.append("failure")

    with pytest.raises(InvalidLoginCredentialsError) as caught:
        await flow.authenticate(
            client_ip="198.51.100.30",
            normalized_identifier="person@example.test",
            verify_real_or_dummy_credentials=real_or_dummy_credentials,
        )

    assert str(caught.value) == "invalid_login_credentials"
    assert calls == ["admission", "real_or_dummy_hash", "failure"]
    defense.record_login_success.assert_not_awaited()


async def test_login_success_clears_failure_state_before_returning() -> None:
    flow, defense = make_flow()
    verified_user = object()

    async def valid_credentials() -> object:
        return verified_user

    result = await flow.authenticate(
        client_ip="198.51.100.31",
        normalized_identifier="person@example.test",
        verify_real_or_dummy_credentials=valid_credentials,
    )

    assert result is verified_user
    defense.record_login_success.assert_awaited_once_with("person@example.test")
    defense.record_login_failure.assert_not_awaited()


async def test_login_does_not_hash_or_issue_after_admission_denial() -> None:
    flow, defense = make_flow()
    credential_check = AsyncMock()
    defense.check_login_attempt.side_effect = RateLimitExceeded(
        policy_name="login_ip",
        result=RateLimitResult(
            allowed=False,
            limit=20,
            remaining=0,
            retry_after_ms=1_000,
            reset_after_ms=5_000,
        ),
    )

    with pytest.raises(RateLimitExceeded):
        await flow.authenticate(
            client_ip="198.51.100.32",
            normalized_identifier="person@example.test",
            verify_real_or_dummy_credentials=credential_check,
        )

    credential_check.assert_not_awaited()
    defense.record_login_failure.assert_not_awaited()
    defense.record_login_success.assert_not_awaited()


async def test_credential_dependency_error_is_not_counted_as_bad_password() -> None:
    flow, defense = make_flow()

    async def unavailable_credentials() -> None:
        raise RuntimeError("password store unavailable")

    with pytest.raises(RuntimeError, match="password store unavailable"):
        await flow.authenticate(
            client_ip="198.51.100.33",
            normalized_identifier="person@example.test",
            verify_real_or_dummy_credentials=unavailable_credentials,
        )

    defense.record_login_failure.assert_not_awaited()
    defense.record_login_success.assert_not_awaited()


async def test_registration_action_only_runs_after_admission() -> None:
    flow, defense = make_flow()
    registration = AsyncMock(return_value="created")

    result = await flow.register(
        client_ip="198.51.100.34",
        normalized_identifier="new_user",
        registration_action=registration,
    )

    assert result == "created"
    defense.check_registration_attempt.assert_awaited_once()
    registration.assert_awaited_once()


async def test_registration_denial_has_no_business_side_effect() -> None:
    flow, defense = make_flow()
    registration = AsyncMock()
    defense.check_registration_attempt.side_effect = RuntimeError("denied")

    with pytest.raises(RuntimeError, match="denied"):
        await flow.register(
            client_ip="198.51.100.35",
            normalized_identifier="new_user",
            registration_action=registration,
        )

    registration.assert_not_awaited()
