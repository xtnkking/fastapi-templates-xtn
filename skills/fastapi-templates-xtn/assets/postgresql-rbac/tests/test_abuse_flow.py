from unittest.mock import AsyncMock

import pytest

from app.abuse_flow import IdentityAbuseFlow, InvalidLoginCredentialsError
from app.rate_limit import RateLimitResult, RateLimitUnavailable
from app.rate_limit_dependencies import RateLimitExceeded


@pytest.mark.parametrize(
    "method", ["authenticate", "complete_temporary_password_reset"]
)
@pytest.mark.asyncio
async def test_invalid_credentials_have_one_generic_error_without_failure_counter(
    method: str,
) -> None:
    defense = AsyncMock()
    flow = IdentityAbuseFlow(defense)
    verify = AsyncMock(return_value=None)
    with pytest.raises(InvalidLoginCredentialsError):
        await getattr(flow, method)(
            client_ip="203.0.113.8",
            normalized_identifier="alice",
            verify_real_or_dummy_credentials=verify,
        )
    verify.assert_awaited_once()
    assert (
        not hasattr(defense, "record_login_failure")
        or not defense.record_login_failure.await_args
    )


@pytest.mark.parametrize(
    "method", ["authenticate", "complete_temporary_password_reset"]
)
@pytest.mark.parametrize(
    "error",
    [
        RateLimitExceeded("login", RateLimitResult(False, 1, 0, 1000, 1000)),
        RateLimitUnavailable("down"),
    ],
)
@pytest.mark.asyncio
async def test_admission_fails_before_credential_callback(
    method: str, error: Exception
) -> None:
    defense = AsyncMock()
    defense.check_login_attempt.side_effect = error
    defense.check_temporary_password_completion.side_effect = error
    verify = AsyncMock(return_value=object())
    flow = IdentityAbuseFlow(defense)
    with pytest.raises(type(error)):
        await getattr(flow, method)(
            client_ip="203.0.113.8",
            normalized_identifier="alice",
            verify_real_or_dummy_credentials=verify,
        )
    verify.assert_not_awaited()


@pytest.mark.asyncio
async def test_registration_only_runs_after_admission() -> None:
    defense = AsyncMock()
    flow = IdentityAbuseFlow(defense)
    action = AsyncMock(return_value="new-user")
    assert (
        await flow.register(
            client_ip="203.0.113.8",
            normalized_identifier="alice",
            registration_action=action,
        )
        == "new-user"
    )
    defense.check_registration_attempt.assert_awaited_once()
    action.assert_awaited_once()
