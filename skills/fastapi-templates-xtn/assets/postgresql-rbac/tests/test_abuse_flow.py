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
    post_admission_check = AsyncMock()
    verify = AsyncMock(return_value=object())
    flow = IdentityAbuseFlow(
        defense,
        post_admission_check=post_admission_check,
    )
    with pytest.raises(type(error)):
        await getattr(flow, method)(
            client_ip="203.0.113.8",
            normalized_identifier="alice",
            verify_real_or_dummy_credentials=verify,
        )
    post_admission_check.assert_not_awaited()
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


@pytest.mark.asyncio
async def test_authentication_runs_admission_then_request_check_then_credentials() -> (
    None
):
    events: list[str] = []
    defense = AsyncMock()
    defense.check_login_attempt.side_effect = lambda **_kwargs: events.append(
        "admission"
    )
    post_admission_check = AsyncMock(side_effect=lambda: events.append("request_check"))

    async def verify_credentials() -> object:
        events.append("credentials")
        return object()

    verify = AsyncMock(side_effect=verify_credentials)

    result = await IdentityAbuseFlow(
        defense,
        post_admission_check=post_admission_check,
    ).authenticate(
        client_ip="203.0.113.8",
        normalized_identifier="alice",
        verify_real_or_dummy_credentials=verify,
    )

    assert result is not None
    assert events == ["admission", "request_check", "credentials"]


@pytest.mark.asyncio
async def test_registration_runs_admission_then_request_check_then_action() -> None:
    events: list[str] = []
    defense = AsyncMock()
    defense.check_registration_attempt.side_effect = lambda **_kwargs: events.append(
        "admission"
    )
    post_admission_check = AsyncMock(side_effect=lambda: events.append("request_check"))

    async def register() -> str:
        events.append("registration")
        return "created"

    action = AsyncMock(side_effect=register)

    result = await IdentityAbuseFlow(
        defense,
        post_admission_check=post_admission_check,
    ).register(
        client_ip="203.0.113.8",
        normalized_identifier="alice",
        registration_action=action,
    )

    assert result == "created"
    assert events == ["admission", "request_check", "registration"]


@pytest.mark.parametrize("method", ["authenticate", "register"])
@pytest.mark.asyncio
async def test_failed_post_admission_check_still_spends_quota_and_skips_action(
    method: str,
) -> None:
    defense = AsyncMock()
    post_admission_check = AsyncMock(side_effect=RuntimeError("invalid_captcha"))
    action = AsyncMock(return_value=object())
    flow = IdentityAbuseFlow(
        defense,
        post_admission_check=post_admission_check,
    )

    with pytest.raises(RuntimeError, match="invalid_captcha"):
        if method == "authenticate":
            await flow.authenticate(
                client_ip="203.0.113.8",
                normalized_identifier="alice",
                verify_real_or_dummy_credentials=action,
            )
        else:
            await flow.register(
                client_ip="203.0.113.8",
                normalized_identifier="alice",
                registration_action=action,
            )

    if method == "authenticate":
        defense.check_login_attempt.assert_awaited_once()
    else:
        defense.check_registration_attempt.assert_awaited_once()
    post_admission_check.assert_awaited_once()
    action.assert_not_awaited()


@pytest.mark.parametrize(
    "error",
    [
        RateLimitExceeded("register", RateLimitResult(False, 1, 0, 1000, 1000)),
        RateLimitUnavailable("down"),
    ],
)
@pytest.mark.asyncio
async def test_registration_admission_failure_skips_request_check_and_action(
    error: Exception,
) -> None:
    defense = AsyncMock()
    defense.check_registration_attempt.side_effect = error
    post_admission_check = AsyncMock()
    action = AsyncMock(return_value=object())
    flow = IdentityAbuseFlow(
        defense,
        post_admission_check=post_admission_check,
    )

    with pytest.raises(type(error)):
        await flow.register(
            client_ip="203.0.113.8",
            normalized_identifier="alice",
            registration_action=action,
        )

    post_admission_check.assert_not_awaited()
    action.assert_not_awaited()
