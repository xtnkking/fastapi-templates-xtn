import asyncio
import threading
import time
from typing import Any, cast

import pytest

from app.passwords import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LENGTH,
    ARGON2_TIME_COST,
    DUMMY_PASSWORD_HASH,
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    validate_login_password_input,
    validate_new_password,
)

VALID_PASSWORD = "correct horse battery staple"


def test_new_password_policy_preserves_the_exact_password() -> None:
    password = "  Correct Horse Battery Staple  "

    assert validate_new_password(password) == password


@pytest.mark.parametrize(
    ("password", "reason_code"),
    [
        ("", "password_empty"),
        ("short", "password_too_short"),
        ("x" * 61, "password_too_long"),
        ("a" * 15, "password_common_or_weak"),
        ("12345678", "password_common_or_weak"),
        ("87654321", "password_common_or_weak"),
        ("abcdefgh", "password_common_or_weak"),
        ("hgfedcba", "password_common_or_weak"),
        ("valid-password\nvalue", "password_contains_control_character"),
        ("valid-password-\ud800", "password_invalid_unicode"),
    ],
)
def test_new_password_policy_rejects_invalid_values(
    password: str,
    reason_code: str,
) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        validate_new_password(password)

    assert caught.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("identity", "password"),
    [
        ("AliceName", "ALICENAME"),
        ("MyAccount", "myaccount"),
    ],
)
def test_new_password_cannot_equal_login_identity(
    identity: str,
    password: str,
) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        validate_new_password(password, identity_values=(identity,))

    assert caught.value.reason_code == "password_same_as_user_name"


def test_username_substring_and_nonsequential_weak_string_are_allowed() -> None:
    assert validate_new_password(
        "safe-AliceName-suffix", identity_values=("AliceName",)
    )
    assert validate_new_password("passwordpassword") == "passwordpassword"


def test_login_validation_does_not_apply_the_new_password_policy() -> None:
    assert validate_login_password_input("old") == "old"


def test_login_validation_rejects_invalid_unicode_as_a_policy_error() -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        validate_login_password_input("candidate-\udfff")

    assert caught.value.reason_code == "password_invalid_unicode"


async def test_hash_and_verify_use_the_fixed_argon2id_profile() -> None:
    manager = PasswordManager(max_concurrent_operations=1)

    encoded = await manager.hash_new_password(VALID_PASSWORD)
    correct = await manager.verify_or_dummy(VALID_PASSWORD, encoded)
    wrong = await manager.verify_or_dummy("wrong", encoded)

    assert encoded.startswith(
        f"$argon2id$v=19$m={ARGON2_MEMORY_COST_KIB},"
        f"t={ARGON2_TIME_COST},p={ARGON2_PARALLELISM}$"
    )
    salt, digest = encoded.rsplit("$", 2)[-2:]
    assert len(salt) == 22
    assert len(digest) == 43
    assert ARGON2_SALT_LENGTH == 16
    assert ARGON2_HASH_LENGTH == 32
    assert correct.verified
    assert not correct.needs_rehash
    assert not correct.used_dummy
    assert not wrong.verified
    assert not wrong.used_dummy


async def test_unknown_account_uses_dummy_hash_but_never_authenticates() -> None:
    manager = PasswordManager(max_concurrent_operations=1)

    result = await manager.verify_or_dummy("an-unknown-account-password", None)

    assert DUMMY_PASSWORD_HASH.startswith("$argon2id$")
    assert not result.verified
    assert not result.needs_rehash
    assert result.used_dummy


async def test_corrupt_stored_hash_is_distinct_from_password_mismatch() -> None:
    manager = PasswordManager(max_concurrent_operations=1)

    with pytest.raises(PasswordHashError):
        await manager.verify_or_dummy(VALID_PASSWORD, "not-an-argon2-hash")


async def test_stored_hash_cannot_request_more_argon2_resources_than_configured() -> (
    None
):
    manager = PasswordManager(max_concurrent_operations=1)
    oversized_cost_hash = DUMMY_PASSWORD_HASH.replace("m=65536", "m=999999999")

    with pytest.raises(PasswordHashError, match="parameters are unsafe"):
        await manager.verify_or_dummy(VALID_PASSWORD, oversized_cost_hash)


async def test_verified_legacy_password_can_be_rehashed_without_new_policy() -> None:
    manager = PasswordManager(max_concurrent_operations=1)

    encoded = await manager.hash_verified_password("old")

    assert (await manager.verify_or_dummy("old", encoded)).verified


async def test_hash_work_is_bounded_even_when_callers_run_concurrently() -> None:
    class TrackingHasher:
        def __init__(self) -> None:
            self.active = 0
            self.maximum = 0
            self.lock = threading.Lock()

        def hash(self, password: str) -> str:
            with self.lock:
                self.active += 1
                self.maximum = max(self.maximum, self.active)
            time.sleep(0.02)
            with self.lock:
                self.active -= 1
            return password

    manager = PasswordManager(max_concurrent_operations=1)
    tracking = TrackingHasher()
    manager._hasher = cast(Any, tracking)

    results = await asyncio.gather(
        *(manager.hash_verified_password(f"legacy-{index}") for index in range(4))
    )

    assert results == [f"legacy-{index}" for index in range(4)]
    assert tracking.maximum == 1
