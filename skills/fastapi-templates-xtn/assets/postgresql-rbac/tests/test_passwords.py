#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查新密码字符范围、弱密码拒绝和 Argon2id 哈希验证
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充文件记录并验证新密码的可见 ASCII 字符规则
# 2026/10/02    XTN       V1.001        验证旧密码 Unicode 输入仍按字符边界处理
# 2026/10/14    XTN       V1.002        新密码边界使用共享常量并逐个验证全部英文标点
# 2026/10/20    XTN       V1.003        收紧新密码策略后仍允许原密码验证，登录独立限制传输长度
# 2026/10/20    XTN       V1.004        验证本地密码队列容量、超时、取消清理和空闲重配
# --------------------------------------------------------------------------------------------------

import asyncio
import string
import threading
import time
from typing import Any, cast

import pytest

import app.core.security.passwords as password_security
from app.core.security.passwords import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LENGTH,
    ARGON2_TIME_COST,
    DUMMY_PASSWORD_HASH,
    MAX_PASSWORD_CHARACTERS,
    MAX_PASSWORD_INPUT_CHARACTERS,
    PasswordBusyError,
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    validate_login_password_input,
    validate_new_password,
)

VALID_PASSWORD = "Correct-Horse-Battery-Staple"


@pytest.mark.parametrize("punctuation", string.punctuation)
def test_new_password_policy_preserves_the_exact_password(punctuation: str) -> None:
    """
        验证所有可见 ASCII 标点均能作为新密码的一部分且原文不被改写。

    :param punctuation: 逐个覆盖全部可见 ASCII 标点，避免把所有标点拼成超过长度上限的密码。
    :return: 无返回值；符合范围的新密码保持原值。
    """
    password = "Abc123" + punctuation + "xyz"

    assert validate_new_password(password) == password


@pytest.mark.parametrize(
    ("password", "reason_code"),
    [
        ("", "password_empty"),
        ("short", "password_too_short"),
        ("x" * (MAX_PASSWORD_CHARACTERS + 1), "password_too_long"),
        ("a" * 15, "password_common_or_weak"),
        ("12345678", "password_common_or_weak"),
        ("87654321", "password_common_or_weak"),
        ("abcdefgh", "password_common_or_weak"),
        ("hgfedcba", "password_common_or_weak"),
        ("valid-password\nvalue", "password_invalid_character"),
        ("valid password", "password_invalid_character"),
        ("valid-password-中文", "password_invalid_character"),
        ("valid-password-😀", "password_invalid_character"),
        ("valid-password-\u200b", "password_invalid_character"),
        ("valid-password-\ud800", "password_invalid_unicode"),
    ],
)
def test_new_password_policy_rejects_invalid_values(password: str, reason_code: str) -> None:
    """
        拒绝越界、弱口令及不可见或非 ASCII 的新密码字符。

    :param password: 待检查的新密码原文。
    :param reason_code: 对应的稳定密码规则失败原因。
    :return: 无返回值；被拒绝的输入匹配预期原因。
    """
    with pytest.raises(PasswordPolicyError) as caught:
        validate_new_password(password)

    assert caught.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("user_name", "password"),
    [
        ("AliceName", "ALICENAME"),
        ("MyAccount", "myaccount"),
    ],
)
def test_new_password_cannot_equal_user_name(user_name: str, password: str) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        validate_new_password(password, user_name=user_name)

    assert caught.value.reason_code == "password_same_as_user_name"


def test_username_substring_and_nonsequential_weak_string_are_allowed() -> None:
    assert validate_new_password(
        "safe-AliceName-suffix", user_name="AliceName"
    )
    assert validate_new_password("passwordpassword") == "passwordpassword"


def test_login_validation_does_not_apply_the_new_password_policy() -> None:
    """
        旧密码验证不套用新密码字符规则，保留既有账号的登录能力。

    :return: 无返回值；短密码和旧有空格仍可进入哈希验证。
    """
    assert validate_login_password_input("old") == "old"
    assert validate_login_password_input("old password") == "old password"


def test_login_validation_keeps_existing_multibyte_passwords_within_character_limit() -> None:
    """
        既有密码可含非 ASCII 字符；输入边界按字符数，不受新密码 ASCII 规则影响。

    :return: 无返回值；长度恰好达到登录上限的旧密码仍可进入哈希验证。
    """
    existing_password = "😀" * MAX_PASSWORD_INPUT_CHARACTERS

    assert validate_login_password_input(existing_password) == existing_password


@pytest.mark.parametrize("password", ["", "x" * (MAX_PASSWORD_INPUT_CHARACTERS + 1)])
def test_login_validation_rejects_empty_and_oversized_input(password: str) -> None:
    """
        登录只拒绝空密码或超过传输上限的输入，不套用设置新密码的长度。

    :param password: 空输入或超过独立传输上限的输入。
    :return: 无返回值；无效输入在昂贵的密码计算前被拒绝。
    """
    reason = "password_empty" if not password else "password_too_long"
    with pytest.raises(PasswordPolicyError, match=reason):
        validate_login_password_input(password)


@pytest.mark.parametrize("minimum,maximum,password,reason", [
    (10, 32, "Ab1!xyZ?", "password_too_short"),
    (8, 24, "Ab1!" + "x" * 28, "password_too_long"),
])
async def test_stricter_policy_keeps_existing_password_hash_verification(minimum: int, maximum: int,
                                                                         password: str, reason: str,
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    """
        调高最短长度或降低最长长度后，原密码仍能验证，新设置的密码必须满足新规则。

    :param minimum: 调整后的新密码最短长度。
    :param maximum: 调整后的新密码最长长度。
    :param password: 原规则下已保存、调整后不再符合新长度的密码。
    :param reason: 重新设置该密码时应被拒绝的长度原因。
    :param monkeypatch: 临时收紧新密码策略，测试后自动恢复。
    :return: 无返回值；验证原密码和升级其哈希不被新密码策略拦截。
    """
    manager = PasswordManager(max_concurrent_operations=1)
    encoded = await manager.hash_new_password(password)
    monkeypatch.setattr(password_security, "MIN_PASSWORD_CHARACTERS", minimum)
    monkeypatch.setattr(password_security, "MAX_PASSWORD_CHARACTERS", maximum)

    assert validate_login_password_input(password) == password
    assert (await manager.verify_or_dummy(password, encoded)).verified
    replacement_hash = await manager.hash_verified_password(password)
    assert (await manager.verify_or_dummy(password, replacement_hash)).verified
    with pytest.raises(PasswordPolicyError, match=reason):
        validate_new_password(password)
    with pytest.raises(PasswordPolicyError, match=reason):
        await manager.hash_new_password(password)


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


async def test_stored_hash_cannot_request_more_argon2_resources_than_configured() -> (None):
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


@pytest.mark.parametrize("cancellation_count", [1, 3])
@pytest.mark.parametrize("worker_fails", [False, True])
async def test_cancelled_hash_holds_capacity_until_native_work_finishes(cancellation_count: int,
                                                                        worker_fails: bool) -> None:
    loop = asyncio.get_running_loop()
    first_started = asyncio.Event()
    first_release = threading.Event()
    second_started = threading.Event()

    class ControlledHasher:
        def hash(self, password: str) -> str:
            if password == "first":
                loop.call_soon_threadsafe(first_started.set)
                if not first_release.wait(5):
                    raise RuntimeError("test did not release native work")
                if worker_fails:
                    raise RuntimeError("controlled worker failure")
            else:
                second_started.set()
            return password

    manager = PasswordManager(max_concurrent_operations=1)
    manager._hasher = cast(Any, ControlledHasher())
    first = asyncio.create_task(manager.hash_verified_password("first"))
    second: asyncio.Task[str] | None = None
    try:
        await asyncio.wait_for(first_started.wait(), timeout=2)
        for _ in range(cancellation_count):
            first.cancel()
            # Let each cancellation reach the caller before sending the next.
            await asyncio.sleep(0)
            assert not first.done()

        second = asyncio.create_task(manager.hash_verified_password("second"))
        await asyncio.sleep(0)
        assert not second_started.is_set()
        assert not second.done()
        first_release.set()

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(first, timeout=2)
        assert await asyncio.wait_for(second, timeout=2) == "second"
        assert second_started.is_set()
    finally:
        first_release.set()
        await asyncio.gather(
            *(task for task in (first, second) if task is not None),
            return_exceptions=True,
        )


async def test_cancelling_waiting_hash_preserves_native_work_capacity() -> None:
    loop = asyncio.get_running_loop()
    first_started = asyncio.Event()
    first_release = threading.Event()
    seen: list[str] = []

    class ControlledHasher:
        def hash(self, password: str) -> str:
            seen.append(password)
            if password == "first":
                loop.call_soon_threadsafe(first_started.set)
                if not first_release.wait(5):
                    raise RuntimeError("test did not release native work")
            return password

    manager = PasswordManager(max_concurrent_operations=1)
    manager._hasher = cast(Any, ControlledHasher())
    first = asyncio.create_task(manager.hash_verified_password("first"))
    try:
        await asyncio.wait_for(first_started.wait(), timeout=2)
        waiting = asyncio.create_task(manager.hash_verified_password("cancelled"))
        await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert manager._waiting_operations == 0
        first_release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        assert await manager.hash_verified_password("last") == "last"
        assert seen == ["first", "last"]
    finally:
        first_release.set()
        await asyncio.gather(first, return_exceptions=True)


class BlockingPasswordHasher:
    """用事件阻挡第一项运算，直接观察哪些任务真正进入了线程。"""

    def __init__(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.started = asyncio.Event()
        self.release = threading.Event()
        self.seen: list[str] = []

    def hash(self, password: str) -> str:
        self.seen.append(password)
        if password == "first":
            self.loop.call_soon_threadsafe(self.started.set)
            if not self.release.wait(5):
                raise RuntimeError("test did not release native work")
        return password


async def test_password_queue_rejects_overflow_without_starting_the_rejected_work() -> None:
    manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=1, wait_timeout_seconds=2)
    hasher = BlockingPasswordHasher()
    manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(manager.hash_verified_password("first"))
    waiting: asyncio.Task[str] | None = None
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        waiting = asyncio.create_task(manager.hash_verified_password("waiting"))
        await asyncio.sleep(0)
        assert manager._waiting_operations == 1

        with pytest.raises(PasswordBusyError) as caught:
            await manager.hash_verified_password("rejected")
        assert caught.value.reason_code == "password_queue_full"
        assert hasher.seen == ["first"]

        hasher.release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        assert await asyncio.wait_for(waiting, timeout=2) == "waiting"
        assert hasher.seen == ["first", "waiting"]
        assert manager._running_operations == manager._waiting_operations == 0
    finally:
        hasher.release.set()
        await asyncio.gather(*(task for task in (first, waiting) if task is not None), return_exceptions=True)


async def test_password_queue_timeout_never_starts_the_expired_work_and_reclaims_its_slot() -> None:
    manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=1, wait_timeout_seconds=0.01)
    hasher = BlockingPasswordHasher()
    manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(manager.hash_verified_password("first"))
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        with pytest.raises(PasswordBusyError) as caught:
            await manager.hash_verified_password("expired")
        assert caught.value.reason_code == "password_queue_timeout"
        assert manager._waiting_operations == 0
        assert manager._running_operations == 1
        assert hasher.seen == ["first"]

        hasher.release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        assert await manager.hash_verified_password("last") == "last"
        assert hasher.seen == ["first", "last"]
        assert manager._running_operations == manager._waiting_operations == 0
    finally:
        hasher.release.set()
        await asyncio.gather(first, return_exceptions=True)


async def test_zero_waiting_capacity_accepts_idle_work_and_rejects_only_while_full() -> None:
    manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=0)
    hasher = BlockingPasswordHasher()
    manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(manager.hash_verified_password("first"))
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        with pytest.raises(PasswordBusyError, match="password_queue_full"):
            await manager.hash_verified_password("rejected")
        assert manager._waiting_operations == 0
        hasher.release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        assert await manager.hash_verified_password("last") == "last"
        assert hasher.seen == ["first", "last"]
    finally:
        hasher.release.set()
        await asyncio.gather(first, return_exceptions=True)


async def test_cancelling_a_waiter_immediately_allows_another_waiter() -> None:
    manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=1, wait_timeout_seconds=2)
    hasher = BlockingPasswordHasher()
    manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(manager.hash_verified_password("first"))
    cancelled: asyncio.Task[str] | None = None
    replacement: asyncio.Task[str] | None = None
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        cancelled = asyncio.create_task(manager.hash_verified_password("cancelled"))
        await asyncio.sleep(0)
        assert manager._waiting_operations == 1
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled

        replacement = asyncio.create_task(manager.hash_verified_password("replacement"))
        await asyncio.sleep(0)
        assert manager._waiting_operations == 1
        hasher.release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        assert await asyncio.wait_for(replacement, timeout=2) == "replacement"
        assert hasher.seen == ["first", "replacement"]
        assert manager._running_operations == manager._waiting_operations == 0
    finally:
        hasher.release.set()
        await asyncio.gather(
            *(task for task in (first, cancelled, replacement) if task is not None), return_exceptions=True,
        )


async def test_password_limits_can_only_be_reconfigured_while_idle() -> None:
    manager = PasswordManager(max_concurrent_operations=2)
    manager.configure_limits(max_concurrent_operations=1, max_waiting_operations=0, wait_timeout_seconds=0.25)
    hasher = BlockingPasswordHasher()
    manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(manager.hash_verified_password("first"))
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        with pytest.raises(RuntimeError):
            manager.configure_limits(max_concurrent_operations=2, max_waiting_operations=4, wait_timeout_seconds=0.5)
        with pytest.raises(PasswordBusyError, match="password_queue_full"):
            await manager.hash_verified_password("rejected")
        hasher.release.set()
        assert await asyncio.wait_for(first, timeout=2) == "first"
        manager.configure_limits(max_concurrent_operations=2, max_waiting_operations=4, wait_timeout_seconds=0.5)
        assert await manager.hash_verified_password("last") == "last"
        assert hasher.seen == ["first", "last"]
    finally:
        hasher.release.set()
        await asyncio.gather(first, return_exceptions=True)


async def test_password_capacity_is_local_to_each_manager() -> None:
    first_manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=0)
    second_manager = PasswordManager(max_concurrent_operations=1, max_waiting_operations=0)
    hasher = BlockingPasswordHasher()
    first_manager._hasher = second_manager._hasher = cast(Any, hasher)
    first = asyncio.create_task(first_manager.hash_verified_password("first"))
    try:
        await asyncio.wait_for(hasher.started.wait(), timeout=2)
        assert await second_manager.hash_verified_password("independent") == "independent"
        with pytest.raises(PasswordBusyError, match="password_queue_full"):
            await first_manager.hash_verified_password("rejected")
        assert hasher.seen == ["first", "independent"]
    finally:
        hasher.release.set()
        await asyncio.gather(first, return_exceptions=True)
