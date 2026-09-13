import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.authentication_service as authentication_service
from app.abuse_flow import InvalidLoginCredentialsError
from app.audit import AuditSource
from app.authentication_service import (
    LocalAuthenticationService,
    _PasswordSnapshot,
)
from app.passwords import PasswordHashError, PasswordVerification
from app.rbac.errors import RbacError, forbidden, unavailable
from app.rbac.models import User


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self._value = value

    async def __aenter__(self) -> object:
        return self._value

    async def __aexit__(self, *_args: object) -> None:
        return None


def _service(manager: Any) -> LocalAuthenticationService:
    return LocalAuthenticationService(
        cast(async_sessionmaker[AsyncSession], Mock()),
        manager,
    )


def _snapshot(*, password_hash: str) -> _PasswordSnapshot:
    return _PasswordSnapshot(
        user_id=uuid.uuid4(),
        user_name="alice",
        is_active=True,
        is_deleted=False,
        token_version=0,
        password_hash=password_hash,
        password_changed_at=datetime.now(UTC),
        must_change_password=False,
    )


@pytest.mark.parametrize(
    ("snapshot", "used_dummy"),
    [
        (None, True),
        (_snapshot(password_hash="$argon2id$stored"), False),
    ],
)
async def test_unknown_and_wrong_passwords_use_one_public_failure(
    monkeypatch: pytest.MonkeyPatch,
    snapshot: _PasswordSnapshot | None,
    used_dummy: bool,
) -> None:
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=False,
            needs_rehash=False,
            used_dummy=used_dummy,
        )
    )
    service = _service(manager)
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )

    with pytest.raises(InvalidLoginCredentialsError) as caught:
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="candidate password",
        )

    assert str(caught.value) == "invalid_login_credentials"
    expected_hash = snapshot.password_hash if snapshot is not None else None
    manager.verify_or_dummy.assert_awaited_once_with(
        "candidate password",
        expected_hash,
    )


async def test_corrupt_stored_hash_fails_closed_as_dependency_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(password_hash="corrupt")
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(side_effect=PasswordHashError("invalid"))
    service = _service(manager)
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )

    with pytest.raises(RbacError) as caught:
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="candidate password",
        )

    assert caught.value.status_code == 503
    assert caught.value.reason_code == "password_credential_unavailable"


async def test_service_self_change_rejects_reusing_the_current_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = Mock()
    manager.hash_new_password = AsyncMock()
    service = _service(manager)
    reauthenticate = AsyncMock()
    monkeypatch.setattr(service, "_reauthenticate_actor", reauthenticate)

    with pytest.raises(RbacError) as caught:
        await service.change_password(
            context=cast(Any, object()),
            current_password="same password value",
            new_password="same password value",
        )

    assert caught.value.status_code == 400
    assert caught.value.reason_code == "new_password_must_differ"
    reauthenticate.assert_not_awaited()
    manager.hash_new_password.assert_not_awaited()


async def test_service_temporary_completion_rejects_reusing_the_temporary_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = Mock()
    manager.hash_new_password = AsyncMock()
    service = _service(manager)
    verify_temporary = AsyncMock()
    monkeypatch.setattr(service, "_verify_temporary_snapshot", verify_temporary)

    with pytest.raises(RbacError) as caught:
        await service.complete_password_reset(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            temporary_password="same password value",
            new_password="same password value",
            request_id=str(uuid.uuid4()),
        )

    assert caught.value.status_code == 400
    assert caught.value.reason_code == "new_password_must_differ"
    verify_temporary.assert_not_awaited()
    manager.hash_new_password.assert_not_awaited()


@pytest.mark.parametrize(
    ("error", "should_write"),
    [
        (forbidden("target_not_allowed"), True),
        (unavailable("authorization_authority_unavailable"), False),
    ],
)
async def test_account_security_denial_audit_excludes_infrastructure_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: RbacError,
    should_write: bool,
) -> None:
    service = _service(Mock())
    write_denied_event = AsyncMock()
    monkeypatch.setattr(service, "_write_denied_event", write_denied_event)
    actor_user_id = uuid.uuid4()
    target_user_id = uuid.uuid4()
    request_id = str(uuid.uuid4())

    await service._write_client_denial(
        error=error,
        action="account_security.password.admin_reset",
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        source=AuditSource.HTTP,
        request_id=request_id,
    )

    if should_write:
        write_denied_event.assert_awaited_once_with(
            action="account_security.password.admin_reset",
            reason_code=error.reason_code,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            source=AuditSource.HTTP,
            request_id=request_id,
        )
    else:
        write_denied_event.assert_not_awaited()


async def test_denial_audit_failure_preserves_the_original_permission_error() -> None:
    class _FailingTransaction:
        async def __aenter__(self) -> None:
            raise OSError("account audit unavailable")

        async def __aexit__(self, *_args: object) -> None:
            return None

    session = SimpleNamespace(begin=Mock(return_value=_FailingTransaction()))
    service = LocalAuthenticationService(
        cast(
            async_sessionmaker[AsyncSession], Mock(return_value=_AsyncContext(session))
        ),
        Mock(),
    )
    error = forbidden("target_not_allowed")

    with pytest.raises(RbacError) as caught:
        try:
            raise error
        except RbacError as exc:
            await service._write_client_denial(
                error=exc,
                action="account_security.password.admin_reset",
                actor_user_id=uuid.uuid4(),
                target_user_id=uuid.uuid4(),
                source=AuditSource.HTTP,
                request_id=str(uuid.uuid4()),
            )
            raise

    assert caught.value is error


async def test_password_rotation_updates_user_row_and_timestamp() -> None:
    user_id = uuid.uuid4()
    old_timestamp = datetime.now(UTC)
    user = User(
        id=user_id,
        user_name="target",
        token_version=3,
        password_hash="$argon2id$old",
        must_change_password=False,
        password_changed_at=old_timestamp,
    )
    changed_at = datetime.now(UTC)
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=changed_at)

    await LocalAuthenticationService._rotate_password(
        cast(AsyncSession, session),
        user=user,
        password_hash="$argon2id$new",
        must_change_password=True,
    )

    assert user.id == user_id
    assert user.password_hash == "$argon2id$new"
    assert user.must_change_password is True
    assert user.password_changed_at == changed_at
    assert user.token_version == 3
    session.scalar.assert_awaited_once()


async def test_successful_login_upgrades_a_stale_hash_after_rechecking_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    new_hash = "$argon2id$v=19$m=65536,t=3,p=4$new-salt-value-123$new-hash-value-123"
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=old_hash,
        password_changed_at=snapshot.password_changed_at,
        must_change_password=False,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=True,
            needs_rehash=True,
            used_dummy=False,
        )
    )
    manager.hash_verified_password = AsyncMock(return_value=new_hash)
    service = LocalAuthenticationService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    identity = await service.authenticate(
        abuse_flow=None,
        client_ip="127.0.0.1",
        user_name="alice",
        password="verified legacy password",
    )

    assert identity.user_id == snapshot.user_id
    assert user.password_hash == new_hash
    assert user.password_changed_at == snapshot.password_changed_at
    assert user.token_version == snapshot.token_version
    manager.hash_verified_password.assert_awaited_once_with("verified legacy password")


async def test_concurrent_stale_hash_upgrade_accepts_the_second_login_outside_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    current_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$current-salt-value$current-hash-value"
    )
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=current_hash,
        password_changed_at=snapshot.password_changed_at,
        must_change_password=False,
    )
    transaction_open = False
    events: list[str] = []

    class _Transaction:
        async def __aenter__(self) -> None:
            nonlocal transaction_open
            assert not transaction_open
            transaction_open = True
            events.append("transaction.enter")

        async def __aexit__(self, *_args: object) -> None:
            nonlocal transaction_open
            transaction_open = False
            events.append("transaction.exit")

    session = SimpleNamespace(begin=Mock(side_effect=_Transaction))
    session_factory = Mock(side_effect=lambda: _AsyncContext(session))
    manager = Mock()

    async def verify_or_dummy(
        _password: str,
        password_hash: str | None,
    ) -> PasswordVerification:
        assert not transaction_open
        if password_hash == old_hash:
            events.append("argon2.verify.old")
            return PasswordVerification(True, True, False)
        assert password_hash == current_hash
        events.append("argon2.verify.current")
        return PasswordVerification(True, False, False)

    async def lock_current_users(
        _session: object,
        _user_ids: set[uuid.UUID],
    ) -> dict[uuid.UUID, User]:
        assert transaction_open
        events.append("database.lock.user")
        return {snapshot.user_id: user}

    manager.verify_or_dummy = AsyncMock(side_effect=verify_or_dummy)
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$unused")
    service = LocalAuthenticationService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(authentication_service, "lock_users", lock_current_users)

    identity = await service.authenticate(
        abuse_flow=None,
        client_ip="127.0.0.1",
        user_name="alice",
        password="verified legacy password",
    )

    assert identity.user_id == snapshot.user_id
    assert identity.token_version == snapshot.token_version
    assert user.password_hash == current_hash
    assert events == [
        "argon2.verify.old",
        "transaction.enter",
        "database.lock.user",
        "transaction.exit",
        "argon2.verify.current",
        "transaction.enter",
        "database.lock.user",
        "transaction.exit",
    ]


async def test_concurrent_hash_only_change_must_be_a_current_verified_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    other_legacy_hash = (
        "$argon2id$v=19$m=32768,t=2,p=2$other-salt-value-1$other-hash-value-1"
    )
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=other_legacy_hash,
        password_changed_at=snapshot.password_changed_at,
        must_change_password=False,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        side_effect=[
            PasswordVerification(True, True, False),
            PasswordVerification(True, True, False),
        ]
    )
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$replacement")
    service = LocalAuthenticationService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="verified legacy password",
        )

    assert session.begin.call_count == 1


@pytest.mark.parametrize(
    "changed_state",
    ["token_version", "inactive", "password_changed_at", "password_hash", "temporary"],
)
async def test_concurrent_rehash_recheck_rejects_changed_authoritative_state(
    monkeypatch: pytest.MonkeyPatch,
    changed_state: str,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    current_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$current-salt-value$current-hash-value"
    )
    snapshot = _snapshot(password_hash=old_hash)
    first_user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=current_hash,
        password_changed_at=snapshot.password_changed_at,
        must_change_password=False,
    )
    assert snapshot.password_changed_at is not None
    second_user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=changed_state != "inactive",
        token_version=(
            snapshot.token_version + 1
            if changed_state == "token_version"
            else snapshot.token_version
        ),
        password_hash=(
            "$argon2id$changed" if changed_state == "password_hash" else current_hash
        ),
        password_changed_at=(
            snapshot.password_changed_at + timedelta(seconds=1)
            if changed_state == "password_changed_at"
            else snapshot.password_changed_at
        ),
        must_change_password=changed_state == "temporary",
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        side_effect=[
            PasswordVerification(True, True, False),
            PasswordVerification(True, False, False),
        ]
    )
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$replacement")
    service = LocalAuthenticationService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        AsyncMock(
            side_effect=[
                {snapshot.user_id: first_user},
                {snapshot.user_id: second_user},
            ]
        ),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="verified legacy password",
        )


async def test_login_rejects_token_version_change_before_hash_upgrade_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version + 1,
        password_hash=old_hash,
        password_changed_at=snapshot.password_changed_at,
        must_change_password=False,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(True, False, False)
    )
    manager.hash_verified_password = AsyncMock()
    service = LocalAuthenticationService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="verified password",
        )

    manager.hash_verified_password.assert_not_awaited()


async def test_concurrent_password_change_cancels_stale_hash_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    concurrent_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$concurrent-salt-12$concurrent-hash-12"
    )
    snapshot = _snapshot(password_hash=old_hash)
    assert snapshot.password_changed_at is not None
    user = User(
        id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=concurrent_hash,
        password_changed_at=snapshot.password_changed_at + timedelta(seconds=1),
        must_change_password=False,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=True,
            needs_rehash=True,
            used_dummy=False,
        )
    )
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$replacement")
    service = LocalAuthenticationService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        service,
        "_load_snapshot_by_user_name",
        AsyncMock(return_value=snapshot),
    )
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.authenticate(
            abuse_flow=None,
            client_ip="127.0.0.1",
            user_name="alice",
            password="verified legacy password",
        )

    assert user.password_hash == concurrent_hash


@pytest.mark.parametrize("holder_case", ["none", "different", "multiple"])
async def test_operator_reset_requires_the_exact_super_admin_holder_set(
    monkeypatch: pytest.MonkeyPatch,
    holder_case: str,
) -> None:
    user_id = uuid.uuid4()
    user = User(id=user_id, user_name="recovery-target", is_active=True)
    session = SimpleNamespace(
        add=Mock(),
        begin=Mock(return_value=_AsyncContext(None)),
    )
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.hash_new_password = AsyncMock(return_value="$argon2id$temporary")
    service = LocalAuthenticationService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )

    calls: list[str] = []

    async def lock_state(locked_session: object) -> None:
        assert locked_session is session
        calls.append("rbac_state")

    async def lock_target(
        locked_session: object,
        user_ids: set[uuid.UUID],
    ) -> dict[uuid.UUID, User]:
        assert locked_session is session
        assert user_ids == {user_id}
        calls.append("users")
        return {user_id: user}

    other_id = uuid.uuid4()
    holder_ids = {
        "none": frozenset(),
        "different": frozenset({other_id}),
        "multiple": frozenset({user_id, other_id}),
    }[holder_case]

    async def load_holders(locked_session: object) -> frozenset[uuid.UUID]:
        assert locked_session is session
        calls.append("holders")
        return holder_ids

    monkeypatch.setattr(authentication_service, "lock_rbac_state", lock_state)
    monkeypatch.setattr(
        authentication_service,
        "lock_users",
        lock_target,
    )
    monkeypatch.setattr(
        authentication_service,
        "load_live_super_admin_holder_ids",
        load_holders,
    )
    load_authority = AsyncMock()
    monkeypatch.setattr(
        authentication_service,
        "load_authority_snapshot",
        load_authority,
    )

    with pytest.raises(RbacError) as caught:
        await service.operator_reset_super_admin_password(
            user_id=user_id,
            temporary_password="temporary recovery password 42",
            request_id=str(uuid.uuid4()),
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "operator_reset_requires_sole_super_admin"
    assert calls == ["rbac_state", "users", "holders"]
    load_authority.assert_not_awaited()
    session.add.assert_not_called()


async def test_operator_reset_accepts_only_the_target_as_sole_super_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    request_id = str(uuid.uuid4())
    temporary_password = "temporary recovery password 42"
    user = User(
        id=user_id,
        user_name="recovery-target",
        is_active=True,
        token_version=7,
    )
    session = SimpleNamespace(
        add=Mock(),
        begin=Mock(return_value=_AsyncContext(None)),
    )
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.hash_new_password = AsyncMock(return_value="$argon2id$temporary")
    service = LocalAuthenticationService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    calls: list[str] = []

    async def lock_state(locked_session: object) -> None:
        assert locked_session is session
        calls.append("rbac_state")

    async def lock_target(
        locked_session: object,
        user_ids: set[uuid.UUID],
    ) -> dict[uuid.UUID, User]:
        assert locked_session is session
        assert user_ids == {user_id}
        calls.append("users")
        return {user_id: user}

    async def load_holders(locked_session: object) -> frozenset[uuid.UUID]:
        assert locked_session is session
        calls.append("holders")
        return frozenset({user_id})

    async def load_authority(
        locked_session: object,
        *,
        user_id: uuid.UUID,
        include_disabled_roles: bool,
    ) -> SimpleNamespace:
        assert locked_session is session
        assert user_id == user.id
        assert include_disabled_roles is True
        calls.append("authority")
        return SimpleNamespace(is_super_admin=True)

    rotate_password = AsyncMock()
    monkeypatch.setattr(authentication_service, "lock_rbac_state", lock_state)
    monkeypatch.setattr(authentication_service, "lock_users", lock_target)
    monkeypatch.setattr(
        authentication_service,
        "load_live_super_admin_holder_ids",
        load_holders,
    )
    monkeypatch.setattr(
        authentication_service,
        "load_authority_snapshot",
        load_authority,
    )
    monkeypatch.setattr(service, "_rotate_password", rotate_password)

    changed = await service.operator_reset_super_admin_password(
        user_id=user_id,
        temporary_password=temporary_password,
        request_id=request_id,
    )

    assert changed is True
    assert calls == ["rbac_state", "users", "holders", "authority"]
    assert user.token_version == 8
    rotate_password.assert_awaited_once_with(
        session,
        user=user,
        password_hash="$argon2id$temporary",
        must_change_password=True,
    )
    event = session.add.call_args.args[0]
    assert event.action == "account_security.password.operator_reset"
    assert event.reason_code == "operator_temporary_password_set"
    assert event.target_user_id == user_id
    assert event.request_id == request_id
