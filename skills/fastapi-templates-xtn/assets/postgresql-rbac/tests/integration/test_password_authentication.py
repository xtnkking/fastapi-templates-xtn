import asyncio
import secrets
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import cast

import pytest
from argon2 import PasswordHasher
from argon2.low_level import Type
from httpx import AsyncClient
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.errors import RbacError
from app.core.security.passwords import PasswordManager, password_manager
from app.db.postgres import SessionFactory
from app.main import app
from app.models.access import Role, User, UserRole
from app.models.account_security import AccountSecurityAuditEvent
from app.services.authentication import LocalAuthenticationService
from tests.integration.conftest import World

PASSWORD = "correct horse battery staple 47"
NEW_PASSWORD = "quiet river lantern mountain 82"
TEMPORARY_PASSWORD = "temporary meadow compass stone 63"
pytestmark = pytest.mark.postgresql


@pytest.fixture(autouse=True)
def known_captcha_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")


async def _captcha(
    client: AsyncClient, scene: str, token: str | None = None
) -> dict[str, str]:
    endpoint = "/api/v1/auth/captcha" if token is None else "/api/v1/me/captcha"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = await client.post(endpoint, json={"scene": scene}, headers=headers)
    assert response.status_code == 200, response.text
    return {
        "captcha_id": response.json()["data"]["captcha_id"],
        "captcha_answer": "AAAAA",
    }


class _ConcurrentRehashPasswordManager(PasswordManager):
    def __init__(self) -> None:
        super().__init__()
        self._rehash_barrier = asyncio.Barrier(2)
        self.rehash_calls = 0

    async def hash_verified_password(self, password: str) -> str:
        replacement = await super().hash_verified_password(password)
        self.rehash_calls += 1
        await self._rehash_barrier.wait()
        return replacement


async def _register(client: AsyncClient, user_name: str, password: str) -> uuid.UUID:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "user_name": user_name,
            "password": password,
            **await _captcha(client, "register"),
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(cast(str, response.json()["data"]["user_id"]))


async def _login(client: AsyncClient, user_name: str, password: str) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": user_name,
            "password": password,
            **await _captcha(client, "login"),
        },
    )
    assert response.status_code == 200, response.text
    return cast(str, response.json()["data"]["access_token"])


async def _enroll_existing_user(user: User, *, user_name: str, password: str) -> None:
    password_hash = await password_manager.hash_new_password(
        password,
        identity_values=(user_name,),
    )
    async with SessionFactory() as session:
        async with session.begin():
            stored = await session.scalar(
                select(User).where(User.id == user.id).with_for_update()
            )
            assert stored is not None
            stored.user_name = user_name
            stored.password_hash = password_hash
            stored.password_changed_at = datetime.now(UTC)


async def _replace_live_super_admin_holders(
    world: World,
    holder_names: tuple[str, ...],
) -> None:
    """Create a deliberately corrupt holder set to exercise the operator guard."""

    role_id = world.roles["super_admin"].id
    actor_id = world.users["super_admin"].id
    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text(
                    "ALTER TABLE user_roles DISABLE TRIGGER "
                    "ct_user_roles_exactly_one_super_admin"
                )
            )
    try:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE user_roles "
                        "SET deleted_at = statement_timestamp(), "
                        "deleted_by_user_id = :actor_id "
                        "WHERE role_id = :role_id AND deleted_at IS NULL"
                    ),
                    {"actor_id": actor_id, "role_id": role_id},
                )
                session.add_all(
                    UserRole(
                        user_id=world.users[name].id,
                        role_id=role_id,
                        assigned_by_user_id=actor_id,
                    )
                    for name in holder_names
                )
    finally:
        # PostgreSQL cannot alter the table after queued trigger events in the
        # same transaction; restore protection even when the corrupt setup fails.
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "ALTER TABLE user_roles ENABLE TRIGGER "
                        "ct_user_roles_exactly_one_super_admin"
                    )
                )


async def test_registration_and_login_persist_complete_local_identity(
    client: AsyncClient,
) -> None:
    user_id = await _register(client, "  Alice  ", PASSWORD)
    access_token = await _login(client, "Alice", PASSWORD)

    assert access_token
    async with SessionFactory() as session:
        user = await session.scalar(select(User).where(User.id == user_id))
        assert user is not None
        assert user.user_name == "Alice"
        assert user.password_hash is not None
        assert user.password_hash.startswith("$argon2id$")
        assert user.password_changed_at is not None
        assert user.must_change_password is False
        role_key = await session.scalar(
            select(Role.key)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == user.id,
                UserRole.deleted_at.is_(None),
            )
        )
        assert role_key == "user"
        account_event = await session.scalar(
            select(AccountSecurityAuditEvent).where(
                AccountSecurityAuditEvent.target_user_id == user.id
            )
        )
        assert account_event is not None
        assert account_event.action == "account_security.registration.completed"


async def test_registration_toggle_blocks_public_creation_but_not_admin_creation(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
) -> None:
    public_status = await client.get("/api/v1/auth/registration/status")
    assert public_status.json()["data"] == {"registration_enabled": True}
    super_token = await access_token(world.users["super_admin"])
    changed = await client.post(
        "/api/v1/auth/registration/status",
        headers={"Authorization": f"Bearer {super_token}"},
        json={"registration_enabled": False},
    )
    assert changed.status_code == 200, changed.text
    assert (await client.get("/api/v1/auth/registration/status")).json()["data"] == {
        "registration_enabled": False
    }
    rejected = await client.post(
        "/api/v1/auth/register",
        json={
            "user_name": "closed_new_user",
            "password": PASSWORD,
            **await _captcha(client, "register"),
        },
    )
    assert rejected.status_code == 403
    assert rejected.json()["message"] == "暂未开放注册"

    manager_token = await access_token(world.users["manager"])
    created = await client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {manager_token}"},
        json={
            "user_name": "admin_created_user",
            "temporary_password": TEMPORARY_PASSWORD,
            **await _captcha(client, "admin_create", manager_token),
        },
    )
    assert created.status_code == 201, created.text
    user_id = uuid.UUID(created.json()["data"]["user_id"])
    async with SessionFactory() as session:
        user = await session.get(User, user_id)
        assert user is not None and user.must_change_password
        assigned = await session.scalar(
            select(Role.key)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id, UserRole.deleted_at.is_(None))
        )
        assert assigned == "user"


async def test_two_concurrent_logins_can_upgrade_one_legacy_hash(
    world: World,
) -> None:
    user_id = world.users["lower"].id
    user_name = "concurrent_rehash"
    legacy_hasher = PasswordHasher(
        time_cost=2,
        memory_cost=32_768,
        parallelism=2,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    legacy_hash = await asyncio.to_thread(legacy_hasher.hash, PASSWORD)
    changed_at = datetime.now(UTC)

    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.user_name = user_name
            token_version = user.token_version
            user.password_hash = legacy_hash
            user.password_changed_at = changed_at

    manager = _ConcurrentRehashPasswordManager()
    service = LocalAuthenticationService(SessionFactory, manager)
    async with asyncio.timeout(30):
        first, second = await asyncio.gather(
            service.authenticate(
                abuse_flow=None,
                client_ip="127.0.0.1",
                user_name=user_name,
                password=PASSWORD,
            ),
            service.authenticate(
                abuse_flow=None,
                client_ip="127.0.0.2",
                user_name=user_name,
                password=PASSWORD,
            ),
        )

    assert first.user_id == second.user_id == user_id
    assert first.token_version == second.token_version == token_version
    assert manager.rehash_calls == 2
    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.password_changed_at == changed_at
    assert user.token_version == token_version
    assert user.must_change_password is False
    assert user.password_hash is not None
    assert user.password_hash != legacy_hash
    verification = await password_manager.verify_or_dummy(
        PASSWORD,
        user.password_hash,
    )
    assert verification.verified is True
    assert verification.needs_rehash is False


async def test_unknown_wrong_and_passwordless_logins_share_one_response(
    client: AsyncClient,
    world: World,
) -> None:
    await _register(client, "alice", PASSWORD)
    responses = [
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "alice",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "unknown",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "passwordless",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
    ]
    async with SessionFactory() as session:
        passwordless = await session.get(User, world.users["blank"].id)
        assert passwordless is not None
        passwordless.user_name = "passwordless"
        await session.commit()

    # Re-run after the passwordless identity exists; it must still look unknown.
    responses[-1] = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": "passwordless",
            "password": NEW_PASSWORD,
            **await _captcha(client, "login"),
        },
    )
    public_shapes = []
    for response in responses:
        assert response.status_code == 401
        body = response.json()
        assert body["code"] == 401001
        assert body["data"] is None
        assert response.headers["WWW-Authenticate"] == "Bearer"
        public_shapes.append((body["code"], body["message"], body["data"]))
    assert len(set(public_shapes)) == 1


async def test_self_password_change_updates_user_and_revokes_old_token(
    client: AsyncClient,
) -> None:
    user_id = await _register(client, "alice", PASSWORD)
    old_token = await _login(client, "alice", PASSWORD)
    async with SessionFactory() as session:
        before = await session.get(User, user_id)
        assert before is not None
        old_hash = before.password_hash
        old_changed_at = before.password_changed_at
        old_token_version = before.token_version

    changed = await client.post(
        "/api/v1/me/password/change",
        headers={"Authorization": f"Bearer {old_token}"},
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            **await _captcha(client, "self_change", old_token),
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["data"] == {"changed": True}

    revoked = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert revoked.status_code == 401
    wrong_old = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": "alice",
            "password": PASSWORD,
            **await _captcha(client, "login"),
        },
    )
    assert wrong_old.status_code == 401
    assert await _login(client, "alice", NEW_PASSWORD)

    async with SessionFactory() as session:
        after = await session.get(User, user_id)
        assert after is not None
        assert after.password_hash is not None
        assert after.password_hash != old_hash
        assert after.must_change_password is False
        assert after.password_changed_at is not None
        assert old_changed_at is not None
        assert after.password_changed_at >= old_changed_at
        assert after.token_version == old_token_version + 1


@pytest.mark.parametrize(
    ("reset_mode", "password_change_required"),
    [("direct", False), ("temporary", True)],
)
async def test_admin_reset_supports_direct_and_temporary_project_modes(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
    reset_mode: str,
    password_change_required: bool,
) -> None:
    manager_password = "silver orchard window planet 94"
    await _enroll_existing_user(
        world.users["manager"],
        user_name="manager",
        password=manager_password,
    )
    manager_token = await access_token(world.users["manager"])
    target_id = await _register(client, "target", PASSWORD)
    old_target_token = await _login(client, "target", PASSWORD)
    selected_settings = get_settings().model_copy(
        update={"admin_password_reset_mode": reset_mode}
    )
    app.dependency_overrides[get_settings] = lambda: selected_settings

    try:
        missing_captcha = await client.post(
            f"/api/v1/users/{target_id}/password/reset",
            headers={"Authorization": f"Bearer {manager_token}"},
            json={"new_password": TEMPORARY_PASSWORD},
        )
        assert missing_captcha.status_code == 422
        assert await _login(client, "target", PASSWORD)

        reset = await client.post(
            f"/api/v1/users/{target_id}/password/reset",
            headers={"Authorization": f"Bearer {manager_token}"},
            json={
                "new_password": TEMPORARY_PASSWORD,
                **await _captcha(client, "admin_reset", manager_token),
            },
        )
        assert reset.status_code == 200, reset.text
        assert ("临时密码" in reset.json()["message"]) is password_change_required
        async with SessionFactory() as session:
            reset_user = await session.get(User, target_id)
            reset_event = await session.scalar(
                select(AccountSecurityAuditEvent).where(
                    AccountSecurityAuditEvent.target_user_id == target_id,
                    AccountSecurityAuditEvent.action
                    == "account_security.password.admin_reset",
                )
            )
        assert reset_user is not None
        assert reset_user.must_change_password is password_change_required
        assert reset_user.password_hash is not None
        assert reset_user.password_changed_at is not None
        assert reset_event is not None
        assert reset_event.reason_code == (
            "temporary_password_set"
            if password_change_required
            else "permanent_password_set"
        )

        old_token_is_revoked = await client.get(
            "/api/v1/me/access",
            headers={"Authorization": f"Bearer {old_target_token}"},
        )
        assert old_token_is_revoked.status_code == 401

        if password_change_required:
            temporary_login = await client.post(
                "/api/v1/auth/login",
                json={
                    "user_name": "target",
                    "password": TEMPORARY_PASSWORD,
                    **await _captcha(client, "login"),
                },
            )
            assert temporary_login.status_code == 403
            assert temporary_login.json()["code"] == 403002
            assert "access_token" not in temporary_login.text

            completed = await client.post(
                "/api/v1/auth/password/reset/complete",
                json={
                    "user_name": "target",
                    "temporary_password": TEMPORARY_PASSWORD,
                    "new_password": NEW_PASSWORD,
                },
            )
            assert completed.status_code == 200, completed.text
            assert "access_token" not in completed.text
            assert await _login(client, "target", NEW_PASSWORD)
            async with SessionFactory() as session:
                completed_user = await session.get(User, target_id)
                completed_event = await session.scalar(
                    select(AccountSecurityAuditEvent).where(
                        AccountSecurityAuditEvent.target_user_id == target_id,
                        AccountSecurityAuditEvent.action
                        == "account_security.password.reset_completed",
                    )
                )
            assert completed_user is not None
            assert completed_user.must_change_password is False
            assert completed_user.password_hash is not None
            assert completed_user.password_hash != reset_user.password_hash
            assert completed_user.password_changed_at is not None
            assert completed_user.password_changed_at >= reset_user.password_changed_at
            assert completed_event is not None
        else:
            assert await _login(client, "target", TEMPORARY_PASSWORD)

        hidden_peer = await client.post(
            f"/api/v1/users/{world.users['peer'].id}/password/reset",
            headers={"Authorization": f"Bearer {manager_token}"},
            json={
                "new_password": TEMPORARY_PASSWORD,
                **await _captcha(client, "admin_reset", manager_token),
            },
        )
        assert hidden_peer.status_code == 404
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.parametrize(
    "holder_names",
    [(), ("manager",), ("super_admin", "manager")],
    ids=["no-holder", "different-sole-holder", "multiple-holders"],
)
async def test_operator_reset_rejects_every_non_exact_holder_set(
    world: World,
    holder_names: tuple[str, ...],
) -> None:
    await _replace_live_super_admin_holders(world, holder_names)
    target_id = world.users["super_admin"].id
    token_version_before = world.users["super_admin"].token_version
    request_id = f"operator-reject-{uuid.uuid4()}"
    service = LocalAuthenticationService(SessionFactory, password_manager)

    with pytest.raises(RbacError) as caught:
        await service.operator_reset_super_admin_password(
            user_id=target_id,
            temporary_password=TEMPORARY_PASSWORD,
            request_id=request_id,
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "operator_reset_requires_sole_super_admin"
    async with SessionFactory() as session:
        target = await session.get(User, target_id)
        event = await session.scalar(
            select(AccountSecurityAuditEvent).where(
                AccountSecurityAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before
    assert target.password_hash is None
    assert target.password_changed_at is None
    assert event is None


async def test_operator_reset_rotates_the_correct_sole_holder_atomically(
    world: World,
) -> None:
    target_id = world.users["super_admin"].id
    token_version_before = world.users["super_admin"].token_version
    request_id = f"operator-success-{uuid.uuid4()}"
    service = LocalAuthenticationService(SessionFactory, password_manager)

    changed = await service.operator_reset_super_admin_password(
        user_id=target_id,
        temporary_password=TEMPORARY_PASSWORD,
        request_id=request_id,
    )

    assert changed is True
    async with SessionFactory() as session:
        target = await session.get(User, target_id)
        event = await session.scalar(
            select(AccountSecurityAuditEvent).where(
                AccountSecurityAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before + 1
    assert target.must_change_password is True
    assert target.password_changed_at is not None
    assert target.password_hash is not None
    assert target.password_hash != TEMPORARY_PASSWORD
    assert event is not None
    assert event.action == "account_security.password.operator_reset"
    assert event.reason_code == "operator_temporary_password_set"
    assert event.target_user_id == target_id
