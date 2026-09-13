import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from argon2 import PasswordHasher
from argon2.low_level import Type
from httpx import AsyncClient
from sqlalchemy import select, text

from app.authentication_service import LocalAuthenticationService
from app.database import SessionFactory
from app.password_models import AccountSecurityAuditEvent, PasswordCredential
from app.passwords import PasswordManager, password_manager
from app.rbac.errors import RbacError
from app.rbac.models import Role, User, UserRole
from tests.integration.conftest import World

PASSWORD = "correct horse battery staple 47"
NEW_PASSWORD = "quiet river lantern mountain 82"
TEMPORARY_PASSWORD = "temporary meadow compass stone 63"
pytestmark = pytest.mark.postgresql


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
        json={"user_name": user_name, "password": password},
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(cast(str, response.json()["data"]["user_id"]))


async def _login(client: AsyncClient, user_name: str, password: str) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"user_name": user_name, "password": password},
    )
    assert response.status_code == 200, response.text
    return cast(str, response.json()["data"]["access_token"])


async def _enroll_existing_user(user: User, *, user_name: str, password: str) -> None:
    password_hash = await password_manager.hash_new_password(
        password,
        identity_values=(user_name, user.email or ""),
    )
    async with SessionFactory() as session:
        async with session.begin():
            stored = await session.scalar(
                select(User).where(User.id == user.id).with_for_update()
            )
            assert stored is not None
            stored.user_name = user_name
            session.add(
                PasswordCredential(
                    user_id=stored.id,
                    password_hash=password_hash,
                    version=1,
                    must_change_password=False,
                    created_by_user_id=None,
                )
            )


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
    access_token = await _login(client, "ALICE", PASSWORD)

    assert access_token
    async with SessionFactory() as session:
        user = await session.scalar(select(User).where(User.id == user_id))
        assert user is not None
        assert user.user_name == "alice"
        credential = await session.scalar(
            select(PasswordCredential).where(
                PasswordCredential.user_id == user.id,
                PasswordCredential.deleted_at.is_(None),
            )
        )
        assert credential is not None
        assert credential.password_hash is not None
        assert credential.password_hash.startswith("$argon2id$")
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


async def test_two_concurrent_logins_can_upgrade_one_legacy_hash(
    world: World,
) -> None:
    user_id = world.users["lower"].id
    user_name = "concurrent-rehash"
    legacy_hasher = PasswordHasher(
        time_cost=2,
        memory_cost=32_768,
        parallelism=2,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    legacy_hash = await asyncio.to_thread(legacy_hasher.hash, PASSWORD)
    credential_id = uuid.uuid4()

    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.user_name = user_name
            token_version = user.token_version
            session.add(
                PasswordCredential(
                    id=credential_id,
                    user_id=user_id,
                    password_hash=legacy_hash,
                    version=1,
                    must_change_password=False,
                )
            )

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
        credential = await session.scalar(
            select(PasswordCredential).where(
                PasswordCredential.user_id == user_id,
                PasswordCredential.deleted_at.is_(None),
            )
        )
    assert credential is not None
    assert credential.id == credential_id
    assert credential.version == 1
    assert credential.must_change_password is False
    assert credential.password_hash is not None
    assert credential.password_hash != legacy_hash
    verification = await password_manager.verify_or_dummy(
        PASSWORD,
        credential.password_hash,
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
            json={"user_name": "alice", "password": NEW_PASSWORD},
        ),
        await client.post(
            "/api/v1/auth/login",
            json={"user_name": "unknown", "password": NEW_PASSWORD},
        ),
        await client.post(
            "/api/v1/auth/login",
            json={"user_name": "passwordless", "password": NEW_PASSWORD},
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
        json={"user_name": "passwordless", "password": NEW_PASSWORD},
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


async def test_self_password_change_rotates_episode_and_revokes_old_token(
    client: AsyncClient,
) -> None:
    user_id = await _register(client, "alice", PASSWORD)
    old_token = await _login(client, "alice", PASSWORD)

    changed = await client.post(
        "/api/v1/me/password/change",
        headers={"Authorization": f"Bearer {old_token}"},
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
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
        json={"user_name": "alice", "password": PASSWORD},
    )
    assert wrong_old.status_code == 401
    assert await _login(client, "alice", NEW_PASSWORD)

    async with SessionFactory() as session:
        episodes = (
            await session.scalars(
                select(PasswordCredential)
                .where(PasswordCredential.user_id == user_id)
                .order_by(PasswordCredential.version)
            )
        ).all()
        assert [episode.version for episode in episodes] == [1, 2]
        assert episodes[0].password_hash is None
        assert episodes[0].deleted_at is not None
        assert episodes[1].password_hash is not None
        assert episodes[1].deleted_at is None


async def test_admin_reset_requires_reauth_and_forces_temporary_completion(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
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

    wrong_reauth = await client.post(
        f"/api/v1/users/{target_id}/password/reset",
        headers={"Authorization": f"Bearer {manager_token}"},
        json={
            "current_password": "wrong password candidate 93",
            "temporary_password": TEMPORARY_PASSWORD,
        },
    )
    assert wrong_reauth.status_code == 403
    assert await _login(client, "target", PASSWORD)

    reset = await client.post(
        f"/api/v1/users/{target_id}/password/reset",
        headers={"Authorization": f"Bearer {manager_token}"},
        json={
            "current_password": manager_password,
            "temporary_password": TEMPORARY_PASSWORD,
        },
    )
    assert reset.status_code == 200, reset.text

    old_token_is_revoked = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {old_target_token}"},
    )
    assert old_token_is_revoked.status_code == 401
    temporary_login = await client.post(
        "/api/v1/auth/login",
        json={"user_name": "target", "password": TEMPORARY_PASSWORD},
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

    hidden_peer = await client.post(
        f"/api/v1/users/{world.users['peer'].id}/password/reset",
        headers={"Authorization": f"Bearer {manager_token}"},
        json={
            "current_password": manager_password,
            "temporary_password": TEMPORARY_PASSWORD,
        },
    )
    assert hidden_peer.status_code == 404

    async with SessionFactory() as session:
        actions = set(
            await session.scalars(
                select(AccountSecurityAuditEvent.action).where(
                    AccountSecurityAuditEvent.target_user_id == target_id
                )
            )
        )
        assert "account_security.password.admin_reset" in actions
        assert "account_security.password.reset_completed" in actions


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
        credential = await session.scalar(
            select(PasswordCredential).where(
                PasswordCredential.user_id == target_id,
                PasswordCredential.deleted_at.is_(None),
            )
        )
        event = await session.scalar(
            select(AccountSecurityAuditEvent).where(
                AccountSecurityAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before
    assert credential is None
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
        credential = await session.scalar(
            select(PasswordCredential).where(
                PasswordCredential.user_id == target_id,
                PasswordCredential.deleted_at.is_(None),
            )
        )
        event = await session.scalar(
            select(AccountSecurityAuditEvent).where(
                AccountSecurityAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before + 1
    assert credential is not None
    assert credential.must_change_password is True
    assert credential.created_by_user_id is None
    assert credential.password_hash is not None
    assert credential.password_hash != TEMPORARY_PASSWORD
    assert event is not None
    assert event.action == "account_security.password.operator_reset"
    assert event.reason_code == "operator_temporary_password_set"
    assert event.target_user_id == target_id
