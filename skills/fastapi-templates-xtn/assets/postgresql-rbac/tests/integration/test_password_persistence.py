import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.security.passwords import DUMMY_PASSWORD_HASH
from app.db.postgres import SessionFactory
from app.models.access import User, UserRole
from app.models.account_security import AccountSecurityAuditEvent
from app.services.authentication import LocalAuthenticationService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def test_passwordless_user_has_no_password_state(world: World) -> None:
    async with SessionFactory() as session:
        user = await session.get(User, world.users["lower"].id)
    assert user is not None
    assert user.password_hash is None
    assert user.password_changed_at is None
    assert user.must_change_password is False


async def test_rotation_updates_same_user_row(world: World) -> None:
    user_id = world.users["lower"].id
    initial_token_version = world.users["lower"].token_version
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            await LocalAuthenticationService._rotate_password(
                session,
                user=user,
                password_hash=DUMMY_PASSWORD_HASH,
                must_change_password=True,
            )

    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.password_hash == DUMMY_PASSWORD_HASH
    assert user.password_changed_at is not None
    assert user.must_change_password is True
    assert user.token_version == initial_token_version


async def test_deleted_user_cannot_retain_password_hash(world: World) -> None:
    user_id = world.users["lower"].id
    changed_at = datetime.now(UTC)
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.password_hash = DUMMY_PASSWORD_HASH
            user.password_changed_at = changed_at

    with pytest.raises(DBAPIError) as caught:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE users SET deleted_at = :deleted_at, is_active = false "
                        "WHERE id = :user_id"
                    ),
                    {"deleted_at": changed_at, "user_id": user_id},
                )
    assert "ck_users_deleted_user_no_password" in str(caught.value)

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
            )
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.password_hash = None
            user.password_changed_at = None
            user.must_change_password = False
            user.is_active = False
            user.deleted_at = changed_at
            user.token_version += 1
            await session.execute(
                text(
                    "UPDATE user_roles SET deleted_at = :deleted_at, "
                    "deleted_by_user_id = :actor_id "
                    "WHERE user_id = :user_id AND deleted_at IS NULL"
                ),
                {
                    "deleted_at": changed_at,
                    "actor_id": world.users["super_admin"].id,
                    "user_id": user_id,
                },
            )

    async with SessionFactory() as session:
        deleted = await session.get(User, user_id)
        assert deleted is not None
        assert deleted.deleted_at is not None
        assert deleted.password_hash is None
        assert deleted.password_changed_at is None
        assert deleted.must_change_password is False
        previous_bindings = (
            await session.scalars(select(UserRole).where(UserRole.user_id == user_id))
        ).all()
        assert {binding.role_id for binding in previous_bindings} == {
            world.roles["user"].id,
            world.roles["viewer"].id,
        }
        assert all(binding.deleted_at is not None for binding in previous_bindings)

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
            )
            deleted = await session.get(User, user_id, with_for_update=True)
            assert deleted is not None
            deleted.deleted_at = None
            deleted.is_active = True
            session.add(UserRole(user_id=user_id, role_id=world.roles["user"].id))

    async with SessionFactory() as session:
        restored = await session.get(User, user_id)
    assert restored is not None
    assert restored.password_hash is None
    assert restored.must_change_password is False
    async with SessionFactory() as session:
        live_bindings = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.user_id == user_id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
    assert len(live_bindings) == 1
    assert live_bindings[0].role_id == world.roles["user"].id
    assert live_bindings[0].id not in {item.id for item in previous_bindings}


@pytest.mark.parametrize(
    "values",
    [
        {
            "password_hash": "not-an-argon2id-hash",
            "password_changed_at": datetime.now(UTC),
            "must_change_password": False,
        },
        {
            "password_hash": DUMMY_PASSWORD_HASH,
            "password_changed_at": None,
            "must_change_password": False,
        },
        {
            "password_hash": None,
            "password_changed_at": datetime.now(UTC),
            "must_change_password": False,
        },
        {
            "password_hash": None,
            "password_changed_at": None,
            "must_change_password": True,
        },
    ],
)
async def test_user_password_fields_reject_invalid_shapes(
    world: World,
    values: dict[str, object],
) -> None:
    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE users SET password_hash = :password_hash, "
                        "must_change_password = :must_change_password, "
                        "password_changed_at = :password_changed_at "
                        "WHERE id = :user_id"
                    ),
                    {
                        "user_id": world.users["lower"].id,
                        "password_hash": values["password_hash"],
                        "must_change_password": values["must_change_password"],
                        "password_changed_at": values["password_changed_at"],
                    },
                )


async def test_account_security_audit_rows_are_append_only(world: World) -> None:
    event_id = uuid.uuid4()
    request_id = str(uuid.uuid4())
    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                AccountSecurityAuditEvent(
                    id=event_id,
                    action="account_security.password.changed",
                    outcome="succeeded",
                    reason_code="password_changed",
                    actor_type="user",
                    actor_user_id=world.users["lower"].id,
                    target_user_id=world.users["lower"].id,
                    source="http",
                    request_id=request_id,
                )
            )

    for statement in (
        "UPDATE account_security_audit_events SET reason_code = 'rewritten' "
        "WHERE id = :event_id",
        "DELETE FROM account_security_audit_events WHERE id = :event_id",
        "TRUNCATE TABLE account_security_audit_events",
    ):
        with pytest.raises(DBAPIError):
            async with SessionFactory() as session:
                async with session.begin():
                    parameters = (
                        {"event_id": event_id} if ":event_id" in statement else {}
                    )
                    await session.execute(text(statement), parameters)

    async with SessionFactory() as session:
        persisted = await session.get(AccountSecurityAuditEvent, event_id)
    assert persisted is not None
    assert persisted.request_id == request_id
