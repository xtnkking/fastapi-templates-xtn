import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.authentication_service import LocalAuthenticationService
from app.database import SessionFactory
from app.password_models import AccountSecurityAuditEvent, PasswordCredential
from app.passwords import DUMMY_PASSWORD_HASH
from app.rbac.models import User
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def test_only_one_live_password_credential_is_allowed_per_user(
    world: World,
) -> None:
    user_id = world.users["lower"].id
    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                PasswordCredential(
                    user_id=user_id,
                    password_hash=DUMMY_PASSWORD_HASH,
                )
            )

    with pytest.raises(DBAPIError) as caught:
        async with SessionFactory() as session:
            async with session.begin():
                session.add(
                    PasswordCredential(
                        user_id=user_id,
                        password_hash=DUMMY_PASSWORD_HASH,
                        version=2,
                    )
                )

    assert "uq_user_password_credentials_live_user" in str(caught.value)


async def test_tombstone_clears_hash_and_a_later_episode_gets_a_new_id(
    world: World,
) -> None:
    user_id = world.users["lower"].id
    actor_id = world.users["super_admin"].id
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()

    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                PasswordCredential(
                    id=first_id,
                    user_id=user_id,
                    password_hash=DUMMY_PASSWORD_HASH,
                    must_change_password=True,
                )
            )

    async with SessionFactory() as session:
        async with session.begin():
            first = await session.get(
                PasswordCredential, first_id, with_for_update=True
            )
            assert first is not None
            first.password_hash = None
            first.must_change_password = False
            first.deleted_at = await session.scalar(
                text("SELECT statement_timestamp()")
            )
            first.deleted_by_user_id = actor_id
            session.add(
                PasswordCredential(
                    id=second_id,
                    user_id=user_id,
                    password_hash=DUMMY_PASSWORD_HASH,
                    version=2,
                )
            )

    async with SessionFactory() as session:
        episodes = (
            await session.scalars(
                select(PasswordCredential)
                .where(PasswordCredential.user_id == user_id)
                .order_by(PasswordCredential.version)
            )
        ).all()

    assert [item.id for item in episodes] == [first_id, second_id]
    assert episodes[0].password_hash is None
    assert episodes[0].deleted_at is not None
    assert episodes[1].password_hash == DUMMY_PASSWORD_HASH
    assert episodes[1].deleted_at is None


async def test_rotation_uses_the_next_historical_version_without_a_live_episode(
    world: World,
) -> None:
    user_id = world.users["lower"].id
    actor_id = world.users["super_admin"].id
    retired_id = uuid.uuid4()

    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                PasswordCredential(
                    id=retired_id,
                    user_id=user_id,
                    password_hash=None,
                    version=7,
                    must_change_password=False,
                    deleted_at=datetime.now(UTC),
                    deleted_by_user_id=actor_id,
                )
            )

    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            created = await LocalAuthenticationService._rotate_password(
                session,
                user=user,
                password_hash=DUMMY_PASSWORD_HASH,
                must_change_password=True,
                created_by_user_id=actor_id,
            )
            await session.flush()
            created_id = created.id

    async with SessionFactory() as session:
        episodes = (
            await session.scalars(
                select(PasswordCredential)
                .where(PasswordCredential.user_id == user_id)
                .order_by(PasswordCredential.version)
            )
        ).all()

    assert [(episode.id, episode.version) for episode in episodes] == [
        (retired_id, 7),
        (created_id, 8),
    ]
    assert episodes[0].password_hash is None
    assert episodes[1].password_hash == DUMMY_PASSWORD_HASH
    assert episodes[1].must_change_password is True


@pytest.mark.parametrize(
    "values",
    [
        {
            "password_hash": "not-an-argon2id-hash",
            "deleted_at": None,
            "must_change_password": False,
        },
        {
            "password_hash": DUMMY_PASSWORD_HASH,
            "deleted_at": datetime.now(UTC),
            "must_change_password": False,
        },
        {
            "password_hash": None,
            "deleted_at": None,
            "must_change_password": False,
        },
        {
            "password_hash": None,
            "deleted_at": datetime.now(UTC),
            "must_change_password": True,
        },
    ],
)
async def test_database_rejects_invalid_credential_shapes(
    world: World,
    values: dict[str, object],
) -> None:
    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "INSERT INTO user_password_credentials "
                        "(id, user_id, password_hash, must_change_password, "
                        "deleted_at) VALUES "
                        "(:id, :user_id, :password_hash, :must_change_password, "
                        ":deleted_at)"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "user_id": world.users["lower"].id,
                        "password_hash": values["password_hash"],
                        "must_change_password": values["must_change_password"],
                        "deleted_at": values["deleted_at"],
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
