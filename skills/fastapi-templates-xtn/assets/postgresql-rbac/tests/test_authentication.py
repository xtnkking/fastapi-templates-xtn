import uuid
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import authentication
from app.rbac.domain import AuthoritySnapshot, AuthorizationContext, Principal
from app.rbac.errors import RbacError
from app.rbac.models import User


def make_context(*, user_id: uuid.UUID, token_version: int) -> AuthorizationContext:
    authority = AuthoritySnapshot.build(
        user_id=user_id,
        user_is_active=True,
        user_is_protected=False,
        token_version=token_version,
        authz_version=0,
        roles=(),
    )
    return AuthorizationContext(
        principal=Principal(
            user_id=user_id,
            token_version=token_version,
            token_id=uuid.uuid4(),
            issued_at=1,
            expires_at=2,
        ),
        authorization_epoch=0,
        authority=authority,
        request_id=str(uuid.uuid4()),
    )


def make_service() -> tuple[
    authentication.AccessTokenRevocationService,
    AsyncMock,
]:
    session = AsyncMock(spec=AsyncSession)
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    transaction = AsyncMock()
    transaction.__aenter__.return_value = transaction
    transaction.__aexit__.return_value = False
    session.begin.return_value = transaction
    factory = MagicMock(return_value=session)
    service = authentication.AccessTokenRevocationService(
        cast(async_sessionmaker[AsyncSession], factory)
    )
    return service, session


async def test_logout_all_increments_version_after_authoritative_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session = make_service()
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        email="current@example.test",
        is_active=True,
        token_version=7,
    )
    lock_state = AsyncMock()
    lock_user_rows = AsyncMock(return_value={user_id: user})
    monkeypatch.setattr(authentication, "lock_rbac_state", lock_state)
    monkeypatch.setattr(authentication, "lock_users", lock_user_rows)

    await service.revoke_all_for_current_user(
        context=make_context(user_id=user_id, token_version=7)
    )

    assert user.token_version == 8
    lock_state.assert_awaited_once_with(session)
    lock_user_rows.assert_awaited_once_with(session, {user_id})


@pytest.mark.parametrize("missing", [False, True])
async def test_logout_all_rejects_missing_or_already_revoked_identity(
    monkeypatch: pytest.MonkeyPatch,
    missing: bool,
) -> None:
    service, _session = make_service()
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        email="current@example.test",
        is_active=True,
        token_version=8,
    )
    monkeypatch.setattr(authentication, "lock_rbac_state", AsyncMock())
    monkeypatch.setattr(
        authentication,
        "lock_users",
        AsyncMock(return_value={} if missing else {user_id: user}),
    )

    with pytest.raises(RbacError) as caught:
        await service.revoke_all_for_current_user(
            context=make_context(user_id=user_id, token_version=7)
        )

    assert caught.value.status_code == 401
    assert user.token_version == 8
