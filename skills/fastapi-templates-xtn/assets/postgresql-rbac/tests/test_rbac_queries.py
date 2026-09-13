import uuid
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.models import Role, User
from app.rbac.queries import (
    load_authority_snapshots_for_users,
    load_live_super_admin_holder_ids,
    load_role_grants_for_roles,
)


class _Rows:
    def __init__(self, *rows: SimpleNamespace) -> None:
        self._rows = rows

    def all(self) -> tuple[SimpleNamespace, ...]:
        return self._rows


def _session_returning(*rows: SimpleNamespace) -> tuple[AsyncSession, AsyncMock]:
    execute = AsyncMock(return_value=_Rows(*rows))
    session = cast(AsyncSession, SimpleNamespace(execute=execute))
    return session, execute


async def test_batch_authority_loader_uses_one_select_for_multiple_users() -> None:
    first_user = User(
        id=uuid.uuid4(),
        user_name="first",
        is_active=True,
        is_protected=False,
        token_version=3,
        authz_version=5,
    )
    second_user = User(
        id=uuid.uuid4(),
        user_name="second",
        is_active=False,
        is_protected=True,
        token_version=7,
        authz_version=11,
    )
    first_role_id = uuid.uuid4()
    second_role_id = uuid.uuid4()
    session, execute = _session_returning(
        SimpleNamespace(
            user_id=first_user.id,
            role_id=first_role_id,
            key="reader",
            management_tier=10,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
            permission_key="projects:read",
        ),
        SimpleNamespace(
            user_id=second_user.id,
            role_id=second_role_id,
            key="disabled-manager",
            management_tier=90,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
            permission_key="projects:update",
        ),
    )

    snapshots = await load_authority_snapshots_for_users(
        session,
        users=(first_user, second_user),
        include_disabled_roles=True,
    )

    execute.assert_awaited_once()
    assert snapshots[first_user.id].permissions == frozenset({"projects:read"})
    assert snapshots[first_user.id].authz_version == 5
    assert snapshots[second_user.id].permissions == frozenset({"projects:update"})
    assert not snapshots[second_user.id].user_is_active
    assert snapshots[second_user.id].is_protected


async def test_batch_role_grant_loader_uses_one_select_for_multiple_roles() -> None:
    roles = (
        Role(
            id=uuid.uuid4(),
            key="reader",
            name="Reader",
            management_tier=10,
            is_active=True,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        ),
        Role(
            id=uuid.uuid4(),
            key="writer",
            name="Writer",
            management_tier=20,
            is_active=True,
            is_system=False,
            is_protected=False,
            is_super_admin=False,
        ),
    )
    session, execute = _session_returning(
        SimpleNamespace(
            role_id=roles[0].id,
            permission_key="projects:read",
        ),
        SimpleNamespace(
            role_id=roles[1].id,
            permission_key="projects:update",
        ),
    )

    grants = await load_role_grants_for_roles(session, roles=roles)

    execute.assert_awaited_once()
    assert grants[roles[0].id].permissions == frozenset({"projects:read"})
    assert grants[roles[1].id].permissions == frozenset({"projects:update"})


async def test_super_admin_holder_loader_returns_the_complete_live_set() -> None:
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()
    scalars = AsyncMock(return_value=SimpleNamespace(all=lambda: [first_id, second_id]))
    session = cast(AsyncSession, SimpleNamespace(scalars=scalars))

    holder_ids = await load_live_super_admin_holder_ids(session)

    assert holder_ids == frozenset({first_id, second_id})
    scalars.assert_awaited_once()
