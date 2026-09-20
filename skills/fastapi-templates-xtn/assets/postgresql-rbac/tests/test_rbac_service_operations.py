import uuid
from typing import cast
from unittest.mock import Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.rbac.domain import AuthorizationContext
from app.rbac.service import RbacService, RoleOperation


def _service() -> tuple[RbacService, Mock]:
    session_factory = Mock()
    service = RbacService(
        cast(async_sessionmaker[AsyncSession], session_factory),
    )
    return service, session_factory


async def test_change_user_roles_rejects_unknown_operation_before_transaction(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    service, session_factory = _service()

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_user_roles(
            context=unprivileged_authorization_context,
            target_user_id=uuid.uuid4(),
            role_ids=(uuid.uuid4(),),
            operation=cast(RoleOperation, "biind"),
        )

    session_factory.assert_not_called()


async def test_role_permission_change_rejects_unknown_operation(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    service, session_factory = _service()

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_role_permissions(
            context=unprivileged_authorization_context,
            role_id=uuid.uuid4(),
            permission_ids=(uuid.uuid4(),),
            operation=cast(RoleOperation, "biind"),
            expected_version=0,
        )

    session_factory.assert_not_called()
