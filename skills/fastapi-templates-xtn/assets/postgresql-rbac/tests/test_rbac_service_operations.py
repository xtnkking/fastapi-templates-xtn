import uuid
from typing import cast
from unittest.mock import Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.rbac.domain import AuthoritySnapshot, AuthorizationContext, Principal
from app.rbac.service import RbacService, RoleOperation


def _context() -> AuthorizationContext:
    principal = Principal(
        user_id=uuid.uuid4(),
        token_version=1,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )
    return AuthorizationContext(
        principal=principal,
        authorization_epoch=0,
        authority=AuthoritySnapshot.build(
            user_id=principal.user_id,
            user_is_active=True,
            user_is_protected=False,
            token_version=principal.token_version,
            authz_version=0,
            roles=(),
        ),
        request_id=str(uuid.uuid4()),
    )


def _service() -> tuple[RbacService, Mock]:
    session_factory = Mock()
    service = RbacService(
        cast(async_sessionmaker[AsyncSession], session_factory),
    )
    return service, session_factory


def _misspelled_operation() -> RoleOperation:
    return cast(RoleOperation, "biind")


async def test_change_user_roles_rejects_unknown_operation_before_transaction() -> None:
    service, session_factory = _service()

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_user_roles(
            context=_context(),
            target_user_id=uuid.uuid4(),
            role_ids=(uuid.uuid4(),),
            operation=_misspelled_operation(),
        )

    session_factory.assert_not_called()


async def test_role_permission_change_rejects_unknown_operation() -> None:
    service, session_factory = _service()

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_role_permissions(
            context=_context(),
            role_id=uuid.uuid4(),
            permission_ids=(uuid.uuid4(),),
            operation=_misspelled_operation(),
            expected_version=0,
        )

    session_factory.assert_not_called()


async def test_role_delegation_change_rejects_unknown_operation() -> None:
    service, session_factory = _service()

    with pytest.raises(ValueError, match="operation must be 'bind' or 'unbind'"):
        await service.change_role_delegation(
            context=_context(),
            role_id=uuid.uuid4(),
            permission_ids=(uuid.uuid4(),),
            operation=_misspelled_operation(),
            expected_version=0,
        )

    session_factory.assert_not_called()
