import logging
import uuid
from collections.abc import Callable
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.audit import RbacAuditAction
from app.core.exceptions import AppError, conflict_409, forbidden_403, not_found_404
from app.core.ids import new_entity_id
from app.services import audit_service as audit_module
from app.services import user_role_transaction as service_module
from app.services.audit_service import AuditService

pytestmark = pytest.mark.usefixtures("audit_request_context")


class _AsyncContextManager:
    def __init__(self, value: object) -> None:
        self._value = value

    async def __aenter__(self) -> object:
        return self._value

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                        traceback: object) -> None:
        return None


class _Session:
    def begin(self) -> _AsyncContextManager:
        return _AsyncContextManager(self)


class _SessionFactory:
    def __call__(self) -> _AsyncContextManager:
        return _AsyncContextManager(_Session())


@pytest.mark.parametrize(
    ("error_factory", "expected_status"),
    ((forbidden_403, 403), (not_found_404, 404), (conflict_409, 409)),
    ids=("403", "404", "409"),
)
async def test_denied_audit_failure_preserves_original_rbac_error(
    monkeypatch: pytest.MonkeyPatch,
    unprivileged_authorization_context: AuthorizationContext,
    error_factory: Callable[[str], AppError],
    expected_status: int,
) -> None:
    original_error = error_factory("original_denial")
    audit_error = RuntimeError("audit-database-password")
    metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "RuntimeError",
    }
    session_factory = cast(async_sessionmaker[AsyncSession], _SessionFactory())
    build_denied_response = Mock(side_effect=audit_error)
    safe_log = Mock(return_value=False)
    safe_exception_metadata = Mock(return_value=metadata)
    monkeypatch.setattr(AuditService, "_response_snapshot", build_denied_response)
    monkeypatch.setattr(audit_module, "safe_log", safe_log)
    monkeypatch.setattr(
        audit_module,
        "safe_exception_metadata",
        safe_exception_metadata,
    )

    with pytest.raises(AppError) as caught:
        async with service_module.user_role_transaction(
            session_factory,
            context=unprivileged_authorization_context,
            action=RbacAuditAction.UPDATE_ROLE,
            target_role_id=new_entity_id("R"),
        ):
            raise original_error

    assert caught.value is original_error
    assert caught.value.status_code == expected_status
    build_denied_response.assert_called_once()
    safe_exception_metadata.assert_called_once_with(audit_error)
    safe_log.assert_called_once_with(
        audit_module.logger,
        logging.ERROR,
        "audit.write.failed",
        extra={"audit_action": "role.update", **metadata},
    )


async def test_success_audit_is_added_before_transaction_commit(
    unprivileged_authorization_context: AuthorizationContext,
    audit_request_context: str,
) -> None:
    session = Mock(spec=AsyncSession)
    transaction = AsyncMock()
    session.begin.return_value = transaction
    factory = Mock(return_value=_AsyncContextManager(session))
    target_role_id = new_entity_id("R")

    async with service_module.user_role_transaction(
        cast(async_sessionmaker[AsyncSession], factory),
        context=unprivileged_authorization_context,
        action=RbacAuditAction.UPDATE_ROLE,
        target_role_id=target_role_id,
    ) as active_session:
        assert active_session is session
        transaction.__aexit__.assert_not_awaited()
        audit = AuditService.audit_success(
            active_session, action=RbacAuditAction.UPDATE_ROLE,
            context=unprivileged_authorization_context, target_role_id=target_role_id,
            reason_code="role_updated", before_state={"name": "old"}, after_state={"name": "new"},
        )

    session.add.assert_called_once_with(audit)
    transaction.__aexit__.assert_awaited_once_with(None, None, None)
    assert audit.outcome == "succeeded"
    assert audit.category == "permission"
    assert audit.target_role_id == target_role_id
    assert audit.request_id == audit_request_context


@pytest.mark.parametrize("failure", ("business", "success_audit"))
async def test_transaction_failure_is_not_misreported_as_policy_denial(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    session = Mock(spec=AsyncSession)
    transaction = AsyncMock()
    session.begin.return_value = transaction
    factory = Mock(return_value=_AsyncContextManager(session))
    denied_audit = AsyncMock()
    monkeypatch.setattr(AuditService, "audit_denied", denied_audit)
    if failure == "success_audit":
        session.add.side_effect = RuntimeError("audit write failed")

    with pytest.raises(RuntimeError) as caught:
        async with service_module.user_role_transaction(
            cast(async_sessionmaker[AsyncSession], factory),
            context=unprivileged_authorization_context,
            action=RbacAuditAction.UPDATE_ROLE,
            target_role_id=new_entity_id("R"),
        ) as active_session:
            if failure == "business":
                raise RuntimeError("business failed")
            AuditService.audit_success(
                active_session, action=RbacAuditAction.UPDATE_ROLE,
                context=unprivileged_authorization_context, reason_code="role_updated",
            )

    denied_audit.assert_not_awaited()
    assert transaction.__aexit__.await_args.args[0] is RuntimeError
    assert transaction.__aexit__.await_args.args[1] is caught.value
