import logging
import uuid
from collections.abc import Callable
from typing import Never, cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import RbacError, conflict, forbidden, not_found
from app.core.security.domain import AuthorizationContext
from app.services import access as service_module
from app.services.access import RbacService


class _AsyncContextManager:
    def __init__(self, value: object) -> None:
        self._value = value

    async def __aenter__(self) -> object:
        return self._value

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        return None


class _Session:
    def begin(self) -> _AsyncContextManager:
        return _AsyncContextManager(self)


class _SessionFactory:
    def __call__(self) -> _AsyncContextManager:
        return _AsyncContextManager(_Session())


@pytest.mark.parametrize(
    ("error_factory", "expected_status"),
    ((forbidden, 403), (not_found, 404), (conflict, 409)),
    ids=("403", "404", "409"),
)
async def test_denied_audit_failure_preserves_original_rbac_error(
    monkeypatch: pytest.MonkeyPatch,
    unprivileged_authorization_context: AuthorizationContext,
    error_factory: Callable[[str], RbacError],
    expected_status: int,
) -> None:
    original_error = error_factory("original_denial")
    audit_error = RuntimeError("audit-database-password")
    metadata = {
        "error_id": str(uuid.uuid4()),
        "exception_type": "RuntimeError",
    }
    service = RbacService(cast(async_sessionmaker[AsyncSession], _SessionFactory()))
    write_denied_audit = AsyncMock(side_effect=audit_error)
    safe_log = Mock(return_value=False)
    safe_exception_metadata = Mock(return_value=metadata)
    monkeypatch.setattr(service, "_write_denied_audit", write_denied_audit)
    monkeypatch.setattr(service_module, "safe_log", safe_log)
    monkeypatch.setattr(
        service_module,
        "safe_exception_metadata",
        safe_exception_metadata,
    )

    async def deny(_session: AsyncSession) -> Never:
        raise original_error

    with pytest.raises(RbacError) as caught:
        await service._run_audited(
            context=unprivileged_authorization_context,
            action="role.update",
            target_user_id=None,
            target_role_id=uuid.uuid4(),
            operation=deny,
        )

    assert caught.value is original_error
    assert caught.value.status_code == expected_status
    write_denied_audit.assert_awaited_once()
    safe_exception_metadata.assert_called_once_with(audit_error)
    safe_log.assert_called_once_with(
        service_module.logger,
        logging.ERROR,
        "audit.write.failed",
        extra={"audit_action": "role.update", **metadata},
    )
