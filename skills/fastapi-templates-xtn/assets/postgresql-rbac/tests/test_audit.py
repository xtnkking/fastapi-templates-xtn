#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查授权审计字段、载荷过滤和标识符校验。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/10    XTN       V1.000        对齐审计 user_id 命名并补充文件职责记录
# 2026/10/16    XTN       V1.001        验证审计自动关联请求上下文、并发隔离及请求结束失效
# 2026/10/24    XTN       V1.002        授权事务省略无关目标并继续验证审计关联 ID
# 2026/10/24    XTN       V1.003        使用 user_role_transaction 事务入口
# --------------------------------------------------------------------------------------------------

import asyncio
import uuid
from contextvars import Context, copy_context
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.commands import reset_super_admin_password as operator_command
from app.core.access.authorization import AuthorizationContext
from app.core.audit import (
    AccountAuditAction,
    AuditSource,
    RbacAuditAction,
    get_audit_request_id,
    sanitize_audit_state,
    validate_audit_action,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.core.business_audit import (
    BusinessAuditActionSpec,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    BusinessAuditSourceType,
)
from app.core.ids import new_audit_id, new_entity_id
from app.core.logging.context import (
    bind_request_context,
    current_request_id,
    deactivate_request_context,
    reset_request_context,
)
from app.core.security.passwords import password_manager
from app.db.postgres_db import SessionFactory
from app.models.postgres.operation_audit import OperationAuditEvent
from app.services.audit_service import AuditService
from app.services.business_audit_service import BusinessAuditService
from app.services.user_role_transaction import user_role_transaction


def test_audit_request_id_rejects_missing_context_without_generating_an_id() -> None:
    assert current_request_id() is None

    with pytest.raises(RuntimeError):
        get_audit_request_id()

    assert current_request_id() is None


def test_audit_request_id_reuses_the_bound_id_until_request_end() -> None:
    request_id = str(uuid.uuid4())
    token = bind_request_context(request_id)
    copied_context = copy_context()
    try:
        assert get_audit_request_id() == request_id
        assert copied_context.run(get_audit_request_id) == request_id
        deactivate_request_context()
        with pytest.raises(RuntimeError):
            get_audit_request_id()
        with pytest.raises(RuntimeError):
            copied_context.run(get_audit_request_id)
    finally:
        deactivate_request_context()
        reset_request_context(token)

    assert current_request_id() is None
    with pytest.raises(RuntimeError):
        copied_context.run(get_audit_request_id)


async def test_audit_request_ids_stay_isolated_between_concurrent_operations() -> None:
    barrier = asyncio.Barrier(2)
    request_ids = (str(uuid.uuid4()), str(uuid.uuid4()))

    async def audit_operation(request_id: str) -> tuple[str, str]:
        """
            同时启动两个操作，确保切换协程后仍读取各自入口的关联 ID。

        :param request_id: 当前操作入口生成的请求 ID。
        :return: 两次读取的请求 ID；函数退出时清理当前操作上下文。
        """
        token = bind_request_context(request_id)
        try:
            before_switch = get_audit_request_id()
            await barrier.wait()
            return before_switch, get_audit_request_id()
        finally:
            deactivate_request_context()
            reset_request_context(token)

    observed = await asyncio.gather(*(audit_operation(request_id) for request_id in request_ids))

    assert observed == [(request_id, request_id) for request_id in request_ids]
    assert current_request_id() is None


async def test_rbac_account_and_business_audits_share_the_operation_request_id(
    audit_request_context: str,
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    session = Mock(spec=AsyncSession)
    session.begin.return_value = AsyncMock()
    session_context = AsyncMock()
    session_context.__aenter__.return_value = session
    factory = cast(async_sessionmaker[AsyncSession], Mock(return_value=session_context))
    user_id = unprivileged_authorization_context.login_info.user_id
    action = "project.settings.update"
    business_audit = BusinessAuditService(
        factory,
        {
            action: BusinessAuditActionSpec(
                domain="project",
                action=action,
                target_type="project",
                allowed_outcomes=frozenset({BusinessAuditOutcome.SUCCEEDED}),
                reason_codes=frozenset({"settings_updated"}),
                source_types=frozenset({BusinessAuditSourceType.USER}),
            ),
        },
    )

    async with user_role_transaction(
        factory,
        context=unprivileged_authorization_context,
        action=RbacAuditAction.CREATE_USER,
        target_user_id=user_id,
    ) as active_session:
        rbac_event = AuditService.audit_success(
            active_session, action=RbacAuditAction.CREATE_USER,
            context=unprivileged_authorization_context, target_user_id=user_id,
            reason_code="user_created",
        )
        account_event = AuditService.audit_success(
            active_session,
            action=AccountAuditAction.REGISTER_USER,
            reason_code="registration_completed",
            context=unprivileged_authorization_context,
            target_user_id=user_id,
            source=AuditSource.HTTP,
        )
        business_event = business_audit.add_succeeded(
            active_session,
            BusinessAuditFacts(
                event_id=new_audit_id("BA"),
                action=action,
                source_type=BusinessAuditSourceType.USER,
                user_id=user_id,
                target_id=str(uuid.uuid4()),
                reason_code="settings_updated",
                entrypoint=AuditSource.HTTP,
            ),
        )

    assert {event.request_id for event in (rbac_event, account_event, business_event)} == {audit_request_context}
    assert [call.args[0] for call in session.add.call_args_list] == [rbac_event, account_event, business_event]


@pytest.mark.parametrize("failure", [None, "service", "dispose"])
async def test_operator_entrypoint_restores_context_even_when_reset_or_dispose_fails(
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    user_id = new_entity_id("U")
    password = "operator-password-42"
    observed_ids: list[str] = []
    copied_contexts: list[Context] = []
    error = RuntimeError("controlled operation failure")

    async def reset_password(**kwargs: str) -> bool:
        """
            在维护服务边界记录入口已绑定的 ID，不访问数据库或计算密码哈希。

        :param kwargs: 入口必须仅传递的目标用户 ID 和新密码。
        :return: 成功时返回 True；service 场景抛出受控异常。
        """
        assert kwargs == {"user_id": user_id, "new_password": password}
        observed_ids.append(get_audit_request_id())
        copied_contexts.append(copy_context())
        if failure == "service":
            raise error
        return True

    async def dispose() -> None:
        """
            记录连接池释放仍属于同一次维护操作，并模拟资源清理失败。

        :return: 无返回值；dispose 场景抛出受控异常。
        """
        observed_ids.append(get_audit_request_id())
        if failure == "dispose":
            raise error

    service = Mock()
    service.reset_super_admin_password = AsyncMock(side_effect=reset_password)
    constructor = Mock(return_value=service)
    dispose_mock = AsyncMock(side_effect=dispose)
    monkeypatch.setattr(operator_command, "OperatorPasswordService", constructor)
    monkeypatch.setattr(operator_command, "engine", Mock(dispose=dispose_mock))
    outer_request_id = str(uuid.uuid4())
    outer_token = bind_request_context(outer_request_id)
    try:
        if failure is None:
            await operator_command._run(user_id, password)
        else:
            with pytest.raises(RuntimeError) as caught:
                await operator_command._run(user_id, password)
            assert caught.value is error

        assert get_audit_request_id() == outer_request_id
        assert len(observed_ids) == 2
        assert observed_ids[0] == observed_ids[1]
        assert observed_ids[0].startswith("operator:")
        assert uuid.UUID(observed_ids[0].removeprefix("operator:")).version == 4
        with pytest.raises(RuntimeError):
            copied_contexts[0].run(get_audit_request_id)
        constructor.assert_called_once_with(SessionFactory, password_manager)
        service.reset_super_admin_password.assert_awaited_once_with(user_id=user_id, new_password=password)
        dispose_mock.assert_awaited_once_with()
    finally:
        deactivate_request_context()
        reset_request_context(outer_token)

    assert current_request_id() is None


@pytest.mark.parametrize("field", ["before_state", "after_state"])
def test_optional_audit_state_binds_none_as_sql_null(field: str) -> None:
    column = OperationAuditEvent.__table__.c[field]
    processor = column.type.bind_processor(PGDialect())  # type: ignore[no-untyped-call]

    assert processor is not None
    assert processor(None) is None


def test_audit_state_accepts_bounded_json_and_normalizes_protocol_values() -> None:
    entity_id = uuid.uuid4()
    occurred_at = datetime.now(UTC)

    state = sanitize_audit_state(
        {
            "user_id": entity_id,
            "occurred_at": occurred_at,
            "roles": ["user", "manager"],
            "changed": True,
        }
    )

    assert state is not None
    assert state["user_id"] == str(entity_id)
    assert state["occurred_at"] == occurred_at.isoformat().replace("+00:00", "Z")


def test_audit_state_accepts_fixed_password_reset_permission_identifier() -> None:
    state = sanitize_audit_state({"permissions": ["users:password:reset"]})

    assert state == {
        "permissions": ["users:password:reset"],
    }


@pytest.mark.parametrize(
    "state",
    [
        {"password": "not-for-audit"},
        {"nested": {"access_token": "not-for-audit"}},
        {"jti": str(uuid.uuid4())},
        {"email": "person@example.test"},
    ],
)
def test_audit_state_rejects_credentials_tokens_and_direct_identifiers(state: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="forbidden sensitive field"):
        sanitize_audit_state(state)


def test_audit_state_rejects_unbounded_or_non_json_values() -> None:
    with pytest.raises(ValueError, match="too many array items"):
        sanitize_audit_state({"items": list(range(101))})
    with pytest.raises(ValueError, match="unsupported audit state value"):
        sanitize_audit_state({"value": object()})
    with pytest.raises(ValueError, match="16 KiB"):
        sanitize_audit_state({"value": "x" * (16 * 1024)})


@pytest.mark.parametrize(
    "value",
    [
        "Bearer raw-token",
        "password=raw-password",
        "password:raw-password",
        "token=raw-token",
        "users:password=raw-password",
        "users:token=raw-token",
        "users:password:reset password=raw-password",
        "https://user:password@example.test/path",
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
def test_audit_state_rejects_obvious_sensitive_values(value: str) -> None:
    with pytest.raises(ValueError, match="sensitive text"):
        sanitize_audit_state({"note": value})


def test_audit_labels_and_correlation_ids_use_stable_machine_formats() -> None:
    assert validate_audit_action("role.permissions.bind") == "role.permissions.bind"
    assert validate_audit_reason("permissions_bound") == "permissions_bound"
    assert validate_audit_request_id(str(uuid.uuid4()))
    assert validate_audit_request_id("job:daily_access_review:20260910")

    with pytest.raises(ValueError, match="invalid audit action"):
        validate_audit_action("Role changed")
    with pytest.raises(ValueError, match="invalid audit reason"):
        validate_audit_reason("not allowed")
    with pytest.raises(ValueError, match="correlation ID"):
        validate_audit_request_id("person@example.test")


def test_operation_audit_model_applies_safe_validators() -> None:
    event = OperationAuditEvent(
        category="permission",
        user_id=new_entity_id("U"),
        action="role.update",
        outcome="succeeded",
        reason_code="role_updated",
        source="service",
        before_state={"version": 1},
        after_state={"version": 2},
        request_id=str(uuid.uuid4()),
    )

    assert event.source == "service"
    assert event.category == "permission"
    with pytest.raises(ValueError, match="forbidden sensitive field"):
        event.after_state = {"jwt_secret": "not-for-audit"}
