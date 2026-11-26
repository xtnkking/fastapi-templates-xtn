#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证统一操作审计的递归脱敏、密码指纹、正文边界和并发请求隔离。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/16    XTN       V1.000        新建
# --------------------------------------------------------------------------------------------------

import asyncio
import hashlib
import hmac
import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access.authorization import AuthorizationContext
from app.core.audit import AccountAuditAction, AuditSource, RbacAuditAction
from app.core.i18n.messages import MessageKey
from app.core.logging.context import (
    bind_request_context,
    current_http_details,
    deactivate_request_context,
    reset_request_context,
)
from app.core.logging.details import BODY_CAPTURE_MAX_BYTES, SUMMARY_MAX_BYTES, HttpLogDetails
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.response import ApiResponse, api_response
from app.models.postgres.operation_audit import OperationAuditEvent
from app.services.audit_service import AuditService

LOG_KEY = b"test-independent-password-fingerprint-key"
USER_ID = "U5N9B2LK7QR4X6D"
REQUEST_ID = "fc67559b-44db-472b-a718-99160e46b663"


def make_details(body: bytes) -> HttpLogDetails:
    request = Request({
        "type": "http", "method": "POST", "path": "/api/v1/users/password/reset",
        "query_string": b"page=2&token=query-secret", "headers": [(b"content-type", b"application/json")],
        "route": SimpleNamespace(name="reset_user_password", path="/api/v1/users/password/reset"),
    })
    details = HttpLogDetails(request, LOG_KEY)
    details.observe_request({"type": "http.request", "body": body, "more_body": False})
    return details


def test_audit_redacts_nested_parameters_and_matches_file_password_fingerprint(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    password = "New-Secret7!"
    details = make_details(json.dumps({
        "user_id": USER_ID, "new_password": password, "captcha_answer": "P7Q9",
        "data": {"items": [{"password": "nested-secret", "user_id": USER_ID}]},
        "unknown-secret-field": "unknown-secret-value",
    }).encode())
    token = bind_request_context(REQUEST_ID, http_details=details)
    session = Mock(spec=AsyncSession)
    try:
        event = AuditService.audit_success(
            session, action=AccountAuditAction.ADMIN_RESET_PASSWORD,
            context=unprivileged_authorization_context, target_user_id=USER_ID,
            message_key=MessageKey.COMMON_OPERATION_SUCCESS,
            data={"changed": True, "password": "response-secret", "message": "nested-text"},
        )
        session.add.assert_called_once_with(event)
        session.commit.assert_not_awaited()
        assert event.user_id == unprivileged_authorization_context.login_info.user_id
        assert event.category == "account"
        assert event.request_data is not None
        assert event.response_data is not None
        assert event.request_data["query"] == {"page": "2", "token": "[REDACTED]"}
        assert event.request_data["body"]["new_password"] == "[REDACTED]"
        assert event.request_data["body"]["data"]["items"][0]["password"] == "[REDACTED]"
        assert event.response_data["data"] == {
            "changed": True, "password": "[REDACTED]", "message": "[REDACTED]",
        }
        assert event.response_data["message"] != "[REDACTED]"
        expected = hmac.new(LOG_KEY, b"password\x00" + password.encode(), hashlib.sha256).hexdigest()[:32]
        assert event.password_fingerprint == expected == details.fields()["password_fingerprint"]
        encoded = json.dumps({"request": event.request_data, "response": event.response_data})
        for secret in (password, "P7Q9", "nested-secret", "response-secret", "query-secret",
                       "unknown-secret-field", "unknown-secret-value", "nested-text"):
            assert secret not in encoded
    finally:
        deactivate_request_context()
        reset_request_context(token)
    assert current_http_details() is None


@pytest.mark.parametrize("body,reason", [
    (b"x" * (BODY_CAPTURE_MAX_BYTES + 1), "body_too_large"),
    (b'{"new_password": "unfinished', "non_json_or_invalid_json"),
])
def test_audit_omits_unrecordable_body_without_losing_operation_id(body: bytes, reason: str) -> None:
    details = make_details(body)
    token = bind_request_context(REQUEST_ID, http_details=details)
    try:
        event = AuditService.audit_success(Mock(spec=AsyncSession), action=AccountAuditAction.ADMIN_RESET_PASSWORD)
        assert event.request_id == REQUEST_ID
        assert event.request_data is not None
        assert event.request_data["body"]["_omitted"] == reason
        assert len(json.dumps(event.request_data).encode()) <= SUMMARY_MAX_BYTES
        assert event.password_fingerprint is None
    finally:
        deactivate_request_context()
        reset_request_context(token)


def test_non_http_audit_has_null_http_fields_and_strict_state_safety(audit_request_context: str) -> None:
    event = AuditService.audit_success(Mock(spec=AsyncSession), action=AccountAuditAction.OPERATOR_RESET_PASSWORD,
                                       source=AuditSource.OPERATOR)
    assert event.request_data is None
    assert event.response_data is None
    assert event.password_fingerprint is None
    assert event.user_id is None
    assert event.request_id == audit_request_context
    with pytest.raises(ValueError, match="sensitive"):
        AuditService.audit_success(Mock(spec=AsyncSession), action=AccountAuditAction.ADMIN_RESET_PASSWORD,
                                   after_state={"password": "[REDACTED]"})
    with pytest.raises(ValueError, match="after_state"):
        AuditService._build_event(action=RbacAuditAction.UPDATE_ROLE, outcome="denied",
                                  after_state={"enabled": False})


def test_success_audit_derives_identity_and_source_without_committing(
    audit_request_context: str,
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    session = Mock(spec=AsyncSession)
    anonymous = AuditService.audit_success(session, action=AccountAuditAction.REGISTER_USER,
                                           target_user_id=USER_ID)
    assert anonymous.user_id is None
    assert anonymous.source == AuditSource.SERVICE
    assert anonymous.target_user_id == USER_ID

    token = bind_request_context(REQUEST_ID, http_details=make_details(b"{}"))
    try:
        http_event = AuditService.audit_success(session, action=AccountAuditAction.REGISTER_USER)
        contextual = AuditService.audit_success(session, action=RbacAuditAction.BIND_USER_ROLES,
                                                context=unprivileged_authorization_context)
        assert http_event.user_id is None
        assert http_event.source == AuditSource.HTTP
        assert contextual.user_id == unprivileged_authorization_context.login_info.user_id
        assert contextual.source == unprivileged_authorization_context.audit_source
    finally:
        deactivate_request_context()
        reset_request_context(token)
    assert session.add.call_count == 3
    session.commit.assert_not_called()
    session.begin.assert_not_called()


@pytest.mark.parametrize("action", ["account_security.password.admin_reset", "api.delete_role"])
def test_success_audit_requires_fixed_action_enum(audit_request_context: str, action: str) -> None:
    session = Mock(spec=AsyncSession)
    with pytest.raises(ValueError):
        AuditService.audit_success(session, action=cast(AccountAuditAction, action))
    session.add.assert_not_called()


async def test_real_http_capture_matches_response_and_keeps_concurrent_requests_separate(
    unprivileged_authorization_context: AuthorizationContext,
) -> None:
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware, log_hmac_key=LOG_KEY)
    barrier = asyncio.Barrier(2)
    events: dict[str, OperationAuditEvent] = {}

    async def reset_user_password(request: Request) -> ApiResponse[None]:
        body = await request.json()
        await barrier.wait()
        events[body["user_id"]] = AuditService.audit_success(
            Mock(spec=AsyncSession), action=AccountAuditAction.ADMIN_RESET_PASSWORD,
            context=unprivileged_authorization_context, target_user_id=body["user_id"],
            message_key=MessageKey.COMMON_OPERATION_SUCCESS, data=None,
        )
        return api_response(request, message_key=MessageKey.COMMON_OPERATION_SUCCESS, data=None)

    app.add_api_route("/api/v1/users/password/reset", reset_user_password, methods=["POST"])
    user_ids = [USER_ID, "U1N2B3LK7QR4X6D"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await asyncio.gather(*(
            client.post("/api/v1/users/password/reset", json={"user_id": user_id, "new_password": f"New-{i}-Pass!"},
                        headers={"Accept-Language": "en" if i else "zh-CN"})
            for i, user_id in enumerate(user_ids)
        ))
    for user_id, response in zip(user_ids, responses, strict=True):
        event = events[user_id]
        assert response.status_code == 200
        assert event.response_data is not None
        assert event.request_data is not None
        assert event.response_data == response.json()
        assert event.response_data["data"] is None
        assert event.request_id == response.headers["X-Request-ID"]
        assert event.request_data["body"]["user_id"] == user_id
    assert events[user_ids[0]].password_fingerprint != events[user_ids[1]].password_fingerprint
    assert current_http_details() is None


def test_snapshot_rejects_credentials_hidden_in_response_message(audit_request_context: str) -> None:
    event = AuditService._build_event(
        action=AccountAuditAction.ADMIN_RESET_PASSWORD,
        response_data={"code": 20000, "message": "password=do-not-store", "data": {"token": "secret-token"}},
    )
    assert "do-not-store" not in json.dumps(event.response_data)
    assert "secret-token" not in json.dumps(event.response_data)


def test_mutation_response_keeps_user_role_details_and_redaction_counts(audit_request_context: str) -> None:
    event = AuditService.audit_success(
        Mock(spec=AsyncSession), action=RbacAuditAction.BIND_USER_ROLES,
        message_key=MessageKey.COMMON_OPERATION_SUCCESS,
        data={
            "user": {"user_id": USER_ID, "user_name": "private-name", "is_active": True,
                     "bound_role_ids": ["R1N2B3LK7QR4X6D"], "effective_permissions": ["users:read"],
                     "other": "secret-one", "another": "secret-two"},
            "role": {"id": "R1N2B3LK7QR4X6D", "is_active": False, "is_protected": False,
                     "level": 10, "permissions": ["roles:read"], "name": "private-name"},
        },
    )
    response = event.response_data
    assert response is not None
    assert event.category == "permission"
    assert response["data"]["user"]["bound_role_ids"] == ["R1N2B3LK7QR4X6D"]
    assert response["data"]["user"]["effective_permissions"] == ["users:read"]
    assert response["data"]["user"]["_redacted_fields"] == 2
    assert response["data"]["role"]["permissions"] == ["roles:read"]
    assert response["data"]["role"]["level"] == 10
    assert response["data"]["role"]["name"] == "[REDACTED]"
    for field, value in (("user_id", "R1N2B3LK7QR4X6D"), ("target_role_id", USER_ID)):
        with pytest.raises(ValueError):
            OperationAuditEvent(**{field: value})
