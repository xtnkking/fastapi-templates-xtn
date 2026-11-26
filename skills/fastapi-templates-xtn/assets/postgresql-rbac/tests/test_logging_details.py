#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线验证文件请求日志的目标身份、密码指纹、脱敏摘要和有界收发观察。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/14    XTN       V1.000        新建
# 2026/10/14    XTN       V1.001        验证响应业务提示保留且请求、嵌套文本和凭据仍脱敏
# 2026/10/15    XTN       V1.002        用真实统一响应验证业务结果与路由函数动作名称
# 2026/10/15    XTN       V1.003        验证集中提取请求目标及创建成功后发送失败时保留新 ID
# --------------------------------------------------------------------------------------------------

import asyncio
import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel
from starlette.types import Message, Receive, Scope, Send

import app.core.logging.details as details_module
from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey
from app.core.logging.context import current_request_id
from app.core.logging.events import SafeJsonFormatter
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.response import api_response
from app.schemas.role import RoleMutationResponse, RoleResponse
from app.schemas.user import UserCreatedResponse, UserPasswordResetRequest

USER_ID = "U5N9B2LK7QR4X6D"
TARGET_USER_ID = "U1N2B3LK7QR4X6D"
ROLE_ID = "R1N2B3LK7QR4X6D"
LOG_KEY = b"Q1vL8nR4yT6wZ3pK9dF2sH5cB7mX0uAg"
PASSWORD = "Example-New-Pass7!"


@contextmanager
def capture_json_events() -> Iterator[list[dict[str, Any]]]:
    logger = logging.getLogger("app")
    previous_level, previous_disabled = logger.level, logger.disabled
    events: list[dict[str, Any]] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            events.append(json.loads(self.format(record)))

    handler = CaptureHandler()
    handler.setFormatter(SafeJsonFormatter(include_exception_details=False))
    logger.setLevel(logging.INFO)
    logger.disabled = False
    logger.addHandler(handler)
    try:
        yield events
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.disabled = previous_disabled


def detail_app(path: str, operation: str, *, status_code: int = 200,
               current_user_id: str | None = USER_ID,
               response_data: BaseModel | dict[str, object] | None = None,
               response_message: str | None = None,
               log_key: bytes | None = LOG_KEY,
               method: str = "POST"
               ) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware, log_hmac_key=log_key)

    async def endpoint(request: Request) -> JSONResponse:
        if request.method == "POST":
            await request.body()
        if current_user_id is not None:
            request.state.user_id = current_user_id
        await asyncio.sleep(0)
        response = api_response(
            request,
            code=(BusinessCode.CREATED if status_code == 201 else
                  BusinessCode.OK if status_code < 400 else BusinessCode.ACCESS_FORBIDDEN),
            message_key=MessageKey.COMMON_SUCCESS if status_code < 400 else MessageKey.ERROR_FORBIDDEN,
            data=response_data if response_data is not None else {"changed": status_code < 400},
        )
        content = response.model_dump(mode="json")
        if response_message is not None:
            content["message"] = response_message
        return JSONResponse(content, status_code=status_code)

    app.add_api_route(path, endpoint, methods=[method], name=operation)
    return app


async def request_log(app: FastAPI, path: str, *, body: object = None,
                      method: str = "POST",
                      params: dict[str, str] | None = None
                      ) -> tuple[dict[str, Any], dict[str, Any]]:
    with capture_json_events() as events:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.request(method, path, json=body, params=params)
    completions = [event for event in events if event["event"] == "http.request.completed"]
    assert len(completions) == 1
    assert completions[0]["request_id"] == response.headers["X-Request-ID"]
    return completions[0], response.json()


@pytest.mark.parametrize(
    ("path", "operation", "password_field"),
    [
        ("/api/v1/auth/register", "register", "password"),
        ("/api/v1/users/create", "create_user", "password"),
        ("/api/v1/users/password/reset", "reset_user_password", "new_password"),
        ("/api/v1/me/password/change", "change_my_password", "new_password"),
    ],
)
async def test_only_setting_new_password_records_keyed_fingerprint_even_when_denied(
    path: str, operation: str, password_field: str
) -> None:
    app = detail_app(path, operation, status_code=403)
    body = {
        password_field: PASSWORD,
        "current_password": "Old-Password7!",
        "captcha_answer": "A7XQ",
        "captcha_id": "b445ed1a-0d52-401e-8c63-51d5d9669ae0",
        "user_id": TARGET_USER_ID,
    }
    event, response = await request_log(app, path, body=body)

    expected = hmac.new(LOG_KEY, b"password\0" + PASSWORD.encode(), hashlib.sha256).hexdigest()[:32]
    assert event["password_fingerprint"] == expected
    assert event["request_data"][password_field] == "[REDACTED]"
    assert event["request_data"]["current_password"] == "[REDACTED]"
    assert event["request_data"]["captcha_answer"] == "[REDACTED]"
    assert event["user_id"] == USER_ID
    assert event["operation_outcome"] == event["outcome"] == "failure"
    assert response["code"] == 40301
    rendered = json.dumps(event)
    for secret in (PASSWORD, "Old-Password7!", "A7XQ", body["captcha_id"]):
        assert secret not in rendered
    if operation == "reset_user_password":
        assert event["target_user_id"] == TARGET_USER_ID


async def test_password_fingerprint_correlates_same_input_and_changes_with_independent_key() -> None:
    path, operation = "/api/v1/users/password/reset", "reset_user_password"
    body = {"user_id": TARGET_USER_ID, "new_password": PASSWORD}
    first, _ = await request_log(detail_app(path, operation), path, body=body)
    second, _ = await request_log(detail_app(path, operation), path, body=body)
    changed_key, _ = await request_log(
        detail_app(path, operation, log_key=b"Another-Independent-Log-Key7!"), path, body=body,
    )
    no_key, _ = await request_log(detail_app(path, operation, log_key=None), path, body=body)

    assert len(first["password_fingerprint"]) == 32
    assert first["password_fingerprint"] == second["password_fingerprint"]
    assert changed_key["password_fingerprint"] != first["password_fingerprint"]
    assert no_key["password_fingerprint"] is None
    assert no_key["request_data"]["new_password"] == "[REDACTED]"


async def test_denial_before_route_business_still_records_requested_target_and_new_password() -> None:
    path = "/api/v1/users/password/reset"
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware, log_hmac_key=LOG_KEY)
    business_ran = False

    async def deny(request: Request) -> None:
        request.state.user_id = USER_ID
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="permission denied")

    async def endpoint(_body: UserPasswordResetRequest) -> dict[str, bool]:
        nonlocal business_ran
        business_ran = True
        return {"changed": True}

    app.add_api_route(path, endpoint, methods=["POST"], name="reset_user_password", dependencies=[Depends(deny)])
    event, _ = await request_log(
        app, path,
        body={"user_id": TARGET_USER_ID, "new_password": PASSWORD,
              "captcha_id": "b445ed1a-0d52-401e-8c63-51d5d9669ae0", "captcha_answer": "A7XQ"},
    )
    assert business_ran is False
    assert event["target_user_id"] == TARGET_USER_ID
    assert event["password_fingerprint"] == hmac.new(
        LOG_KEY, b"password\0" + PASSWORD.encode(), hashlib.sha256,
    ).hexdigest()[:32]
    assert event["operation_outcome"] == "failure"


@pytest.mark.parametrize(
    ("path", "operation"),
    [
        ("/api/v1/auth/login", "login"),
        ("/controlled/unrelated", "reset_user_password"),
        ("/api/v1/users/password/reset", "unrelated"),
    ],
)
async def test_login_and_unrelated_endpoints_never_fingerprint_password(path: str, operation: str) -> None:
    app = detail_app(
        path, operation, current_user_id=None,
        response_data={"access_token": "Response-Token-Secret", "password_hash": "$argon2id$stored-secret"},
    )
    event, response = await request_log(
        app, path,
        body={
            "password": PASSWORD,
            "new_password": PASSWORD,
            "current_password": "Old-Secret7!",
            "user_id": TARGET_USER_ID,
            "user_name": "private_user_name",
            "token": "Request-Token-Secret",
            "captcha_answer": "A7XQ",
        },
    )

    assert event["password_fingerprint"] is None
    assert event["user_id"] is None
    assert event["response_data"]["data"]["access_token"] == "[REDACTED]"
    assert event["response_data"]["data"]["password_hash"] == "[REDACTED]"
    assert response["data"]["access_token"] == "Response-Token-Secret"
    rendered = json.dumps(event)
    for secret in (PASSWORD, "Old-Secret7!", "private_user_name", "Request-Token-Secret",
                   "Response-Token-Secret", "$argon2id$stored-secret", "A7XQ"):
        assert secret not in rendered


async def test_ordinary_request_keeps_fixed_empty_fields_and_cannot_restore_removed_fields() -> None:
    path = "/api/v1/me/user_info"
    event, _ = await request_log(detail_app(path, "get_user_info", method="GET"), path, method="GET")

    for field in ("target_user_id", "target_role_id", "password_fingerprint", "reason_code",
                  "request_data", "failure_phase", "error_id", "exception_type", "exception_module"):
        assert field in event
        assert event[field] is None
    assert {"service", "service_version", "environment", "target_type", "target_id"}.isdisjoint(event)
    assert event["response_data"]["data"] == {"changed": True}

    record = logging.LogRecord("app.test", logging.INFO, __file__, 1, "safe.event", (), None)
    for field in ("service", "service_version", "environment", "target_type", "target_id"):
        setattr(record, field, "must-not-appear")
    rendered = SafeJsonFormatter(include_exception_details=False).format(record)
    assert "must-not-appear" not in rendered


async def test_file_action_uses_the_actual_route_function_name() -> None:
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/controlled/action")
    async def read_operation_details(request: Request) -> dict[str, Any]:
        return api_response(
            request, message_key=MessageKey.COMMON_QUERY_SUCCESS, data={"changed": True},
        ).model_dump(mode="json")

    event, response = await request_log(app, "/controlled/action", method="GET")

    assert event["action"] == read_operation_details.__name__
    assert event["business_code"] == response["code"] == int(BusinessCode.OK)
    assert event["operation_outcome"] == event["outcome"] == "success"


@pytest.mark.parametrize(("message", "status_code"), [
    ("查询成功", 200), ("Query succeeded", 200), ("无权限", 403),
])
async def test_response_message_is_readable_without_exposing_request_or_nested_text(
    message: str, status_code: int,
) -> None:
    path = "/api/v1/users/password/reset"
    event, response = await request_log(
        detail_app(path, "reset_user_password", status_code=status_code, response_message=message,
                   response_data={"message": "Nested-Message-Secret", "access_token": "Response-Token-Secret"}),
        path, body={"new_password": PASSWORD, "message": "Request-Message-Secret"},
    )
    assert response["message"] == event["response_data"]["message"] == message
    assert event["request_data"]["message"] == "[REDACTED]"
    assert event["response_data"]["data"]["message"] == "[REDACTED]"
    rendered = json.dumps(event)
    for secret in (PASSWORD, "Request-Message-Secret", "Nested-Message-Secret", "Response-Token-Secret"):
        assert secret not in rendered


async def test_response_message_still_filters_obvious_credentials_without_changing_response() -> None:
    path = "/api/v1/me/user_info"
    message = "操作失败 password=Message-Password-Secret Bearer Message-Token-Secret"
    event, response = await request_log(
        detail_app(path, "get_user_info", method="GET", response_message=message), path, method="GET",
    )
    assert response["message"] == message
    assert event["response_data"]["message"] == "操作失败 password=[REDACTED] Bearer [REDACTED]"
    assert "Message-Password-Secret" not in json.dumps(event)
    assert "Message-Token-Secret" not in json.dumps(event)


async def test_target_query_distinguishes_managed_user_from_authenticated_caller() -> None:
    path = "/api/v1/users/detail"
    event, _ = await request_log(
        detail_app(path, "get_user_detail", status_code=403, method="GET"), path, method="GET",
        params={"user_id": TARGET_USER_ID, "token": "Query-Token-Secret"},
    )
    assert event["user_id"] == USER_ID
    assert event["target_user_id"] == TARGET_USER_ID
    assert event["request_data"]["user_id"] == TARGET_USER_ID
    assert "Query-Token-Secret" not in json.dumps(event)


async def test_unknown_fields_and_free_text_never_reveal_unclassified_secrets() -> None:
    path = "/api/v1/users/password/reset"
    event, _ = await request_log(
        detail_app(path, "reset_user_password", response_data={"description": "Response-Free-Text-Secret"}),
        path,
        body={
            "new_password": PASSWORD,
            "user_id": TARGET_USER_ID,
            "custom_field": "Unknown-Field-Secret",
            "message": "Request-Free-Text-Secret",
            "description": "Request-Description-Secret",
        },
    )
    rendered = json.dumps(event)
    for secret in ("Response-Free-Text-Secret", "Unknown-Field-Secret",
                   "Request-Free-Text-Secret", "Request-Description-Secret"):
        assert secret not in rendered
    assert event["request_data"]["user_id"] == TARGET_USER_ID


def test_formatter_accepts_only_exact_hex_password_fingerprint() -> None:
    formatter = SafeJsonFormatter(include_exception_details=False)
    for unsafe in ("Raw-Password-Secret", "f" * 31, "f" * 33, "g" * 32, "A" * 32, False):
        record = logging.LogRecord("app.test", logging.INFO, __file__, 1, "safe.event", (), None)
        record.password_fingerprint = unsafe
        rendered = formatter.format(record)
        assert json.loads(rendered)["password_fingerprint"] == "[REDACTED]"
        if isinstance(unsafe, str):
            assert unsafe not in rendered
    record.password_fingerprint = "3a166777f70713fdadd6004df6bf4634"
    assert json.loads(formatter.format(record))["password_fingerprint"] == "3a166777f70713fdadd6004df6bf4634"


async def test_unknown_field_names_cannot_smuggle_sensitive_plaintext_into_logs() -> None:
    path = "/api/v1/users/password/reset"
    event, _ = await request_log(
        detail_app(path, "reset_user_password", response_data={"Response-Secret-In-Key": "ignored"}),
        path,
        body={"user_id": TARGET_USER_ID, "new_password": PASSWORD,
              "Request-Secret-In-Key": "ignored", PASSWORD: "ignored"},
    )
    rendered = json.dumps(event)
    assert "Request-Secret-In-Key" not in rendered
    assert "Response-Secret-In-Key" not in rendered
    assert PASSWORD not in rendered
    assert event["request_data"]["_redacted_fields"] >= 2
    assert event["request_data"]["new_password"] == "[REDACTED]"


@pytest.mark.parametrize(
    "body",
    ["Raw-Root-Secret7!", ["Raw-Root-Secret7!"], {"page": "Raw-Root-Secret7!"}],
    ids=["root-string", "root-array", "numeric-field-string"],
)
async def test_json_scalars_cannot_hide_secret_in_root_array_or_machine_field(body: object) -> None:
    path = "/api/v1/users/password/reset"
    event, _ = await request_log(detail_app(path, "reset_user_password"), path, body=body)
    assert "Raw-Root-Secret7!" not in json.dumps(event)
    assert event["password_fingerprint"] is None


async def test_large_query_summary_cannot_discard_request_identity_or_enlarge_log() -> None:
    path = "/api/v1/users/detail"
    event, _ = await request_log(
        detail_app(path, "get_user_detail", method="GET"), path, method="GET",
        params={"user_id": TARGET_USER_ID, **{f"field_{index}": "Z" * 1000 for index in range(30)}},
    )
    assert event["request_id"]
    assert event["user_id"] == USER_ID
    assert len(json.dumps(event["request_data"]).encode()) <= 4096
    assert len(json.dumps(event).encode()) <= 16 * 1024
    assert "Z" * 100 not in json.dumps(event)


async def test_role_target_is_distinct_and_invalid_target_is_not_a_business_id() -> None:
    path = "/api/v1/roles/update"
    app = detail_app(path, "update_role", status_code=403)
    valid, _ = await request_log(app, path, body={"role_id": ROLE_ID})
    invalid, _ = await request_log(app, path, body={"role_id": "not-a-role-id"})
    assert valid["target_role_id"] == ROLE_ID
    assert valid["target_user_id"] is None
    assert invalid["target_role_id"] is None


@pytest.mark.parametrize(
    ("path", "operation", "data", "target_user_id", "target_role_id"),
    [
        ("/api/v1/auth/register", "register", UserCreatedResponse(user_id=TARGET_USER_ID), TARGET_USER_ID, None),
        ("/api/v1/users/create", "create_user", {"user_id": TARGET_USER_ID}, TARGET_USER_ID, None),
        ("/api/v1/roles/create", "create_role", RoleMutationResponse(
            role=RoleResponse(id=ROLE_ID, key="support", name="客服", description="",
                              level=1, is_active=True, is_system=False, is_protected=False,
                              permissions=(), version=1, deleted_at=None),
        ), None, ROLE_ID),
        ("/api/v1/roles/create", "create_role", {"role": {"id": ROLE_ID}}, None, ROLE_ID),
    ],
    ids=["register-model", "user-create-dict", "role-create-model", "role-create-dict"],
)
async def test_created_target_comes_from_success_data_without_route_assignments(
    path: str, operation: str, data: BaseModel | dict[str, object],
    target_user_id: str | None, target_role_id: str | None,
) -> None:
    event, response = await request_log(
        detail_app(path, operation, status_code=201, response_data=data), path,
        body={"user_id": USER_ID, "role_id": "R9N2B3LK7QR4X6D"},
    )

    assert response["code"] == int(BusinessCode.CREATED)
    assert event["user_id"] == USER_ID
    assert event["target_user_id"] == target_user_id
    assert event["target_role_id"] == target_role_id


@pytest.mark.parametrize(("path", "operation"), [
    ("/api/v1/auth/register", "register"),
    ("/api/v1/users/create", "create_user"),
    ("/api/v1/roles/create", "create_role"),
])
async def test_failed_creation_ignores_fabricated_request_and_response_target(
    path: str, operation: str,
) -> None:
    event, _ = await request_log(
        detail_app(path, operation, status_code=403,
                   response_data={"user_id": TARGET_USER_ID, "role": {"id": ROLE_ID}}),
        path, body={"user_id": TARGET_USER_ID, "role_id": ROLE_ID},
    )

    assert event["target_user_id"] is None
    assert event["target_role_id"] is None
    assert event["operation_outcome"] == "failure"


@pytest.mark.parametrize(("status_code", "current_user_id"), [
    (200, USER_ID), (403, USER_ID), (403, None),
], ids=["success", "business-denied", "unauthenticated"])
async def test_self_password_target_uses_only_authenticated_user(
    status_code: int, current_user_id: str | None,
) -> None:
    path = "/api/v1/me/password/change"
    event, _ = await request_log(
        detail_app(path, "change_my_password", status_code=status_code, current_user_id=current_user_id),
        path, body={"user_id": TARGET_USER_ID, "new_password": PASSWORD},
    )

    assert event["user_id"] == event["target_user_id"] == current_user_id
    assert event["target_role_id"] is None


@pytest.mark.parametrize(("path", "operation", "method", "target_user_id"), [
    ("/api/v1/users/list", "list_users", "GET", None),
    ("/api/v1/roles/list", "list_roles", "GET", None),
    ("/controlled/unrelated", "create_user", "POST", None),
    ("/api/v1/users/sessions/list", "list_user_sessions", "GET", TARGET_USER_ID),
])
async def test_target_extraction_distinguishes_total_lists_unrelated_routes_and_user_sessions(
    path: str, operation: str, method: str, target_user_id: str | None,
) -> None:
    inputs = {"user_id": TARGET_USER_ID, "role_id": ROLE_ID}
    event, _ = await request_log(
        detail_app(path, operation, method=method,
                   response_data={"user_id": TARGET_USER_ID, "role": {"id": ROLE_ID},
                                  "items": [{"user_id": TARGET_USER_ID, "id": ROLE_ID}]}),
        path, method=method, params=inputs if method == "GET" else None,
        body=inputs if method == "POST" else None,
    )

    assert event["target_user_id"] == target_user_id
    assert event["target_role_id"] is None


async def test_legacy_target_state_cannot_override_the_requested_target() -> None:
    path = "/api/v1/users/password/reset"
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.post(path)
    async def reset_user_password(request: Request) -> dict[str, Any]:
        await request.body()
        request.state.user_id = USER_ID
        request.state.target_user_id = USER_ID
        request.state.target_role_id = ROLE_ID
        return api_response(request, message_key=MessageKey.COMMON_SUCCESS, data=None).model_dump(mode="json")

    event, _ = await request_log(app, path, body={"user_id": TARGET_USER_ID})

    assert event["user_id"] == USER_ID
    assert event["target_user_id"] == TARGET_USER_ID
    assert event["target_role_id"] is None


async def test_created_target_survives_failure_before_response_headers_are_sent() -> None:
    path = "/api/v1/users/create"

    async def controlled_app(scope: Scope, receive: Receive, send: Send) -> None:
        scope["route"] = SimpleNamespace(path=path, name="create_user")
        scope.setdefault("state", {})["user_id"] = USER_ID
        response = api_response(
            Request(scope), code=BusinessCode.CREATED, message_key=MessageKey.COMMON_CREATED,
            data=UserCreatedResponse(user_id=TARGET_USER_ID),
        )
        await JSONResponse(response.model_dump(mode="json"), status_code=201)(scope, receive, send)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def failing_send(_message: Message) -> None:
        raise OSError("controlled send failure")

    scope: Scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
        "headers": [], "client": ("127.0.0.1", 1234), "server": ("test", 80),
    }
    with capture_json_events() as events:
        with pytest.raises(OSError, match="controlled send failure"):
            await RequestLoggingMiddleware(controlled_app)(scope, receive, failing_send)

    completion = [event for event in events if event["event"] == "http.request.completed"]
    assert len(completion) == 1
    assert completion[0]["target_user_id"] == TARGET_USER_ID
    assert completion[0]["target_role_id"] is None
    assert completion[0]["operation_outcome"] == "success"
    assert completion[0]["outcome"] == "error"
    assert completion[0]["response_started"] is False
    assert completion[0]["response_data"] is None


async def test_created_target_observer_failure_cannot_change_success_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_created_target(_self: object, _data: object) -> None:
        raise OSError("controlled target observer failure")

    monkeypatch.setattr(details_module.HttpLogDetails, "record_created_target", fail_created_target)
    path = "/api/v1/users/create"
    event, response = await request_log(
        detail_app(path, "create_user", status_code=201, response_data=UserCreatedResponse(user_id=TARGET_USER_ID)),
        path, body={"password": PASSWORD},
    )

    assert response["code"] == int(BusinessCode.CREATED)
    assert response["data"] == {"user_id": TARGET_USER_ID}
    assert event["operation_outcome"] == "success"
    assert event["target_user_id"] is None


async def test_multichunk_json_capture_preserves_original_request_and_response() -> None:
    path = "/api/v1/users/password/reset"
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware, log_hmac_key=LOG_KEY)
    seen: list[dict[str, Any]] = []

    async def endpoint(request: Request) -> StreamingResponse:
        seen.append(await request.json())
        request.state.user_id = USER_ID

        async def content() -> AsyncIterator[bytes]:
            yield b'{"code":20000,"data":{"token":"Response-'
            await asyncio.sleep(0)
            yield b'Token-Secret","changed":true}}'

        return StreamingResponse(content(), media_type="application/json")

    app.add_api_route(path, endpoint, methods=["POST"], name="reset_user_password")

    async def content() -> AsyncIterator[bytes]:
        raw = json.dumps({"user_id": TARGET_USER_ID, "new_password": PASSWORD}).encode()
        yield raw[:20]
        await asyncio.sleep(0)
        yield raw[20:]

    with capture_json_events() as events:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(path, content=content(), headers={"Content-Type": "application/json"})
    completion = [event for event in events if event["event"] == "http.request.completed"]
    assert len(completion) == 1
    assert seen == [{"user_id": TARGET_USER_ID, "new_password": PASSWORD}]
    assert response.json()["data"]["token"] == "Response-Token-Secret"
    assert completion[0]["request_data"]["new_password"] == "[REDACTED]"
    assert completion[0]["response_data"]["data"]["token"] == "[REDACTED]"
    assert completion[0]["target_user_id"] == TARGET_USER_ID


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b"Raw-Unparseable-Secret", "application/json"),
        (b"Raw-Text-Secret", "text/plain"),
        (b'{"unknown":"' + b"X" * 100_000 + b'"}', "application/json"),
    ],
    ids=["invalid-json", "non-json", "too-large"],
)
async def test_non_json_invalid_or_large_body_is_bounded_without_raw_contents(
    content: bytes, content_type: str
) -> None:
    path = "/api/v1/users/password/reset"
    app = detail_app(path, "reset_user_password")
    with capture_json_events() as events:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(path, content=content, headers={"Content-Type": content_type})
    completion = [event for event in events if event["event"] == "http.request.completed"]
    assert response.status_code == 200
    assert len(completion) == 1
    rendered = json.dumps(completion[0])
    assert len(rendered.encode()) <= 16 * 1024
    assert "Raw-Unparseable-Secret" not in rendered
    assert "Raw-Text-Secret" not in rendered
    assert "X" * 100 not in rendered
    assert completion[0]["password_fingerprint"] is None


async def test_logging_observer_failure_does_not_change_http_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_fields(_self: object) -> dict[str, object]:
        raise OSError("controlled log observer failure")

    monkeypatch.setattr(details_module.HttpLogDetails, "fields", fail_fields)
    app = detail_app("/controlled/ok", "controlled_ok")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/controlled/ok", json={"password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["data"] == {"changed": True}


async def test_logging_never_reads_request_body_before_application_needs_it() -> None:
    received = 0

    async def controlled_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive() -> Message:
        nonlocal received
        received += 1
        return {"type": "http.request", "body": PASSWORD.encode(), "more_body": False}

    async def send(_message: Message) -> None:
        return None

    scope: Scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": "/controlled/unread", "raw_path": b"/controlled/unread",
        "query_string": b"", "headers": [], "client": ("127.0.0.1", 1234), "server": ("test", 80),
    }
    with capture_json_events() as events:
        await RequestLoggingMiddleware(controlled_app, log_hmac_key=LOG_KEY)(scope, receive, send)
    assert received == 0
    assert events[0]["request_data"] is None
    assert events[0]["password_fingerprint"] is None


async def test_concurrent_targets_and_password_fingerprints_do_not_mix() -> None:
    path = "/api/v1/users/password/reset"
    app = detail_app(path, "reset_user_password")
    other_target, other_password = "U9N2B3LK7QR4X6D", "Another-New-Pass8!"
    with capture_json_events() as events:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            responses = await asyncio.gather(
                client.post(path, json={"user_id": TARGET_USER_ID, "new_password": PASSWORD}),
                client.post(path, json={"user_id": other_target, "new_password": other_password}),
            )
    completions = {event["request_id"]: event for event in events if event["event"] == "http.request.completed"}
    assert len(completions) == 2
    for response, target, password in zip(responses, (TARGET_USER_ID, other_target),
                                          (PASSWORD, other_password), strict=True):
        event = completions[response.headers["X-Request-ID"]]
        assert event["target_user_id"] == target
        assert event["password_fingerprint"] == hmac.new(
            LOG_KEY, b"password\0" + password.encode(), hashlib.sha256,
        ).hexdigest()[:32]
    assert current_request_id() is None
