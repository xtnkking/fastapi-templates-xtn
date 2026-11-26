#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    中英文响应、语言协商和验证错误文案的离线测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        多语言异常测试引用独立异常处理模块
# 2026/09/29    XTN       V1.001        使用临时成功路由验证多语言响应，错误方法检查转向现有业务路由
# 2026/09/29    XTN       V1.002        验证密码规则错误由统一错误模块转换且保持消息键
# 2026/09/29    XTN       V1.003        验证不允许的新密码字符映射为双语提示
# 2026/09/30    XTN       V1.004        对分离后的语言协商与翻译入口继续执行同一契约测试
# 2026/09/30    XTN       V1.005        验证简化的中英文选择规则和默认中文回退
# 2026/09/30    XTN       V1.006        移除临时密码专属错误文案断言
# 2026/10/10    XTN       V1.007        密码策略长度错误使用统一消息键
# 2026/10/14    XTN       V1.008        密码长度文案读取共享上下限并核对两种语言的动态变化
# 2026/10/16    XTN       V1.009        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/20    XTN       V1.010        密码字段长度提示读取真实约束，业务策略提示独立保留
# 2026/10/20    XTN       V1.011        验证密码计算队列满和等待超时通过 HTTP 返回双语 503
# 2026/10/22    XTN       V1.012        双语异常测试对齐当前用户检查入口
# 2026/11/26    XTN       V1.013        异常注入对齐本人权限链路并补齐类型检查
# --------------------------------------------------------------------------------------------------

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response

import app.core.security.passwords as password_security
from app.api.v1.endpoints import auth as auth_api
from app.core.codes import BusinessCode
from app.core.exception_handlers import (
    handle_access_error,
    handle_database_unavailable,
    handle_http_error,
    handle_rate_limit_exceeded,
    handle_request_validation_error,
    handle_unexpected_error,
)
from app.core.exceptions import (
    AppError,
    conflict_409,
    forbidden_403,
    invalid_request_400,
    not_found_404,
    password_policy_response_400,
    stale_resource_version_409,
    unauthenticated_401,
    unavailable_503,
)
from app.core.i18n.language import DEFAULT_LOCALE, SUPPORTED_LOCALES, apply_language_headers, select_locale
from app.core.i18n.messages import CATALOGS, MessageKey, translate_for_locale
from app.core.i18n.validation_messages import validation_message
from app.core.rate_limit.limiter import RateLimitExceeded, RateLimitResult
from app.core.security.passwords import PasswordBusyError, PasswordPolicyError
from app.dependencies.rate_limit import rate_limit_login
from app.main import app


def _request(*, accept_language: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if accept_language is not None:
        headers.append((b"accept-language", accept_language.encode("latin-1")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/controlled-test",
            "headers": headers,
        }
    )


def _body(response: Response) -> dict[str, object]:
    raw_body = response.body
    assert isinstance(raw_body, bytes)
    parsed = json.loads(raw_body)
    assert isinstance(parsed, dict)
    return parsed


@pytest.fixture
def mock_login_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        为登录参数错误用例模拟已通过限流和验证码，只检查双语参数提示。

    :param monkeypatch: 临时替换登录前置依赖，当前用例结束后自动恢复。
    :return: 无返回值；测试请求可进入真实的请求模型校验。
    """
    async def admitted_request() -> None:
        """
            允许当前测试继续校验参数，不执行真实 Redis 限流。

        :return: 无返回值；仅用于显式使用本夹具的测试。
        """
    monkeypatch.setitem(app.dependency_overrides,
                        rate_limit_login, admitted_request)
    # 本组只检查请求模型的双语提示；验证码错误由验证码自己的测试覆盖。
    login_route = next(route for route in auth_api.router.routes if isinstance(route, APIRoute)
                       and route.endpoint is auth_api.login)
    captcha_check = next(
        item.call for item in login_route.dependant.dependencies if item.name == "captcha_checked")
    assert captcha_check is not None
    monkeypatch.setitem(app.dependency_overrides,
                        captcha_check, admitted_request)


def test_catalogs_are_complete_bounded_and_safe() -> None:
    expected_keys = {key.value for key in MessageKey}

    assert DEFAULT_LOCALE == "zh-CN"
    assert SUPPORTED_LOCALES == ("zh-CN", "en")
    assert set(CATALOGS) == set(SUPPORTED_LOCALES)
    for catalog in CATALOGS.values():
        assert set(catalog) == expected_keys
        assert all(value == value.strip() for value in catalog.values())
        assert all(0 < len(value) <= 200 for value in catalog.values())
        assert all(
            "\r" not in value
            and "\n" not in value
            and not any(ord(character) < 32 for character in value)
            for value in catalog.values()
        )


@pytest.mark.parametrize("locale", ["zh-CN", "en"])
@pytest.mark.parametrize("error_type,bound", [("too_short", 1), ("too_long", 1024),
                                              ("too_short", 8), ("too_long", 32)])
def test_password_and_list_length_messages_remain_distinct(locale: str, error_type: str, bound: int) -> None:
    """
        密码字段按真实字段约束说明长度，列表字段仍使用列表数量提示。

    :param locale: 当前请求选择的中文或英文。
    :param error_type: 原生字段错误为太短或太长。
    :param bound: 当前字段实际限制，不凭密码字段名猜测新旧密码。
    :return: 无返回值；三种密码字段均能正确翻译，且不回显原文或影响列表错误。
    """
    request = _request(accept_language=locale)
    too_short = error_type == "too_short"
    message = (
        f"密码至少需要 {bound} 个字符" if too_short else f"密码最多允许 {bound} 个字符"
    ) if locale == "zh-CN" else (
        f"The password must contain at least {bound} characters" if too_short
        else f"The password must contain at most {bound} characters"
    )
    for field in ("password", "current_password", "new_password"):
        error = {"type": error_type, "loc": ("body", field), "input": "private-password",
                 "ctx": {"min_length" if too_short else "max_length": bound}}
        assert validation_message(request, error) == message
    list_error = {"type": error_type, "loc": ("body", "role_ids")}
    assert validation_message(
        request, list_error) == CATALOGS[locale][MessageKey.VALIDATION_LIST_LENGTH.value]


@pytest.mark.parametrize("minimum,maximum", [(8, 32), (10, 28)])
@pytest.mark.parametrize("locale", ["zh-CN", "en"])
def test_password_length_messages_read_current_shared_bounds(minimum: int, maximum: int, locale: str,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    """
        新密码策略提示读取当前上下限；没有真实边界的字段错误使用通用长度提示。

    :param minimum: 当前测试临时采用的最短密码字符数。
    :param maximum: 当前测试临时采用的最长密码字符数。
    :param locale: 中文或英文，用同一组数字核对两种语言。
    :param monkeypatch: 临时修改密码模块常量，用例结束后恢复，不改动请求模型或应用配置。
    :return: 无返回值；业务策略提示动态更新，不把新密码范围套到未知密码字段。
    """
    monkeypatch.setattr(password_security, "MIN_PASSWORD_CHARACTERS", minimum)
    monkeypatch.setattr(password_security, "MAX_PASSWORD_CHARACTERS", maximum)
    expected = (
        f"密码长度须为 {minimum}～{maximum} 位" if locale == "zh-CN"
        else f"The password must be {minimum}-{maximum} characters long"
    )
    assert translate_for_locale(
        locale, MessageKey.ERROR_PASSWORD_LENGTH) == expected
    request = _request(accept_language=locale)
    for error_type in ("too_short", "too_long"):
        for field in ("password", "current_password", "new_password"):
            fallback = MessageKey.VALIDATION_STRING_TOO_SHORT if error_type == "too_short" else (
                MessageKey.VALIDATION_STRING_TOO_LONG
            )
            for context in (None, {}, {"min_length": -1, "max_length": "wrong"}):
                error = {"type": error_type, "loc": (
                    "body", field), "ctx": context}
                assert validation_message(
                    request, error) == CATALOGS[locale][fallback.value]
    assert validation_message(request, {"type": "too_long", "loc": ("body", "role_ids")}) == (
        CATALOGS[locale][MessageKey.VALIDATION_LIST_LENGTH.value]
    )


@pytest.mark.parametrize(
    ("reason_code", "message_key"),
    [
        ("password_same_as_user_name", MessageKey.ERROR_PASSWORD_SAME_AS_USER_NAME),
        ("password_common_or_weak", MessageKey.ERROR_PASSWORD_COMMON_OR_WEAK),
        ("password_too_short", MessageKey.ERROR_PASSWORD_LENGTH),
        ("password_invalid_unicode", MessageKey.ERROR_PASSWORD_CHARACTERS),
        ("password_invalid_character", MessageKey.ERROR_PASSWORD_CHARACTERS),
        ("unknown_password_rule", MessageKey.ERROR_BAD_REQUEST),
    ],
)
def test_password_policy_error_uses_shared_error_contract(reason_code: str,
                                                          message_key: MessageKey) -> None:
    """
        验证密码规则原因码转换为统一错误，未知原因仍退回普通请求错误。

    :param reason_code: 密码规则产生的固定内部原因码。
    :param message_key: 该规则应使用的中英文公共消息键。
    :return: 无返回值；错误状态、业务码及文案键必须保持原契约。
    """
    error = password_policy_response_400(PasswordPolicyError(reason_code))

    assert error.status_code == 400
    assert error.business_code == (
        BusinessCode.BAD_REQUEST if reason_code == "unknown_password_rule" else BusinessCode.PASSWORD_POLICY_INVALID
    )
    assert error.message_key == message_key
    assert error.reason_code == reason_code


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, "zh-CN"),
        ("", "zh-CN"),
        ("   ", "zh-CN"),
        ("*", "zh-CN"),
        ("zh", "zh-CN"),
        ("ZH-cn", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("en", "en"),
        ("EN-us", "en"),
        ("en-US,en;q=.9,zh-CN;q=.8", "en"),
        ("zh-CN,zh;q=.9,en;q=.8", "zh-CN"),
        ("fr", "zh-CN"),
        ("fr;q=1, en;q=.8", "en"),
        ("en;q=.4, zh-CN;q=.9", "zh-CN"),
        ("en;q=.8, zh-CN;q=.8", "en"),
        ("en;q=0, zh-CN;q=.2", "zh-CN"),
        ("zh-CN;q=0, *;q=1", "zh-CN"),
        ("zh-CN;q=0, zh;q=1", "zh-CN"),
        ("zh;q=0, *;q=1", "zh-CN"),
        ("zh;q=0", "zh-CN"),
        ("en;q=0, *;q=1", "zh-CN"),
        ("zh;q=0, en;q=0", "zh-CN"),
        ("*;q=1, en;q=1", "en"),
        ("en-US;q=.1, en-GB;q=1, zh;q=.5", "en"),
        ("en;q=not-a-number, zh-CN;q=.2", "zh-CN"),
        ("en;q=NaN", "zh-CN"),
        ("en;q=Infinity", "zh-CN"),
        ("en;q=-1", "zh-CN"),
        ("en;q=2", "zh-CN"),
        (",".join(["fr"] * 19 + ["en"]), "en"),
        (",".join(["fr"] * 20 + ["en"]), "zh-CN"),
    ],
)
def test_accept_language_negotiation(header: str | None, expected: str) -> None:
    assert select_locale(header) == expected


@pytest.mark.parametrize(
    "malicious_header",
    [
        "en\x00zh-CN",
        "../../en",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "en\u202ezh-CN",
        "en," * 300,
        "en;q=" + "9" * 600,
    ],
)
def test_untrusted_language_values_never_escape_supported_locales(malicious_header: str) -> None:
    assert select_locale(malicious_header) == DEFAULT_LOCALE


def test_language_headers_preserve_existing_vary_once() -> None:
    message: dict[str, object] = {
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"vary", b"Origin, Accept-Encoding")],
    }
    headers = MutableHeaders(scope=message)

    apply_language_headers(headers, "en")
    apply_language_headers(headers, "en")

    assert headers["Content-Language"] == "en"
    vary = [part.strip().casefold() for part in headers["Vary"].split(",")]
    assert vary == ["origin", "accept-encoding", "accept-language"]


@pytest.mark.parametrize(
    ("accept_language", "expected_locale", "expected_message"),
    [
        (None, "zh-CN", "操作成功"),
        ("zh-CN", "zh-CN", "操作成功"),
        ("en", "en", "Operation successful"),
        ("fr;q=1,en-US;q=.8", "en", "Operation successful"),
    ],
)
async def test_http_response_localizes_only_human_message(accept_language: str | None,
                                                          expected_locale: str,
                                                          expected_message: str,
                                                          success_app: FastAPI
                                                          ) -> None:
    """
        验证语言协商只改变成功响应文案，不改变业务数据和请求 ID 契约。

    :param accept_language: 可选的请求语言头。
    :param expected_locale: 应协商得到的受支持语言。
    :param expected_message: 该语言下的通用操作成功文案。
    :param success_app: 临时注册成功路由并保留真实中间件的应用。
    :return: 无返回值；文案、语言头和统一响应字段必须正确。
    """
    headers = {"Accept-Language": accept_language} if accept_language else None
    transport = ASGITransport(app=success_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/controlled-test/success", headers=headers)

    body = response.json()
    assert set(body) == {"code", "message", "data", "request_id"}
    assert body["code"] == int(BusinessCode.OK)
    assert body["message"] == expected_message
    assert body["data"] == {"status": "ok"}
    assert response.headers["Content-Language"] == expected_locale
    assert [
        item.strip().casefold() for item in response.headers["Vary"].split(",")
    ].count("accept-language") == 1
    assert response.headers["X-Request-ID"] == body["request_id"]


async def test_concurrent_requests_do_not_share_locale(success_app: FastAPI) -> None:
    """
        验证并发成功请求各自保持语言上下文，不读取相邻请求的语言。

    :param success_app: 附加临时成功路由并保留真实中间件的应用。
    :return: 无返回值；每个响应必须与自己的语言头一致。
    """
    transport = ASGITransport(app=success_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        responses = await asyncio.gather(
            *(
                client.get(
                    "/controlled-test/success",
                    headers={"Accept-Language": "en" if index %
                             2 else "zh-CN"},
                )
                for index in range(20)
            )
        )

    for index, response in enumerate(responses):
        expected_locale = "en" if index % 2 else "zh-CN"
        expected_message = "Operation successful" if index % 2 else "操作成功"
        assert response.headers["Content-Language"] == expected_locale
        assert response.json()["message"] == expected_message


async def test_validation_outer_and_field_messages_are_localized(mock_login_guards: None) -> None:
    """
        缺失登录参数通过真实 HTTP 返回中英文参数错误，不依赖 Redis。

    :param mock_login_guards: 模拟本次请求已通过登录限流和验证码。
    :return: 无返回值；外层及字段级错误均使用请求选择的语言。
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        zh_response, en_response = await asyncio.gather(
            client.post("/api/v1/auth/login", json={}),
            client.post(
                "/api/v1/auth/login",
                json={},
                headers={"Accept-Language": "en"},
            ),
        )

    zh_body = zh_response.json()
    en_body = en_response.json()
    assert zh_response.status_code == en_response.status_code == 422
    assert zh_body["code"] == en_body["code"] == int(
        BusinessCode.VALIDATION_FAILED)
    assert zh_body["message"] == "请求参数校验失败"
    assert en_body["message"] == "Request validation failed"
    assert {error["message"] for error in zh_body["data"]["errors"]} == {
        "此字段为必填项"
    }
    assert {error["message"] for error in en_body["data"]["errors"]} == {
        "This field is required"
    }
    assert [error["field"] for error in zh_body["data"]["errors"]] == [
        error["field"] for error in en_body["data"]["errors"]
    ]
    assert zh_response.headers["Content-Language"] == "zh-CN"
    assert en_response.headers["Content-Language"] == "en"


async def test_custom_and_unknown_validation_types_do_not_echo_raw_messages() -> None:
    request = _request(accept_language="en")
    response = await handle_request_validation_error(
        request,
        RequestValidationError(
            [
                {
                    "type": "username_reserved",
                    "loc": ("body", "user_name"),
                    "msg": "raw framework message",
                    "input": "admin",
                },
                {
                    "type": "future_unknown_type",
                    "loc": ("body", "password"),
                    "msg": "sensitive raw detail",
                    "input": "secret-value",
                },
            ]
        ),
    )

    rendered = str(_body(response))
    assert "This username cannot be used" in rendered
    assert "Invalid value" in rendered
    assert "raw framework message" not in rendered
    assert "sensitive raw detail" not in rendered
    assert "secret-value" not in rendered


async def test_validation_fields_do_not_echo_untrusted_keys(mock_login_guards: None) -> None:
    """
        非法额外字段名在真实登录参数错误中被隐藏，避免回显不可信内容。

    :param mock_login_guards: 模拟本次请求已通过登录限流和验证码。
    :return: 无返回值；参数错误只显示受控的位置和字段提示。
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        extra_field_response = await client.post(
            "/api/v1/auth/login",
            json={"leaked-secret-as-key": "do-not-reflect"},
            headers={"Accept-Language": "en"},
        )

    extra_field_rendered = extra_field_response.text
    assert extra_field_response.status_code == 422
    assert "leaked-secret-as-key" not in extra_field_rendered
    assert "do-not-reflect" not in extra_field_rendered

    nested_key_response = await handle_request_validation_error(
        _request(accept_language="en"),
        RequestValidationError(
            [
                {
                    "type": "int_parsing",
                    "loc": ("body", "metadata", "private-dict-key"),
                    "msg": "private raw message",
                    "input": "private-value",
                }
            ]
        ),
    )
    nested_body = _body(nested_key_response)
    assert nested_body["data"] == {
        "errors": [{"field": "body.metadata", "message": "Must be an integer"}]
    }
    assert "private-dict-key" not in str(nested_body)
    assert "private raw message" not in str(nested_body)
    assert "private-value" not in str(nested_body)


async def test_domain_rate_limit_database_and_unexpected_errors_translate() -> None:
    request = _request(accept_language="en")
    domain = await handle_access_error(request, forbidden_403("private_reason"))
    limited = await handle_rate_limit_exceeded(
        request,
        RateLimitExceeded(
            policy_name="private_policy",
            result=RateLimitResult(
                allowed=False,
                limit=5,
                remaining=0,
                retry_after_ms=1_001,
                reset_after_ms=2_000,
            ),
        ),
    )
    unavailable = await handle_database_unavailable(
        request,
        OperationalError(
            "private statement",
            {},
            RuntimeError("offline"),
            connection_invalidated=True,
        ),
    )
    unexpected = await handle_unexpected_error(request, RuntimeError("private"))

    assert _body(domain)[
        "message"] == "You are not allowed to perform this operation"
    assert _body(limited)["message"] == "Too many requests; try again later"
    assert _body(unavailable)["message"] == "Service temporarily unavailable"
    assert _body(unexpected)["message"] == "Internal server error"
    combined = " ".join(
        str(_body(response)) for response in (domain, limited, unavailable, unexpected)
    )
    assert "private_reason" not in combined
    assert "private_policy" not in combined
    assert "private statement" not in combined


@pytest.mark.parametrize(
    ("error", "status_code", "business_code", "english_message"),
    [
        (
            unauthenticated_401("private"),
            401,
            BusinessCode.INVALID_AUTHENTICATION,
            "Authentication failed",
        ),
        (
            forbidden_403("private"),
            403,
            BusinessCode.ACCESS_FORBIDDEN,
            "You are not allowed to perform this operation",
        ),
        (not_found_404("private"), 404, BusinessCode.NOT_FOUND, "Resource not found"),
        (
            conflict_409("private"),
            409,
            BusinessCode.CONFLICT,
            "The current resource state conflicts with this operation",
        ),
        (
            stale_resource_version_409("private"),
            409,
            BusinessCode.ROLE_VERSION_STALE,
            "The resource was updated; refresh and try again",
        ),
        (
            invalid_request_400("private"),
            400,
            BusinessCode.BAD_REQUEST,
            "Invalid request",
        ),
        (
            unavailable_503("private"),
            503,
            BusinessCode.SERVICE_UNAVAILABLE,
            "Service temporarily unavailable",
        ),
    ],
)
async def test_all_domain_error_categories_translate_by_key(error: AppError, status_code: int,
                                                            business_code: BusinessCode, english_message: str) -> None:
    response = await handle_access_error(_request(accept_language="en"), error)

    body = _body(response)
    assert response.status_code == status_code
    assert body["code"] == int(business_code)
    assert body["message"] == english_message
    assert "private" not in str(body)


@pytest.mark.parametrize(
    ("status_code", "business_code", "english_message"),
    [
        (400, BusinessCode.BAD_REQUEST, "Invalid request"),
        (401, BusinessCode.INVALID_AUTHENTICATION, "Authentication failed"),
        (
            403,
            BusinessCode.ACCESS_FORBIDDEN,
            "You are not allowed to perform this operation",
        ),
        (404, BusinessCode.NOT_FOUND, "Resource not found"),
        (405, BusinessCode.METHOD_NOT_ALLOWED, "Method not allowed"),
        (
            409,
            BusinessCode.CONFLICT,
            "The current resource state conflicts with this operation",
        ),
        (413, BusinessCode.PAYLOAD_TOO_LARGE, "Request content is too large"),
        (415, BusinessCode.UNSUPPORTED_MEDIA_TYPE,
         "Unsupported request media type"),
        (422, BusinessCode.VALIDATION_FAILED, "Request validation failed"),
        (429, BusinessCode.RATE_LIMITED, "Too many requests"),
        (500, BusinessCode.INTERNAL_ERROR, "Internal server error"),
        (503, BusinessCode.SERVICE_UNAVAILABLE, "Service temporarily unavailable"),
    ],
)
async def test_framework_error_catalog_is_complete(status_code: int, business_code: BusinessCode,
                                                   english_message: str) -> None:
    response = await handle_http_error(
        _request(accept_language="en"),
        StarletteHTTPException(status_code=status_code),
    )

    body = _body(response)
    assert response.status_code == status_code
    assert body["code"] == int(business_code)
    assert body["message"] == english_message


async def test_missing_bearer_token_uses_english_and_keeps_security_headers() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/me/user_info", headers={"Accept-Language": "en"}
        )

    assert response.status_code == 401
    assert response.json()["code"] == int(BusinessCode.INVALID_AUTHENTICATION)
    assert response.json()["message"] == "Authentication failed"
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Content-Language"] == "en"


async def test_framework_404_and_405_are_localized_without_contract_changes() -> None:
    """
        验证不存在的路径和现有业务路由的错误方法均返回本地化框架错误。

    :return: 无返回值；404 和 405 的业务码及英文文案必须保持契约。
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing, method = await asyncio.gather(
            client.get("/not-present", headers={"Accept-Language": "en"}),
            client.post("/api/v1/me/user_info",
                        headers={"Accept-Language": "en"}),
        )

    assert missing.status_code == 404
    assert missing.json()["code"] == int(BusinessCode.NOT_FOUND)
    assert missing.json()["message"] == "Resource not found"
    assert method.status_code == 405
    assert method.json()["code"] == int(BusinessCode.METHOD_NOT_ALLOWED)
    assert method.json()["message"] == "Method not allowed"


async def test_unhandled_500_keeps_language_headers() -> None:
    from app.dependencies.auth import check_token

    async def explode() -> None:
        raise RuntimeError("private-unhandled-failure")

    app.dependency_overrides[check_token] = explode
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/me/user_info",
                headers={"Accept-Language": "en"},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json()["message"] == "Internal server error"
    assert response.headers["Content-Language"] == "en"
    assert [
        item.strip().casefold() for item in response.headers["Vary"].split(",")
    ].count("accept-language") == 1


@pytest.mark.parametrize("reason_code", ["password_queue_full", "password_queue_timeout"])
@pytest.mark.parametrize(
    "locale,message",
    [("zh-CN", "系统繁忙，请稍后重试"), ("en", "The system is busy; try again later")],
)
async def test_password_busy_returns_localized_503(reason_code: str, locale: str, message: str,
                                                   monkeypatch: pytest.MonkeyPatch,
                                                   caplog: pytest.LogCaptureFixture) -> None:
    """
        两种密码排队拒绝均通过真实异常登记返回双语 503，不掉进 500 或公开内部原因。

    :param reason_code: 密码计算队列满或等待超时的安全原因码。
    :param locale: 本次请求选择的中文或英文。
    :param message: 对应语言的公开繁忙提示。
    :param monkeypatch: 临时把认证依赖替换成繁忙异常，不访问数据库或 Redis。
    :param caplog: 捕获日志，核对内部原因只供服务端排查。
    :return: 无返回值；响应契约、响应头和日志原因必须正确。
    """
    from app.dependencies.auth import check_token

    async def deny_password_work() -> None:
        """
            模拟密码任务因队列繁忙而未能开始，不执行实际密码计算。

        :return: 不正常返回，直接抛出当前测试指定的繁忙异常。
        """
        raise PasswordBusyError(reason_code)

    monkeypatch.setitem(app.dependency_overrides,
                        check_token, deny_password_work)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/me/user_info", headers={"Accept-Language": locale})

    body = response.json()
    assert response.status_code == 503
    assert body == {"code": 50301, "message": message,
                    "data": None, "request_id": body["request_id"]}
    assert body["request_id"]
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert response.headers["Content-Language"] == locale
    assert response.headers["Cache-Control"] == "no-store"
    assert [part.strip().casefold() for part in response.headers["Vary"].split(
        ",")].count("accept-language") == 1
    assert "Retry-After" not in response.headers
    assert "WWW-Authenticate" not in response.headers
    assert reason_code not in response.text
    assert "PasswordBusyError" not in response.text
    records = [
        record for record in caplog.records if record.msg == "password.busy"]
    assert len(records) == 1
    assert records[0].__dict__["reason_code"] == reason_code
