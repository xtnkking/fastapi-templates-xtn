#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查身份接口文档、用户名及密码边界和安全本地化提示。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件记录并同步中文接口文档断言，保留行为校验
# 2026/09/29    XTN       V1.001        对齐新密码可见 ASCII 字符说明及长度提示
# 2026/09/30    XTN       V1.002        移除临时密码请求模型断言
# 2026/10/09    XTN       V1.003        验证验证码枚举的字符串契约和非法用途双语提示
# 2026/10/09    XTN       V1.004        验证码请求从所属模型模块导入
# 2026/10/10    XTN       V1.005        验证统一密码长度、原文保留及新旧字段的双语错误提示
# 2026/10/14    XTN       V1.006        隔离验证码存储并验证六个密码字段的统一长度边界和动态双语提示
# 2026/10/20    XTN       V1.007        区分登录传输边界和新密码策略长度，保留旧密码验证入口
# 2026/10/24    XTN       V1.008        验证码场景名称明确具体用户操作
# 2026/11/26    XTN       V1.009        新增技术及客服保留名仍返回明确的用户名错误
# 2026/11/26    XTN       V1.010        保留名数字下划线变体保持明确的请求错误类型
# 2026/11/26    XTN       V1.011        新密码字段统一引用密码规则说明和长度边界
# --------------------------------------------------------------------------------------------------

"""验证身份接口文档、输入边界和安全本地化提示，不连接数据库或 Redis。"""

import uuid
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ValidationError

import app.dependencies.captcha as captcha_dependencies
from app.core.captcha import CaptchaScene
from app.core.security.password_rules import (
    MAX_PASSWORD_CHARACTERS,
    MAX_PASSWORD_INPUT_CHARACTERS,
    MIN_PASSWORD_CHARACTERS,
)
from app.dependencies.rate_limit import rate_limit_login, rate_limit_public_captcha, rate_limit_register
from app.main import app
from app.schemas.auth import LoginRequest, PasswordChangeRequest, RegisterRequest
from app.schemas.captcha import CaptchaCreateRequest
from app.schemas.user import UserCreateRequest, UserPasswordResetRequest
from app.services.captcha_service import captcha_service


@pytest.fixture
def mock_schema_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        为参数校验用例隔离限流和验证码存储边界，不连接 Redis。
        仍执行真实验证码依赖的字段读取；只模拟其最终校验已通过，继续检查其他请求字段。
        仅使用本夹具的用例得到替换，其他限流测试仍执行真实的限流逻辑。

    :param monkeypatch: 临时替换依赖并在每个用例结束后恢复。
    :return: 无返回值；参数请求可以继续到实际的 Pydantic 校验。
    """
    async def admitted_request() -> None:
        """
            代替本用例的限流依赖，允许请求继续到真实参数校验。

        :return: 无返回值；不连接 Redis，不执行业务操作。
        """
    for dependency in (rate_limit_public_captcha, rate_limit_register, rate_limit_login):
        monkeypatch.setitem(app.dependency_overrides, dependency, admitted_request)
    # 实际执行顺序仍是先验证码依赖、再校验路由的其他业务字段；这里仅替换 Redis 边界。
    monkeypatch.setattr(captcha_dependencies, "get_redis", lambda _request: object())
    monkeypatch.setattr(captcha_service, "verify_captcha", AsyncMock())


@pytest.mark.parametrize("value", [
    "login", "register", "admin_create_user", "admin_reset_user_password", "user_change_password",
])
def test_captcha_scene_enum_preserves_request_strings(value: str) -> None:
    """
        前端仍可提交原有五种用途字符串；解析为枚举后序列化仍保持原值。

    :param value: 前端约定的验证码用途字符串。
    :return: 无返回值；请求模型使用枚举，并保持原有 JSON 字符串契约。
    """
    body = CaptchaCreateRequest.model_validate({"scene": value})
    assert isinstance(body.scene, CaptchaScene)
    assert body.model_dump(mode="json") == {"scene": value}


@pytest.mark.parametrize("locale, message, field_message", [
    ("zh-CN", "请求参数校验失败", "值不在允许范围内"),
    ("en", "Request validation failed", "Value is not supported"),
])
async def test_invalid_captcha_enum_has_localized_field_error(locale: str, message: str, field_message: str,
                                                              mock_schema_rate_limits: None) -> None:
    """
        非法验证码用途经实际 HTTP 参数校验后返回统一的中英文错误，且不签发图片。

    :param locale: 本次请求选择的中文或英文。
    :param message: 对应语言的请求参数错误总提示。
    :param field_message: 对应语言的验证码用途字段提示。
    :param mock_schema_rate_limits: 临时模拟限流依赖，检查参数错误时不连接 Redis。
    :return: 无返回值；非法用途返回 HTTP 422、业务码 42201 和安全的字段错误。
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/auth/captcha", json={"scene": "unsupported"},
                                     headers={"Accept-Language": locale})
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == 42201
    assert body["message"] == message
    assert body["data"]["errors"] == [{"field": "body.scene", "message": field_message}]


def test_openapi_describes_trimmed_usernames_and_password_contracts() -> None:
    """
        区分原密码传输边界和新密码策略长度，并说明用户名先去首尾空白。

    :return: 无返回值；所有身份请求公开的长度、字符与保密标记符合实际契约。
    """
    schemas = app.openapi()["components"]["schemas"]
    for model in ("RegisterRequest", "LoginRequest", "UserCreateRequest"):
        username = schemas[model]["properties"]["user_name"]
        assert (username["minLength"], username["maxLength"]) == (3, 32)
        assert username["pattern"] == r"^[A-Za-z0-9_]{3,32}$"
        assert "先去掉首尾空白" in username["description"]
    for model, field in (
        ("RegisterRequest", "password"),
        ("PasswordChangeRequest", "new_password"),
        ("UserPasswordResetRequest", "new_password"),
        ("UserCreateRequest", "password"),
    ):
        password = schemas[model]["properties"][field]
        assert (password["minLength"], password["maxLength"]) == (MIN_PASSWORD_CHARACTERS, MAX_PASSWORD_CHARACTERS)
        assert f"{MIN_PASSWORD_CHARACTERS}～{MAX_PASSWORD_CHARACTERS}" in password["description"]
        assert password["writeOnly"] is True
        assert "可见的英文字母" in password["description"]
        assert "大写字母" in password["description"]
        assert "小写字母" in password["description"]
        assert "数字" in password["description"]
        assert "特殊符号" in password["description"]
    for model, field in (("LoginRequest", "password"), ("PasswordChangeRequest", "current_password")):
        password = schemas[model]["properties"][field]
        assert (password["minLength"], password["maxLength"]) == (1, MAX_PASSWORD_INPUT_CHARACTERS)
        assert password["writeOnly"] is True
        assert password["description"]


@pytest.mark.parametrize("request_model,field", [
    (RegisterRequest, "password"),
    (PasswordChangeRequest, "new_password"),
    (UserPasswordResetRequest, "new_password"),
    (UserCreateRequest, "password"),
])
@pytest.mark.parametrize("length", [
    MIN_PASSWORD_CHARACTERS - 1, MIN_PASSWORD_CHARACTERS,
    MAX_PASSWORD_CHARACTERS, MAX_PASSWORD_CHARACTERS + 1,
])
def test_new_http_password_fields_keep_policy_length_boundaries(request_model: type[BaseModel],
                                                                field: str, length: int) -> None:
    """
        四个设置新密码的字段接受策略上下限本身，拒绝少一位或多一位的输入。

    :param request_model: 注册、改密、管理员重置或新增用户的实际请求模型。
    :param field: 本次检查的密码字段，其他字段保持合法。
    :param length: 位于新密码长度边界或边界之外一位的密码长度。
    :return: 无返回值；合法长度保留原文，越界错误只指向本次密码字段。
    """
    body: dict[str, object] = {"captcha_id": uuid.uuid4(), "captcha_answer": "AB234"}
    if "user_name" in request_model.model_fields:
        body["user_name"] = "Alice"
    if "user_id" in request_model.model_fields:
        body["user_id"] = "UABCDEFGHIJKLMN"
    if "current_password" in request_model.model_fields:
        body["current_password"] = "Existing-password"
    if "new_password" in request_model.model_fields:
        body["new_password"] = "Different-password"
    password = "Ab1!" + "x" * (length - 4)
    body[field] = password
    if MIN_PASSWORD_CHARACTERS <= length <= MAX_PASSWORD_CHARACTERS:
        parsed = request_model.model_validate(body)
        assert getattr(parsed, field).get_secret_value() == password
    else:
        with pytest.raises(ValidationError) as caught:
            request_model.model_validate(body)
        errors = caught.value.errors()
        assert [error["loc"] for error in errors] == [(field,)]
        assert errors[0]["type"] == ("too_short" if length < MIN_PASSWORD_CHARACTERS else "too_long")


def test_trim_happens_before_username_length_and_preserves_passwords() -> None:
    """
        首尾空白不占用户名长度额度，所有密码字段按原文传输，不被请求层改写。

    :return: 无返回值；新旧密码各用自己的长度边界，不擅自去除密码中的空白。
    """
    captcha = {"captcha_id": uuid.uuid4(), "captcha_answer": "AB234"}
    username = "Alice_" + "a" * 26
    login = LoginRequest.model_validate({"user_name": f"  {username}  ", "password": " old-password ", **captcha})
    change = PasswordChangeRequest.model_validate({
        "current_password": " old-password ", "new_password": "!Valid-Password?", **captcha,
    })
    assert login.user_name == username
    assert login.password.get_secret_value() == " old-password "
    assert change.current_password.get_secret_value() == " old-password "
    assert change.new_password.get_secret_value() == "!Valid-Password?"
    assert "Valid-Password" not in repr(change)


@pytest.mark.parametrize("request_model,field", [
    (LoginRequest, "password"), (PasswordChangeRequest, "current_password"),
])
@pytest.mark.parametrize("length", [0, 1, MIN_PASSWORD_CHARACTERS - 1,
                                    MAX_PASSWORD_CHARACTERS + 1, MAX_PASSWORD_INPUT_CHARACTERS,
                                    MAX_PASSWORD_INPUT_CHARACTERS + 1])
def test_existing_password_fields_only_limit_transport(request_model: type[BaseModel], field: str, length: int) -> None:
    """
        登录和本人改密的旧密码不受新密码长度影响，只限制非空和传输上限。

    :param request_model: 登录或本人改密的真实请求模型。
    :param field: 当前用于验证旧密码的字段。
    :param length: 传输边界及新密码策略边界附近的字符数。
    :return: 无返回值；原密码不会因新策略而被拦截，过大的输入仍会被拒绝。
    """
    body = {"captcha_id": uuid.uuid4(), "captcha_answer": "AB234"}
    if request_model is LoginRequest:
        body["user_name"] = "Alice"
    else:
        body["new_password"] = "Different-password"
    body[field] = "x" * length
    if 1 <= length <= MAX_PASSWORD_INPUT_CHARACTERS:
        parsed = request_model.model_validate(body)
        assert getattr(parsed, field).get_secret_value() == body[field]
    else:
        with pytest.raises(ValidationError) as caught:
            request_model.model_validate(body)
        assert caught.value.errors()[0]["loc"] == (field,)
        assert caught.value.errors()[0]["type"] == ("too_short" if length == 0 else "too_long")


@pytest.mark.parametrize("username", ["  ab  ", "a" * 33, "测试用户", "alice-name", "alice\nname"])
@pytest.mark.parametrize("locale", ["zh-CN", "en"])
async def test_username_failures_have_actionable_localized_messages(username: str, locale: str,
                                                                    mock_schema_rate_limits: None) -> None:
    """
        通过真实请求验证用户名长度与格式失败的提示，避免泛化成无法理解的参数错误。

    :param username: 非法长度或格式的用户名。
    :param locale: 本次请求选择的中英文语言。
    :param mock_schema_rate_limits: 临时模拟注册限流，参数校验不依赖 Redis。
    :return: 无返回值；响应说明允许字符和长度，并且不回显输入。
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/auth/register", headers={"Accept-Language": locale}, json={
            "user_name": username, "password": "safe-password", "captcha_id": str(uuid.uuid4()),
            "captcha_answer": "AB234",
        })
    assert response.status_code == 422
    expected = (
        "去掉首尾空白后，用户名须为 3～32 位英文字母、数字或下划线" if locale == "zh-CN"
        else "After trimming surrounding whitespace, the username must be 3-32 ASCII letters, digits or underscores"
    )
    assert response.json()["data"]["errors"] == [{"field": "body.user_name", "message": expected}]
    assert "safe-password" not in response.text
    assert "AB234" not in response.text


@pytest.mark.parametrize("path,password,bound", [
    ("/api/v1/auth/register", "x" * (MIN_PASSWORD_CHARACTERS - 1), MIN_PASSWORD_CHARACTERS),
    ("/api/v1/auth/register", "x" * (MAX_PASSWORD_CHARACTERS + 1), MAX_PASSWORD_CHARACTERS),
    ("/api/v1/auth/login", "", 1),
    ("/api/v1/auth/login", "x" * (MAX_PASSWORD_INPUT_CHARACTERS + 1), MAX_PASSWORD_INPUT_CHARACTERS),
])
@pytest.mark.parametrize("locale", ["zh-CN", "en"])
async def test_password_length_has_actionable_localized_messages(password: str, bound: int, locale: str, path: str,
                                                                 mock_schema_rate_limits: None) -> None:
    """
        注册和登录各自说明实际字段边界，错误响应不包含密码原文。

    :param password: 太短或太长的密码。
    :param bound: 本次字段实际执行的最短或最长长度。
    :param locale: 本次请求选择的中英文语言。
    :param path: 当前验证的注册或登录接口路径。
    :param mock_schema_rate_limits: 临时放行限流和验证码存储校验，保留真实的密码模型校验。
    :return: 无返回值；两种语言均返回明确、无敏感输入的长度提示。
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(path, headers={"Accept-Language": locale}, json={
            "user_name": "Alice", "password": password, "captcha_id": str(uuid.uuid4()), "captcha_answer": "AB234",
        })
    assert response.status_code == 422
    too_short = len(password) < bound
    expected = (
        f"密码至少需要 {bound} 个字符" if too_short else f"密码最多允许 {bound} 个字符"
    ) if locale == "zh-CN" else (
        f"The password must contain at least {bound} characters" if too_short
        else f"The password must contain at most {bound} characters"
    )
    assert response.json()["data"]["errors"] == [{"field": "body.password", "message": expected}]
    if password:
        assert password not in response.text
    assert "AB234" not in response.text


@pytest.mark.parametrize("user_name", [
    "ROOT", "ADMINS", "KEFU", "DATA", "PYTHON", "MYSQL", "PHP", "JAVA",
    "admin01", "ADMIN_001", "_admin_", "01admin", "python123", "01_KEFU_23",
])
def test_reserved_name_error_remains_distinct_from_format_error(user_name: str) -> None:
    """
        保留用户名仍使用单独的错误类型，不能被格式校验覆盖为含糊提示。

    :param user_name: 系统、客服、数据和开发技术等不同类别的保留用户名。
    :return: 无返回值；大小写变化和首尾空格都无法绕过保留名规则。
    """
    with pytest.raises(ValidationError) as caught:
        LoginRequest.model_validate({
            "user_name": f"  {user_name}  ", "password": "old", "captcha_id": uuid.uuid4(), "captcha_answer": "AB234",
        })
    assert caught.value.errors()[0]["type"] == "username_reserved"
