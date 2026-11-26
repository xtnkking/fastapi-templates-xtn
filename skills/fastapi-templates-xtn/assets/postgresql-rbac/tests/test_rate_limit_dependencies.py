#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    已登录用户分业务限流登记、计数顺序及隔离性的离线测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/26    XTN       V1.000        补充文件职责，对齐认证接口的简洁操作 ID
# 2026/09/27    XTN       V1.001        对齐权限详情处理函数的操作 ID
# 2026/09/29    XTN       V2.000        改用路由函数名和认证依赖显式选择的额度档位
# 2026/10/02    XTN       V2.001        验证验证码档位不可误用通用扣次入口
# 2026/10/04    XTN       V2.002        验证场景单次提取后选择准确的预查窗口
# 2026/10/04    XTN       V2.003        由 Service 统一选策略，依赖只提供业务名和主体
# 2026/10/08    XTN       V3.000        限流维度和策略改由依赖直接声明
# 2026/10/08    XTN       V3.001        跟随普通额度字符串移除仅提示用途的类型别名
# 2026/10/09    XTN       V3.002        跟随用户限流预查、计数和验证码用途读取的新名称
# 2026/10/09    XTN       V3.003        对齐验证码无效用途限流的直观业务名称
# 2026/10/10    XTN       V3.004        移除只读预查测试并验证用户及验证码每次只计数一次
# 2026/10/10    XTN       V3.005        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V3.006        对齐已登录业务限流键的简化前缀
# 2026/10/20    XTN       V3.007        按真实请求方法验证本人及管理接口配置，移除已删除的额度名参数
# 2026/10/24    XTN       V3.008        验证码场景名称明确具体用户操作
# --------------------------------------------------------------------------------------------------

import json
import uuid
from types import SimpleNamespace
from typing import Literal
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

import app.dependencies.rate_limit as rate_limit_module
from app.core.access.authorization import LoginInfo
from app.core.config import Settings, get_settings
from app.core.ids import new_entity_id
from app.core.rate_limit.limiter import (
    RateLimitExceeded,
    RateLimitResult,
    RateLimitUnavailable,
)
from app.dependencies.rate_limit import (
    get_captcha_scene,
    rate_limit_private_captcha,
    rate_limit_user,
)


def settings() -> Settings:
    """
        读取测试进程已校验的限流配置；限流没有可关闭开关。

    :return: 当前测试使用的应用配置。
    """
    return get_settings()


def login_info() -> LoginInfo:
    return LoginInfo(
        user_id=new_entity_id("U"),
        token_version=0,
        token_id=uuid.uuid4(),
        issued_at=1,
        expires_at=2,
    )


def request_for(*, method: Literal["GET", "POST"], route_name: str,
                rate_limit_redis: object | None = None
                ) -> Request:
    """
        构造带稳定路由函数名的最小请求，不依赖 OpenAPI 元数据。

    :param method: 当前路由允许的 GET 或 POST 方法。
    :param route_name: FastAPI 从处理函数取得的服务端路由名称。
    :param rate_limit_redis: 可选的模拟限流 Redis 客户端。
    :return: 可直接调用限流依赖的 Starlette 请求对象。
    """
    app = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=rate_limit_redis))
    return Request(
        {
            "type": "http",
            "method": method,
            "headers": [],
            "app": app,
            "route": SimpleNamespace(name=route_name),
        }
    )


def json_request_for(*, route_name: str, payload: object,
                     content_type: str = "application/json") -> Request:
    body = json.dumps(payload).encode("utf-8")
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    app = SimpleNamespace(state=SimpleNamespace(rate_limit_redis=object()))

    return Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", content_type.encode("ascii"))],
            "app": app,
            "route": SimpleNamespace(name=route_name),
        },
        receive,
    )


@pytest.mark.parametrize(
    ("route_name", "method", "management", "limit"),
    [
        ("list_roles", "GET", True, 300),
        ("get_permission_detail", "GET", True, 300),
        ("get_user_info", "GET", False, 600),
        ("create_role", "POST", True, 60),
        ("reset_user_password", "POST", True, 60),
        ("create_user", "POST", True, 60),
        ("revoke_user_sessions", "POST", True, 60),
        ("change_my_password", "POST", False, 120),
    ],
)
@pytest.mark.asyncio
async def test_each_operation_gets_its_own_key_and_class_quota(
    route_name: str, method: Literal["GET", "POST"], management: bool, limit: int
) -> None:
    redis = AsyncMock()
    redis.eval.return_value = [1, 60000]
    await rate_limit_user(
        request_for(method=method, route_name=route_name, rate_limit_redis=redis),
        login_info(), settings(), management=management,
    )
    redis.eval.assert_awaited_once()
    assert redis.eval.await_args.args[3:] == (str(limit), "60")
    assert f":{route_name}:user_id:" in redis.eval.await_args.args[2]


@pytest.mark.asyncio
async def test_allowed_user_check_hides_user_id_in_redis_key() -> None:
    current_user = login_info()
    app_settings = settings()
    redis_mock = AsyncMock()
    redis_mock.eval.return_value = [1, 60000]
    request = request_for(
        method="GET",
        route_name="get_user_info",
        rate_limit_redis=redis_mock,
    )
    await rate_limit_user(
        request,
        current_user,
        app_settings,
    )
    key = redis_mock.eval.await_args.args[2]
    assert key.startswith("rate_limit:get_user_info:user_id:")
    assert str(current_user.user_id) not in key


@pytest.mark.asyncio
async def test_denied_user_check_raises_rate_limit_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        业务窗口只计数一次，耗尽结果继续抛给统一 HTTP 异常处理。

    :param monkeypatch: 隔离 Redis 计数并返回已耗尽的固定窗口。
    :return: 无返回值；拒绝携带实际业务名和原始窗口结果。
    """
    denied = RateLimitResult(False, 60, 0, 750, 750)
    check = AsyncMock(return_value=denied)
    monkeypatch.setattr(rate_limit_module, "check_rate_limit", check)
    request = request_for(
        method="POST",
        route_name="bind_role_permissions",
        rate_limit_redis=object(),
    )
    with pytest.raises(RateLimitExceeded) as caught:
        await rate_limit_user(
            request,
            login_info(),
            settings(),
            management=True,
        )
    assert caught.value.policy_name == "bind_role_permissions"
    assert caught.value.result is denied
    check.assert_awaited_once()


@pytest.mark.parametrize(
    ("payload", "expected_policy"),
    [
        ({"scene": "admin_create_user"}, "captcha_create_admin_create_user"),
        ({"scene": "admin_reset_user_password"}, "captcha_create_admin_reset_user_password"),
        ({"scene": "user_change_password"}, "captcha_create_user_change_password"),
        ({"scene": "login"}, "captcha_invalid_scene"),
        ({"scene": "register"}, "captcha_invalid_scene"),
        ({"scene": "unknown"}, "captcha_invalid_scene"),
        ({}, "captcha_invalid_scene"),
        (
            {"scene": "admin_reset_user_password", "unexpected_field": "ignored-by-limiter"},
            "captcha_create_admin_reset_user_password",
        ),
    ],
)
@pytest.mark.asyncio
async def test_authenticated_captcha_charges_its_exact_window_once(monkeypatch: pytest.MonkeyPatch,
                                                                   payload: object, expected_policy: str) -> None:
    """
        正常用途和无效用途均按独立窗口扣一次，不执行只读预查。

    :param monkeypatch: 隔离 Redis 计数边界。
    :param payload: 用于选择验证码用途的请求体。
    :param expected_policy: 该用途对应的正常或拒绝窗口业务名。
    :return: 无返回值；每个请求仅调用一次计数并使用五分钟额度。
    """
    check = AsyncMock(return_value=RateLimitResult(True, 10, 9, 300000, 0))
    monkeypatch.setattr(rate_limit_module, "check_rate_limit", check)
    request = json_request_for(
        route_name="create_authenticated_captcha",
        payload=payload,
    )

    scene = await get_captcha_scene(request)
    await rate_limit_private_captcha(
        request,
        login_info(),
        settings(),
        scene=scene,
    )

    check.assert_awaited_once()
    assert check.await_args is not None
    policy = check.await_args.kwargs["policy"]
    assert policy.name == expected_policy
    assert policy.limit == 10
    assert policy.window_seconds == 300


@pytest.mark.asyncio
async def test_authenticated_captcha_charges_rejection_window_for_text_plain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        文本媒体类型即使带正确 JSON 用途，也只消耗一次拒绝额度。

    :param monkeypatch: 隔离 Redis 计数边界。
    :return: 无返回值；不使用正常验证码用途窗口。
    """
    check = AsyncMock(return_value=RateLimitResult(True, 10, 9, 300000, 0))
    monkeypatch.setattr(rate_limit_module, "check_rate_limit", check)
    request = json_request_for(
        route_name="create_authenticated_captcha",
        payload={"scene": "admin_reset_user_password"},
        content_type="text/plain",
    )

    scene = await get_captcha_scene(request)
    await rate_limit_private_captcha(
        request,
        login_info(),
        settings(),
        scene=scene,
    )

    check.assert_awaited_once()
    assert check.await_args is not None
    assert check.await_args.kwargs["policy"].name == "captcha_invalid_scene"


@pytest.mark.asyncio
async def test_authenticated_captcha_accepts_vendor_json_media_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        带 JSON 后缀的自定义媒体类型按实际验证码用途计数一次。

    :param monkeypatch: 隔离 Redis 计数边界。
    :return: 无返回值；使用管理员重置验证码的独立窗口。
    """
    check = AsyncMock(return_value=RateLimitResult(True, 10, 9, 300000, 0))
    monkeypatch.setattr(rate_limit_module, "check_rate_limit", check)
    request = json_request_for(
        route_name="create_authenticated_captcha",
        payload={"scene": "admin_reset_user_password"},
        content_type="application/vnd.xtn+json; charset=utf-8",
    )

    scene = await get_captcha_scene(request)
    await rate_limit_private_captcha(
        request,
        login_info(),
        settings(),
        scene=scene,
    )

    check.assert_awaited_once()
    assert check.await_args is not None
    assert check.await_args.kwargs["policy"].name == "captcha_create_admin_reset_user_password"


@pytest.mark.asyncio
async def test_rate_limit_store_failure_fails_closed_as_503(monkeypatch: pytest.MonkeyPatch) -> None:
    check = AsyncMock(side_effect=RateLimitUnavailable("private Redis endpoint"))
    monkeypatch.setattr(rate_limit_module, "check_rate_limit", check)
    request = request_for(
        method="POST",
        route_name="bind_role_permissions",
        rate_limit_redis=object(),
    )
    with pytest.raises(RateLimitUnavailable, match="private Redis endpoint"):
        await rate_limit_user(
            request,
            login_info(),
            settings(),
            management=True,
        )


@pytest.mark.asyncio
async def test_missing_route_name_fails_closed() -> None:
    request = request_for(
        method="POST",
        route_name="",
        rate_limit_redis=object(),
    )
    with pytest.raises(RateLimitUnavailable, match="stable route name"):
        await rate_limit_user(
            request,
            login_info(),
            settings(),
        )
