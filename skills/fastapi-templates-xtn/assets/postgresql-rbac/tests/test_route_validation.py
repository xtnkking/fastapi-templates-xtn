#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    业务路由方法、参数位置和认证依赖的离线启动校验测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/26    XTN       V1.000        补充文件职责，对齐简洁操作 ID 与路由校验文案
# 2026/09/27    XTN       V1.001        验证登录后验证码不能漏掉独立场景限流声明
# 2026/09/29    XTN       V2.000        改为验证自动限流认证依赖和稳定路由函数名
# 2026/09/29    XTN       V2.001        通过 API 装配层验证公开入口和特殊认证规则
# 2026/09/29    XTN       V2.002        使用独立 v1 路由校验模块
# 2026/10/04    XTN       V2.003        路由限流策略改由 Service 统一构造
# 2026/10/22    XTN       V2.004        验证权限闭包接线，拒绝仅验 Token 或未调用的权限工厂
# 2026/10/22    XTN       V2.005        独立业务窗口测试使用简短本人查询配置
# --------------------------------------------------------------------------------------------------

"""验证业务路由在启动前接入必要的登录依赖和输入约定。"""

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request, routing
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.api.v1.route_validation import validate_v1_api_routes
from app.core.config import get_settings
from app.dependencies.auth import (
    check_token,
    get_captcha_user,
    get_current_user,
)
from app.dependencies.permission import require_permission
from app.main import app


def endpoint() -> dict[str, str]:
    """
        返回测试路由的固定结果。

    :return: 不访问外部服务的固定字典。
    """
    return {"result": "ok"}


def new_app(*, method: str = "GET", authenticated: bool = True,
            hidden: bool = False, route_name: str = "list_orders") -> FastAPI:
    """
        构造一个嵌套路由应用，用于验证启动期接口接线规则。

    :param method: 测试路由声明的 HTTP 方法。
    :param authenticated: 是否接入本人业务认证依赖。
    :param hidden: 是否从内部 OpenAPI 模型隐藏；不影响实际安全校验。
    :param route_name: FastAPI 路由名称，也是该业务的内部限流名称。
    :return: 尚未运行生命周期的隔离 FastAPI 应用。
    """

    async def list_orders() -> dict[str, str]:
        """
            返回测试业务结果。

        :return: 不访问外部资源的固定字典。
        """
        return {"result": "ok"}

    router = APIRouter()
    router.add_api_route(
        "/orders/list",
        list_orders,
        methods=[method],
        name=route_name,
        include_in_schema=not hidden,
        dependencies=[Depends(get_current_user)] if authenticated else [],
    )
    parent = APIRouter(prefix="/v1")
    parent.include_router(router)
    application = FastAPI()
    application.include_router(parent, prefix="/api")
    return application


def test_bundled_routes_have_complete_route_configuration() -> None:
    """
        验证模板内全部业务路由满足启动校验。

    :return: 无返回值；任何接线遗漏都会使测试失败。
    """
    validate_v1_api_routes(app)


@pytest.mark.parametrize("invalid_dependency", ["token_only", "unrelated_factory", "permission_factory"])
def test_ordinary_route_rejects_incomplete_auth_dependencies(invalid_dependency: str) -> None:
    """Ordinary routes need account authorization, not a bare Token or unrelated closure."""
    def unrelated_factory() -> Callable[[], Awaitable[None]]:
        async def dependency() -> None:
            return None

        return dependency

    dependency: Callable[..., Any]
    if invalid_dependency == "token_only":
        dependency = check_token
    elif invalid_dependency == "permission_factory":
        dependency = require_permission
    else:
        dependency = unrelated_factory()
    application = FastAPI()
    application.add_api_route(
        "/api/v1/orders/list", endpoint,
        dependencies=[Depends(dependency)],
    )
    with pytest.raises(ValueError, match="authenticated authorization dependency"):
        validate_v1_api_routes(application)


@pytest.mark.parametrize("hidden", [False, True])
def test_new_nested_business_route_needs_no_extra_registry(hidden: bool) -> None:
    """
        验证新路由只需接入认证依赖，不再维护限流装饰器或操作 ID 表。

    :param hidden: 是否隐藏内部 OpenAPI 模型。
    :return: 无返回值；两种路由都应通过校验。
    """
    validate_v1_api_routes(new_app(hidden=hidden))


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"method": "DELETE"}, "exactly one GET or POST"),
        ({"authenticated": False}, "authenticated authorization dependency"),
        ({"route_name": "Invalid Name"}, "static lowercase ASCII identifier"),
    ],
)
def test_route_errors_name_the_actual_method_and_nested_path(
    options: dict[str, object], message: str
) -> None:
    """
        验证错误信息同时指出真实方法、完整路径和接线原因。

    :param options: 传给测试应用构造器的故障选项。
    :param message: 预期错误中的关键说明。
    :return: 无返回值；校验器必须拒绝错误接线。
    """
    with pytest.raises(ValueError) as caught:
        validate_v1_api_routes(new_app(**options))  # type: ignore[arg-type]
    assert "/api/v1/orders/list" in str(caught.value)
    assert message in str(caught.value)


def test_duplicate_route_names_are_rejected() -> None:
    """
        验证两个已登录业务不能共用同一个内部限流名称。

    :return: 无返回值；重复名称必须在启动前被拒绝。
    """
    application = new_app()
    application.add_api_route(
        "/api/v1/invoices/list",
        endpoint,
        name="list_orders",
        dependencies=[Depends(get_current_user)],
    )
    with pytest.raises(ValueError, match="duplicate route name 'list_orders'"):
        validate_v1_api_routes(application)


def test_authenticated_captcha_requires_scene_authorization_dependency() -> None:
    """
        验证登录后验证码接口不能误用普通写入额度依赖。

    :return: 无返回值；固定验证码路由必须使用场景专用认证依赖。
    """

    async def create_authenticated_captcha() -> dict[str, str]:
        """
            返回测试验证码结果。

        :return: 不访问外部资源的固定字典。
        """
        return {"result": "ok"}

    application = FastAPI()
    application.add_api_route(
        "/api/v1/me/captcha",
        create_authenticated_captcha,
        methods=["POST"],
        dependencies=[Depends(get_current_user)],
    )

    with pytest.raises(ValueError, match="scene-specific authorization dependency"):
        validate_v1_api_routes(application)


def test_unlisted_auth_route_requires_login_dependency() -> None:
    """
        验证认证业务新增路径不会因为共享 /auth 前缀而自动变成公开入口。

    :return: 无返回值；未列入公开清单且缺少登录依赖的路由必须在启动时失败。
    """
    application = FastAPI()
    application.add_api_route("/api/v1/auth/other", endpoint, methods=["POST"])

    with pytest.raises(ValueError, match="authenticated authorization dependency"):
        validate_v1_api_routes(application)


@pytest.mark.parametrize("authenticated", [False, True])
def test_current_logout_requires_active_token_dependency(authenticated: bool) -> None:
    """
        验证退出只需有效 Token 依赖；缺少认证时不能启动。

    :param authenticated: 是否接入 Token 和 Redis 登录记录验证。
    :return: 无返回值；合法退出无需限流依赖，遗漏认证仍被拒绝。
    """
    application = FastAPI()
    application.add_api_route(
        "/api/v1/auth/logout",
        endpoint,
        methods=["POST"],
        dependencies=[Depends(check_token)] if authenticated else [],
    )

    if authenticated:
        validate_v1_api_routes(application)
    else:
        with pytest.raises(ValueError, match="current-session logout must validate the active Token"):
            validate_v1_api_routes(application)


def test_eager_route_support_uses_same_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        验证旧版 FastAPI 的直接路由列表也执行同一套检查。

    :param monkeypatch: 临时移除新版延迟路由遍历接口。
    :return: 无返回值；合法路由应通过校验。
    """
    application = FastAPI()
    application.router.routes.append(
        APIRoute(
            "/api/v1/eager/detail",
            endpoint,
            name="read_eager",
            dependencies=[Depends(get_current_user)],
        )
    )
    monkeypatch.setattr(routing, "iter_route_contexts", None)
    validate_v1_api_routes(application)


@pytest.mark.asyncio
async def test_route_names_keep_distinct_business_windows() -> None:
    """
        验证同一额度档位下的两个路由仍使用各自独立的业务名称。

    :return: 无返回值；两个响应应返回不同策略名和相同额度值。
    """
    router = APIRouter()

    @router.get("/orders/list")
    async def list_orders(request: Request) -> dict[str, str | int]:
        """
            返回订单列表测试策略。

        :param request: 提供已匹配路由名称的当前请求。
        :return: 当前策略名称和额度。
        """
        return {
            "policy": str(getattr(request.scope.get("route"), "name", None)),
            "limit": get_settings().rate_limit_user_read,
        }

    @router.get("/invoices/list")
    async def list_invoices(request: Request) -> dict[str, str | int]:
        """
            返回发票列表测试策略。

        :param request: 提供已匹配路由名称的当前请求。
        :return: 当前策略名称和额度。
        """
        return {
            "policy": str(getattr(request.scope.get("route"), "name", None)),
            "limit": get_settings().rate_limit_user_read,
        }

    application = FastAPI()
    application.include_router(
        router,
        prefix="/api/v1",
        dependencies=[Depends(get_current_user)],
    )
    validate_v1_api_routes(application)

    application.dependency_overrides[get_current_user] = lambda: None
    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        orders = await client.get("/api/v1/orders/list")
        invoices = await client.get("/api/v1/invoices/list")
    assert orders.status_code == invoices.status_code == 200
    assert orders.json() == {"policy": "list_orders", "limit": 600}
    assert invoices.json() == {"policy": "list_invoices", "limit": 600}


@pytest.mark.asyncio
async def test_real_lifespan_rejects_missing_auth_before_external_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        验证缺少认证依赖时，生命周期在创建日志和外部连接前失败。

    :param monkeypatch: 将所有外部资源工厂替换成禁止调用的测试对象。
    :return: 无返回值；非法应用不得进入服务阶段。
    """
    application = new_app(authenticated=False)
    redis_factory = MagicMock(side_effect=AssertionError(
        "Redis must not be created for an invalid route"))
    limit_redis_factory = MagicMock(
        side_effect=AssertionError("limiter Redis must not be created"))
    log_factory = MagicMock(side_effect=AssertionError(
        "logging must not start before route validation"))
    database = MagicMock()
    database.connect.side_effect = AssertionError(
        "PostgreSQL must not be used for an invalid route")
    database.dispose = AsyncMock()
    monkeypatch.setattr(main_module, "create_redis_client", redis_factory)
    monkeypatch.setattr(
        main_module, "create_rate_limit_redis_client", limit_redis_factory)
    monkeypatch.setattr(main_module, "configure_logging", log_factory)
    monkeypatch.setattr(main_module, "engine", database)

    with pytest.raises(ValueError, match="authenticated authorization dependency"):
        async with main_module.lifespan(application):
            pytest.fail(
                "an invalid application must never reach the serving phase")

    redis_factory.assert_not_called()
    limit_redis_factory.assert_not_called()
    log_factory.assert_not_called()
    assert database.mock_calls == []


def test_captcha_route_accepts_the_scene_dependency() -> None:
    """
        验证固定登录后验证码路由接入专用依赖后通过校验。

    :return: 无返回值；合法接线不应抛出异常。
    """

    async def create_authenticated_captcha() -> dict[str, str]:
        """
            返回测试验证码结果。

        :return: 不访问外部资源的固定字典。
        """
        return {"result": "ok"}

    application = FastAPI()
    application.add_api_route(
        "/api/v1/me/captcha",
        create_authenticated_captcha,
        methods=["POST"],
        dependencies=[Depends(get_captcha_user)],
    )
    validate_v1_api_routes(application)
