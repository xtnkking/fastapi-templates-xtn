#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    按 API 层传入的规则校验路由，并整理明确要求某项权限的接口，不连接数据库或 Redis。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        启动校验 GET 查询、POST 请求体的目标 ID 约定
# 2026/09/23    XTN       V1.002        说明公开入口白名单、登录依赖检查和业务限流装配要求
# 2026/09/26    XTN       V1.003        对齐认证路由操作 ID，改用直接的路由校验错误文案
# 2026/09/27    XTN       V1.004        强制登录后验证码路由声明独立场景限流
# 2026/09/29    XTN       V2.000        删除 OpenAPI 操作 ID 和路由限流标签依赖
# 2026/09/29    XTN       V2.001        由 API 装配层传入公开入口和特殊认证规则，移除业务路由硬编码
# 2026/10/02    XTN       V2.002        直接验证路由限流标识，不构造虚假的额度配置
# 2026/10/13    XTN       V2.003        补充依赖递归搜索和路由静态接线校验的通俗步骤
# 2026/10/22    XTN       V2.004        直接识别同一权限检查代码，不接受未调用的权限工厂
# 2026/11/28    XTN       V2.005        沿现有路由及依赖遍历收集权限关联接口，校验全部通过后返回
# --------------------------------------------------------------------------------------------------


from collections.abc import Callable, Collection, Mapping

from fastapi import FastAPI, routing
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from app.core.rate_limit.limiter import require_rate_limit_identifier


def _uses_dependency(dependant: Dependant, expected: Callable[..., object]) -> bool:
    """
        检查接口依赖树是否包含指定依赖，包括同一工厂创建的权限检查函数。

    :param dependant: FastAPI 已解析的接口或子依赖。
    :param expected: 固定依赖函数，或已经指定权限的检查函数。
    :return: 当前节点或任一子依赖使用目标函数时为 True，整棵树都没使用时为 False。
    """
    # 不同权限会创建不同函数对象，但执行同一段检查代码；比较代码本身，不只比较名称。
    call = dependant.call
    expected_code = getattr(expected, "__code__", None)
    same_check = expected_code is not None and getattr(call, "__code__", None) is expected_code
    # 逐层查看框架接线，不执行依赖，也不把只有 check_token 的普通接口当成完整认证。
    return call is expected or same_check or any(
        _uses_dependency(child, expected) for child in dependant.dependencies
    )


def validate_api_routes(app: FastAPI, *,
                        public_routes: Collection[tuple[str, str]],
                        authenticated_dependencies: Collection[Callable[..., object]],
                        special_routes: Mapping[tuple[str, str], tuple[Callable[..., object], str]]
                        ) -> dict[str, tuple[tuple[str, str], ...]]:
    """
        根据 API 层声明的例外，在启动阶段指出缺少登录或违反输入约定的业务路由。
        检查实际路由，包括新版 FastAPI 延迟包含的子路由。
        同一次遍历整理权限对应的请求方法和完整路径，只收录真实权限检查函数。
        不执行依赖，不创建数据库表，不连接数据库或 Redis。

    :param app: 已包含全部业务路由、尚未接受请求的 FastAPI 应用。
    :param public_routes: 允许匿名访问的完整方法与路径；未列出的新路由仍须认证。
    :param authenticated_dependencies: 普通已登录业务允许使用的认证依赖。
    :param special_routes: 需要指定认证依赖的路由及其缺失时的错误说明。
    :return: 权限键到接口元组的映射，接口按方法和完整路径去重排序；没有关联接口的权限不占一项。
    :raises ValueError: 发现登录依赖、路由名称、方法或参数位置错误，异常指出方法和路径。
    """
    # 1. 获取完整路由，兼容新版延迟展开和旧版直接展开，随后只检查 /api/ 下的业务接口。
    iter_contexts = getattr(routing, "iter_route_contexts", None)
    contexts = iter_contexts(app.routes) if callable(iter_contexts) else app.routes
    # API 层提供的真实权限检查函数是识别依据；普通函数即使伪造同名标记，也不能冒充它。
    permission_dependencies = tuple(
        dependency for dependency in authenticated_dependencies
        if getattr(dependency, "__code__", None) is not None
        and isinstance(getattr(dependency, "permission_key", None), str)
    )
    permission_api_routes: dict[str, set[tuple[str, str]]] = {}
    # 路由函数名也是已登录业务的内部限流名称，必须稳定且不可重复。
    seen: dict[str, str] = {}
    for context in contexts:
        route = getattr(context, "original_route", context)
        if not isinstance(route, APIRoute):
            continue
        path = str(getattr(context, "path", route.path))
        if not path.startswith("/api/"):
            continue
        methods = getattr(context, "methods", route.methods) or set()
        location = f"{'/'.join(sorted(methods))} {path}"
        route_name = route.name
        # 2. 每个业务接口只能使用一个 GET 或 POST，函数名还要稳定、合规且不重复。
        try:
            if len(methods) != 1 or not methods <= {"GET", "POST"}:
                raise ValueError("business routes must declare exactly one GET or POST method")
            method = next(iter(methods))
            if not isinstance(route_name, str):
                raise ValueError("business route needs a stable function name")
            # 函数名就是内部业务限流名；只检查标识格式，不创建虚构的额度。
            require_rate_limit_identifier(route_name, field_name="route name")
            if route_name in seen:
                raise ValueError(f"duplicate route name {route_name!r}; already used by {seen[route_name]}")
            seen[route_name] = location
            dependant = getattr(context, "dependant", route.dependant)
            if "{" in path or "}" in path:
                raise ValueError("business routes must not contain path parameters; use GET query or POST JSON body")
            # 3. 连子依赖一起检查输入位置，并读取真实权限检查函数的标记，不执行任何依赖。
            # FastAPI 已把 Annotated 别名和嵌套依赖展开在这里，无需再解析路由源码。
            pending = [dependant]
            while pending:
                current = pending.pop()
                if current.path_params:
                    raise ValueError("business target IDs must not use path parameters")
                if method == "GET" and current.body_params:
                    raise ValueError("GET business routes must use query parameters instead of a request body")
                if method == "POST" and any(
                    field.name == "id" or field.name.endswith(("_id", "_ids"))
                    for field in current.query_params
                ):
                    raise ValueError("POST target IDs must be declared in a JSON request body, not query parameters")
                permission_key = getattr(current.call, "permission_key", None)
                if isinstance(permission_key, str) and permission_key and any(
                    getattr(current.call, "__code__", None) is getattr(dependency, "__code__", None)
                    for dependency in permission_dependencies
                ):
                    # 一个权限可以保护多个接口；同一接口重复引用该权限时只记录一次。
                    permission_api_routes.setdefault(permission_key, set()).add((method, path))
                pending.extend(current.dependencies)
            # 4. 匿名白名单才可跳过登录检查；特殊接口核对指定依赖，其余接口核对通用登录依赖。
            operation = (method, path)
            if operation in public_routes:
                continue
            # 少量特殊入口按 API 层声明的依赖逐一检查；普通业务仍统一要求登录授权依赖。
            special_rule = special_routes.get(operation)
            if special_rule is not None:
                dependency, error_message = special_rule
                if not _uses_dependency(dependant, dependency):
                    raise ValueError(error_message)
                continue
            if not any(_uses_dependency(dependant, dependency) for dependency in authenticated_dependencies):
                raise ValueError("business route must use an authenticated authorization dependency")
        except ValueError as exc:
            raise ValueError(f"Invalid API route configuration for {location}: {exc}") from exc
    # 5. 全部路由通过后才交回这次应用的目录，调用方不会拿到部分成功的结果。
    return {key: tuple(sorted(routes)) for key, routes in sorted(permission_api_routes.items())}
