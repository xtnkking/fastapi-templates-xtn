#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    服务启动入口：管理共享资源，装配异常处理、中间件和业务路由。
#    具体请求日志和错误响应各归其模块；不建表、不执行迁移或初始化数据。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        使用明确命名的限流策略模块，保持启动和请求行为
# 2026/09/23    XTN       V1.002        解释启动资源、错误码映射、请求日志边界及健康检查例外
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.004        入口聚焦生命周期与装配，用清理栈替代多层嵌套
# 2026/09/26    XTN       V1.005        请求日志注释统一使用直白职责名称
# 2026/09/27    XTN       V1.006        统一请求体限制、安全响应头并复用默认 Redis 客户端
# 2026/09/29    XTN       V1.007        默认关闭 Swagger、ReDoc 和 OpenAPI 文档入口
# 2026/09/29    XTN       V1.008        删除默认健康检查入口，部署探针改为按需添加
# 2026/09/29    XTN       V1.009        日志输出配置改从有界输出模块导入
# 2026/09/29    XTN       V1.010        启动时使用 API 层声明的公开入口与认证规则校验业务路由
# 2026/09/29    XTN       V1.011        从独立的 v1 路由校验模块导入启动认证规则
# 2026/09/30    XTN       V1.012        简化标准输出日志的启动和关闭流程
# 2026/09/30    XTN       V1.013        限流客户端仅依据独立单机 URL 决定是否创建
# 2026/10/08    XTN       V1.014        限流额度由配置模型校验，不重复构造策略集合
# 2026/10/14    XTN       V1.015        启用文件日志并在退出时清理控制台和文件处理器
# 2026/10/14    XTN       V1.016        从配置传入日志文件大小上限
# 2026/10/14    XTN       V1.017        日志只接收输出配置，应用名称和版本用于 FastAPI 信息
# 2026/10/14    XTN       V1.018        为统一请求日志注入独立密码指纹密钥
# 2026/10/20    XTN       V1.019        启动时为共享密码处理器应用本进程的计算与排队限制
# --------------------------------------------------------------------------------------------------

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI

from app.api.v1.route_validation import validate_v1_api_routes
from app.api.v1.router import router as v1_router
from app.core.config import get_settings
from app.core.exception_handlers import register_exception_handlers
from app.core.logging.events import safe_log
from app.core.logging.output import configure_logging
from app.core.middleware import (
    RequestBodyLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.security.passwords import password_manager
from app.db.postgres_db import engine
from app.db.redis_db import close_redis_client, create_rate_limit_redis_client, create_redis_client

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
        管理进程共享资源：启动时设置密码计算限制、准备日志和 Redis，退出时关闭客户端及连接池。
        yield 前完成启动，yield 期间接收请求，离开上下文时按登记的反向顺序清理。
        部分启动或关闭失败时，仍尝试其余清理；不建表、迁移或补写初始数据。

    :param app: 保存进程共享客户端的应用，不在 app.state 中保存单次请求或用户。
    :yield: 资源准备完成后交回控制权，开始正常处理请求。
    """
    # 1. 加载配置并检查接口接线，及早发现遗漏的登录依赖或限流规则。
    validate_v1_api_routes(app)
    settings = get_settings()
    # 在接收请求前设置本进程的密码任务名额；各业务复用同一个处理器，不在路由中单独排队。
    password_manager.configure_limits(
        max_concurrent_operations=settings.password_max_running,
        max_waiting_operations=settings.password_max_waiting,
        wait_timeout_seconds=settings.password_wait_timeout_seconds,
    )

    # 2. 先启用日志，使后续启动、运行和关闭共用安全的日志出口。
    log_handlers = configure_logging(
        log_level=settings.log_level,
        include_exception_details=settings.log_include_exception_details,
        log_file_max_mb=settings.log_file_max_mb,
    )
    app.state.log_handlers = log_handlers

    try:
        async with AsyncExitStack() as cleanup_stack:
            # 3. 登记连接池清理。先登记的后关闭，保证 Redis 清理出错时也会释放数据库池。
            cleanup_stack.push_async_callback(engine.dispose)

            # 4. 主 Redis 负责登录会话与验证码；创建成功后只登记一次关闭。
            redis = create_redis_client(settings)
            cleanup_stack.push_async_callback(close_redis_client, redis)
            app.state.redis = redis

            # 5. 默认让限流复用主客户端与连接池；只有显式独立配置才创建第二个客户端。
            if settings.rate_limit_redis_url is None:
                rate_limit_redis = redis
            else:
                rate_limit_redis = create_rate_limit_redis_client(settings)
                cleanup_stack.push_async_callback(
                    close_redis_client,
                    rate_limit_redis,
                )
            app.state.rate_limit_redis = rate_limit_redis

            safe_log(logger, logging.INFO, "application.started")
            # 6. 服务开始接收请求；退出时清理独立限流 Redis、主 Redis 和数据库池。
            yield
    finally:
        # 7. 其他资源清理后记录停止事件，再移除日志处理器并关闭文件，保留共用标准输出。
        safe_log(logger, logging.INFO, "application.stopped")
        for log_handler in log_handlers:
            logging.getLogger("app").removeHandler(log_handler)
            log_handler.close()


# 应用名称、版本和请求体上限都从同一份 Settings 读取，避免入口散落硬编码。
settings = get_settings()
app = FastAPI(
    title=settings.service_name,
    version=settings.service_version,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# 登记统一错误响应，具体异常处理逻辑见 core/exception_handlers.py。
register_exception_handlers(app)

# Starlette 后添加的中间件在更外层。以下调用顺序最终形成：
# 请求日志 -> 安全响应头 -> 请求体限制 -> 路由/异常处理。
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=settings.request_body_max_bytes,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware, log_hmac_key=settings.log_hmac_key.get_secret_value().encode("utf-8"))

# /api/v1 前缀由 v1_router 统一管理，默认只装配业务接口。
app.include_router(v1_router)
