#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    请求认证依赖；依次验证 JWT、Redis 登录状态及当前数据库用户状态。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        授权状态查询归仓储，保留认证和连接释放顺序
# 2026/09/23    XTN       V1.002        说明认证、权限和限流顺序，明确依赖别名及拒绝审计边界
# 2026/09/26    XTN       V1.003        依赖别名直接说明数据库会话、配置和当前身份内容
# 2026/09/26    XTN       V1.004        使失效账号原因码直接指向用户状态
# 2026/09/29    XTN       V2.000        由认证依赖按接口类型选择限流额度，移除路由标签耦合
# 2026/09/29    XTN       V2.001        令牌验签与 Redis 会话核对分别使用职责明确的模块
# 2026/09/30    XTN       V2.002        将具体权限检查交给独立依赖，保留身份核验与限流顺序
# 2026/09/30    XTN       V2.003        数据库请求会话依赖由 db 模块直接提供给查询接口
# 2026/10/02    XTN       V2.004        从专名模块导入 PostgreSQL 故障分类
# 2026/10/02    XTN       V2.005        说明共用授权加载同时用于本人和管理接口
# 2026/10/02    XTN       V2.006        从数据库入口直接复用故障分类，不再依赖独立文件
# 2026/10/02    XTN       V2.007        显式区分通用业务扣次和验证码按场景扣次
# 2026/10/04    XTN       V2.008        登录后验证码无效参数直接执行拒绝限流
# 2026/10/04    XTN       V2.009        登录后验证码在身份确认后统一按场景或错误请求扣次
# 2026/10/04    XTN       V2.010        验证码场景只读取一次并传入额度预查与扣次
# 2026/10/04    XTN       V2.011        验证码额度选择统一交给限流 Service
# 2026/10/08    XTN       V2.012        退出登录的限流维度只填写实际操作者 ID
# 2026/10/08    XTN       V2.013        额度分类使用普通字符串，解释写在实际配置映射旁
# 2026/10/09    XTN       V2.014        跟随用户限流和验证码用途读取的直观名称
# 2026/10/09    XTN       V2.015        退出依赖只交付身份，计数规则归限流模块
# 2026/10/10    XTN       V2.016        JWT与活跃登录通过后单次计数，删除只读预查和重复扣次
# 2026/10/10    XTN       V2.017        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V2.018        用通俗步骤说明登录核验、用户限流和当前权限读取
# 2026/10/13    XTN       V2.019        会话核验撤销不再传入服务与环境配置
# 2026/10/16    XTN       V2.020        授权上下文不再传递由审计自动读取的请求 ID
# 2026/10/16    XTN       V2.021        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V2.022        删除全局权限版本读取，认证只加载当前用户实时权限
# 2026/10/19    XTN       V2.023        精简认证说明，按登录凭据、限流和账号检查说明流程
# 2026/10/20    XTN       V2.024        登录信息改用直观命名，显式限流后读取用户，删除身份依赖别名
# 2026/10/20    XTN       V2.025        上下文入口按返回内容命名，管理准备函数标明不检查具体权限
# 2026/10/20    XTN       V2.026        Token 信息直观命名，业务次数选择统一交给限流模块
# 2026/10/20    XTN       V2.027        请求头读取器和解析结果按 Token 用途命名，说明框架字段含义
# 2026/10/20    XTN       V2.028        登录记录检查和删除入口使用直观的会话业务名称
# 2026/10/22    XTN       V2.029        删除退出专用依赖，退出直接复用登录信息校验
# 2026/10/22    XTN       V2.030        Token 和当前用户入口直观命名，删除管理准备依赖
# 2026/10/22    XTN       V2.031        共用用户仓储先核验账号和版本，再读取权限，删除重复判断
# 2026/10/22    XTN       V2.032        当前账号检查统一使用直观的 check_current_user 入口
# 2026/10/23    XTN       V2.033        登录记录检查与退出改由 Redis 仓储访问
# 2026/10/24    XTN       V2.034        当前账号与角色权限信息统一命名为 user_info
# --------------------------------------------------------------------------------------------------

import logging
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError

from app.core.access.authorization import AuthorizationContext, LoginInfo
from app.core.audit import AuditSource
from app.core.config import Settings, get_settings
from app.core.exceptions import AppError, unauthenticated_401, unavailable_503
from app.core.logging.events import (
    safe_exception_metadata,
    safe_log,
)
from app.core.security.jwt_tokens import (
    MAX_BEARER_TOKEN_BYTES,
    AccessTokenInfo,
    decode_access_token,
)
from app.db.postgres_db import DatabaseUnavailableError, SessionFactory, database_error_category
from app.db.redis_db import get_redis
from app.dependencies.rate_limit import (
    get_captcha_scene,
    rate_limit_private_captcha,
    rate_limit_user,
)
from app.repositories.postgres.user_repository import user_repository
from app.repositories.redis.login_session_repository import login_session_repository

# 读取 Authorization: Bearer 请求头，缺少 Token 时由本模块返回统一错误。
read_token_header = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)
# 注入已校验的应用配置，避免每个接口重复读取环境变量。
AppSettings = Annotated[Settings, Depends(get_settings)]


async def _clear_invalid_login(*, request: Request, login_info: LoginInfo) -> None:
    """
        账号失效时，尝试从 Redis 删除这次登录，后续请求就会被拒绝。
        只清理匹配版本的登录；清理失败仍返回原来的身份错误。

    :param request: 用于取得当前应用 Redis 客户端的请求对象。
    :param login_info: 已通过 JWT 与 Redis 校验、但数据库状态无效的身份。
    :return: 无返回值；已尝试清理本次登录。
    """
    # 1. 用已核验的 Token 信息撤销这次登录，不影响同一用户的其他登录。
    try:
        await login_session_repository.delete_login_session(
            get_redis(request),
            token_info=AccessTokenInfo(
                user_id=login_info.user_id,
                token_id=login_info.token_id,
                issued_at=login_info.issued_at,
                expires_at=login_info.expires_at,
            ),
            user_token_version=login_info.token_version,
        )
    except AppError:
        # Redis 故障已有日志，登录也可能刚被其他请求清除；继续保留原身份错误。
        return
    except Exception as exc:
        # 2. 清理失败只记安全日志，仍由调用方返回原本的账号无效错误。
        safe_log(
            logger,
            logging.ERROR,
            "security.inactive_token_cleanup.failed",
            extra=safe_exception_metadata(exc),
        )


async def _load_current_user(request: Request, login_info: LoginInfo) -> AuthorizationContext:
    """
        读取当前用户的账号状态、有效角色和权限，并核对登录版本。
        调用方已经完成 Token 验证和对应业务的限流，这里只负责数据库用户检查。

    :param request: 当前请求，用来读取 Redis 并保存已确认的用户 ID。
    :param login_info: 已通过 JWT 和 Redis 登录检查的身份。
    :return: 当前登录身份、本次读到的完整权限和审计来源。
    :raises AppError: 用户不可用、令牌版本失效或依赖不可用。
    """
    try:
        # 1. 根据已验证的用户 ID 查询账号和权限，读完就归还数据库连接。
        async with SessionFactory() as session:
            user_info = await user_repository.check_current_user(
                session,
                user_id=login_info.user_id,
                token_version=login_info.token_version,
            )
    except AppError as exc:
        # 用户不存在、已删除、停用或登录版本已变时，清理本次旧登录并提示重新登录。
        if exc.reason_code == "user_no_longer_active":
            await _clear_invalid_login(
                request=request,
                login_info=login_info,
            )
            raise unauthenticated_401("user_inactive_or_revoked") from exc
        raise
    except (SQLAlchemyError, DatabaseUnavailableError) as exc:
        # 连接或超时故障转成 503；SQL 写错等其他问题保留原异常。
        category = database_error_category(exc)
        if category is None:
            raise
        safe_log(
            logger,
            logging.ERROR,
            "dependency.database.unavailable",
            extra={
                "dependency": "postgresql",
                "dependency_operation": "load_current_user",
                "error_category": category,
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable_503("authorization_store_unavailable") from exc
    # 2. 仓储已检查账号和版本；记下可信用户 ID，供日志和私有验证码使用。
    request.state.user_id = str(login_info.user_id)
    # 整理当前身份和权限，具体管理权限仍由后面的依赖检查。
    return AuthorizationContext(
        login_info=login_info,
        user_info=user_info,
        audit_source=AuditSource.HTTP,
    )


async def check_token(request: Request,
                      token_header: HTTPAuthorizationCredentials | None = Depends(read_token_header),
                      settings: Settings = Depends(get_settings)
                      ) -> LoginInfo:
    """
        验证 Token 和 Redis 登录记录，返回这次登录的信息。
        退出登录直接使用它；普通业务还要检查数据库中的账号。

    :param request: 当前请求，用于取得应用的 Redis 客户端。
    :param token_header: 框架解析的认证请求头，包含认证方式和 Token 字符串；缺少或不是 Bearer 时为 None。
    :param settings: Token 签名和有效期等校验配置。
    :return: 已验证的用户 ID、Token 编号、登录版本及有效期。
    :raises AppError: Token 缺失、无效、已撤销，或 Redis 不可用。
    """
    # 1. 先检查请求头、Token 长度和签名；无效 Token 不访问 Redis。
    if token_header is None or token_header.scheme.lower() != "bearer":
        raise unauthenticated_401("missing_bearer_token")
    # credentials 是 FastAPI 对象的固定字段名，里面保存真正的 Token 字符串。
    token = token_header.credentials
    if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
        raise unauthenticated_401("bearer_token_too_large")
    token_info = decode_access_token(token, settings)
    # 2. Redis 必须保留这个 JTI 的有效登录记录，同时取得绑定的登录版本。
    token_version = await login_session_repository.check_login_session(get_redis(request), token_info=token_info)
    # 3. 把已验证的登录信息交给后续依赖，不把原始 Token 继续传来传去。
    return LoginInfo(
        user_id=token_info.user_id,
        token_version=token_version,
        token_id=token_info.token_id,
        issued_at=token_info.issued_at,
        expires_at=token_info.expires_at,
    )


async def get_current_user(request: Request,
                           login_info: LoginInfo = Depends(check_token),
                           settings: Settings = Depends(get_settings)
                           ) -> AuthorizationContext:
    """
        获取账号状态正常的当前用户，供本人业务接口使用。
        先验证 Token，再限流、检查账号和登录版本，不要求管理权限。

    :param request: 当前本人业务请求，方法决定读取或写入额度。
    :param login_info: 已通过 JWT 和 Redis 登录检查的身份。
    :param settings: 当前业务的限流配置。
    :return: AuthorizationContext；login_info 保存登录信息，authority 保存当前账号与权限，不是 User 对象。
    :raises AppError: 身份、账号、数据库、Redis 或限流状态不允许继续。
    """
    # 1. Token 和 Redis 登录检查已通过；限流模块按请求方法选择本人接口的次数。
    await rate_limit_user(request, login_info, settings)
    # 2. 限流通过才查数据库，确认账号、登录版本和当前角色权限。
    return await _load_current_user(request, login_info)


async def get_captcha_user(request: Request,
                           login_info: LoginInfo = Depends(check_token),
                           settings: Settings = Depends(get_settings)
                           ) -> AuthorizationContext:
    """
        检查已登录用户申请验证码的次数和账号状态。
        按用途和用户 ID 限流，通过后才查询账号。

    :param request: 包含验证码用途的当前请求。
    :param login_info: 已通过 JWT 和 Redis 登录检查的身份。
    :param settings: 验证码限流配置。
    :return: 已确认可用的账号及完整权限。
    :raises AppError: 身份、账号、数据库、Redis 或验证码额度不允许继续。
    """
    # 1. 只读取一次验证码用途，避免同一请求反复拆解 JSON。
    scene = await get_captcha_scene(request)
    # 2. 按用途和已验证的用户 ID 计数，无效用途也有自己的拒绝额度。
    await rate_limit_private_captcha(request, login_info, settings, scene=scene)
    # 3. 再确认数据库账号和登录版本，通过后才允许路由生成验证码。
    return await _load_current_user(request, login_info)
