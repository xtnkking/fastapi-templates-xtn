#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    FastAPI 限流依赖；直接列出业务、计数主体、额度和窗口，再调用 Redis 限流核心。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        对齐限流策略模块名称，保持原有配额与计费顺序
# 2026/09/23    XTN       V1.002        说明额度档位、路由登记和验证码独立计数，纠正退出登录的注释边界
# 2026/09/26    XTN       V1.003        延迟读取验证码解析器，消除认证依赖循环导入
# 2026/09/26    XTN       V1.004        对齐认证操作 ID 并改用明确的登记规则名称
# 2026/09/27    XTN       V2.000        统一匿名、验证码和已登录业务的限流适配
# 2026/09/27    XTN       V2.001        对齐详情与本人会话接口的处理函数操作 ID
# 2026/09/29    XTN       V3.000        删除路由限流装饰器，改由认证依赖直接选择额度
# 2026/09/29    XTN       V3.001        删除无人读取的旧请求限流结果状态
# 2026/09/29    XTN       V3.002        额度类型别名改用普通赋值形式
# 2026/10/02    XTN       V3.003        合并仅转发的已登录策略入口
# 2026/10/02    XTN       V3.004        去掉始终不会返回的预检空策略分支
# 2026/10/02    XTN       V3.005        通用扣次不再静默跳过验证码场景
# 2026/10/04    XTN       V3.006        收拢限流策略选择，减少预检时的单次跳转
# 2026/10/04    XTN       V3.007        公开验证码预检直接执行拒绝额度，删除转发函数
# 2026/10/04    XTN       V3.008        公开验证码发图与拒绝额度统一在请求依赖中执行
# 2026/10/04    XTN       V3.009        仅提取验证码场景并供预查与扣次复用
# 2026/10/04    XTN       V3.010        只读取限流输入，业务额度与场景判断统一交给 Service
# 2026/10/08    XTN       V3.011        可信 IP 解析归入请求依赖，减少 HTTP 辅助模块跳转
# 2026/10/08    XTN       V4.000        公开入口显式声明业务名、IP 维度与额度
# 2026/10/08    XTN       V4.001        IP 读取直接接收请求，限流维度与主体类型分开填写
# 2026/10/08    XTN       V4.002        移除额度类型提示清单，逐用途说明验证码实际判断
# 2026/10/08    XTN       V4.003        主体类型使用普通字符串，保留实际校验与维度说明
# 2026/10/09    XTN       V4.004        辅助函数置顶，验证码入口相邻，用户预查和计数采用直观名称
# 2026/10/09    XTN       V4.005        验证码用途名单注明领取入口、登录条件和计数对象
# 2026/10/09    XTN       V4.006        验证码用途名单引用公共枚举的自动生成结果
# 2026/10/09    XTN       V4.007        当前登录退出的计数规则归回本模块
# 2026/10/09    XTN       V4.008        验证码错误申请改用无效用途名称并补清计数边界
# 2026/10/10    XTN       V4.009        逐步说明共用限流入口的参数检查、预查、计数及拒绝流程
# 2026/10/10    XTN       V4.010        用次数变化示例解释 consume 参数及两步检查的原因
# 2026/10/10    XTN       V4.011        删除只读预查，每次调用直接计数并检查
# 2026/10/10    XTN       V4.012        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V4.013        补齐各限流入口的通俗取值与计数步骤
# 2026/10/13    XTN       V4.014        限流构键不再传递服务命名空间，保留业务及 IP 或用户 ID
# 2026/10/19    XTN       V4.015        精简限流说明，保留共用入口的逐步解释
# 2026/10/20    XTN       V4.016        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/20    XTN       V4.017        按请求方法集中选择本人或管理次数，删除额度名称及转查函数
# 2026/10/22    XTN       V4.018        删除当前登录退出的专用限流
# 2026/10/22    XTN       V4.019        按本人和管理分组选择次数，使用简短配置名称
# 2026/10/22    XTN       V4.020        明确普通与管理额度由业务选择，不按有无权限要求分类
# 2026/10/24    XTN       V4.021        已登录验证码用途使用完整业务名并自动分开计数
# --------------------------------------------------------------------------------------------------


import ipaddress
from json import JSONDecodeError
from typing import Annotated

from fastapi import Depends, Request

from app.core.access.authorization import LoginInfo
from app.core.captcha import PRIVATE_CAPTCHA_SCENES, PUBLIC_CAPTCHA_SCENES
from app.core.config import Settings, get_settings
from app.core.rate_limit.limiter import (
    RateLimitExceeded,
    RateLimitPolicy,
    RateLimitUnavailable,
    check_rate_limit,
)
from app.db.redis_db import get_rate_limit_redis

# 验证码用途在 core/captcha.py 维护，这里使用按登录要求分好的名单。
# captcha_invalid_scene 统计缺少用途、用途错误或发错入口的申请，防止乱填用途绕过限流。
# 它不统计验证码答案输错；各用途的次数统一从验证码限流配置读取。


# -------------------------------- 辅助函数 --------------------------------
# 先集中放置取 IP、读取验证码用途、选择配置次数和调用 Redis 的共用代码。
def get_limit_ip(request: Request) -> str:
    """
        从服务端确认的连接地址读取客户端 IP，不信任用户可伪造的转发头。

    :param request: 当前请求，client 包含服务端确认的来源地址和端口。
    :return: 标准化的 IP；缺失或无效时返回空串，后续限流拒绝请求。
    """
    # 1. 取服务端看到的连接地址，不直接使用客户端自己填的 X-Forwarded-For 等请求头。
    client = request.client
    host = client.host if client is not None else ""
    # 2. 将有效 IPv4/IPv6 转为统一写法；缺少或写错地址时返回空串，由计数入口拒绝。
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return ""


async def get_captcha_scene(request: Request) -> str | None:
    """
        读取申请的验证码用途，例如 login（登录）、register（注册）。
        这里只读用途；限流函数判断用途，路由模型校验完整参数。

    :param request: 包含验证码申请 JSON 请求体的 FastAPI 请求对象。
    :return: 请求体中的用途文字；缺失、非文字或无法解析时返回 None。
    """
    # 1. 确认请求声明的是 JSON；忽略 charset 等参数，同时允许 application/*+json。
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not (
        media_type.startswith("application/") and media_type.endswith("+json")
    ):
        return None
    try:
        # 2. 读取 JSON；框架会缓存请求体，后面的路由模型仍能读取同一份内容。
        payload = await request.json()
    except (JSONDecodeError, UnicodeDecodeError):
        return None
    # 3. 缺少文字用途时返回 None，按无效用途申请限流。
    if not isinstance(payload, dict):
        return None
    scene = payload.get("scene")
    return scene if isinstance(scene, str) else None


async def _check_quota(request: Request, settings: Settings, *,
                       scope: str | None,
                       subject_type: str,
                       key_parts: list[str],
                       limit: int,
                       window_seconds: int
                       ) -> None:
    """
        按业务和计数对象，在 Redis 中加一次计数并检查是否超限。
        这里只检查次数；密码、账号和权限仍由后续代码检查。

    :param request: 提供限流 Redis 客户端的当前请求。
    :param settings: 限流 HMAC 摘要密钥配置。
    :param scope: 服务端确定的业务名称，例如 login、register，各业务分开计数。
    :param subject_type: 计数对象的类型；ip 表示来源 IP，user_id 表示当前登录用户的 ID。
    :param key_parts: 只放一个可信计数值，例如 ["127.0.0.1"] 或 [当前用户ID]。
    :param limit: 一个时间窗口内最多允许的请求次数，例如 20。
    :param window_seconds: 统计多久内的次数，单位秒；例如 300 表示从首次计数起的五分钟。
    :return: 无返回值；未超限时允许调用方继续执行。
    :raises RateLimitExceeded: 当前 IP 或用户的本业务次数已超限。
    :raises RateLimitUnavailable: 业务名称、计数对象或规则无效，或 Redis 无法可靠完成限流。
    :raises AppError: 应用尚未提供限流 Redis 客户端。
    """
    # 1. 确认限制哪个业务：名称不能为空，具体格式在第 3 步检查。
    if not isinstance(scope, str) or not scope:
        raise RateLimitUnavailable("protected operation needs a stable route name")

    # 2. 再确认“限制谁”。ip 是按来源 IP，user_id 是按当前登录用户的 ID。
    # key_parts 必须只有一个非空值；可信 IP 或已验证用户 ID 由调用方提供。
    if subject_type not in {"ip", "user_id"} or len(key_parts) != 1 or not key_parts[0]:
        raise RateLimitUnavailable("trusted rate-limit subject is unavailable")

    # 3. 整理限流规则，检查名称格式、允许次数和窗口秒数，此时还没访问 Redis。
    try:
        policy = RateLimitPolicy(name=scope, limit=limit, window_seconds=window_seconds)
    except ValueError as exc:
        # 配置错误返回 503，不能误报成用户请求超限。
        raise RateLimitUnavailable("rate-limit policy is invalid") from exc

    # 4. 在 Redis 中加一次计数，再判断是否超限。
    # 例如原来有 7 次，执行后变成 8 次；上限 10 次时，第 10 次通过，第 11 次拒绝。
    # 超限也计数，后续业务失败不退次数；窗口到期后重新计数。
    # Lua 将计数和首次设置过期时间一起执行，避免并发请求漏计或留下永不过期的 key。
    # Redis 连接或返回数据异常时抛出服务不可用，不能跳过限流继续业务。
    result = await check_rate_limit(
        # 复用应用启动时创建的限流 Redis 客户端。
        get_rate_limit_redis(request),
        # 本次使用的限流规则。
        policy=policy,
        # key 中标明按 IP 还是用户 ID 计数。
        subject_type=subject_type,
        # 实际计数值：来源 IP 或当前用户 ID。
        subject=key_parts[0],
        # 用配置中的密钥计算摘要，Redis key 不直接保存原始 IP 或用户 ID。
        key_secret=settings.rate_limit_hmac_key.get_secret_value().encode("utf-8"),
    )

    # 5. 超限就停止业务，统一异常处理器返回 HTTP 429。
    # Retry-After 用剩余窗口秒数告诉客户端还需等待多久。
    if not result.allowed:
        raise RateLimitExceeded(policy_name=scope, result=result)

    # 6. 未抛异常表示限流通过，调用方继续检查验证码、账号或业务条件。


# -------------------------------- 登录和注册 --------------------------------
# 这两个入口不要求登录，只能按各自业务和来源 IP 计数。
async def rate_limit_register(request: Request,
                              settings: Annotated[Settings, Depends(get_settings)]
                              ) -> None:
    """
        按来源 IP 限制注册提交次数，通过后才校验验证码和创建账号。

    :param request: 从服务端连接信息提取可信来源 IP。
    :param settings: 注册业务每小时允许次数的配置。
    :return: 无返回值；超额时阻止注册路由。
    """
    # 按可信来源 IP 统计一小时内的注册次数。
    await _check_quota(
        request, settings,
        scope="register",
        subject_type="ip",  # 按来源 IP 计数。
        key_parts=[get_limit_ip(request)],
        limit=settings.rate_limit_register_ip_per_hour,
        window_seconds=3600,
    )


async def rate_limit_login(request: Request,
                           settings: Annotated[Settings, Depends(get_settings)]
                           ) -> None:
    """
        按来源 IP 限制登录提交次数，通过后才校验验证码和密码。

    :param request: 从服务端连接信息提取可信来源 IP。
    :param settings: 登录业务每五分钟允许次数的配置。
    :return: 无返回值；超额时阻止验证码和密码校验。
    """
    # 按可信来源 IP 统计五分钟内的登录次数，不按用户名封锁账号。
    await _check_quota(
        request, settings,
        scope="login",
        subject_type="ip",  # 按来源 IP 计数。
        key_parts=[get_limit_ip(request)],
        limit=settings.rate_limit_login_ip_per_five_minutes,
        window_seconds=300,
    )


# -------------------------------- 验证码申请 --------------------------------
# 两个验证码入口放在一起：未登录按 IP，已登录按当前用户 ID；每个用途单独计数。
async def rate_limit_public_captcha(request: Request,
                                    settings: Annotated[Settings, Depends(get_settings)]
                                    ) -> None:
    """
        未登录申请验证码时，按“用途 + 来源 IP”限流。
        login（登录）和 register（注册）各自计数，其他用途合并计入 captcha_invalid_scene。
        无效用途通过限流后仍会被参数或业务校验拒绝，不生成图片。

    :param request: 未登录调用方提交的验证码申请。
    :param settings: 验证码申请次数配置，默认每五分钟 10 次。
    :return: 无返回值；超限或 Redis 不可用时阻止路由继续执行。
    """
    # 1. 先读用户想获取哪种验证码，例如登录或注册。
    scene = await get_captcha_scene(request)
    # 2. 合法用途分别计数；无效用途合并为该 IP 的错误申请次数，避免随机用途绕过限制。
    scope = f"captcha_create_{scene}" if scene in PUBLIC_CAPTCHA_SCENES else "captcha_invalid_scene"
    # 3. 生成图片前计数并检查五分钟次数。
    await _check_quota(
        request, settings,
        scope=scope,
        subject_type="ip",
        key_parts=[get_limit_ip(request)],
        limit=settings.rate_limit_captcha_create_per_five_minutes,
        window_seconds=300,
    )


async def rate_limit_private_captcha(request: Request, login_info: LoginInfo, settings: Settings, *,
                                     scene: str | None
                                     ) -> None:
    """
        已登录申请验证码时，按“用途 + 当前用户 ID”限流。
        admin_create_user 用于新增用户，admin_reset_user_password 用于重置他人密码，
        user_change_password 用于修改本人密码；每个用途各自计数。
        无效用途合并计入 captcha_invalid_scene，通过限流后仍会被参数或业务校验拒绝。

    :param request: 已登录用户的验证码申请请求。
    :param login_info: 已通过 JWT 和 Redis 登录检查的身份，提供当前用户 ID。
    :param settings: 验证码申请次数配置，默认每五分钟 10 次。
    :param scene: 申请用途；缺少、未知、非文字或发错入口时按无效用途计数。
    :return: 无返回值；超限时不签发验证码。
    """
    # 1. 合法用途各自计数，错误用途统一计入错误申请次数。
    scope = (
        f"captcha_create_{scene}"
        if scene in PRIVATE_CAPTCHA_SCENES
        else "captcha_invalid_scene"
    )
    # 2. 通过 JWT 和 Redis 登录检查后，按当前用户 ID 计数；随后还会检查账号状态。
    # 不接受请求体里的用户 ID。
    await _check_quota(
        request, settings,
        scope=scope,
        subject_type="user_id",
        key_parts=[str(login_info.user_id)],
        limit=settings.rate_limit_captcha_create_per_five_minutes,
        window_seconds=300,
    )


# -------------------------------- 已登录用户 --------------------------------
# 普通业务在查询账号前计数一次；验证码使用上方专用入口，退出当前登录不计数。


async def rate_limit_user(request: Request, login_info: LoginInfo, settings: Settings, *,
                          management: bool = False
                          ) -> None:
    """
        按“接口业务 + 当前用户 ID”限流，每个接口分别计数。
        验证码申请使用上面的专用函数；退出当前登录不调用限流。

    :param request: 当前请求，提供业务路由名称与限流 Redis 客户端。
    :param login_info: 已通过 JWT 和 Redis 登录检查的身份；账号状态随后检查。
    :param settings: 业务限流额度与 HMAC 密钥配置。
    :param management: False 使用普通接口次数，True 使用管理业务次数；由业务选择，与用户角色及权限要求无关。
    :return: 无返回值；未超限时继续检查账号和业务条件。
    :raises RateLimitExceeded: 当前用户的本接口次数已超限。
    :raises AppError: 限流策略或 Redis 不可用。
    :raises RateLimitUnavailable: 路由名称或计数主体无效，或 Redis 无法可靠完成限流。
    """
    # 1. 先读取业务所选的普通或管理额度，再按 GET 查询、POST 修改取 60 秒内允许的次数。
    if management:
        # 业务明确选择管理额度，例如查用户列表、重置用户密码。
        if request.method == "GET":
            limit = settings.rate_limit_admin_read
        else:
            limit = settings.rate_limit_admin_write
    else:
        # 普通业务额度；本人接口和未选择管理额度的权限接口都使用它。
        if request.method == "GET":
            limit = settings.rate_limit_user_read
        else:
            limit = settings.rate_limit_user_write

    # 2. 按业务和当前用户 ID 计数一次，超限时不再查询数据库。
    await _check_quota(
        request, settings,
        scope=getattr(request.scope.get("route"), "name", None),
        subject_type="user_id",
        key_parts=[str(login_info.user_id)],
        limit=limit,
        window_seconds=60,
    )
