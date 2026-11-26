#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    一次性验证码、登录会话和限流在独立 Redis 中的维护测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/04    XTN       V1.000        补充文件说明并对齐验证码统一扣次入口
# 2026/10/08    XTN       V1.001        改用限流依赖的业务窗口入口
# 2026/10/09    XTN       V1.002        对齐验证码无效用途限流的直观业务名称
# 2026/10/09    XTN       V1.003        Redis维护测试对齐无状态验证码服务及图片方法
# 2026/10/10    XTN       V1.004        统一用户 ID 与当前用户命名
# 2026/10/10    XTN       V1.005        按验证码数据模型读取标识并保留真实服务验证边界
# 2026/10/12    XTN       V1.006        验证码接口参数统一为用户 ID
# 2026/10/13    XTN       V1.007        核对摘要存储、五分钟有效期与 GETDEL 错误用户消费
# 2026/10/13    XTN       V1.008        验证码记录键只传入验证码 UUID
# 2026/10/13    XTN       V1.009        会话活跃检查与列表只传用户和登录输入
# 2026/10/14    XTN       V1.010        验证码服务调用改传统一用途枚举
# 2026/10/20    XTN       V1.011        同步登录会话检查与删除入口，保留原有行为断言
# 2026/10/24    XTN       V1.012        验证码场景名称明确具体用户操作
# --------------------------------------------------------------------------------------------------

"""Redis-only checks; run only against a confirmed disposable empty instance."""

import asyncio
import os
import secrets
from types import SimpleNamespace

import pytest
from redis.asyncio import Redis
from starlette.requests import Request

from app.core.captcha import CaptchaScene
from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.rate_limit.limiter import RateLimitExceeded
from app.core.security.jwt_tokens import decode_access_token
from app.dependencies.rate_limit import _check_quota
from app.repositories.redis.login_session_repository import (
    login_session_repository,
)
from app.services.auth_service import auth_service
from app.services.captcha_service import captcha_service
from tests.integration.safety import confirmed_redis_only_target


async def test_atomic_captcha_and_session_limit_against_isolated_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        在明确确认的空 Redis 中核对验证码单次消费、独立签发及原有会话限额。

    :param monkeypatch: 固定随机验证码答案，便于只用测试数据核对答案摘要。
    :return: 无返回值；错误用户与并发提交均只能消费一次，验证码保留五分钟有效期。
    """
    if os.environ.get("TEST_REDIS_ISOLATION_CONFIRMED") != "yes":
        pytest.skip("requires an explicitly confirmed disposable Redis instance")
    if not os.environ.get("TEST_CAPTCHA_REDIS_URL"):
        pytest.skip("requires a separate disposable TEST_CAPTCHA_REDIS_URL")
    url = confirmed_redis_only_target()
    redis = Redis.from_url(url, decode_responses=True)
    try:
        assert await redis.dbsize() == 0, "refusing a nonempty Redis target"
        monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
        settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
        service = captcha_service
        captcha_user_id = new_entity_id("U")
        initial = await service.create_captcha(
            redis, settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id,
        )
        initial_key = service.build_redis_key(initial.captcha_id)
        assert await redis.get(initial_key) == service.hash_captcha_code(
            settings, initial.captcha_id, "AAAAA", scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
        )
        assert 0 < await redis.ttl(initial_key) <= service.EXPIRE_SECONDS

        def fail_render(_answer: str) -> str:
            raise RuntimeError("image renderer failed")

        with monkeypatch.context() as patch:
            patch.setattr(service, "build_png_base64_image", fail_render)
            with pytest.raises(RuntimeError, match="image renderer failed"):
                await service.create_captcha(
                    redis, settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id,
                )

        await service.verify_captcha(
            redis, settings,
            captcha_id=initial.captcha_id, answer="AAAAA",
            scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
        )
        wrong_user = await service.create_captcha(
            redis, settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
        )
        with pytest.raises(AppError) as rejected:
            await service.verify_captcha(
                redis, settings,
                captcha_id=wrong_user.captcha_id, answer="AAAAA",
                scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=new_entity_id("U")
            )
        assert rejected.value.status_code == 400
        assert await redis.get(service.build_redis_key(wrong_user.captcha_id)) is None
        with pytest.raises(AppError):
            await service.verify_captcha(
                redis, settings,
                captcha_id=wrong_user.captcha_id, answer="AAAAA",
                scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
            )
        initial = await service.create_captcha(
            redis, settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id,
        )
        next_image = await service.create_captcha(
            redis, settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
        )
        await service.verify_captcha(
            redis, settings,
            captcha_id=initial.captcha_id, answer="AAAAA",
            scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=captcha_user_id
        )
        decisions = await asyncio.gather(
            *(
                service.verify_captcha(
                    redis, settings,
                    captcha_id=next_image.captcha_id,
                    answer="AAAAA",
                    scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD,
                    user_id=captcha_user_id,
                )
                for _ in range(2)
            ),
            return_exceptions=True,
        )
        assert sum(result is None for result in decisions) == 1
        assert sum(isinstance(result, AppError) for result in decisions) == 1

        user_id = new_entity_id("U")
        token_info = [
            decode_access_token(
                await auth_service.issue_access_token(
                    redis,
                    user_id=user_id,
                    user_token_version=0,
                    settings=settings,
                ),
                settings,
            )
            for _ in range(3)
        ]
        with pytest.raises(AppError):
            await login_session_repository.check_login_session(redis, token_info=token_info[0])
        assert await login_session_repository.check_login_session(redis, token_info=token_info[1]) == 0
        assert await login_session_repository.check_login_session(redis, token_info=token_info[2]) == 0
        assert (
            len(
                await login_session_repository.list_active_sessions(
                    redis, user_id=user_id, token_version=0
                )
            )
            == 2
        )

        newer_token = decode_access_token(
            await auth_service.issue_access_token(
                redis, user_id=user_id, user_token_version=1, settings=settings
            ),
            settings,
        )
        with pytest.raises(AppError) as stale:
            await auth_service.issue_access_token(
                redis, user_id=user_id, user_token_version=0, settings=settings
            )
        assert stale.value.status_code == 401
        assert (
            await login_session_repository.check_login_session(redis, token_info=newer_token) == 1
        )
        assert (
            len(
                await login_session_repository.list_active_sessions(
                    redis, user_id=user_id, token_version=1
                )
            )
            == 1
        )

        request = Request({
            "type": "http", "method": "POST", "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(rate_limit_redis=redis)),
        })
        for _ in range(10):
            await _check_quota(request, settings, scope="captcha_invalid_scene",
                               subject_type="ip", key_parts=["203.0.113.8"], limit=10, window_seconds=300)
        with pytest.raises(RateLimitExceeded):
            await _check_quota(request, settings, scope="captcha_invalid_scene",
                               subject_type="ip", key_parts=["203.0.113.8"], limit=10, window_seconds=300)
        await _check_quota(request, settings, scope="captcha_invalid_scene",
                           subject_type="user_id", key_parts=[str(captcha_user_id)], limit=10, window_seconds=300)
        await _check_quota(request, settings, scope="captcha_create_login",
                           subject_type="ip", key_parts=["203.0.113.8"], limit=10, window_seconds=300)
    finally:
        await redis.aclose()
