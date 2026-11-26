#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在已准备的隔离环境核对图形验证码单次消费和Redis会话注册。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        对齐无状态验证码服务并补充实际维护记录
# 2026/10/10    XTN       V1.001        验证码消费者按数据模型取值而不依赖位置元组
# 2026/10/12    XTN       V1.002        验证码接口参数统一为用户 ID
# 2026/10/13    XTN       V1.003        保留答错单次作废并补充摘要存储、有效期及用户绑定检查
# 2026/10/13    XTN       V1.004        验证码记录键只传入验证码 UUID
# 2026/10/13    XTN       V1.005        会话读取、撤销和列表不再传入配置
# 2026/10/14    XTN       V1.006        验证码服务调用改传统一用途枚举
# 2026/10/20    XTN       V1.007        同步登录会话检查与删除入口，保留原有行为断言
# 2026/10/24    XTN       V1.008        验证码场景名称明确具体用户操作
# --------------------------------------------------------------------------------------------------

import asyncio
import secrets
from typing import cast

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

import app.services.captcha_service as captcha
from app.core.captcha import CaptchaScene
from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.core.security.jwt_tokens import decode_access_token
from app.main import app
from app.repositories.redis.login_session_repository import (
    login_session_repository,
)
from app.schemas.captcha import CaptchaResponse
from app.services.auth_service import auth_service

pytestmark = pytest.mark.postgresql


async def test_captcha_is_single_use_for_success_failure_and_scene_mismatch(client: AsyncClient,
                                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """
        在已准备的隔离 Redis 中验证摘要存储、正确并发及错误答案或绑定的单次消费。

    :param client: 明确隔离的集成环境客户端；夹具负责准备共享测试资源。
    :param monkeypatch: 固定验证码随机答案为 AAAAA，仅在该测试内生效。
    :return: 无返回值；正确提交只放行一次，答案、用途或用户错误后也不能重用。
    """
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    redis = cast(Redis, app.state.redis)
    settings = get_settings()
    service = captcha.captcha_service

    challenge = await service.create_captcha(redis, settings, scene=CaptchaScene.LOGIN, user_id=None)
    redis_key = service.build_redis_key(challenge.captcha_id)
    assert await redis.get(redis_key) == service.hash_captcha_code(
        settings, challenge.captcha_id, "AAAAA", scene=CaptchaScene.LOGIN, user_id=None
    )
    assert 0 < await redis.ttl(redis_key) <= service.EXPIRE_SECONDS
    attempts = await asyncio.gather(
        service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
        ),
        service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
        ),
        return_exceptions=True,
    )
    assert sum(item is None for item in attempts) == 1
    assert sum(isinstance(item, AppError) for item in attempts) == 1

    challenge = await service.create_captcha(redis, settings, scene=CaptchaScene.REGISTER, user_id=None)
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="WRONG", scene=CaptchaScene.REGISTER, user_id=None
        )
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.REGISTER, user_id=None
        )

    challenge = await service.create_captcha(redis, settings, scene=CaptchaScene.LOGIN, user_id=None)
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.REGISTER, user_id=None
        )
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
        )

    user_id = new_entity_id("U")
    challenge = await service.create_captcha(redis, settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id)
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA",
            scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=new_entity_id("U")
        )
    with pytest.raises(AppError):
        await service.verify_captcha(
            redis, settings,
            captcha_id=challenge.captcha_id, answer="AAAAA", scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id
        )


async def test_new_issue_keeps_old_valid_and_consumption_has_one_winner(client: AsyncClient,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    redis = cast(Redis, app.state.redis)
    settings = get_settings()
    service = captcha.captcha_service
    user_id = new_entity_id("U")
    old = await service.create_captcha(redis, settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id)
    results = await asyncio.gather(
        service.create_captcha(redis, settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id),
        service.create_captcha(redis, settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id),
        return_exceptions=True,
    )
    assert len(results) == 2
    assert isinstance(results[0], CaptchaResponse)
    assert isinstance(results[1], CaptchaResponse)
    await service.verify_captcha(
        redis, settings,
        captcha_id=old.captcha_id, answer="AAAAA", scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id
    )
    next_id = results[0].captcha_id
    decisions = await asyncio.gather(
        service.verify_captcha(
            redis, settings,
            captcha_id=next_id, answer="AAAAA", scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id
        ),
        service.verify_captcha(
            redis, settings,
            captcha_id=next_id, answer="AAAAA", scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id
        ),
        return_exceptions=True,
    )
    assert sum(result is None for result in decisions) == 1
    assert sum(isinstance(result, AppError) for result in decisions) == 1


async def test_active_sessions_limit_and_version_change_do_not_count_old_tokens(client: AsyncClient) -> None:
    settings = get_settings().model_copy(update={"max_active_sessions_per_user": 2})
    redis = cast(Redis, app.state.redis)
    user_id = new_entity_id("U")
    issued = [
        decode_access_token(
            await auth_service.issue_access_token(
                redis, user_id=user_id, user_token_version=1, settings=settings
            ),
            settings,
        )
        for _ in range(3)
    ]
    with pytest.raises(AppError) as old:
        await login_session_repository.check_login_session(redis, token_info=issued[0])
    assert old.value.status_code == 401
    assert await login_session_repository.check_login_session(redis, token_info=issued[1]) == 1
    assert await login_session_repository.check_login_session(redis, token_info=issued[2]) == 1
    assert (
        len(
            await login_session_repository.list_active_sessions(
                redis, user_id=user_id, token_version=1
            )
        )
        == 2
    )

    await login_session_repository.delete_login_session(
        redis, token_info=issued[1], user_token_version=1
    )
    assert (
        len(
            await login_session_repository.list_active_sessions(
                redis, user_id=user_id, token_version=1
            )
        )
        == 1
    )

    newest = decode_access_token(
        await auth_service.issue_access_token(
            redis, user_id=user_id, user_token_version=2, settings=settings
        ),
        settings,
    )
    assert await login_session_repository.check_login_session(redis, token_info=newest) == 2
    with pytest.raises(AppError):
        await login_session_repository.check_login_session(redis, token_info=issued[2])
    assert (
        len(
            await login_session_repository.list_active_sessions(
                redis, user_id=user_id, token_version=2
            )
        )
        == 1
    )
