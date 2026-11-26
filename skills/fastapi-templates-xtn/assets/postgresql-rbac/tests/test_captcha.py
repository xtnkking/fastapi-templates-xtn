#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    图形验证码独立签发、业务绑定与单次消费的离线测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/04    XTN       V1.000        补充文件说明并验证无需旧图标识的签发流程
# 2026/10/09    XTN       V1.001        对齐无状态验证码服务并核对资源隔离及单次消费分支
# 2026/10/10    XTN       V1.002        验证服务返回明确的验证码数据模型而非完整接口响应
# 2026/10/12    XTN       V1.003        验证码接口和 Redis 记录统一用户 ID 命名
# 2026/10/13    XTN       V1.004        验证摘要存储和 GETDEL 单次消费及错误绑定作废
# 2026/10/13    XTN       V1.005        验证简化后的 captcha 加 UUID 键和原有资源及摘要绑定
# 2026/10/14    XTN       V1.006        验证码服务调用改传统一用途枚举
# 2026/10/24    XTN       V1.007        验证码场景名称明确具体用户操作
# --------------------------------------------------------------------------------------------------

import asyncio
import base64
import re
import secrets
import uuid
from typing import cast
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

import app.services.captcha_service as captcha
from app.core.captcha import CaptchaScene
from app.core.config import Settings, get_settings
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.schemas.captcha import CaptchaResponse


def mock_service() -> tuple[captcha.CaptchaService, AsyncMock, Settings]:
    """
        为共享验证码服务准备当前测试独立的 Redis 模拟连接和配置。

    :return: 无请求状态的服务、可检查调用的 Redis 模拟连接及本次配置。
    """
    client = AsyncMock()
    client.getdel.return_value = "a" * 64
    client.set.return_value = True
    return captcha.captcha_service, client, get_settings()


@pytest.mark.parametrize("scene,user_id", [
    (CaptchaScene.LOGIN, None),
    (CaptchaScene.REGISTER, None),
    (CaptchaScene.ADMIN_CREATE_USER, "UABCDEFGHIJKLMN"),
    (CaptchaScene.ADMIN_RESET_USER_PASSWORD, "UABCDEFGHIJKLMN"),
    (CaptchaScene.USER_CHANGE_PASSWORD, "UABCDEFGHIJKLMN"),
])
def test_scene_user_check_accepts_matching_enum_parameters(scene: CaptchaScene, user_id: str | None) -> None:
    """
        公开用途不绑定用户，已登录用途必须有用户；检查通过时不改写传入参数。

    :param scene: 当前统一枚举中的验证码用途。
    :param user_id: 公开用途传 None，已登录用途传当前用户 ID。
    :return: 无返回值；参数检查只放行，不再返回用于替换用户 ID 的值。
    """
    captcha.captcha_service.validate_scene_user(scene, user_id)


@pytest.mark.parametrize("scene,user_id", [
    ("login", None),
    ("unknown_scene", None),
    (CaptchaScene.LOGIN, "UABCDEFGHIJKLMN"),
    (CaptchaScene.REGISTER, ""),
    (CaptchaScene.USER_CHANGE_PASSWORD, None),
    (CaptchaScene.ADMIN_RESET_USER_PASSWORD, ""),
    (CaptchaScene.ADMIN_CREATE_USER, 123),
])
def test_scene_user_check_rejects_unknown_or_mismatched_parameters(scene: object, user_id: object) -> None:
    """
        拒绝误传字符串、未知用途，以及用途与用户身份要求不一致的调用。

    :param scene: 故意传入错误类型或需要核对用户参数的用途枚举。
    :param user_id: 故意缺失、附带或使用错误类型的用户标识。
    :return: 无返回值；保持原有验证码无效业务异常。
    """
    with pytest.raises(AppError) as caught:
        captcha.captcha_service.validate_scene_user(cast(CaptchaScene, scene), cast(str | None, user_id))
    assert caught.value.status_code == 400


@pytest.mark.parametrize("scene,user_id,expected_digest", [
    (CaptchaScene.LOGIN, None, "9c06d366af0b70d9706c0d4d02ced35bf53a523eaf5ce020e6e208b3b5ab7d31"),
    (CaptchaScene.ADMIN_RESET_USER_PASSWORD, "UABCDEFGHIJKLMN",
     "4a869624fcd30a7c9abd48b367e6f6ee6d616900a0c462c2326ab6fd20ec25ad"),
])
def test_enum_scene_uses_the_expected_full_digest(scene: CaptchaScene,
                                                  user_id: str | None,
                                                  expected_digest: str) -> None:
    """
        固定密钥、用途、用户、验证码 ID 和答案，核对完整摘要。

    :param scene: 分别覆盖公开和已登录验证码用途。
    :param user_id: 公开用途保持 None，已登录用途绑定固定用户。
    :param expected_digest: 当前业务名称对应的完整 64 字符 HMAC-SHA256 结果。
    :return: 无返回值；结果必须与预期摘要逐字相同，不截短摘要。
    """
    settings = get_settings().model_copy(update={
        "rate_limit_hmac_key": SecretStr("captcha-digest-test-key-0123456789abcdef"),
    })
    # 编码顺序：[scene.value, user_id or "", str(captcha_id), answer.upper()]。
    digest = captcha.captcha_service.hash_captcha_code(
        settings, uuid.UUID("1a4a441e-a162-4e70-bf48-ec52740b3cec"), "aB7k9", scene=scene, user_id=user_id
    )
    assert digest == expected_digest
    assert len(digest) == 64


async def test_issue_returns_png_and_never_stores_plaintext_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        签发可显示的 PNG，并仅把带业务绑定的答案摘要写入 Redis。

    :param monkeypatch: 固定答案，便于确认 Redis 值不含明文答案。
    :return: 无返回值；新键使用 NX 写入并设置五分钟有效期。
    """
    service, redis, settings = mock_service()
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")

    data = await service.create_captcha(
        cast(Redis, redis), settings, scene=CaptchaScene.LOGIN, user_id=None
    )

    assert isinstance(data, CaptchaResponse)
    assert set(data.model_dump()) == {"captcha_id", "image_base64", "expires_in"}
    assert data.captcha_id.version == 4
    assert data.expires_in == service.EXPIRE_SECONDS
    assert base64.b64decode(data.image_base64.removeprefix("data:image/png;base64,")).startswith(
        b"\x89PNG\r\n\x1a\n"
    )
    args = redis.set.await_args
    assert args is not None
    assert args.args[0] == f"captcha:{data.captcha_id}"
    assert args.kwargs == {"ex": service.EXPIRE_SECONDS, "nx": True}
    assert re.fullmatch(r"[0-9a-f]{64}", args.args[1])
    assert args.args[1] == service.hash_captcha_code(
        settings, data.captcha_id, "AAAAA", scene=CaptchaScene.LOGIN, user_id=None
    )
    assert "AAAAA" not in args.args[1]
    redis.getdel.assert_not_awaited()
    redis.eval.assert_not_awaited()


async def test_render_failure_does_not_store_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        绘图失败时不保存无法交付给用户的验证码。

    :param monkeypatch: 临时把绘图方法替换为明确抛出异常的实现。
    :return: 无返回值；绘图错误向上传递，Redis 尚未写入。
    """
    service, redis, settings = mock_service()

    def fail_render(_answer: str) -> str:
        """
            模拟绘图失败，确认签发服务尚未写入验证码。

        :param _answer: 当前随机答案；本模拟不读取或记录答案。
        :return: 不正常返回，直接抛出绘图故障。
        :raises RuntimeError: 模拟图片生成失败。
        """
        raise RuntimeError("image renderer failed")

    monkeypatch.setattr(service, "build_png_base64_image", fail_render)
    with pytest.raises(RuntimeError, match="image renderer failed"):
        await service.create_captcha(
            cast(Redis, redis), settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=new_entity_id("U")
        )
    redis.set.assert_not_awaited()


async def test_challenge_is_required_and_wrong_answer_is_rejected() -> None:
    """
        答案错误时返回验证码无效，并确认提交已执行一次原子读取删除。

    :return: 无返回值；返回 HTTP 400，只消费本次验证码键。
    """
    service, redis, settings = mock_service()
    captcha_id = uuid.uuid4()
    redis.getdel.return_value = service.hash_captcha_code(
        settings, captcha_id, "AAAAA", scene=CaptchaScene.REGISTER, user_id=None
    )
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=captcha_id, answer="wrong", scene=CaptchaScene.REGISTER, user_id=None
        )
    assert caught.value.status_code == 400
    redis.getdel.assert_awaited_once_with(service.build_redis_key(captcha_id))


async def test_invalid_unicode_answer_still_consumes_the_challenge() -> None:
    """
        即使输入包含异常 Unicode 字符，也只能尝试一次且不能使摘要计算崩溃。

    :return: 无返回值；输入被拒绝，验证码已执行一次 GETDEL。
    """
    service, redis, settings = mock_service()
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=uuid.uuid4(),
            answer="\ud800",
            scene=CaptchaScene.LOGIN,
            user_id=None,
        )
    assert caught.value.status_code == 400
    redis.getdel.assert_awaited_once()


async def test_private_scene_requires_authenticated_user_id() -> None:
    """
        本人改密等私有用途缺少已登录用户时不能签发验证码。

    :return: 无返回值；业务异常阻止 Redis 写入。
    """
    service, redis, settings = mock_service()
    with pytest.raises(AppError):
        await service.create_captcha(
            cast(Redis, redis), settings, scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=None,
        )
    redis.set.assert_not_awaited()


async def test_redis_error_fails_closed_before_verifying_business_operation() -> None:
    """
        原子消费命令失败时不能假定验证码正确。

    :return: 无返回值；Redis 连接故障转换成 HTTP 503。
    """
    service, redis, settings = mock_service()
    redis.getdel.side_effect = RedisConnectionError("not-available")
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=uuid.uuid4(), answer="AB234", scene=CaptchaScene.LOGIN, user_id=None
        )
    assert caught.value.status_code == 503


async def test_private_user_id_and_scene_are_bound_to_the_answer_digest() -> None:
    """
        相同业务、用户和验证码 ID 下的正确答案可忽略字母大小写通过。

    :return: 无返回值；仅一次 GETDEL，不使用查询再删除或 Lua 消费。
    """
    service, redis, settings = mock_service()
    user_id = new_entity_id("U")
    captcha_id = uuid.uuid4()
    redis.getdel.return_value = service.hash_captcha_code(
        settings, captcha_id, "aB234", scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id
    )
    await service.verify_captcha(
        cast(Redis, redis), settings,
        captcha_id=captcha_id,
        answer="Ab234",
        scene=CaptchaScene.USER_CHANGE_PASSWORD,
        user_id=user_id,
    )
    redis.getdel.assert_awaited_once_with(service.build_redis_key(captcha_id))
    redis.get.assert_not_awaited()
    redis.eval.assert_not_awaited()
    redis.delete.assert_not_awaited()


async def test_private_issues_are_independent_and_do_not_read_an_old_image(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        同一用户可连续领取新图，签发过程不查询或删除旧验证码。

    :param monkeypatch: 固定随机答案，便于核对两个 ID 各自的绑定摘要。
    :return: 无返回值；两次签发各写入一个独立的验证码键。
    """
    service, redis, settings = mock_service()
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    user_id = new_entity_id("U")
    first = await service.create_captcha(
        cast(Redis, redis), settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id,
    )
    second = await service.create_captcha(
        cast(Redis, redis), settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id,
    )
    assert first.captcha_id != second.captcha_id
    assert [call.args[0] for call in redis.set.await_args_list] == [
        service.build_redis_key(first.captcha_id),
        service.build_redis_key(second.captcha_id),
    ]
    assert [call.args[1] for call in redis.set.await_args_list] == [
        service.hash_captcha_code(settings, image.captcha_id, "AAAAA",
                                  scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=user_id)
        for image in (first, second)
    ]
    redis.get.assert_not_awaited()
    redis.getdel.assert_not_awaited()
    redis.eval.assert_not_awaited()


async def test_issue_fails_closed_when_new_key_is_already_occupied() -> None:
    """
        新 ID 对应的 Redis 键若已存在，不覆盖别人的验证码记录。

    :return: 无返回值；签发返回服务不可用错误。
    """
    service, redis, settings = mock_service()
    redis.set.return_value = None
    with pytest.raises(AppError) as caught:
        await service.create_captcha(
            cast(Redis, redis), settings, scene=CaptchaScene.USER_CHANGE_PASSWORD, user_id=new_entity_id("U")
        )
    assert caught.value.status_code == 503
    redis.eval.assert_not_awaited()


@pytest.mark.parametrize("mismatch", ["answer", "scene", "user_id"])
async def test_wrong_binding_consumes_only_the_presented_challenge(mismatch: str) -> None:
    """
        错误答案、用途或用户均作废本次验证码，随后正确提交也不能重用。

    :param mismatch: 本次只改变答案、用途或所属用户，其余参数保持正确。
    :return: 无返回值；两次提交均返回 HTTP 400，另一张验证码仍保留。
    """
    service, redis, settings = mock_service()
    stored_user_id = new_entity_id("U")
    presented_id = uuid.uuid4()
    redis_key = service.build_redis_key(presented_id)
    other_key = service.build_redis_key(uuid.uuid4())
    stored = {
        redis_key: service.hash_captcha_code(
            settings, presented_id, "AAAAA", scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=stored_user_id
        ),
        other_key: "a" * 64,
    }

    def consume(key: str) -> str | None:
        """
            用内存字典一次取出并删除验证码，模拟 Redis GETDEL 的原子效果。

        :param key: 本次提交的验证码 Redis 键。
        :return: 已取出的答案摘要；验证码已不存在时返回 None。
        """
        return stored.pop(key, None)

    redis.getdel.side_effect = consume
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=presented_id,
            answer="WRONG" if mismatch == "answer" else "AAAAA",
            scene=CaptchaScene.USER_CHANGE_PASSWORD if mismatch == "scene" else CaptchaScene.ADMIN_RESET_USER_PASSWORD,
            user_id=new_entity_id("U") if mismatch == "user_id" else stored_user_id,
        )
    assert caught.value.status_code == 400
    assert redis_key not in stored
    assert other_key in stored
    with pytest.raises(AppError) as retry:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=presented_id, answer="AAAAA",
            scene=CaptchaScene.ADMIN_RESET_USER_PASSWORD, user_id=stored_user_id
        )
    assert retry.value.status_code == 400
    assert redis.getdel.await_count == 2
    assert all(call.args == (redis_key,) for call in redis.getdel.await_args_list)


@pytest.mark.parametrize("raw", ["invalid", "a" * 63, "G" * 64, b"a" * 64, True, {}])
async def test_consumed_corrupted_digest_fails_closed(raw: object) -> None:
    """
        Redis 中不是有效答案摘要的记录也已取出删除，但不能放行业务。

    :param raw: 模拟损坏摘要或不符合文本客户端约定的回包。
    :return: 无返回值；返回服务不可用且不执行额外读取或删除命令。
    """
    service, redis, settings = mock_service()
    redis.getdel.return_value = raw
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=uuid.uuid4(), answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
        )
    assert caught.value.status_code == 503
    redis.getdel.assert_awaited_once()
    redis.get.assert_not_awaited()
    redis.eval.assert_not_awaited()
    redis.delete.assert_not_awaited()


async def test_concurrent_correct_submissions_have_one_winner() -> None:
    """
        同一张验证码的两个正确提交竞争同一次原子消费，只有一个能通过。

    :return: 无返回值；一个成功，一个收到验证码无效错误，记录已删除。
    """
    service, redis, settings = mock_service()
    captcha_id = uuid.uuid4()
    redis_key = service.build_redis_key(captcha_id)
    stored = {
        redis_key: service.hash_captcha_code(settings, captcha_id, "AAAAA", scene=CaptchaScene.LOGIN, user_id=None)
    }

    def consume(key: str) -> str | None:
        """
            使用一次字典 pop 模拟两个提交对同一验证码的原子竞争。

        :param key: 两次提交使用的同一个验证码键。
        :return: 首次返回答案摘要，之后返回 None。
        """
        return stored.pop(key, None)

    redis.getdel.side_effect = consume
    decisions = await asyncio.gather(
        *(
            service.verify_captcha(
                cast(Redis, redis), settings,
                captcha_id=captcha_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
            )
            for _ in range(2)
        ),
        return_exceptions=True,
    )
    assert sum(decision is None for decision in decisions) == 1
    errors = [decision for decision in decisions if isinstance(decision, AppError)]
    assert len(errors) == 1 and errors[0].status_code == 400
    assert not stored


async def test_shared_service_keeps_each_redis_and_settings_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    """
        同一共享实例交替使用两组连接和配置时，各验证码仍在原资源中校验。

    :param monkeypatch: 固定随机答案，使两组验证码都可按相同输入校验。
    :return: 无返回值；签发和校验均使用传入的 Redis 和摘要密钥，记录名只由验证码 ID 决定。
    """
    service, first_redis, first_settings = mock_service()
    second_redis = AsyncMock()
    second_redis.set.return_value = True
    second_settings = first_settings.model_copy(
        update={
            "service_name": "captcha-other-service",
            "app_environment": "captcha-other-environment",
            "rate_limit_hmac_key": SecretStr("captcha-other-key-0123456789abcdef"),
        }
    )
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    first = await service.create_captcha(
        cast(Redis, first_redis), first_settings, scene=CaptchaScene.LOGIN, user_id=None
    )
    second = await service.create_captcha(
        cast(Redis, second_redis), second_settings, scene=CaptchaScene.LOGIN, user_id=None
    )
    first_id = first.captcha_id
    second_id = second.captcha_id
    first_call = first_redis.set.await_args
    second_call = second_redis.set.await_args
    assert first_call is not None and second_call is not None
    assert first_call.args[0] == service.build_redis_key(first_id)
    assert second_call.args[0] == service.build_redis_key(second_id)
    assert service.build_redis_key(first_id) == f"captcha:{first_id}"
    assert service.hash_captcha_code(first_settings, first_id, "AAAAA", scene=CaptchaScene.LOGIN, user_id=None) != (
        service.hash_captcha_code(second_settings, first_id, "AAAAA", scene=CaptchaScene.LOGIN, user_id=None)
    )
    first_redis.getdel.return_value = first_call.args[1]
    second_redis.getdel.return_value = second_call.args[1]
    # 第二组已完成签发后再使用第一组，验证共享实例没有记住上一次连接或配置。
    await service.verify_captcha(
        cast(Redis, first_redis), first_settings,
        captcha_id=first_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
    )
    await service.verify_captcha(
        cast(Redis, second_redis), second_settings,
        captcha_id=second_id, answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
    )
    first_redis.set.assert_awaited_once()
    second_redis.set.assert_awaited_once()
    first_redis.getdel.assert_awaited_once_with(first_call.args[0])
    second_redis.getdel.assert_awaited_once_with(second_call.args[0])


async def test_missing_or_expired_challenge_is_invalid() -> None:
    """
        Redis 返回空值表示验证码过期、已用或不存在，不能继续业务。

    :return: 无返回值；返回 HTTP 400 并且只调用一次 GETDEL。
    """
    service, redis, settings = mock_service()
    redis.getdel.return_value = None
    with pytest.raises(AppError) as caught:
        await service.verify_captcha(
            cast(Redis, redis), settings,
            captcha_id=uuid.uuid4(), answer="AAAAA", scene=CaptchaScene.LOGIN, user_id=None
        )
    assert caught.value.status_code == 400
    redis.getdel.assert_awaited_once()
