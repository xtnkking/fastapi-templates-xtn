#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    为五类业务签发图形验证码，通过 Redis GETDEL 保证答对答错都只能尝试一次。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        说明验证码共享连接和配置来源
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/27    XTN       V1.003        明确验证码校验后立即作废的公开方法名称
# 2026/09/30    XTN       V1.004        验证码键说明改为单机 Redis 语义
# 2026/10/02    XTN       V1.005        解释 Lua 刷新竞争与单次消费的关键阶段
# 2026/10/04    XTN       V1.006        删除旧图替换指针，独立签发并保持原子单次消费
# 2026/10/09    XTN       V1.007        签发和存储校验引用公共验证码用途及登录要求
# 2026/10/09    XTN       V1.008        共享无请求状态的验证码服务，分步说明生成、作废、绑定和答案校验
# 2026/10/10    XTN       V1.009        签发返回验证码业务模型，完整 API 响应由路由组装
# 2026/10/12    XTN       V1.010        验证码参数和 Redis 用户字段统一使用 user_id
# 2026/10/13    XTN       V1.011        只保存绑定摘要并用 GETDEL 原子读取删除，简化一次性校验
# 2026/10/13    XTN       V1.012        用通俗注释解释验证码生成、摘要绑定和先删除再校验
# 2026/10/13    XTN       V1.013        补充无效验证码错误构造函数的具体步骤
# 2026/10/13    XTN       V1.014        验证码键简化为 captcha 加 UUID，不再读取环境和服务标识
# 2026/10/14    XTN       V1.015        直接接收验证码用途枚举，简化业务与用户参数检查
# 2026/10/16    XTN       V1.016        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/19    XTN       V1.017        精简验证码注释，突出生成和一次性校验步骤
# --------------------------------------------------------------------------------------------------

import base64
import hashlib
import hmac
import io
import json
import re
import secrets
import uuid
from typing import Final

from PIL import Image, ImageDraw, ImageFont
from redis.exceptions import RedisError

from app.core.captcha import CaptchaScene
from app.core.codes import BusinessCode
from app.core.config import Settings
from app.core.exceptions import AppError, unavailable_503
from app.core.i18n.messages import MessageKey
from app.db.redis_db import RedisClient
from app.schemas.captcha import CaptchaResponse


def _invalid() -> AppError:
    """
        创建统一的“验证码无效”错误，供校验失败时抛出。

    :return: HTTP 400 的验证码无效错误。
    """
    # 这里只创建错误，由调用处 raise。
    return AppError(
        status_code=400,
        business_code=BusinessCode.CAPTCHA_INVALID,
        message_key=MessageKey.ERROR_CAPTCHA_INVALID,
        reason_code="captcha_invalid_or_expired",
    )


class CaptchaService:
    """
        create_captcha 生成图片，verify_captcha 校验答案。
        每张验证码只能提交一次，答错也作废；想再试，需要重新获取一张。
        限流和登录检查由路由依赖处理，本类不保存单次请求的数据。
    """

    # Redis 验证码记录的前缀。
    REDIS_KEY_PREFIX: Final = "captcha"
    # 有效期 300 秒（5 分钟）；提交后即作废，答错也一样。
    EXPIRE_SECONDS: Final = 300
    # 答案位数；修改时需同步调整图片布局和前端提示。
    CODE_LENGTH: Final = 5
    # 排除 I、O、0、1 等易混淆字符；校验答案时不区分字母大小写。
    CODE_SOURCE: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    # 图片宽、高和字体大小，单位：像素。
    IMAGE_WIDTH: Final = 184
    IMAGE_HEIGHT: Final = 66
    FONT_SIZE: Final = 35
    # 随机干扰线的数量。
    NOISE_LINE_COUNT: Final = 5

    def build_redis_key(self, captcha_id: uuid.UUID) -> str:
        """
            用验证码 ID 拼出 Redis 记录名。
            业务和用户不放进 key，提交到错误业务或由错误用户提交也要作废原记录。

        :param captcha_id: 本次生成或提交的 UUIDv4 验证码标识。
        :return: captcha:UUID 格式的 Redis 键，例如 captcha:1a4a441e-a162-4e70-bf48-ec52740b3cec。
        """
        # 业务和用户绑定在答案摘要中，key 只负责找到这张验证码。
        return f"{self.REDIS_KEY_PREFIX}:{captcha_id}"

    def hash_captcha_code(self, settings: Settings,
                          captcha_id: uuid.UUID,
                          answer: str, *,
                          scene: CaptchaScene,
                          user_id: str | None
                          ) -> str:
        """
            用业务、用户、验证码 ID、答案和服务端密钥计算答案摘要。
            校验时按相同规则重算；业务、用户或答案不同都不能通过，字母不区分大小写。

        :param settings: 当前应用配置，提供服务端摘要密钥。
        :param captcha_id: 本次验证码标识。
        :param answer: 新生成或用户提交的验证码答案。
        :param scene: 服务端指定的验证码业务。
        :param user_id: 已登录业务传当前用户 ID；登录和注册传 None。
        :return: 由 64 个小写十六进制字符组成的 SHA-256 HMAC 摘要。
        """
        # 1. 读取服务端密钥，不能返回给前端或写入日志。
        secret = settings.rate_limit_hmac_key.get_secret_value().encode()
        # 2. 用 JSON 分清四个字段，答案统一转大写；这些原文不会存进 Redis。
        raw_value = json.dumps([scene.value, user_id or "", str(captcha_id), answer.upper()], separators=(",", ":"))
        # 3. 计算摘要；生成和校验共用这套规则。
        return hmac.new(
            secret,
            raw_value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def validate_scene_user(scene: CaptchaScene,
                            user_id: str | None
                            ) -> None:
        """
            检查验证码业务是否传对用户参数；这里只查参数，不负责登录认证。

        :param scene: 服务端指定的验证码业务枚举。
        :param user_id: 已登录业务传当前用户 ID；登录和注册业务必须传 None。
        :return: 无返回值；参数不符合要求时抛出错误。
        :raises AppError: 未传用途枚举，或用户参数不满足该用途的登录要求。
        """
        # 1. 业务必须使用统一枚举，不能传任意字符串。
        if not isinstance(scene, CaptchaScene):
            raise _invalid()
        # 2. 需要登录的业务必须传认证依赖确认的用户 ID。
        if scene.requires_login:
            # 漏传或传空值都拒绝。
            if not isinstance(user_id, str) or not user_id:
                raise _invalid()
        elif user_id is not None:
            # 登录、注册还没有当前用户，必须传 None。
            raise _invalid()

    def build_png_base64_image(self, answer: str) -> str:
        """
            把答案画成带干扰线的 PNG 图片，再转成前端可显示的 Base64。

        :param answer: 本次生成的验证码答案，仅用于绘图，不写入响应字段或日志。
        :return: 前端可直接展示的 PNG Base64 数据 URL。
        """
        # 1. 创建浅色画布，准备画笔和字体。
        image = Image.new("RGB", (self.IMAGE_WIDTH, self.IMAGE_HEIGHT), (249, 251, 252))
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default(size=self.FONT_SIZE)

        # 2. 画随机干扰线；四个坐标分别是线段的起点和终点。
        for _ in range(self.NOISE_LINE_COUNT):
            coordinates = (
                secrets.randbelow(self.IMAGE_WIDTH),
                secrets.randbelow(self.IMAGE_HEIGHT),
                secrets.randbelow(self.IMAGE_WIDTH),
                secrets.randbelow(self.IMAGE_HEIGHT),
            )
            draw.line(coordinates, fill=(125, 157, 148), width=1)
        for index, letter in enumerate(answer):
            # 3. 每个字符单独画在透明小画布上，稍微旋转后贴到图片中。
            glyph = Image.new("RGBA", (42, 53), (0, 0, 0, 0))
            ImageDraw.Draw(glyph).text((7, 2), letter, font=font, fill=(24, 48, 61))
            glyph = glyph.rotate(secrets.randbelow(25) - 12)
            image.paste(glyph, (14 + 29 * index, 6), glyph)

        # 4. 图片在内存中转成 Base64，不另存文件。
        stream = io.BytesIO()
        image.save(stream, "PNG")
        # 加上图片格式前缀，前端即可当作图片地址使用。
        return "data:image/png;base64," + base64.b64encode(stream.getvalue()).decode()

    async def create_captcha(self, redis: RedisClient,
                             settings: Settings, *,
                             scene: CaptchaScene,
                             user_id: str | None
                             ) -> CaptchaResponse:
        """
            随机生成答案、画图，把答案摘要存入 Redis，再返回 ID 和图片。
            调用方须先通过限流；每张验证码有效五分钟，答对答错都只能尝试一次。

        :param redis: 应用已创建的 Redis 客户端。
        :param settings: 当前应用的验证码摘要密钥配置。
        :param scene: 本次验证码的业务枚举。
        :param user_id: 已登录业务的当前用户 ID；公开登录和注册业务传 None。
        :return: 验证码 ID 和 PNG Base64 图片，完整 API 响应由路由组装。
        :raises AppError: 用途或登录要求不满足、存储不可用或新 ID 的记录键已存在。
        """
        # 1. 按用途枚举检查用户参数；公开业务传 None，已登录业务传当前用户 ID。
        self.validate_scene_user(scene, user_id)
        # 随机生成验证码 ID 和正确答案。
        captcha_id = uuid.uuid4()
        answer = "".join(secrets.choice(self.CODE_SOURCE) for _ in range(self.CODE_LENGTH))

        # 2. 生成 Redis key 和答案摘要；已登录业务绑定用户，登录、注册不绑定用户或 IP。
        redis_key = self.build_redis_key(captcha_id)
        code_hash = self.hash_captcha_code(settings, captcha_id, answer, scene=scene, user_id=user_id)

        # 3. 先画图再存 Redis，避免画图失败时留下无用记录。
        image_base64 = self.build_png_base64_image(answer)
        try:
            # nx=True 防止覆盖已有记录；ex 设置过期秒数；只保存摘要，不保存答案原文。
            stored = await redis.set(redis_key, code_hash, ex=self.EXPIRE_SECONDS, nx=True)
        except RedisError as exc:
            # 保存失败就不发图，避免用户拿到无法校验的验证码。
            raise unavailable_503("captcha_store_unavailable") from exc
        if stored is not True:
            # 记录已存在等情况也不能视为保存成功。
            raise unavailable_503("captcha_store_unavailable")
        # 4. 返回 ID 和图片，响应码及提示文案由路由填写。
        return CaptchaResponse(captcha_id=captcha_id, image_base64=image_base64)

    async def verify_captcha(self, redis: RedisClient,
                             settings: Settings, *,
                             captcha_id: uuid.UUID,
                             answer: str,
                             scene: CaptchaScene,
                             user_id: str | None
                             ) -> None:
        """
            先取出并删除验证码，再核对业务、用户和答案，答错也不能重试。
            校验失败就抛出错误，阻止后续业务。

        :param redis: 应用已创建的 Redis 客户端。
        :param settings: 当前应用的答案摘要密钥配置。
        :param captcha_id: 用户本次提交的验证码标识。
        :param answer: 用户输入的验证码答案，比较时忽略字母大小写。
        :param scene: 当前接口在代码中指定的业务枚举。
        :param user_id: 已登录业务的当前用户 ID；公开登录和注册业务传 None。
        :return: 无返回值；正常结束表示校验通过，验证码已作废。
        :raises AppError: 验证码错误、过期、已使用、用途或所属用户不匹配，或存储不可用。
        """
        # 1. 先检查接口指定的业务和已认证用户；参数有误时不进入 Redis 消费步骤。
        self.validate_scene_user(scene, user_id)
        redis_key = self.build_redis_key(captcha_id)
        try:
            # 2. GETDEL 一次完成读取和删除，答错也作废；并发请求只有一个能取到记录。
            expected_code_hash = await redis.getdel(redis_key)
        except RedisError as exc:
            # Redis 故障时停止业务，不能跳过验证码。
            raise unavailable_503("captcha_store_unavailable") from exc
        if expected_code_hash is None:
            # 不存在、过期或已用过，统一提示验证码无效。
            raise _invalid()
        # 3. 摘要应是 64 个小写十六进制字符；格式不对说明存储异常，已删记录不恢复。
        if not isinstance(expected_code_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_code_hash) is None:
            raise unavailable_503("captcha_store_unavailable")

        # 4. 按本次业务、用户、ID 和答案重算摘要；任一不匹配都拒绝，原记录不会恢复。
        input_code_hash = self.hash_captcha_code(settings, captcha_id, answer, scene=scene, user_id=user_id)
        # 用专门的摘要比较方法，避免比较耗时泄露匹配位置。
        if not hmac.compare_digest(expected_code_hash, input_code_hash):
            raise _invalid()


# 路由和依赖共用服务对象；用户、答案和 Redis 连接随调用传入，不保存在对象上。
captcha_service = CaptchaService()
