"""Five-scene, one-use graphical challenges backed by atomic Redis scripts."""

import base64
import hashlib
import hmac
import io
import json
import secrets
import uuid
from collections.abc import Awaitable
from typing import Final, cast

from PIL import Image, ImageDraw, ImageFont
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.api_contract import BusinessCode
from app.rbac.errors import RbacError, unavailable
from app.settings import Settings

CAPTCHA_TTL_SECONDS: Final = 300
_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_SCENES: Final = frozenset(
    {"login", "register", "admin_create", "admin_reset", "self_change"}
)
_PRIVATE_SCENES: Final = frozenset({"admin_create", "admin_reset", "self_change"})

_ISSUE: Final = r"""
local previous = ARGV[1]
local scene = ARGV[2]
local owner = ARGV[3]
local new_id = ARGV[4]
local ttl = tonumber(ARGV[6])
if previous ~= '' then
    local raw = redis.call('GET', KEYS[2])
    if not raw then return 0 end
    local ok, record = pcall(cjson.decode, raw)
    if not ok or type(record) ~= 'table' then return -1 end
    if record.scene ~= scene or record.owner ~= owner then return 0 end
    if owner ~= '' and redis.call('GET', KEYS[3]) ~= previous then return 0 end
    redis.call('DEL', KEYS[2])
elseif owner ~= '' then
    local old_id = redis.call('GET', KEYS[3])
    if old_id then
        redis.call('DEL', ARGV[7] .. old_id)
    end
end
redis.call('SET', KEYS[1], ARGV[5], 'EX', ttl)
if owner ~= '' then redis.call('SET', KEYS[3], new_id, 'EX', ttl) end
return 1
"""

_CONSUME: Final = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if not ok or type(record) ~= 'table' then return -1 end
redis.call('DEL', KEYS[1])
if record.index and record.index ~= '' then
    if redis.call('GET', record.index) == ARGV[1] then
        redis.call('DEL', record.index)
    end
end
if record.scene == ARGV[2] and record.owner == ARGV[3]
    and record.digest == ARGV[4] then return 1 end
return 0
"""


def _invalid() -> RbacError:
    return RbacError(
        status_code=400,
        business_code=BusinessCode.BAD_REQUEST,
        public_message="验证码无效或已失效，请重新获取",
        reason_code="captcha_invalid_or_expired",
    )


def _captcha_image(answer: str) -> str:
    image = Image.new("RGB", (184, 66), (249, 251, 252))
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=35)
    for _i in range(5):
        x1, y1, x2, y2 = (
            secrets.randbelow(184),
            secrets.randbelow(66),
            secrets.randbelow(184),
            secrets.randbelow(66),
        )
        draw.line((x1, y1, x2, y2), fill=(125, 157, 148), width=1)
    for i, letter in enumerate(answer):
        glyph = Image.new("RGBA", (42, 53), (0, 0, 0, 0))
        ImageDraw.Draw(glyph).text((7, 2), letter, font=font, fill=(24, 48, 61))
        glyph = glyph.rotate(secrets.randbelow(25) - 12)
        image.paste(glyph, (14 + 29 * i, 6), glyph)
    stream = io.BytesIO()
    image.save(stream, "PNG")
    return "data:image/png;base64," + base64.b64encode(stream.getvalue()).decode()


class CaptchaService:
    def __init__(self, redis: Redis, settings: Settings) -> None:
        self.redis = redis
        self.settings = settings

    def _prefix(self) -> str:
        namespace = f"{self.settings.app_environment}:{self.settings.service_name}"
        digest = hashlib.sha256(namespace.encode()).hexdigest()[:24]
        return f"captcha:{{{digest}}}:"

    def _key(self, captcha_id: uuid.UUID) -> str:
        return f"{self._prefix()}{captcha_id}"

    def _index(self, scene: str, owner_id: uuid.UUID | None) -> str:
        if owner_id is None:
            return f"{self._prefix()}anonymous"
        return f"{self._prefix()}owner:{scene}:{owner_id}"

    def _digest(self, captcha_id: uuid.UUID, answer: str) -> str:
        secret = self.settings.rate_limit_hmac_key.get_secret_value().encode()
        return hmac.new(
            secret,
            f"{captcha_id}:{answer.upper()}".encode("utf-8", "backslashreplace"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _owner(scene: str, owner_id: uuid.UUID | None) -> str:
        if scene not in _SCENES or (scene in _PRIVATE_SCENES) != (owner_id is not None):
            raise _invalid()
        return str(owner_id) if owner_id is not None else ""

    async def issue(
        self,
        *,
        scene: str,
        owner_id: uuid.UUID | None,
        previous_captcha_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID, str]:
        owner = self._owner(scene, owner_id)
        captcha_id = uuid.uuid4()
        answer = "".join(secrets.choice(_ALPHABET) for _ in range(5))
        index = self._index(scene, owner_id) if owner else ""
        record = json.dumps(
            {
                "scene": scene,
                "owner": owner,
                "digest": self._digest(captcha_id, answer),
                "index": index,
            },
            separators=(",", ":"),
        )
        image = _captcha_image(answer)
        try:
            result = await cast(
                Awaitable[object],
                self.redis.eval(
                    _ISSUE,
                    3,
                    self._key(captcha_id),
                    self._key(previous_captcha_id)
                    if previous_captcha_id
                    else self._key(captcha_id),
                    self._index(scene, owner_id),
                    str(previous_captcha_id) if previous_captcha_id else "",
                    scene,
                    owner,
                    str(captcha_id),
                    record,
                    CAPTCHA_TTL_SECONDS,
                    self._prefix(),
                ),
            )
        except RedisError as exc:
            raise unavailable("captcha_store_unavailable") from exc
        if result == 0:
            raise _invalid()
        if result != 1:
            raise unavailable("captcha_store_unavailable")
        return captcha_id, image

    async def consume(
        self,
        *,
        captcha_id: uuid.UUID,
        answer: str,
        scene: str,
        owner_id: uuid.UUID | None,
    ) -> None:
        owner = self._owner(scene, owner_id)
        try:
            result = await cast(
                Awaitable[object],
                self.redis.eval(
                    _CONSUME,
                    1,
                    self._key(captcha_id),
                    str(captcha_id),
                    scene,
                    owner,
                    self._digest(captcha_id, answer),
                ),
            )
        except RedisError as exc:
            raise unavailable("captcha_store_unavailable") from exc
        if result == 1:
            return
        if result == 0:
            raise _invalid()
        raise unavailable("captcha_store_unavailable")
