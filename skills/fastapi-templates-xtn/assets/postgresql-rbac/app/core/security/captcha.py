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
from redis.exceptions import RedisError

from app.core.api_contract import BusinessCode
from app.core.config import Settings
from app.core.errors import RbacError, unavailable
from app.core.i18n import MessageKey
from app.db.redis import RedisClient

CAPTCHA_TTL_SECONDS: Final = 300
_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_SCENES: Final = frozenset(
    {"login", "register", "admin_create", "admin_reset", "self_change"}
)
_PRIVATE_SCENES: Final = frozenset({"admin_create", "admin_reset", "self_change"})
_POINTER_ATTEMPTS: Final = 3

_ISSUE: Final = r"""
local previous = ARGV[1]
local scene = ARGV[2]
local owner = ARGV[3]
local new_id = ARGV[4]
local ttl = tonumber(ARGV[6])
-- Retry a changed private pointer before any mutation. All accessed keys are
-- explicit EVAL inputs, including the previous private challenge.
if previous == '' and owner ~= '' then
    if (redis.call('GET', KEYS[3]) or '') ~= ARGV[7] then return 2 end
end
if previous ~= '' then
    local raw = redis.call('GET', KEYS[2])
    if not raw then return 0 end
    local ok, record = pcall(cjson.decode, raw)
    if not ok or type(record) ~= 'table' then return -1 end
    if record.scene ~= scene or record.owner ~= owner then return 0 end
    if owner ~= '' and redis.call('GET', KEYS[3]) ~= previous then return 0 end
    redis.call('DEL', KEYS[2])
elseif owner ~= '' then
    if ARGV[7] ~= '' then
        redis.call('DEL', KEYS[4])
    end
end
redis.call('SET', KEYS[1], ARGV[5], 'EX', ttl)
if owner ~= '' then redis.call('SET', KEYS[3], new_id, 'EX', ttl) end
return 1
"""

_CONSUME: Final = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
if raw ~= ARGV[5] then return 0 end
local ok, record = pcall(cjson.decode, raw)
if not ok or type(record) ~= 'table' then return -1 end
redis.call('DEL', KEYS[1])
if record.index and record.index ~= '' then
    if redis.call('GET', KEYS[2]) == ARGV[1] then
        redis.call('DEL', KEYS[2])
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
        message_key=MessageKey.ERROR_CAPTCHA_INVALID,
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
    def __init__(self, redis: RedisClient, settings: Settings) -> None:
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
            for _attempt in range(_POINTER_ATTEMPTS):
                current_id = ""
                old_key = self._key(captcha_id)
                if owner and previous_captcha_id is None:
                    pointer = await self.redis.get(index)
                    if pointer is not None:
                        if not isinstance(pointer, str):
                            raise ValueError("invalid captcha pointer")
                        parsed_id = uuid.UUID(pointer)
                        if parsed_id.version != 4 or str(parsed_id) != pointer:
                            raise ValueError("invalid captcha pointer")
                        current_id = pointer
                        old_key = self._key(parsed_id)
                result = await cast(
                    Awaitable[object],
                    self.redis.eval(
                        _ISSUE,
                        4,
                        self._key(captcha_id),
                        self._key(previous_captcha_id)
                        if previous_captcha_id
                        else self._key(captcha_id),
                        self._index(scene, owner_id),
                        old_key,
                        str(previous_captcha_id) if previous_captcha_id else "",
                        scene,
                        owner,
                        str(captcha_id),
                        record,
                        str(CAPTCHA_TTL_SECONDS),
                        current_id,
                    ),
                )
                if result != 2:
                    break
            else:
                raise unavailable("captcha_store_unavailable")
        except (RedisError, ValueError) as exc:
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
            key = self._key(captcha_id)
            raw = await self.redis.get(key)
            if raw is None:
                raise _invalid()
            if not isinstance(raw, str):
                raise ValueError("invalid captcha record")
            record = json.loads(raw)
            if not isinstance(record, dict) or set(record) != {
                "scene",
                "owner",
                "digest",
                "index",
            }:
                raise ValueError("invalid captcha record")
            index = record["index"]
            if (
                record["scene"] not in _SCENES
                or not isinstance(record["owner"], str)
                or not isinstance(index, str)
                or not isinstance(record["digest"], str)
                or len(record["digest"]) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in record["digest"]
                )
            ):
                raise ValueError("invalid captcha record")
            if record["scene"] in _PRIVATE_SCENES:
                stored_owner = uuid.UUID(record["owner"])
                if (
                    stored_owner.version != 4
                    or str(stored_owner) != record["owner"]
                    or index != self._index(record["scene"], stored_owner)
                ):
                    raise ValueError("invalid captcha index")
            elif record["owner"] or index:
                raise ValueError("invalid public captcha binding")
            result = await cast(
                Awaitable[object],
                self.redis.eval(
                    _CONSUME,
                    2,
                    key,
                    index or key,
                    str(captcha_id),
                    scene,
                    owner,
                    self._digest(captcha_id, answer),
                    raw,
                ),
            )
        except (RedisError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise unavailable("captcha_store_unavailable") from exc
        if result == 1:
            return
        if result == 0:
            raise _invalid()
        raise unavailable("captcha_store_unavailable")
