from json import JSONDecodeError

from fastapi import Request
from pydantic import ValidationError

from app.schemas.authentication import CaptchaCreateRequest


def _is_json_media_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


async def parse_captcha_create_request(
    request: Request,
) -> CaptchaCreateRequest | None:
    """Parse only JSON CAPTCHA issue requests accepted by the API contract."""
    if not _is_json_media_type(request.headers.get("content-type", "")):
        return None
    try:
        payload = await request.json()
        return CaptchaCreateRequest.model_validate(payload)
    except (JSONDecodeError, UnicodeDecodeError, ValidationError):
        return None
