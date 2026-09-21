from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from importlib.resources import files
from types import MappingProxyType
from typing import Any

from fastapi import Request
from starlette.datastructures import MutableHeaders


class MessageKey(StrEnum):
    COMMON_SUCCESS = "common.success"
    COMMON_QUERY_SUCCESS = "common.query_success"
    COMMON_CREATED = "common.created"
    COMMON_OPERATION_SUCCESS = "common.operation_success"

    AUTH_CAPTCHA_CREATED = "auth.captcha_created"
    AUTH_REGISTRATION_SETTINGS_UPDATED = "auth.registration_settings_updated"
    AUTH_REGISTRATION_SUCCEEDED = "auth.registration_succeeded"
    AUTH_LOGIN_SUCCEEDED = "auth.login_succeeded"
    AUTH_LOGOUT_SUCCEEDED = "auth.logout_succeeded"
    AUTH_PASSWORD_CHANGED_RELOGIN = "auth.password_changed_relogin"
    AUTH_PASSWORD_RESET_SUCCEEDED = "auth.password_reset_succeeded"
    AUTH_TEMPORARY_PASSWORD_SET = "auth.temporary_password_set"
    AUTH_USER_CREATED = "auth.user_created"
    AUTH_PASSWORD_SETUP_RELOGIN = "auth.password_setup_relogin"

    HEALTH_LIVE = "health.live"
    HEALTH_READY = "health.ready"

    ERROR_BAD_REQUEST = "error.bad_request"
    ERROR_UNAUTHENTICATED = "error.unauthenticated"
    ERROR_FORBIDDEN = "error.forbidden"
    ERROR_PASSWORD_CHANGE_REQUIRED = "error.password_change_required"
    ERROR_NOT_FOUND = "error.not_found"
    ERROR_METHOD_NOT_ALLOWED = "error.method_not_allowed"
    ERROR_CONFLICT = "error.conflict"
    ERROR_STALE_RESOURCE_VERSION = "error.stale_resource_version"
    ERROR_PAYLOAD_TOO_LARGE = "error.payload_too_large"
    ERROR_UNSUPPORTED_MEDIA_TYPE = "error.unsupported_media_type"
    ERROR_VALIDATION_FAILED = "error.validation_failed"
    ERROR_RATE_LIMITED = "error.rate_limited"
    ERROR_RATE_LIMITED_RETRY = "error.rate_limited_retry"
    ERROR_INTERNAL = "error.internal"
    ERROR_SERVICE_UNAVAILABLE = "error.service_unavailable"
    ERROR_REQUEST_FAILED = "error.request_failed"
    ERROR_PASSWORD_SAME_AS_USER_NAME = "error.password_same_as_user_name"
    ERROR_PASSWORD_COMMON_OR_WEAK = "error.password_common_or_weak"
    ERROR_USER_NAME_TAKEN = "error.user_name_taken"
    ERROR_REGISTRATION_CLOSED = "error.registration_closed"
    ERROR_CAPTCHA_INVALID = "error.captcha_invalid"

    VALIDATION_INVALID = "validation.invalid"
    VALIDATION_REQUIRED = "validation.required"
    VALIDATION_EXTRA_FORBIDDEN = "validation.extra_forbidden"
    VALIDATION_STRING_TYPE = "validation.string_type"
    VALIDATION_STRING_TOO_SHORT = "validation.string_too_short"
    VALIDATION_STRING_TOO_LONG = "validation.string_too_long"
    VALIDATION_STRING_PATTERN = "validation.string_pattern"
    VALIDATION_INTEGER = "validation.integer"
    VALIDATION_BOOLEAN = "validation.boolean"
    VALIDATION_UUID = "validation.uuid"
    VALIDATION_LIST = "validation.list"
    VALIDATION_LIST_LENGTH = "validation.list_length"
    VALIDATION_NUMBER_RANGE = "validation.number_range"
    VALIDATION_LITERAL = "validation.literal"
    VALIDATION_JSON_INVALID = "validation.json_invalid"
    VALIDATION_USER_NAME_RESERVED = "validation.user_name_reserved"
    VALIDATION_PASSWORDS_MUST_DIFFER = "validation.passwords_must_differ"
    VALIDATION_ROLE_FIELDS_REQUIRED = "validation.role_fields_required"
    VALIDATION_ROLE_FIELDS_NOT_NULL = "validation.role_fields_not_null"
    VALIDATION_PERMISSION_IDS_UNIQUE = "validation.permission_ids_unique"
    VALIDATION_ROLE_IDS_UNIQUE = "validation.role_ids_unique"
    VALIDATION_PERMISSION_KEYS_UNIQUE = "validation.permission_keys_unique"


DEFAULT_LOCALE = "zh-CN"
SUPPORTED_LOCALES = ("zh-CN", "en")
_CATALOG_FILES: Mapping[str, str] = MappingProxyType(
    {"zh-CN": "zh-CN.json", "en": "en.json"}
)
_MAX_ACCEPT_LANGUAGE_LENGTH = 512
_MAX_LANGUAGE_RANGES = 20
_LANGUAGE_TAG_PATTERN = re.compile(r"^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$")
_PUBLIC_FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
_PUBLIC_LOCATION_ROOTS = frozenset({"body", "query", "path", "header", "cookie"})


def _load_catalog(locale: str, file_name: str) -> Mapping[str, str]:
    catalog_path = files("app.assets.locales").joinpath(file_name)
    try:
        raw_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to load i18n catalog for {locale}") from exc
    if not isinstance(raw_catalog, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) or not value.strip()
        for key, value in raw_catalog.items()
    ):
        raise RuntimeError(f"invalid i18n catalog for {locale}")

    expected_keys = {key.value for key in MessageKey}
    actual_keys = set(raw_catalog)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise RuntimeError(
            f"i18n catalog key mismatch for {locale}; missing={missing}, extra={extra}"
        )
    return MappingProxyType(dict(raw_catalog))


CATALOGS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        locale: _load_catalog(locale, file_name)
        for locale, file_name in _CATALOG_FILES.items()
    }
)


def _normalize_language_range(language_range: str) -> str | None:
    normalized = language_range.strip().replace("_", "-").casefold()
    if normalized == "*":
        return normalized
    if not _LANGUAGE_TAG_PATTERN.fullmatch(language_range.strip().replace("_", "-")):
        return None
    return normalized


def _match_specificity(language_range: str, locale: str) -> int | None:
    if language_range == "*":
        return 0
    if locale == "zh-CN":
        return {
            "zh": 1,
            "zh-hans": 2,
            "zh-sg": 2,
            "zh-cn": 3,
        }.get(language_range)
    if locale == "en":
        if language_range == "en":
            return 1
        if language_range.startswith("en-"):
            return 2
    return None


def select_locale(accept_language: str | None) -> str:
    """Select one supported locale from a bounded Accept-Language value."""

    if (
        not accept_language
        or len(accept_language) > _MAX_ACCEPT_LANGUAGE_LENGTH
        or any(
            ord(character) < 32 and character != "\t" for character in accept_language
        )
    ):
        return DEFAULT_LOCALE

    parsed_ranges: list[tuple[str, float, int]] = []
    for position, raw_range in enumerate(
        accept_language.split(",")[:_MAX_LANGUAGE_RANGES]
    ):
        parts = [part.strip() for part in raw_range.split(";")]
        language_range = (
            _normalize_language_range(parts[0]) if parts and parts[0] else None
        )
        if language_range is None:
            continue
        quality = 1.0
        malformed = False
        for parameter in parts[1:]:
            if not parameter.casefold().startswith("q="):
                continue
            try:
                quality = float(parameter[2:].strip())
            except ValueError:
                malformed = True
            if not 0.0 <= quality <= 1.0:
                malformed = True
            break
        if not malformed:
            parsed_ranges.append((language_range, quality, position))

    effective_matches: dict[str, tuple[float, int, int]] = {}
    for locale in SUPPORTED_LOCALES:
        matches = [
            (specificity, quality, position)
            for language_range, quality, position in parsed_ranges
            if (specificity := _match_specificity(language_range, locale)) is not None
        ]
        if matches:
            specificity, quality, position = max(
                matches,
                key=lambda item: (item[0], item[1], -item[2]),
            )
            effective_matches[locale] = (quality, specificity, position)

    candidates: list[tuple[float, bool, int, int, str]] = []
    for locale_index, locale in enumerate(SUPPORTED_LOCALES):
        effective_match = effective_matches.get(locale)
        if effective_match is None:
            continue
        quality, specificity, position = effective_match
        if quality > 0.0:
            candidates.append(
                (
                    -quality,
                    specificity == 0,
                    position,
                    locale_index,
                    locale,
                )
            )
    if candidates:
        return min(candidates)[4]

    default_match = effective_matches.get(DEFAULT_LOCALE)
    if default_match is not None and default_match[0] == 0.0:
        for locale in SUPPORTED_LOCALES:
            if locale != DEFAULT_LOCALE and locale not in effective_matches:
                return locale
    return DEFAULT_LOCALE


def locale_for_request(request: Request) -> str:
    locale = getattr(request.state, "locale", None)
    if locale in CATALOGS:
        return str(locale)
    locale = select_locale(request.headers.get("accept-language"))
    request.state.locale = locale
    return locale


def translate(request: Request, key: MessageKey) -> str:
    locale = locale_for_request(request)
    return CATALOGS[locale][key.value]


_VALIDATION_MESSAGE_KEYS: Mapping[str, MessageKey] = MappingProxyType(
    {
        "missing": MessageKey.VALIDATION_REQUIRED,
        "extra_forbidden": MessageKey.VALIDATION_EXTRA_FORBIDDEN,
        "string_type": MessageKey.VALIDATION_STRING_TYPE,
        "string_too_short": MessageKey.VALIDATION_STRING_TOO_SHORT,
        "string_too_long": MessageKey.VALIDATION_STRING_TOO_LONG,
        "string_pattern_mismatch": MessageKey.VALIDATION_STRING_PATTERN,
        "int_type": MessageKey.VALIDATION_INTEGER,
        "int_parsing": MessageKey.VALIDATION_INTEGER,
        "bool_type": MessageKey.VALIDATION_BOOLEAN,
        "bool_parsing": MessageKey.VALIDATION_BOOLEAN,
        "uuid_type": MessageKey.VALIDATION_UUID,
        "uuid_parsing": MessageKey.VALIDATION_UUID,
        "list_type": MessageKey.VALIDATION_LIST,
        "too_short": MessageKey.VALIDATION_LIST_LENGTH,
        "too_long": MessageKey.VALIDATION_LIST_LENGTH,
        "greater_than": MessageKey.VALIDATION_NUMBER_RANGE,
        "greater_than_equal": MessageKey.VALIDATION_NUMBER_RANGE,
        "less_than": MessageKey.VALIDATION_NUMBER_RANGE,
        "less_than_equal": MessageKey.VALIDATION_NUMBER_RANGE,
        "literal_error": MessageKey.VALIDATION_LITERAL,
        "enum": MessageKey.VALIDATION_LITERAL,
        "json_invalid": MessageKey.VALIDATION_JSON_INVALID,
        "username_reserved": MessageKey.VALIDATION_USER_NAME_RESERVED,
        "passwords_must_differ": MessageKey.VALIDATION_PASSWORDS_MUST_DIFFER,
        "role_fields_required": MessageKey.VALIDATION_ROLE_FIELDS_REQUIRED,
        "role_fields_not_null": MessageKey.VALIDATION_ROLE_FIELDS_NOT_NULL,
        "permission_ids_unique": MessageKey.VALIDATION_PERMISSION_IDS_UNIQUE,
        "role_ids_unique": MessageKey.VALIDATION_ROLE_IDS_UNIQUE,
        "permission_keys_unique": MessageKey.VALIDATION_PERMISSION_KEYS_UNIQUE,
    }
)


def validation_message(request: Request, error: Mapping[str, Any]) -> str:
    error_type = error.get("type")
    key = (
        _VALIDATION_MESSAGE_KEYS.get(error_type)
        if isinstance(error_type, str)
        else None
    )
    return translate(request, key or MessageKey.VALIDATION_INVALID)


def validation_field(error: Mapping[str, Any]) -> str:
    """Return a bounded field hint without reflecting user-controlled map keys."""

    location = error.get("loc")
    if not isinstance(location, (tuple, list)) or not location:
        return "request"
    root = location[0]
    if not isinstance(root, str) or root not in _PUBLIC_LOCATION_ROOTS:
        return "request"
    if error.get("type") == "extra_forbidden" or len(location) < 2:
        return root
    field = location[1]
    if not isinstance(field, str) or not _PUBLIC_FIELD_PATTERN.fullmatch(field):
        return root
    return f"{root}.{field}"


def apply_language_headers(headers: MutableHeaders, locale: str) -> None:
    headers["Content-Language"] = locale
    vary = [item.strip() for item in headers.get("Vary", "").split(",") if item.strip()]
    if not any(item.casefold() == "accept-language" for item in vary):
        vary.append("Accept-Language")
    headers["Vary"] = ", ".join(vary)
