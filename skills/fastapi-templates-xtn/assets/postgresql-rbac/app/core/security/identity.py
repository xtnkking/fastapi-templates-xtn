"""Username normalization and reserved-name rules shared by identity entry points."""

import re

RESERVED_USER_NAMES = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "superadmin",
        "super_admin",
        "sysadmin",
        "system",
        "support",
        "user",
        "test",
        "guest",
        "ceshi",
    }
)


def normalize_identity(value: str | None, *, field: str) -> str:
    if field != "user_name" or value is None:
        raise ValueError("user_name is required")
    normalized = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_]{3,32}", normalized) is None:
        raise ValueError("user_name must be 3-32 ASCII letters, digits, or underscores")
    if normalized.casefold() in RESERVED_USER_NAMES:
        raise ValueError("reserved_user_name")
    return normalized
