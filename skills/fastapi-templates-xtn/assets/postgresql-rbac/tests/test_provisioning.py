import pytest

from app.core.security.identity import normalize_identity


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("  Mixed_Name  ", "Mixed_Name"),
        ("abc", "abc"),
        ("A" * 32, "A" * 32),
    ],
)
def test_user_name_trims_but_preserves_case(value: str, expected: str) -> None:
    assert normalize_identity(value, field="user_name") == expected


@pytest.mark.parametrize(
    "value", [None, "  ", "ab", "a" * 33, "has space", "name@example", "\u4e2d\u6587"]
)
def test_user_name_rejects_non_ascii_or_out_of_bounds(value: str | None) -> None:
    with pytest.raises(ValueError):
        normalize_identity(value, field="user_name")


def test_other_identity_fields_are_not_accepted() -> None:
    with pytest.raises(ValueError):
        normalize_identity("person@example.test", field="email")


@pytest.mark.parametrize(
    "value",
    [
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
        "ADMIN",
        "CESHI",
    ],
)
def test_reserved_user_names_are_rejected_by_exact_case_insensitive_match(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="reserved_user_name"):
        normalize_identity(value, field="user_name")

    assert normalize_identity(f"{value}123", field="user_name") == f"{value}123"
