import pytest

from app.rbac.provisioning import _normalize_identity


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("  Mixed.Case@Example.Test  ", "mixed.case@example.test"),
        ("\uff35\uff33\uff25\uff32\uff3f\uff2e\uff21\uff2d\uff25", "user_name"),
    ],
)
def test_identity_normalization(value: str | None, expected: str | None) -> None:
    assert _normalize_identity(value, field="identity") == expected


def test_identity_normalization_rejects_a_provided_blank() -> None:
    with pytest.raises(ValueError, match="identity must not be empty when provided"):
        _normalize_identity("  ", field="identity")


def test_identity_normalization_rejects_invalid_unicode() -> None:
    with pytest.raises(ValueError, match="identity must contain valid Unicode"):
        _normalize_identity("user_\ud800", field="identity")
