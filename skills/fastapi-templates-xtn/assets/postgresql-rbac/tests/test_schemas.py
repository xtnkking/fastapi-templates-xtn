import pytest
from pydantic import ValidationError

from app.rbac.schemas import (
    RoleCreateRequest,
    RoleDelegationReplaceRequest,
    RolePermissionsReplaceRequest,
)


@pytest.mark.parametrize(
    ("model", "field"),
    [
        (RoleCreateRequest, "permissions"),
        (RolePermissionsReplaceRequest, "permissions"),
        (RoleDelegationReplaceRequest, "delegable_permissions"),
    ],
)
def test_privileged_permission_inputs_reject_invalid_and_oversized_keys(
    model: type[
        RoleCreateRequest | RolePermissionsReplaceRequest | RoleDelegationReplaceRequest
    ],
    field: str,
) -> None:
    base: dict[str, object] = (
        {"key": "role-key", "name": "Role", "management_tier": 10}
        if model is RoleCreateRequest
        else {}
    )

    with pytest.raises(ValidationError):
        model.model_validate({**base, field: ["Invalid permission"]})
    with pytest.raises(ValidationError):
        model.model_validate({**base, field: [f"resource:{'x' * 121}"]})


@pytest.mark.parametrize(
    ("model", "field"),
    [
        (RoleCreateRequest, "permissions"),
        (RolePermissionsReplaceRequest, "permissions"),
        (RoleDelegationReplaceRequest, "delegable_permissions"),
    ],
)
def test_privileged_permission_inputs_reject_duplicates(
    model: type[
        RoleCreateRequest | RolePermissionsReplaceRequest | RoleDelegationReplaceRequest
    ],
    field: str,
) -> None:
    base: dict[str, object] = (
        {"key": "role-key", "name": "Role", "management_tier": 10}
        if model is RoleCreateRequest
        else {}
    )

    with pytest.raises(ValidationError):
        model.model_validate({**base, field: ["projects:read", "projects:read"]})


@pytest.mark.parametrize(
    "permission_key",
    ["roles:permissions:update", "roles:delegation:update"],
)
def test_privileged_permission_inputs_accept_multisegment_keys(
    permission_key: str,
) -> None:
    request = RolePermissionsReplaceRequest(permissions=[permission_key])

    assert request.permissions == [permission_key]
