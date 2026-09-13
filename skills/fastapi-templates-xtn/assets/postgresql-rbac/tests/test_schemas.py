import uuid

import pytest
from pydantic import ValidationError

from app.rbac.schemas import (
    PermissionIdsRequest,
    RoleCreateRequest,
    RoleIdsRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
    RoleVersionRequest,
    SuperAdminTransferRequest,
)


def test_role_create_separates_creation_from_permission_grants() -> None:
    request = RoleCreateRequest(
        key="project_manager",
        name="Project manager",
        description="Manages project work",
        management_tier=200,
    )

    assert request.description == "Manages project work"
    with pytest.raises(ValidationError):
        RoleCreateRequest.model_validate(
            {
                "key": "project_manager",
                "name": "Project manager",
                "management_tier": 200,
                "permissions": ["projects:read"],
            }
        )

    with pytest.raises(ValidationError):
        RoleCreateRequest(
            key="tier_zero",
            name="Tier zero",
            management_tier=0,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"expected_version": 0},
        {"expected_version": 0, "name": None},
        {"expected_version": 0, "description": None},
    ],
)
def test_role_update_requires_a_non_null_mutable_field(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate(payload)


def test_role_update_rejects_authority_fields() -> None:
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate(
            {
                "expected_version": 0,
                "name": "Renamed",
                "management_tier": 999,
            }
        )


def test_role_version_inputs_require_a_nonnegative_integer() -> None:
    assert RoleVersionRequest(expected_version=0).expected_version == 0
    assert RoleUpdateRequest(expected_version=3, name="Renamed").expected_version == 3

    with pytest.raises(ValidationError):
        RoleVersionRequest(expected_version=-1)


@pytest.mark.parametrize("value", ["1", 1.0, True])
def test_role_version_inputs_reject_coercion(value: object) -> None:
    role_id = uuid.uuid4()
    payloads = (
        (RoleVersionRequest, {"expected_version": value}),
        (RoleUpdateRequest, {"expected_version": value, "name": "Renamed"}),
        (
            PermissionIdsRequest,
            {"expected_version": value, "permission_ids": [role_id]},
        ),
    )

    for model, payload in payloads:
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_permission_batches_require_one_to_one_hundred_unique_ids() -> None:
    first = uuid.uuid4()

    with pytest.raises(ValidationError):
        PermissionIdsRequest(expected_version=0, permission_ids=[])
    with pytest.raises(ValidationError):
        PermissionIdsRequest(expected_version=0, permission_ids=[first, first])
    with pytest.raises(ValidationError):
        PermissionIdsRequest(
            expected_version=0,
            permission_ids=[uuid.uuid4() for _ in range(101)],
        )

    request = PermissionIdsRequest(
        expected_version=0,
        permission_ids=[uuid.uuid4() for _ in range(100)],
    )
    assert len(request.permission_ids) == 100


def test_role_batches_require_one_to_ten_unique_ids() -> None:
    first = uuid.uuid4()

    with pytest.raises(ValidationError):
        RoleIdsRequest(role_ids=[])
    with pytest.raises(ValidationError):
        RoleIdsRequest(role_ids=[first, first])
    with pytest.raises(ValidationError):
        RoleIdsRequest(role_ids=[uuid.uuid4() for _ in range(11)])

    request = RoleIdsRequest(role_ids=[uuid.uuid4() for _ in range(10)])
    assert len(request.role_ids) == 10


def test_super_admin_transfer_accepts_only_the_target_user_id() -> None:
    target_user_id = uuid.uuid4()

    request = SuperAdminTransferRequest(target_user_id=target_user_id)

    assert request.target_user_id == target_user_id
    with pytest.raises(ValidationError):
        SuperAdminTransferRequest.model_validate(
            {"target_user_id": target_user_id, "is_super_admin": True}
        )


def test_role_mutation_snapshot_is_immutable() -> None:
    role = RoleResponse(
        id=uuid.uuid4(),
        key="reader",
        name="Reader",
        description="Read access",
        management_tier=10,
        is_active=True,
        is_system=False,
        is_protected=False,
        permissions=("projects:read",),
        delegable_permissions=(),
        version=3,
        deleted_at=None,
    )
    result = RoleMutationResponse(changed=True, role=role)

    assert result.role.permissions == ("projects:read",)
    with pytest.raises(ValidationError):
        role.version = 4
    with pytest.raises(ValidationError):
        result.changed = False
