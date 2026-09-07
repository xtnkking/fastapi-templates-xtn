import uuid

import pytest
from pydantic import ValidationError

from app.rbac.schemas import (
    OwnershipTransferRequest,
    PermissionIdsRequest,
    RoleCreateRequest,
    RoleIdsRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
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


@pytest.mark.parametrize("payload", [{}, {"name": None}, {"description": None}])
def test_role_update_requires_a_non_null_mutable_field(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate(payload)


def test_role_update_rejects_authority_fields() -> None:
    with pytest.raises(ValidationError):
        RoleUpdateRequest.model_validate({"name": "Renamed", "management_tier": 999})


@pytest.mark.parametrize(
    ("model", "field"),
    [
        (PermissionIdsRequest, "permission_ids"),
        (RoleIdsRequest, "role_ids"),
    ],
)
def test_identifier_batches_require_one_to_one_hundred_unique_ids(
    model: type[PermissionIdsRequest | RoleIdsRequest],
    field: str,
) -> None:
    first = uuid.uuid4()

    with pytest.raises(ValidationError):
        model.model_validate({field: []})
    with pytest.raises(ValidationError):
        model.model_validate({field: [first, first]})
    with pytest.raises(ValidationError):
        model.model_validate({field: [uuid.uuid4() for _ in range(101)]})

    request = model.model_validate({field: [uuid.uuid4() for _ in range(100)]})
    assert len(getattr(request, field)) == 100


def test_ownership_transfer_accepts_only_the_target_user_id() -> None:
    target_user_id = uuid.uuid4()

    request = OwnershipTransferRequest(target_user_id=target_user_id)

    assert request.target_user_id == target_user_id
    with pytest.raises(ValidationError):
        OwnershipTransferRequest.model_validate(
            {"target_user_id": target_user_id, "is_owner": True}
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
        is_owner=False,
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
