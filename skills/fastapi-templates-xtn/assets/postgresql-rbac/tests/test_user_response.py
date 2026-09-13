import uuid

from app.main import app
from app.rbac.schemas import UserResponse, UserRoleMutationResponse


def test_user_response_separates_assigned_and_effective_authority() -> None:
    base_role_id = uuid.uuid4()
    disabled_role_id = uuid.uuid4()
    response = UserResponse(
        id=uuid.uuid4(),
        is_active=True,
        assigned_role_ids=(base_role_id, disabled_role_id),
        effective_role_ids=(base_role_id,),
        effective_management_tier=0,
        effective_permissions=(),
        authz_version=3,
    )

    assert response.assigned_role_ids == (base_role_id, disabled_role_id)
    assert response.effective_role_ids == (base_role_id,)
    assert response.effective_management_tier == 0

    properties = UserResponse.model_json_schema()["properties"]
    assert {
        "assigned_role_ids",
        "effective_role_ids",
        "effective_management_tier",
        "effective_permissions",
    } <= properties.keys()
    assert {
        "role_ids",
        "management_tier",
        "permissions",
        "delegable_permissions",
    }.isdisjoint(properties)
    assert "disabled roles" in properties["assigned_role_ids"]["description"]
    assert "active" in properties["effective_role_ids"]["description"]

    openapi_properties = app.openapi()["components"]["schemas"]["UserResponse"][
        "properties"
    ]
    assert set(openapi_properties) == set(properties)

    mutation = UserRoleMutationResponse(changed=True, user=response)
    assert mutation.user is response
    assert isinstance(mutation.user.assigned_role_ids, tuple)
