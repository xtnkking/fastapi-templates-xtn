import uuid
from datetime import datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.rbac.domain import MAX_ROLES_PER_USER

PermissionKeyInput = Annotated[
    str,
    Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_.-]*(?::[a-z][a-z0-9_.-]*)+$",
    ),
]


def _role_update_json_schema(schema: dict[str, Any]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    properties["name"] = {
        "type": "string",
        "minLength": 1,
        "maxLength": 160,
        "title": "Name",
    }
    properties["description"] = {
        "type": "string",
        "maxLength": 1000,
        "title": "Description",
    }
    schema["anyOf"] = [
        {"required": ["name"]},
        {"required": ["description"]},
    ]


class RoleCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,79}$")
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=1000)
    management_tier: int = Field(ge=1, le=999)


class RoleUpdateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra=_role_update_json_schema,
    )

    expected_version: int = Field(strict=True, ge=0)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_at_least_one_field(self) -> Self:
        mutable_fields = self.model_fields_set & {"name", "description"}
        if not mutable_fields:
            raise ValueError("at least one role field is required")
        if any(getattr(self, field_name) is None for field_name in mutable_fields):
            raise ValueError("role fields cannot be null")
        return self


class RoleVersionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(strict=True, ge=0)


class PermissionIdsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(strict=True, ge=0)
    permission_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)

    @field_validator("permission_ids")
    @classmethod
    def unique_permission_ids(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(value) != len(set(value)):
            raise ValueError("permission IDs must be unique")
        return value


class RoleIdsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_ids: list[uuid.UUID] = Field(
        min_length=1,
        max_length=MAX_ROLES_PER_USER,
    )

    @field_validator("role_ids")
    @classmethod
    def unique_role_ids(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(value) != len(set(value)):
            raise ValueError("role IDs must be unique")
        return value


# These full-set commands remain available to internal migration code. They are
# deliberately not used by the public API, which exposes explicit bind/unbind.
class RolePermissionsReplaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permissions: list[PermissionKeyInput] = Field(default_factory=list, max_length=200)

    @field_validator("permissions")
    @classmethod
    def unique_permissions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("permission keys must be unique")
        return value


class RoleDelegationReplaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delegable_permissions: list[PermissionKeyInput] = Field(
        default_factory=list,
        max_length=200,
    )

    @field_validator("delegable_permissions")
    @classmethod
    def unique_permissions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("permission keys must be unique")
        return value


class UserStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class SuperAdminTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_user_id: uuid.UUID


class RoleResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    key: str
    name: str
    description: str
    management_tier: int
    is_active: bool
    is_system: bool
    is_protected: bool
    permissions: tuple[str, ...]
    delegable_permissions: tuple[str, ...]
    version: int
    deleted_at: datetime | None


class RoleMutationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    changed: bool
    role: RoleResponse


class PermissionResponse(BaseModel):
    id: uuid.UUID
    key: str
    description: str


class UserResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    is_active: bool
    assigned_role_ids: tuple[uuid.UUID, ...] = Field(
        description=(
            "Live assignments visible to the caller, including visible disabled roles."
        )
    )
    effective_role_ids: tuple[uuid.UUID, ...] = Field(
        description=(
            "Visible assigned roles that are active and contribute current authority."
        )
    )
    effective_management_tier: int = Field(
        description="Maximum tier from effective roles; zero when none are effective."
    )
    effective_permissions: tuple[str, ...] = Field(
        description="Permission union from effective roles only."
    )
    effective_delegable_permissions: tuple[str, ...] = Field(
        description="Delegable permission union from effective roles only."
    )
    authz_version: int


class UserRoleMutationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    changed: bool
    user: UserResponse


class OperationResponse(BaseModel):
    changed: bool


class AuthorityResponse(BaseModel):
    user_id: uuid.UUID
    management_tier: int
    permissions: list[str]
    delegable_permissions: list[str]
    authz_version: int
    authorization_epoch: int
