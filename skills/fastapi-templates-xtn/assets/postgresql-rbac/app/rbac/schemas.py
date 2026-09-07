import uuid
from datetime import datetime
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PermissionKeyInput = Annotated[
    str,
    Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_.-]*(?::[a-z][a-z0-9_.-]*)+$",
    ),
]


class RoleCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,79}$")
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=1000)
    management_tier: int = Field(ge=1, le=999)


class RoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_at_least_one_field(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one role field is required")
        if any(
            getattr(self, field_name) is None for field_name in self.model_fields_set
        ):
            raise ValueError("role fields cannot be null")
        return self


class PermissionIdsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permission_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)

    @field_validator("permission_ids")
    @classmethod
    def unique_permission_ids(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(value) != len(set(value)):
            raise ValueError("permission IDs must be unique")
        return value


class RoleIdsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)

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


class OwnershipTransferRequest(BaseModel):
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
    is_owner: bool
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
    id: uuid.UUID
    is_active: bool
    management_tier: int
    role_ids: list[uuid.UUID]
    permissions: list[str]
    delegable_permissions: list[str]
    authz_version: int


class UserRoleMutationResponse(BaseModel):
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
