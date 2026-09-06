import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    management_tier: int = Field(ge=0, le=999)
    permissions: list[PermissionKeyInput] = Field(default_factory=list, max_length=200)

    @field_validator("permissions")
    @classmethod
    def unique_permissions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("permission keys must be unique")
        return value


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


class RoleResponse(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    management_tier: int
    is_active: bool
    is_system: bool
    is_protected: bool
    is_owner: bool
    permissions: list[str]
    delegable_permissions: list[str]
    version: int


class PermissionResponse(BaseModel):
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


class AuthorityResponse(BaseModel):
    user_id: uuid.UUID
    management_tier: int
    permissions: list[str]
    delegable_permissions: list[str]
    authz_version: int
    authorization_epoch: int
