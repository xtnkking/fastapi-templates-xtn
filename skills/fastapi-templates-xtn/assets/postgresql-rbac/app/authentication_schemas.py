import uuid
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from app.rbac.provisioning import normalize_identity


class _ClosedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _UsernameRequest(_ClosedRequest):
    user_name: str = Field(min_length=1, max_length=160)

    @field_validator("user_name")
    @classmethod
    def normalize_user_name(cls, value: str) -> str:
        normalized = normalize_identity(value, field="user_name")
        assert normalized is not None
        return normalized


class RegistrationRequest(_UsernameRequest):
    password: SecretStr = Field(min_length=1, max_length=128)


class LoginRequest(_UsernameRequest):
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordChangeRequest(_ClosedRequest):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_changed_password(self) -> Self:
        if (
            self.current_password.get_secret_value()
            == self.new_password.get_secret_value()
        ):
            raise ValueError("new_password must differ from current_password")
        return self


class AdminPasswordResetRequest(_ClosedRequest):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    temporary_password: SecretStr = Field(min_length=1, max_length=128)


class PasswordResetCompletionRequest(_UsernameRequest):
    temporary_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_changed_password(self) -> Self:
        if (
            self.temporary_password.get_secret_value()
            == self.new_password.get_secret_value()
        ):
            raise ValueError("new_password must differ from temporary_password")
        return self


class RegistrationData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: uuid.UUID


class AccessTokenData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    access_token: str = Field(min_length=1, repr=False)
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(strict=True, ge=1)
    password_change_required: Literal[False] = False


class PasswordMutationData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    changed: bool
