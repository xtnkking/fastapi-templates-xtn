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
from pydantic_core import PydanticCustomError

from app.core.security.identity import normalize_identity


class _ClosedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _UsernameRequest(_ClosedRequest):
    user_name: str = Field(min_length=1, max_length=40)

    @field_validator("user_name")
    @classmethod
    def normalize_user_name(cls, value: str) -> str:
        try:
            normalized = normalize_identity(value, field="user_name")
        except ValueError as exc:
            if str(exc) == "reserved_user_name":
                raise PydanticCustomError(
                    "username_reserved", "username_reserved"
                ) from exc
            raise
        assert normalized is not None
        return normalized


class _CaptchaAnswer(_ClosedRequest):
    captcha_id: uuid.UUID
    captcha_answer: str = Field(min_length=1, max_length=16)


class RegistrationRequest(_UsernameRequest, _CaptchaAnswer):
    password: SecretStr = Field(min_length=1, max_length=128)


class LoginRequest(_UsernameRequest, _CaptchaAnswer):
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordChangeRequest(_CaptchaAnswer):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_changed_password(self) -> Self:
        if (
            self.current_password.get_secret_value()
            == self.new_password.get_secret_value()
        ):
            raise PydanticCustomError("passwords_must_differ", "passwords_must_differ")
        return self


class AdminPasswordResetRequest(_CaptchaAnswer):
    new_password: SecretStr = Field(min_length=1, max_length=128)


class AdminUserCreateRequest(_UsernameRequest, _CaptchaAnswer):
    temporary_password: SecretStr = Field(min_length=1, max_length=128)


class RegistrationStatusUpdateRequest(_ClosedRequest):
    registration_enabled: bool = Field(strict=True)


class RegistrationStatusData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    registration_enabled: bool


class CaptchaCreateRequest(_ClosedRequest):
    scene: Literal["login", "register", "admin_create", "admin_reset", "self_change"]
    previous_captcha_id: uuid.UUID | None = None


class CaptchaData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    captcha_id: uuid.UUID
    image_base64: str
    expires_in: Literal[300] = 300


class ActiveSessionsData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    active_count: int = Field(ge=0)
    login_times: tuple[str, ...]


class PasswordResetCompletionRequest(_UsernameRequest):
    temporary_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_changed_password(self) -> Self:
        if (
            self.temporary_password.get_secret_value()
            == self.new_password.get_secret_value()
        ):
            raise PydanticCustomError("passwords_must_differ", "passwords_must_differ")
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
