from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
    model_validator,
)
from pydantic_extra_types.phone_numbers import PhoneNumber

from .utils import BDPhone, EmailSchema


class PasswordConfirmMixin(BaseModel):
    password: str = Field(min_length=8, max_length=100)
    confirm_password: str = Field(max_length=100)

    @model_validator(mode="after")
    def verify_passwords_match(self) -> "PasswordConfirmMixin":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class UserBase(BaseModel):
    email: EmailStr
    first_name: str = Field(max_length=100)
    last_name: str = Field(max_length=100)


class UserCreate(UserBase, PasswordConfirmMixin):
    phone: BDPhone


class UserUpdate(BaseModel):
    first_name: str | None = Field(None, max_length=100)
    last_name: str | None = Field(None, max_length=100)
    username: str | None = Field(None, max_length=100)


class UserResponse(UserBase):
    id: UUID = Field(frozen=True)
    username: str | None = None
    phone: PhoneNumber = Field(frozen=True)

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    model_config = ConfigDict(from_attributes=True)


class UserLogin(EmailSchema):
    password: str = Field(min_length=8, max_length=100)


class ChangePassword(PasswordConfirmMixin):
    old_password: str = Field(min_length=8, max_length=100)
