from typing import Annotated, Generic, TypeVar

from pydantic import BaseModel, EmailStr, Field
from pydantic_extra_types.phone_numbers import PhoneNumberValidator

# A Generic Type for "Data" in responses
T = TypeVar("T")

# Reusable Types
BDPhone = Annotated[
    str,
    PhoneNumberValidator(
        supported_regions=["BD", "US"],
        default_region="BD",
        number_format="E164",
    ),
]


class MsgResponse(BaseModel):
    detail: str


class DataResponse(BaseModel, Generic[T]):
    data: T
    message: str = "Success"


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefresh(BaseModel):
    refresh: str


class EmailSchema(BaseModel):
    email: EmailStr


class PhoneSchema(BaseModel):
    phone: BDPhone


class TokenSchema(BaseModel):
    token: str


class OTPSchema(BaseModel):
    otp: str = Field(max_length=6)


class TokenAction(BaseModel, Generic[T]):
    token: str
    data: T


class OTPAction(BaseModel, Generic[T]):
    otp: str
    data: T
