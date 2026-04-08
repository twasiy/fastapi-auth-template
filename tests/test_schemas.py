import pytest
from uuid import uuid4
from pydantic import ValidationError

from app.schemas.users import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserLogin,
    ChangePassword,
    PasswordConfirmMixin,
)
from app.schemas.utils import (
    MsgResponse,
    DataResponse,
    Token,
    EmailSchema,
    OTPSchema,
    TokenAction,
)


# ── PasswordConfirmMixin ───────────────────────────────────────────────────────


class TestPasswordConfirmMixin:
    def test_matching_passwords_pass(self):
        obj = PasswordConfirmMixin(password="Valid123!", confirm_password="Valid123!")
        assert obj.password == "Valid123!"

    def test_mismatched_passwords_raise(self):
        with pytest.raises(ValidationError, match="Passwords do not match"):
            PasswordConfirmMixin(password="Valid123!", confirm_password="Different!")

    def test_password_too_short_raises(self):
        with pytest.raises(ValidationError):
            PasswordConfirmMixin(password="short", confirm_password="short")

    def test_password_max_length_exceeded_raises(self):
        long_pw = "a" * 101
        with pytest.raises(ValidationError):
            PasswordConfirmMixin(password=long_pw, confirm_password=long_pw)


# ── UserCreate ─────────────────────────────────────────────────────────────────


class TestUserCreate:
    def _valid(self, **overrides):
        data = {
            "email": "user@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "phone": "+8801711111111",
        }
        data.update(overrides)
        return UserCreate(**data)

    def test_valid_creates_successfully(self):
        user = self._valid()
        assert user.email == "user@example.com"

    def test_invalid_email_raises(self):
        with pytest.raises(ValidationError):
            self._valid(email="not-an-email")

    def test_password_mismatch_raises(self):
        with pytest.raises(ValidationError, match="Passwords do not match"):
            self._valid(password="Pass123!", confirm_password="Different!")

    def test_invalid_phone_raises(self):
        with pytest.raises(ValidationError):
            self._valid(phone="not-a-phone")

    def test_first_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            self._valid(first_name="a" * 101)

    def test_last_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            self._valid(last_name="b" * 101)


# ── UserUpdate ─────────────────────────────────────────────────────────────────


class TestUserUpdate:
    def test_all_fields_optional(self):
        obj = UserUpdate()  # type: ignore
        assert obj.first_name is None
        assert obj.last_name is None
        assert obj.username is None

    def test_partial_update_works(self):
        obj = UserUpdate(first_name="Jane")  # type: ignore
        assert obj.first_name == "Jane"
        assert obj.last_name is None

    def test_username_too_long_raises(self):
        with pytest.raises(ValidationError):
            UserUpdate(username="u" * 101)  # type: ignore


# ── UserResponse ───────────────────────────────────────────────────────────────


class TestUserResponse:
    def test_full_name_computed_correctly(self):
        user = UserResponse(
            id=uuid4(),
            email="user@example.com",
            first_name="John",
            last_name="Doe",
            phone="+8801711111111",  # type: ignore
        )
        assert user.full_name == "John Doe"

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            UserResponse(  # type: ignore
                email="user@example.com",
                first_name="John",
                last_name="Doe",
                # missing id and phone
            )


# ── UserLogin ──────────────────────────────────────────────────────────────────


class TestUserLogin:
    def test_valid_login(self):
        obj = UserLogin(email="user@example.com", password="Password1!")
        assert obj.email == "user@example.com"

    def test_invalid_email_raises(self):
        with pytest.raises(ValidationError):
            UserLogin(email="bad-email", password="Password1!")

    def test_short_password_raises(self):
        with pytest.raises(ValidationError):
            UserLogin(email="user@example.com", password="short")


# ── ChangePassword ─────────────────────────────────────────────────────────────


class TestChangePassword:
    def test_valid_change_password(self):
        obj = ChangePassword(
            old_password="OldPass123!",
            password="NewPass123!",
            confirm_password="NewPass123!",
        )
        assert obj.old_password == "OldPass123!"

    def test_mismatched_new_passwords_raise(self):
        with pytest.raises(ValidationError, match="Passwords do not match"):
            ChangePassword(
                old_password="OldPass123!",
                password="NewPass123!",
                confirm_password="WrongNew!",
            )


# ── Utility Schemas ────────────────────────────────────────────────────────────


class TestUtilitySchemas:
    def test_msg_response(self):
        obj = MsgResponse(detail="Success")
        assert obj.detail == "Success"

    def test_data_response_generic(self):
        obj = DataResponse[str](data="hello", message="Done")
        assert obj.data == "hello"
        assert obj.message == "Done"

    def test_data_response_default_message(self):
        obj = DataResponse[int](data=42)
        assert obj.message == "Success"

    def test_token_default_type(self):
        obj = Token(access_token="acc", refresh_token="ref")
        assert obj.token_type == "bearer"

    def test_otp_schema_max_length(self):
        with pytest.raises(ValidationError):
            OTPSchema(otp="1234567")  # 7 chars, max is 6

    def test_otp_schema_valid(self):
        obj = OTPSchema(otp="123456")
        assert obj.otp == "123456"

    def test_token_action_generic(self):
        class Inner(EmailSchema):
            pass

        obj = TokenAction[EmailSchema](
            token="some-token", data={"email": "test@example.com"}  # type: ignore
        )
        assert obj.token == "some-token"
        assert obj.data.email == "test@example.com"

    def test_email_schema_valid(self):
        obj = EmailSchema(email="hello@world.com")
        assert obj.email == "hello@world.com"

    def test_email_schema_invalid_raises(self):
        with pytest.raises(ValidationError):
            EmailSchema(email="not-valid")
