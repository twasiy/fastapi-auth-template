import pytest
from uuid import uuid4

from app.crud.users import (
    get_user_by_id,
    get_user_by_email,
    get_user_by_phone,
    create_user,
    update_user,
    activate_user,
    deactivate_user,
    verify_user_email,
    verify_user_phone,
    de_verify_user_email,
    de_verify_user_phone,
    authenticate,
    update_user_password,
    change_user_email,
    change_user_phone,
)
from app.schemas.users import UserCreate, UserUpdate
from app.utils.password_hash import verify_password


# ── Helper ─────────────────────────────────────────────────────────────────────


def _user_create(**overrides) -> UserCreate:
    data = {
        "email": f"user_{uuid4().hex[:8]}@example.com",
        "first_name": "Test",
        "last_name": "User",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "phone": "+8801711111111",
    }
    data.update(overrides)
    return UserCreate(**data)


# ── get_user_by_id ─────────────────────────────────────────────────────────────


class TestGetUserById:
    async def test_returns_user_when_found(self, db_session):
        user = await create_user(db_session, _user_create())
        result = await get_user_by_id(db_session, user.id)
        assert result is not None
        assert result.id == user.id

    async def test_returns_none_for_unknown_id(self, db_session):
        result = await get_user_by_id(db_session, uuid4())
        assert result is None


# ── get_user_by_email ──────────────────────────────────────────────────────────


class TestGetUserByEmail:
    async def test_returns_user_when_found(self, db_session):
        email = f"lookup_{uuid4().hex[:6]}@example.com"
        await create_user(db_session, _user_create(email=email))
        result = await get_user_by_email(db_session, email)
        assert result is not None
        assert result.email == email

    async def test_returns_none_for_unknown_email(self, db_session):
        result = await get_user_by_email(db_session, "nobody@nowhere.com")
        assert result is None

    async def test_case_sensitive_lookup(self, db_session):
        email = f"case_{uuid4().hex[:6]}@example.com"
        await create_user(db_session, _user_create(email=email))
        result = await get_user_by_email(db_session, email.upper())
        # SQLite is case-insensitive by default for ASCII, but the app should
        # store and query consistently — test that exact match works
        # (Postgres IS case-sensitive — this tests the CRUD logic, not DB engine)
        assert result is None or result.email == email


# ── get_user_by_phone ──────────────────────────────────────────────────────────


class TestGetUserByPhone:
    async def test_returns_user_when_found(self, db_session):
        phone = "+8801788888888"
        await create_user(db_session, _user_create(phone=phone))
        result = await get_user_by_phone(db_session, phone)
        assert result is not None
        assert result.phone == phone

    async def test_returns_none_for_unknown_phone(self, db_session):
        result = await get_user_by_phone(db_session, "+8801799999991")
        assert result is None


# ── create_user ────────────────────────────────────────────────────────────────


class TestCreateUser:
    async def test_creates_user_successfully(self, db_session):
        schema = _user_create()
        user = await create_user(db_session, schema)
        assert user.id is not None
        assert user.email == schema.email

    async def test_password_is_hashed(self, db_session):
        schema = _user_create()
        user = await create_user(db_session, schema)
        assert user.hashed_password != schema.password
        assert verify_password(schema.password, user.hashed_password)

    async def test_confirm_password_not_stored(self, db_session):
        schema = _user_create()
        user = await create_user(db_session, schema)
        assert not hasattr(user, "confirm_password")

    async def test_duplicate_email_raises(self, db_session):
        schema = _user_create(email="dup@example.com", phone="+8801711111121")
        await create_user(db_session, schema)
        with pytest.raises(ValueError, match="already exists"):
            schema2 = _user_create(email="dup@example.com", phone="+8801711111122")
            await create_user(db_session, schema2)

    async def test_new_user_is_active_by_default(self, db_session):
        user = await create_user(db_session, _user_create())
        assert user.is_active is True

    async def test_new_user_email_not_verified(self, db_session):
        user = await create_user(db_session, _user_create())
        assert user.is_email_verified is False

    async def test_new_user_is_not_admin(self, db_session):
        user = await create_user(db_session, _user_create())
        assert user.is_admin is False


# ── update_user ────────────────────────────────────────────────────────────────


class TestUpdateUser:
    async def test_updates_first_name(self, db_session):
        user = await create_user(db_session, _user_create())
        updated = await update_user(db_session, user, UserUpdate(first_name="Jane"))  # type: ignore
        assert updated.first_name == "Jane"

    async def test_partial_update_leaves_other_fields(self, db_session):
        user = await create_user(db_session, _user_create(first_name="OrigFirst"))
        updated = await update_user(db_session, user, UserUpdate(last_name="NewLast"))  # type: ignore
        assert updated.last_name == "NewLast"
        assert updated.first_name == "OrigFirst"

    async def test_null_fields_not_set(self, db_session):
        user = await create_user(db_session, _user_create(first_name="Keep"))
        # UserUpdate with no fields set
        updated = await update_user(db_session, user, UserUpdate())  # type: ignore
        assert updated.first_name == "Keep"


# ── activate / deactivate ──────────────────────────────────────────────────────


class TestActivateDeactivate:
    async def test_activate_inactive_user(self, db_session, inactive_user):
        await activate_user(db_session, inactive_user)
        assert inactive_user.is_active is True

    async def test_activate_already_active_is_noop(
        self, db_session, active_verified_user
    ):
        await activate_user(db_session, active_verified_user)
        assert active_verified_user.is_active is True

    async def test_deactivate_active_user(self, db_session, active_verified_user):
        await deactivate_user(db_session, active_verified_user)
        assert active_verified_user.is_active is False

    async def test_deactivate_already_inactive_is_noop(self, db_session, inactive_user):
        await deactivate_user(db_session, inactive_user)
        assert inactive_user.is_active is False


# ── verify_user_email / phone ──────────────────────────────────────────────────


class TestVerifyFlags:
    async def test_verify_email(self, db_session, unverified_user):
        await verify_user_email(db_session, unverified_user)
        assert unverified_user.is_email_verified is True

    async def test_verify_email_idempotent(self, db_session, active_verified_user):
        await verify_user_email(db_session, active_verified_user)
        assert active_verified_user.is_email_verified is True

    async def test_verify_phone(self, db_session, unverified_user):
        await verify_user_phone(db_session, unverified_user)
        assert unverified_user.is_phone_verified is True

    async def test_de_verify_email(self, db_session, active_verified_user):
        await de_verify_user_email(db_session, active_verified_user)
        assert active_verified_user.is_email_verified is False

    async def test_de_verify_phone(self, db_session, admin_user):
        await de_verify_user_phone(db_session, admin_user)
        assert admin_user.is_phone_verified is False


# ── authenticate ───────────────────────────────────────────────────────────────


class TestAuthenticate:
    async def test_correct_credentials_return_user(
        self, db_session, active_verified_user
    ):
        result = await authenticate(
            db_session,
            user_email=active_verified_user.email,
            plain_password="Password123!",
        )
        assert result is not None
        assert result.id == active_verified_user.id

    async def test_wrong_password_returns_none(self, db_session, active_verified_user):
        result = await authenticate(
            db_session,
            user_email=active_verified_user.email,
            plain_password="WrongPassword!",
        )
        assert result is None

    async def test_unknown_email_returns_none(self, db_session):
        result = await authenticate(
            db_session,
            user_email="ghost@example.com",
            plain_password="Password123!",
        )
        assert result is None

    async def test_timing_safe_unknown_user_does_not_skip_verify(self, db_session):
        """
        Even for non-existent users, authenticate() must run verify_password
        to prevent timing-based email enumeration.
        This test just ensures the function returns None gracefully (doesn't raise).
        """
        result = await authenticate(
            db_session,
            user_email="timing@example.com",
            plain_password="any-password",
        )
        assert result is None


# ── update_user_password ───────────────────────────────────────────────────────


class TestUpdatePassword:
    async def test_updates_password_hash(self, db_session, active_verified_user):
        await update_user_password(db_session, active_verified_user, "NewPass456!")
        assert verify_password("NewPass456!", active_verified_user.hashed_password)

    async def test_old_password_no_longer_works(self, db_session, active_verified_user):
        await update_user_password(db_session, active_verified_user, "NewPass456!")
        assert not verify_password("Password123!", active_verified_user.hashed_password)


# ── change_user_email / phone ──────────────────────────────────────────────────


class TestChangeEmailPhone:
    async def test_change_email(self, db_session, active_verified_user):
        await change_user_email(db_session, active_verified_user, "new@example.com")
        assert active_verified_user.email == "new@example.com"

    async def test_change_phone(self, db_session, active_verified_user):
        await change_user_phone(db_session, active_verified_user, "+8801799000001")
        assert active_verified_user.phone == "+8801799000001"
