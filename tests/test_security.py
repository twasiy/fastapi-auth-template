import pytest
from datetime import timedelta
from unittest.mock import patch, MagicMock
from uuid import uuid4
from pydantic import SecretStr

# ── Patch settings before import ──────────────────────────────────────────────
mock_settings = MagicMock()
mock_settings.SECRET_KEY = SecretStr("super-secret-test-key-that-is-long-enough")
mock_settings.ALGORITHM = "HS256"
mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
mock_settings.RESET_TOKEN_EXPIRE_MINUTES = 15
mock_settings.EMAIL_ACTIVATION_TOKEN_EXPIRE_DAYS = 1
mock_settings.EMAIL_CHANGE_TOKEN_EXPIRE_HOURS = 1

with patch("app.core.security.settings", mock_settings):
    from app.core.security import (
        TokenType,
        create_token,
        verify_token,
        create_access_token,
        create_refresh_token,
        create_password_reset_token,
        create_email_verification_token,
        create_email_change_token,
        verify_access_token,
        verify_refresh_token,
        verify_password_reset_token,
        verify_email_verification_token,
        verify_email_change_token,
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

USER_ID = uuid4()


def _patch_settings(fn):
    """Decorator: run function with patched settings."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with patch("app.core.security.settings", mock_settings):
            return fn(*args, **kwargs)

    return wrapper


# ── create_token ──────────────────────────────────────────────────────────────


class TestCreateToken:
    @_patch_settings
    def test_returns_string(self):
        token = create_token(
            data={"sub": str(USER_ID)},
            expires_delta=timedelta(minutes=5),
            token_type=TokenType.ACCESS,
        )
        assert isinstance(token, str)
        assert len(token) > 20

    @_patch_settings
    def test_token_contains_correct_type(self):
        token = create_token(
            data={"sub": str(USER_ID)},
            expires_delta=timedelta(minutes=5),
            token_type=TokenType.REFRESH,
        )
        payload = verify_token(token, TokenType.REFRESH)
        assert payload["type"] == TokenType.REFRESH

    @_patch_settings
    def test_token_contains_jti(self):
        token = create_token(
            data={"sub": str(USER_ID)},
            expires_delta=timedelta(minutes=5),
            token_type=TokenType.ACCESS,
        )
        payload = verify_token(token, TokenType.ACCESS)
        assert "jti" in payload
        assert len(payload["jti"]) > 0

    @_patch_settings
    def test_each_token_has_unique_jti(self):
        """JTI must be globally unique for revocation to work."""
        t1 = create_token({"sub": str(USER_ID)}, timedelta(minutes=5), TokenType.ACCESS)
        t2 = create_token({"sub": str(USER_ID)}, timedelta(minutes=5), TokenType.ACCESS)
        p1 = verify_token(t1, TokenType.ACCESS)
        p2 = verify_token(t2, TokenType.ACCESS)
        assert p1["jti"] != p2["jti"]

    @_patch_settings
    def test_sub_is_coerced_to_string(self):
        token = create_token(
            data={"sub": USER_ID},  # UUID, not str
            expires_delta=timedelta(minutes=5),
            token_type=TokenType.ACCESS,
        )
        payload = verify_token(token, TokenType.ACCESS)
        assert payload["sub"] == str(USER_ID)


# ── verify_token ──────────────────────────────────────────────────────────────


class TestVerifyToken:
    @_patch_settings
    def test_valid_token_returns_payload(self):
        token = create_token(
            {"sub": str(USER_ID)}, timedelta(minutes=5), TokenType.ACCESS
        )
        payload = verify_token(token, TokenType.ACCESS)
        assert payload["sub"] == str(USER_ID)

    @_patch_settings
    def test_wrong_token_type_raises(self):
        token = create_token(
            {"sub": str(USER_ID)}, timedelta(minutes=5), TokenType.ACCESS
        )
        with pytest.raises(ValueError, match="Invalid token type"):
            verify_token(token, TokenType.REFRESH)

    @_patch_settings
    def test_expired_token_raises(self):
        token = create_token(
            {"sub": str(USER_ID)}, timedelta(seconds=-1), TokenType.ACCESS
        )
        with pytest.raises(ValueError, match="Token expired"):
            verify_token(token, TokenType.ACCESS)

    @_patch_settings
    def test_tampered_token_raises(self):
        token = create_token(
            {"sub": str(USER_ID)}, timedelta(minutes=5), TokenType.ACCESS
        )
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(ValueError, match="Invalid token"):
            verify_token(tampered, TokenType.ACCESS)

    @_patch_settings
    def test_garbage_string_raises(self):
        with pytest.raises(ValueError):
            verify_token("not.a.token", TokenType.ACCESS)


# ── Typed convenience functions ────────────────────────────────────────────────


class TestConvenienceFunctions:
    @_patch_settings
    def test_access_token_round_trip(self):
        token = create_access_token(USER_ID)
        payload = verify_access_token(token)
        assert payload["sub"] == str(USER_ID)
        assert payload["type"] == TokenType.ACCESS

    @_patch_settings
    def test_refresh_token_round_trip(self):
        token = create_refresh_token(USER_ID)
        payload = verify_refresh_token(token)
        assert payload["sub"] == str(USER_ID)
        assert payload["type"] == TokenType.REFRESH

    @_patch_settings
    def test_password_reset_token_round_trip(self):
        token = create_password_reset_token(USER_ID)
        payload = verify_password_reset_token(token)
        assert payload["sub"] == str(USER_ID)
        assert payload["type"] == TokenType.RESET

    @_patch_settings
    def test_email_verification_token_round_trip(self):
        token = create_email_verification_token(USER_ID)
        payload = verify_email_verification_token(token)
        assert payload["sub"] == str(USER_ID)
        assert payload["type"] == TokenType.ACTIVATION

    @_patch_settings
    def test_email_change_token_round_trip(self):
        token = create_email_change_token(USER_ID)
        payload = verify_email_change_token(token)
        assert payload["sub"] == str(USER_ID)
        assert payload["type"] == TokenType.CHANGE

    @_patch_settings
    def test_access_token_rejects_refresh(self):
        token = create_refresh_token(USER_ID)
        with pytest.raises(ValueError, match="Invalid token type"):
            verify_access_token(token)

    @_patch_settings
    def test_refresh_token_rejects_access(self):
        token = create_access_token(USER_ID)
        with pytest.raises(ValueError, match="Invalid token type"):
            verify_refresh_token(token)

    @_patch_settings
    def test_integer_subject_works(self):
        token = create_access_token(42)
        payload = verify_access_token(token)
        assert payload["sub"] == "42"

    @_patch_settings
    def test_string_subject_works(self):
        token = create_access_token("user-abc")
        payload = verify_access_token(token)
        assert payload["sub"] == "user-abc"
