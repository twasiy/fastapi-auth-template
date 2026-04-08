from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt

from app.core import settings


class TokenType:
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    ACTIVATION = "activation"
    CHANGE = "change"


def create_token(data: dict, expires_delta: timedelta, token_type: str) -> str:
    to_encode = data.copy()
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid4()),
            "type": token_type,
        }
    )

    secret_key = settings.SECRET_KEY.get_secret_value()

    return jwt.encode(to_encode, secret_key, algorithm=settings.ALGORITHM)


def verify_token(token: str, token_type: str) -> dict:
    secret_key = settings.SECRET_KEY.get_secret_value()
    try:
        payload = jwt.decode(token, secret_key, algorithms=[settings.ALGORITHM])

        if payload.get("type") != token_type:
            raise ValueError(f"Invalid token type. Expected: {token_type}")

        return payload

    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


def create_access_token(subject: UUID | int | str) -> str:
    return create_token(
        data={"sub": str(subject)},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type=TokenType.ACCESS,
    )


def create_refresh_token(subject: UUID | int | str) -> str:
    return create_token(
        data={"sub": str(subject)},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        token_type=TokenType.REFRESH,
    )


def create_password_reset_token(subject: UUID | int | str) -> str:
    return create_token(
        data={"sub": str(subject)},
        expires_delta=timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES),
        token_type=TokenType.RESET,
    )


def create_email_verification_token(subject: UUID | int | str) -> str:
    return create_token(
        data={"sub": str(subject)},
        expires_delta=timedelta(days=settings.EMAIL_ACTIVATION_TOKEN_EXPIRE_DAYS),
        token_type=TokenType.ACTIVATION,
    )


def create_email_change_token(subject: UUID | int | str) -> str:
    return create_token(
        data={"sub": str(subject)},
        expires_delta=timedelta(hours=settings.EMAIL_CHANGE_TOKEN_EXPIRE_HOURS),
        token_type=TokenType.CHANGE,
    )


def verify_access_token(token: str) -> dict:
    return verify_token(token, token_type=TokenType.ACCESS)


def verify_refresh_token(token: str) -> dict:
    return verify_token(token, token_type=TokenType.REFRESH)


def verify_password_reset_token(token: str) -> dict:
    return verify_token(token, token_type=TokenType.RESET)


def verify_email_verification_token(token: str) -> dict:
    return verify_token(token, token_type=TokenType.ACTIVATION)


def verify_email_change_token(token: str) -> dict:
    return verify_token(token, token_type=TokenType.CHANGE)
