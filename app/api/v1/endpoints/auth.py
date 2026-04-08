import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from app.api.v1.dependencies import (
    AsyncDB,
    CurrentActiveUser,
    DefaultRateLimit,
    EmailRateLimit,
    OTPRateLimit,
    RedisConn,
    StrictRateLimit,
)
from app.core import (
    create_access_token,
    create_email_verification_token,
    create_password_reset_token,
    create_refresh_token,
    verify_email_verification_token,
    verify_password_reset_token,
    verify_refresh_token,
)
from app.crud import (
    activate_user,
    authenticate,
    get_user_by_id,
    update_user_password,
    verify_user_email,
    verify_user_phone,
)
from app.schemas import (
    ChangePassword,
    MsgResponse,
    OTPSchema,
    PasswordConfirmMixin,
    Token,
    TokenAction,
    TokenRefresh,
    TokenSchema,
    UserLogin,
)
from app.services import send_email, send_sms
from app.utils import paths, subjects, templates

router = APIRouter()


@router.post("/login", status_code=status.HTTP_200_OK, response_model=Token)
async def login(db: AsyncDB, _: StrictRateLimit, obj_in: UserLogin):
    user = await authenticate(
        db=db, user_email=obj_in.email, plain_password=obj_in.password
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password",
        )

    try:
        await activate_user(db=db, db_user=user)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during verification",
        )

    tokens = {
        "access": create_access_token(user.id),
        "refresh": create_refresh_token(user.id),
    }

    return tokens


@router.post("/refresh", response_model=Token)
async def refresh_token(
    db: AsyncDB, redis: RedisConn, _: StrictRateLimit, obj_in: TokenRefresh
):
    try:
        payload = verify_refresh_token(obj_in.refresh)
        user_id = UUID(payload.get("sub"))
        jti = payload.get("jti")
        exp = payload.get("exp")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    blacklisted = await redis.is_token_blacklisted(jti=jti)  # type: ignore
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked"
        )

    user = await get_user_by_id(db=db, user_id=user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
        )

    now = datetime.now(timezone.utc).timestamp()
    seconds_left = int(exp - now)  # type: ignore

    await redis.blacklist_token(jti=jti, expiry_seconds=seconds_left)  # type: ignore

    tokens = {
        "access": create_access_token(user.id),
        "refresh": create_refresh_token(user.id),
    }

    return tokens


@router.post("/logout", status_code=status.HTTP_200_OK, response_model=MsgResponse)
async def logout(redis: RedisConn, _: StrictRateLimit, obj_in: TokenRefresh):
    try:
        payload = verify_refresh_token(token=obj_in.refresh)

        jti = payload.get("jti")
        exp = payload.get("exp")
    except ValueError:
        return {"detail": "Successfully logged out"}

    blacklisted = await redis.is_token_blacklisted(jti=jti)  # type: ignore
    if blacklisted:
        return {"detail": "Successfully logged out"}

    now = datetime.now(timezone.utc).timestamp()
    seconds_left = int(exp - now)  # type: ignore

    if seconds_left > 0:
        await redis.blacklist_token(jti=jti, expiry_seconds=seconds_left)  # type: ignore

    return {"detail": "Successfully logged out"}


@router.post(
    "/change-password", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def change_password(
    db: AsyncDB,
    current_user: CurrentActiveUser,
    _: StrictRateLimit,
    obj_in: ChangePassword,
):
    user = await authenticate(
        db=db, user_email=current_user.email, plain_password=obj_in.old_password
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password"
        )

    try:
        await update_user_password(db=db, db_user=user, new_password=obj_in.password)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during verification",
        )

    return {"detail": "Password updated successfully"}


@router.post(
    "/forgot-password", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def forgot_password(
    background_tasks: BackgroundTasks,
    current_user: CurrentActiveUser,
    _: EmailRateLimit,
):
    token = create_password_reset_token(current_user.id)
    background_tasks.add_task(
        send_email,
        user=current_user,
        email_to=current_user.email,
        token=token,
        subject=subjects.RESET_PASSWORD,
        template_name=templates.RESET_PASSWORD,
        path=paths.RESET_PASSWORD,
    )

    return {"detail": "If that email exists, a password reset link has been sent."}


@router.post(
    "/reset-password", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def reset_password(
    db: AsyncDB,
    redis: RedisConn,
    _: DefaultRateLimit,
    obj_in: TokenAction[PasswordConfirmMixin],
):
    try:
        payload = verify_password_reset_token(obj_in.token)

        user_id = payload.get("sub")
        jti = payload.get("jti")
        exp = payload.get("exp")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token"
        )

    blacklisted = await redis.is_token_blacklisted(jti=jti)  # type: ignore
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked"
        )

    user = await get_user_by_id(db=db, user_id=UUID(user_id))

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
        )

    await update_user_password(db=db, db_user=user, new_password=obj_in.data.password)

    now = datetime.now(timezone.utc).timestamp()
    seconds_left = int(exp - now)  # type: ignore

    await redis.blacklist_token(jti=jti, expiry_seconds=seconds_left)  # type: ignore

    return {"detail": "Password updated successfully"}


@router.post(
    "/verify-email-request", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def verify_email_request(
    current_user: CurrentActiveUser, background_task: BackgroundTasks, _: EmailRateLimit
):
    token = create_email_verification_token(current_user.id)

    background_task.add_task(
        send_email,
        user=current_user,
        email_to=current_user.email,
        token=token,
        subject=subjects.VERIFY_EMAIL,
        template_name=templates.VERIFICATION,
        path=paths.VERIFY_EMAIL,
    )

    return {"detail": "If that email exists, an email verification email has been sent"}


@router.post(
    "/verify-email", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def verify_email(
    db: AsyncDB, redis: RedisConn, _: DefaultRateLimit, obj_in: TokenSchema
):
    try:
        payload = verify_email_verification_token(token=obj_in.token)
        user_id = UUID(payload.get("sub"))
        jti = payload.get("jti")
        exp = payload.get("exp")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token"
        )

    blacklisted = await redis.is_token_blacklisted(jti=jti)  # type: ignore
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked"
        )

    user = await get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User not found"
        )

    now = datetime.now(timezone.utc).timestamp()
    seconds_left = int(exp - now)  # type: ignore

    try:
        await verify_user_email(db=db, db_user=user)
        await redis.blacklist_token(jti=jti, expiry_seconds=seconds_left)  # type: ignore
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during verification",
        )

    return {
        "detail": "Your email address has been successfully verified. You can now log in."
    }


@router.post(
    "/verify-phone-request", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def verify_phone_request(
    redis: RedisConn,
    background_tasks: BackgroundTasks,
    current_user: CurrentActiveUser,
    _: OTPRateLimit,
):
    phone = str(current_user.phone)
    existing_code = await redis.get_otp(phone=phone)
    if existing_code:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="A code was recently sent. Please wait 5 minutes before requesting a new one.",
        )

    # Generate a secure 6-digit OTP
    otp_code = f"{secrets.randbelow(1000000):06d}"

    await redis.save_otp(phone=phone, code=otp_code, expire=300)

    background_tasks.add_task(send_sms, phone=phone, otp=otp_code)

    return {"detail": "Verification code sent"}


@router.post(
    "/verify-phone", status_code=status.HTTP_200_OK, response_model=MsgResponse
)
async def verify_phone(
    db: AsyncDB,
    redis: RedisConn,
    current_user: CurrentActiveUser,
    _: DefaultRateLimit,
    obj_in: OTPSchema,
):
    phone = str(current_user.phone)
    stored_code = await redis.get_otp(phone=phone)

    if not stored_code or stored_code != obj_in.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code",
        )

    try:
        await verify_user_phone(db=db, db_user=current_user)
        await redis.delete_value(f"otp:{phone}")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during verification",
        )

    return {"detail": "Phone number verified successfully"}
