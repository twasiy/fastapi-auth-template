import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from app.api.v1.dependencies import (
    AsyncDB,
    CurrentActiveUser,
    DefaultRateLimit,
    RedisConn,
    StrictRateLimit,
)
from app.core import (
    create_email_change_token,
    create_email_verification_token,
    verify_email_change_token,
)
from app.crud import (
    change_user_email,
    change_user_phone,
    create_user,
    de_verify_user_email,
    de_verify_user_phone,
    get_user_by_id,
    update_user,
)
from app.schemas import (
    EmailSchema,
    MsgResponse,
    OTPAction,
    PhoneSchema,
    TokenAction,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.services import send_email, send_sms
from app.utils import paths, subjects, templates

router = APIRouter()


@router.post(
    "/register", status_code=status.HTTP_201_CREATED, response_model=MsgResponse
)
async def register(
    db: AsyncDB,
    background_tasks: BackgroundTasks,
    _: DefaultRateLimit,
    obj_in: UserCreate,
):
    try:
        user = await create_user(db=db, obj_in=obj_in)

        token = create_email_verification_token(user.id)

        background_tasks.add_task(
            send_email,
            user=user,
            email_to=user.email,
            token=token,
            subject=subjects.ACTIVATION,
            template_name=templates.ACTIVATION,
            path=paths.ACTIVATE,
        )

        return {
            "detail": "Registration successful. Please check your email inbox to verify your account."
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/me", response_model=UserResponse)
async def user_profile(_: DefaultRateLimit, current_user: CurrentActiveUser):
    try:
        return current_user
    except HTTPException as e:
        raise e


@router.put("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
async def update_user_profile(
    db: AsyncDB, _: StrictRateLimit, current_user: CurrentActiveUser, obj_in: UserUpdate
):
    try:
        updated_user = await update_user(
            db=db, current_user=current_user, obj_in=obj_in
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cannot update profile"
        )

    return updated_user


@router.post(
    "/me/email-change-request",
    status_code=status.HTTP_200_OK,
    response_model=MsgResponse,
)
async def change_email_request(
    _: StrictRateLimit,
    background_tasks: BackgroundTasks,
    current_user: CurrentActiveUser,
):
    token = create_email_change_token(current_user.id)

    background_tasks.add_task(
        send_email,
        user=current_user,
        email_to=current_user.email,
        token=token,
        subject=subjects.CHANGE_EMAIL,
        template_name=templates.EMAIL_CHANGE,
        path=paths.CHANGE_EMAIL,
    )

    return {"detail": "If that email exists, a change email link has been sent."}


@router.post(
    "/me/confirm-email-change",
    status_code=status.HTTP_200_OK,
    response_model=MsgResponse,
)
async def change_email_confirm(
    db: AsyncDB, redis: RedisConn, obj_in: TokenAction[EmailSchema]
):
    try:
        payload = verify_email_change_token(obj_in.token)

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

    db_user = await get_user_by_id(db=db, user_id=user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User not found"
        )

    await change_user_email(db=db, db_user=db_user, new_email=obj_in.data.email)

    await de_verify_user_email(db=db, db_user=db_user)

    now = datetime.now(timezone.utc).timestamp()
    seconds_left = int(exp - now)  # type: ignore

    await redis.blacklist_token(jti=jti, expiry_seconds=seconds_left)  # type: ignore

    return {"detail": "Email changed successfully"}


@router.post(
    "/me/phone-change-request",
    status_code=status.HTTP_200_OK,
    response_model=MsgResponse,
)
async def change_phone_request(
    redis: RedisConn,
    _: StrictRateLimit,
    background_tasks: BackgroundTasks,
    current_user: CurrentActiveUser,
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
    "/me/confirm-phone-change",
    status_code=status.HTTP_200_OK,
    response_model=MsgResponse,
)
async def change_phone_confirm(
    db: AsyncDB,
    redis: RedisConn,
    current_user: CurrentActiveUser,
    obj_in: OTPAction[PhoneSchema],
):
    phone = str(current_user.phone)
    stored_code = await redis.get_otp(phone=phone)

    if not stored_code or stored_code != obj_in.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code",
        )

    await change_user_phone(db=db, db_user=current_user, new_phone=obj_in.data.phone)

    await de_verify_user_phone(db=db, db_user=current_user)

    await redis.delete_value(f"otp:{phone}")

    return {"detail": "Successfully changed phone number"}
