from uuid import UUID

from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio.session import AsyncSession

from app.models import User
from app.schemas import BDPhone, UserCreate, UserUpdate
from app.utils import hash_password, verify_password


async def get_user_by_id(db: AsyncSession, user_id: UUID | int) -> User | None:
    return await db.get(User, user_id)


async def get_user_by_email(db: AsyncSession, user_email: str) -> User | None:
    stmt = select(User).where(User.email == user_email)
    user_res = await db.execute(stmt)

    return user_res.scalar_one_or_none()


async def get_user_by_phone(db: AsyncSession, user_phone: BDPhone) -> User | None:
    stmt = select(User).where(User.phone == user_phone)
    user_res = await db.execute(stmt)

    return user_res.scalar_one_or_none()


async def create_user(db: AsyncSession, obj_in: UserCreate) -> User:
    user_data: dict = obj_in.model_dump(exclude={"confirm_password", "password"})
    user_data["hashed_password"] = hash_password(obj_in.password)

    user: User = User(**user_data)

    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        return user
    except IntegrityError:
        await db.rollback()
        raise ValueError(
            "User with this email or phone already exists",
        )


async def update_user(db: AsyncSession, current_user: User, obj_in: UserUpdate) -> User:
    update_data: dict = obj_in.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(current_user, field, value)

    db.add(current_user)
    try:
        await db.commit()
        await db.refresh(current_user)
    except IntegrityError:
        await db.rollback()
        raise ValueError("The update failed due to a data conflict")

    return current_user


async def activate_user(db: AsyncSession, db_user: User) -> None:
    if not db_user.is_active:
        db_user.is_active = True
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


async def verify_user_email(db: AsyncSession, db_user: User) -> None:
    if not db_user.is_email_verified:
        db_user.is_email_verified = True
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


async def verify_user_phone(db: AsyncSession, db_user: User) -> None:
    if not db_user.is_phone_verified:
        db_user.is_phone_verified = True
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


async def deactivate_user(db: AsyncSession, db_user: User) -> None:
    if db_user.is_active:
        db_user.is_active = False
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


async def de_verify_user_email(db: AsyncSession, db_user: User) -> None:
    if db_user.is_email_verified:
        db_user.is_email_verified = False
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


async def de_verify_user_phone(db: AsyncSession, db_user: User) -> None:
    if db_user.is_phone_verified:
        db_user.is_phone_verified = False
        db.add(db_user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Failed due to a data conflict")


DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$Rk5PdzR4WGxSOG1lZTVaMg$O9fVzXk2t16b5aF7d5Y4dC/4wUq6B6J8sQj1kL1p7jE"


async def authenticate(
    db: AsyncSession, user_email: str, plain_password: str
) -> User | None:
    db_user: User | None = await get_user_by_email(db=db, user_email=user_email)

    if not db_user:
        # Prevent timing attacks by running password verification even when user doesn't exist
        # This ensures the response time is similar whether or not the email exists
        verify_password(plain_password=plain_password, hashed_password=DUMMY_HASH)
        return None

    verified: bool = verify_password(
        plain_password=plain_password, hashed_password=db_user.hashed_password
    )

    if not verified:
        return None

    return db_user


async def update_user_password(
    db: AsyncSession, db_user: User, new_password: str
) -> None:
    db_user.hashed_password = hash_password(new_password)

    db.add(db_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise ValueError("Failed due to a data conflict")


async def change_user_email(
    db: AsyncSession, db_user: User, new_email: EmailStr
) -> None:
    db_user.email = new_email

    db.add(db_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise ValueError("Failed due to a data conflict")


async def change_user_phone(
    db: AsyncSession, db_user: User, new_phone: BDPhone
) -> None:
    db_user.phone = new_phone

    db.add(db_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise ValueError("Failed due to a data conflict")
