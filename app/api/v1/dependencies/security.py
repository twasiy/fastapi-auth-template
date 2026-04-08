from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing_extensions import Annotated

from app.core import verify_access_token
from app.crud import get_user_by_id
from app.models import User

from .database import AsyncDB, RedisConn

oauth2_scheme = HTTPBearer()

AuthCred = Annotated[HTTPAuthorizationCredentials, Depends(oauth2_scheme)]


async def get_current_user(db: AsyncDB, redis: RedisConn, cred: AuthCred) -> "User":
    try:
        payload = verify_access_token(cred.credentials)

        user_id = UUID(payload.get("sub"))
        jti = payload.get("jti")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await redis.is_token_blacklisted(jti=jti):  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    user = await get_user_by_id(db=db, user_id=user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return user


async def get_current_active_user(
    db: AsyncDB, redis: RedisConn, cred: AuthCred
) -> "User":
    try:
        user = await get_current_user(db=db, redis=redis, cred=cred)
    except Exception as e:
        raise e

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account disabled"
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentActiveUser = Annotated[User, Depends(get_current_active_user)]
