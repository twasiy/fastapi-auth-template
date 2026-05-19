from typing_extensions import Annotated
from typing import AsyncGenerator, Generator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from redis.asyncio import Redis, ConnectionPool

from app.db import AsyncSessionLocal, SyncSessionLocal
from app.core import settings, RedisService

pool = ConnectionPool.from_url(settings.REDIS_URL, decode_responses=True)


# For handling async database connection in the user facing endpoints
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


# For handling sync database connection in the background task by celery workers
def get_sync_db() -> Generator[Session, None, None]:
    with SyncSessionLocal() as session:
        yield session


# Redis dependency connection
async def get_redis_service():
    async with Redis(connection_pool=pool) as client:
        yield RedisService(client)


AsyncDB = Annotated[AsyncSession, Depends(get_async_db)]
SyncDB = Annotated[Session, Depends(get_sync_db)]
RedisConn = Annotated[RedisService, Depends(get_redis_service)]
