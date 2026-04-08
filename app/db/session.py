from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core import settings

sync_engine = create_engine(settings.SYNC_DATABASE_URI.unicode_string(), echo=False)
async_engine = create_async_engine(
    settings.ASYNC_DATABASE_URI.unicode_string(), echo=False
)

SyncSessionLocal = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,  # specifically needed for async session
)
