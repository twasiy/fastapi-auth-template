import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch
from uuid import uuid4
import os

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import fakeredis.aioredis as fakeredis_async

# 1. Environment and Mock Setup
os.environ.update(
    {
        "SECRET_KEY": "super-secret-test-key-that-is-long-enough",
        "POSTGRES_USER": "test",
        "POSTGRES_DB": "testdb",
        "POSTGRES_PASSWORD": "test",
        "POSTGRES_SERVER": "localhost",
        "REDIS_URL": "redis://localhost:6379/0",
        "TWILIO_ACCOUNT_SID": "ACtest",
        "TWILIO_AUTH_TOKEN": "authtest",
        "TWILIO_PHONE_NUMBER": "+8801711000000",
        "CORS_ORIGINS": '["http://localhost:3000"]',
    }
)

from app.models.base import Base
from app.models import User
from app.utils import hash_password
from app.core import create_access_token

# Mock settings globally
from pydantic import SecretStr

mock_settings = MagicMock()
mock_settings.SECRET_KEY = SecretStr("super-secret-test-key-that-is-long-enough")
mock_settings.ALGORITHM = "HS256"
mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
mock_settings.API_V1_STR = "/api/v1"

# 2. Database Fixtures (The Fix)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine):
    """
    Creates a fresh session for each test and rolls back ALL changes,
    ensuring UNIQUE constraints don't fail on subsequent tests.
    """
    connection = await test_engine.connect()
    # Start a transaction
    trans = await connection.begin()

    Session = async_sessionmaker(
        bind=connection,
        expire_on_commit=False,
    )
    session = Session()

    yield session

    # Roll back everything after the test, including hardcoded fixture data
    await session.close()
    await trans.rollback()
    await connection.close()


# 3. Redis and App Fixtures


@pytest_asyncio.fixture
async def fake_redis():
    redis = fakeredis_async.FakeRedis(decode_responses=True)
    yield redis
    await redis.flushall()
    await redis.aclose()


@pytest_asyncio.fixture
async def redis_service(fake_redis):
    from app.core.redis_service import RedisService

    return RedisService(fake_redis)


@pytest.fixture(scope="session")
def app():
    with patch("app.core.config.settings", mock_settings):
        from app.main import app as fastapi_app

        return fastapi_app


@pytest_asyncio.fixture
async def async_client(app, db_session, redis_service):
    from app.api.v1.dependencies.database import get_async_db, get_redis_service

    app.dependency_overrides[get_async_db] = lambda: db_session
    app.dependency_overrides[get_redis_service] = lambda: redis_service

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client
    app.dependency_overrides.clear()


# 4. User Factories (Hardcoded data is now safe because of rollback)
@pytest_asyncio.fixture
async def active_verified_user(db_session) -> User:
    user = User(
        id=uuid4(),
        email="verified@example.com",
        first_name="Test",
        last_name="User",
        username="testuser",
        phone="+8801711111111",
        hashed_password=hash_password("Password123!"),
        is_active=True,
        is_email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()  # Use flush instead of commit inside tests to keep trans alive
    return user


@pytest_asyncio.fixture
async def admin_user(db_session) -> User:
    user = User(
        id=uuid4(),
        email="admin@example.com",
        phone="+8801744444444",
        hashed_password=hash_password("AdminPass123!"),
        is_active=True,
        is_email_verified=True,
        is_admin=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


# Add these back to your conftest.py
@pytest_asyncio.fixture
async def inactive_user(db_session) -> User:
    user = User(
        id=uuid4(),
        email="inactive@example.com",
        phone="+8801722222222",
        hashed_password=hash_password("Password123!"),
        is_active=False,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def unverified_user(db_session) -> User:
    user = User(
        id=uuid4(),
        email="unverified@example.com",
        phone="+8801733333333",
        hashed_password=hash_password("Password123!"),
        is_active=True,
        is_email_verified=False,
    )
    db_session.add(user)
    await db_session.flush()
    return user


# 5. Token Helpers
@pytest.fixture
def access_token_for(active_verified_user):
    return create_access_token(active_verified_user.id)


@pytest.fixture
def auth_headers(access_token_for):
    return {"Authorization": f"Bearer {access_token_for}"}
