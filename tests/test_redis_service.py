import pytest_asyncio
import asyncio
import fakeredis.aioredis as fakeredis_async

from app.core.redis_service import RedisService


@pytest_asyncio.fixture
async def redis():
    client = fakeredis_async.FakeRedis(decode_responses=True)
    service = RedisService(client)
    yield service
    await client.flushall()
    await client.aclose()


# ── set_value / get_value / delete_value ──────────────────────────────────────


class TestBasicKeyValue:
    async def test_set_and_get(self, redis):
        await redis.set_value("key1", "hello", expire=60)
        result = await redis.get_value("key1")
        assert result == "hello"

    async def test_missing_key_returns_none(self, redis):
        result = await redis.get_value("nonexistent_key")
        assert result is None

    async def test_delete_removes_key(self, redis):
        await redis.set_value("del_key", "value", expire=60)
        await redis.delete_value("del_key")
        result = await redis.get_value("del_key")
        assert result is None

    async def test_delete_nonexistent_does_not_raise(self, redis):
        # Should be idempotent
        await redis.delete_value("does_not_exist")

    async def test_value_expires(self, redis):
        """Key with 1 second expiry should be gone after expiry."""
        await redis.set_value("expiring", "val", expire=1)
        await asyncio.sleep(1.1)
        result = await redis.get_value("expiring")
        assert result is None


# ── Token Blacklisting ─────────────────────────────────────────────────────────


class TestTokenBlacklist:
    async def test_blacklist_and_check(self, redis):
        jti = "test-jti-123"
        await redis.blacklist_token(jti, expiry_seconds=300)
        assert await redis.is_token_blacklisted(jti) is True

    async def test_non_blacklisted_token_returns_false(self, redis):
        assert await redis.is_token_blacklisted("clean-jti") is False

    async def test_zero_expiry_does_not_blacklist(self, redis):
        """Edge case: zero or negative expiry should skip blacklisting."""
        jti = "zero-expiry-jti"
        await redis.blacklist_token(jti, expiry_seconds=0)
        assert await redis.is_token_blacklisted(jti) is False

    async def test_blacklist_uses_prefixed_key(self, redis):
        """Key must be namespaced as 'blacklist:<jti>'."""
        jti = "my-unique-jti"
        await redis.blacklist_token(jti, expiry_seconds=60)
        # Verify raw key exists in underlying client
        raw = await redis.client.exists(f"blacklist:{jti}")
        assert raw == 1

    async def test_blacklisted_token_expires(self, redis):
        jti = "expiring-jti"
        await redis.blacklist_token(jti, expiry_seconds=1)
        await asyncio.sleep(1.1)
        assert await redis.is_token_blacklisted(jti) is False


# ── OTP ────────────────────────────────────────────────────────────────────────


class TestOTP:
    async def test_save_and_get_otp(self, redis):
        await redis.save_otp(phone="+8801711111111", code="123456", expire=300)
        result = await redis.get_otp(phone="+8801711111111")
        assert result == "123456"

    async def test_get_otp_missing_returns_none(self, redis):
        result = await redis.get_otp(phone="+8801799999999")
        assert result is None

    async def test_otp_uses_prefixed_key(self, redis):
        phone = "+8801711111111"
        await redis.save_otp(phone=phone, code="654321", expire=60)
        raw = await redis.client.exists(f"otp:{phone}")
        assert raw == 1

    async def test_otp_expires(self, redis):
        await redis.save_otp(phone="+8801700000001", code="000000", expire=1)
        await asyncio.sleep(1.1)
        result = await redis.get_otp(phone="+8801700000001")
        assert result is None

    async def test_overwrite_otp(self, redis):
        phone = "+8801711111112"
        await redis.save_otp(phone=phone, code="111111", expire=60)
        await redis.save_otp(phone=phone, code="999999", expire=60)
        result = await redis.get_otp(phone=phone)
        assert result == "999999"


# ── Rate Limiting ──────────────────────────────────────────────────────────────


class TestRateLimit:
    async def test_first_request_is_allowed(self, redis):
        allowed, retry_after = await redis.check_rate_limit(
            "ip:/test", limit=5, window=60
        )
        assert allowed is True
        assert retry_after == 0

    async def test_within_limit_is_allowed(self, redis):
        for _ in range(5):
            allowed, _ = await redis.check_rate_limit("ip:/test2", limit=5, window=60)
        assert allowed is True  # type: ignore

    async def test_exceeding_limit_is_denied(self, redis):
        for _ in range(5):
            await redis.check_rate_limit("ip:/test3", limit=5, window=60)
        allowed, retry_after = await redis.check_rate_limit(
            "ip:/test3", limit=5, window=60
        )
        assert allowed is False
        assert retry_after > 0

    async def test_rate_limit_uses_prefixed_key(self, redis):
        key = "ip:/test4"
        await redis.check_rate_limit(key, limit=5, window=60)
        raw = await redis.client.exists(f"rate_limit:{key}")
        assert raw == 1

    async def test_different_keys_are_independent(self, redis):
        for _ in range(5):
            await redis.check_rate_limit("key-a", limit=5, window=60)
        # key-a is at limit, key-b should still be fine
        allowed, _ = await redis.check_rate_limit("key-b", limit=5, window=60)
        assert allowed is True
