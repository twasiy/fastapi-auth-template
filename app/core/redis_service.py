from redis.asyncio import Redis


class RedisService:
    def __init__(self, redis_client: Redis) -> None:
        self.client = redis_client

    async def set_value(self, key: str, value: str, expire: int) -> None:
        await self.client.setex(key, expire, value)

    async def get_value(self, key: str) -> str | None:
        return await self.client.get(key)

    async def delete_value(self, key: str) -> None:
        await self.client.delete(key)

    async def blacklist_token(self, jti: str, expiry_seconds: int) -> None:
        if expiry_seconds > 0:
            await self.client.setex(f"blacklist:{jti}", expiry_seconds, "true")

    async def is_token_blacklisted(self, jti: str) -> bool:
        return await self.client.exists(f"blacklist:{jti}") > 0

    async def get_otp(self, phone: str) -> str:
        return await self.client.get(f"otp:{phone}")

    async def save_otp(self, phone: str, code: str, expire: int = 60) -> None:
        await self.client.setex(f"otp:{phone}", expire, code)

    async def check_rate_limit(
        self, key: str, limit: int, window: int
    ) -> tuple[bool, int]:
        full_key = f"rate_limit:{key}"

        current_count = await self.client.incr(full_key)

        if current_count == 1:
            await self.client.expire(full_key, window)

        if current_count > limit:
            ttl = await self.client.ttl(full_key)
            return False, ttl
        return True, 0
