from fastapi import Depends, HTTPException, Request, status
from typing_extensions import Annotated

from .database import RedisConn


class RateLimiter:
    def __init__(self, requests: int, window: int) -> None:
        self.requests = requests
        self.window = window

    async def __call__(self, request: Request, redis: RedisConn) -> None:
        key = f"{request.client.host}:{request.url.path}"

        allowed, retry_after = await redis.check_rate_limit(
            key=key, limit=self.requests, window=self.window
        )

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. retry after {retry_after} seconds",
            )


StrictRateLimit = Annotated[None, Depends(RateLimiter(requests=3, window=60))]
DefaultRateLimit = Annotated[None, Depends(RateLimiter(requests=20, window=60))]
OTPRateLimit = Annotated[None, Depends(RateLimiter(requests=1, window=60))]
EmailRateLimit = Annotated[None, Depends(RateLimiter(requests=1, window=60))]
