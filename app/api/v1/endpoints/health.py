from fastapi import APIRouter, status, HTTPException
from typing import Dict
from app.api.v1.dependencies import AsyncDB, RedisConn
from sqlalchemy import text

router = APIRouter()


@router.get("/ping", status_code=status.HTTP_200_OK)
async def simple_ping():
    return {"status": "ok", "message": "pong"}


@router.get("/status", status_code=status.HTTP_200_OK)
async def full_status(db: AsyncDB, redis: RedisConn) -> Dict:
    health_status = {"database": "down", "redis": "down", "overall": "unhealthy"}

    # 1. Check Database
    try:
        # Simple query to see if DB responds
        await db.execute(text("SELECT 1"))
        health_status["database"] = "up"
    except Exception as e:
        health_status["database"] = f"error: {str(e)}"

    # 2. Check Redis
    try:
        # Ping the redis server through your service
        await redis.client.ping()
        health_status["redis"] = "up"
    except Exception as e:
        health_status["redis"] = f"error: {str(e)}"

    # 3. Final Verdict
    if health_status["database"] == "up" and health_status["redis"] == "up":
        health_status["overall"] = "healthy"
        return health_status

    # If anything is down, return a 503 Service Unavailable
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=health_status
    )
