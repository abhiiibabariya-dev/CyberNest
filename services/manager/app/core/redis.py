"""CyberNest Manager — Redis connection for caching, pub/sub, and session state."""

import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()

redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=50,
    decode_responses=True,
)

redis_client = redis.Redis(connection_pool=redis_pool)


async def get_redis() -> redis.Redis:
    return redis_client


async def close_redis():
    await redis_client.aclose()
