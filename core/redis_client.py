import logging
import redis.asyncio as redis
from typing import Optional

from core.config import settings

logger = logging.getLogger(__name__)

redis_client: Optional[redis.Redis] = None

async def init_redis():
    """Initialize Redis connection"""
    global redis_client
    try:
        redis_client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Continuing without cache.")
        redis_client = None

async def close_redis():
    """Close Redis connection"""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")

async def get_redis() -> Optional[redis.Redis]:
    """Get Redis client"""
    return redis_client

async def cache_get(key: str) -> Optional[str]:
    """Get value from cache"""
    if not redis_client:
        return None
    try:
        return await redis_client.get(key)
    except Exception as e:
        logger.error(f"Redis get error: {e}")
        return None

async def cache_set(key: str, value: str, ttl: int = 3600):
    """Set value in cache with TTL"""
    if not redis_client:
        return
    try:
        await redis_client.setex(key, ttl, value)
    except Exception as e:
        logger.error(f"Redis set error: {e}")