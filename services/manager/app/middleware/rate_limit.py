"""CyberNest — Rate limiting middleware using Redis sliding window."""

import time
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.core.redis import redis_client

logger = structlog.get_logger()

# Rate limit configs: path_prefix -> (max_requests, window_seconds)
RATE_LIMITS = {
    "/api/v1/auth/": (10, 60),       # 10 requests per minute for auth
    "/api/v1/logs/ingest": (1000, 1),  # 1000 EPS for log ingestion
    "/api/v1/search": (30, 60),       # 30 searches per minute
    "/api/v1/": (200, 60),            # 200 requests per minute default
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        max_requests, window = self._get_limit(path)
        key = f"ratelimit:{client_ip}:{path.split('/')[3] if len(path.split('/')) > 3 else 'default'}"

        try:
            current = await redis_client.incr(key)
            if current == 1:
                await redis_client.expire(key, window)

            if current > max_requests:
                ttl = await redis_client.ttl(key)
                logger.warning("Rate limit exceeded", ip=client_ip, path=path, limit=max_requests)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Retry after {ttl}s.",
                    headers={"Retry-After": str(ttl)},
                )
        except HTTPException:
            raise
        except Exception:
            # If Redis is down, allow the request
            pass

        response = await call_next(request)
        return response

    def _get_limit(self, path: str) -> tuple[int, int]:
        for prefix, limit in RATE_LIMITS.items():
            if path.startswith(prefix):
                return limit
        return (200, 60)
