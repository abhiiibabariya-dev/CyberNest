"""
CyberNest Manager -- Redis sliding window rate limiter middleware.

Applies per-user (1000 req/min) and per-IP on auth routes (10 req/min).
Returns HTTP 429 with Retry-After header when limits are exceeded.
"""

from __future__ import annotations

import time
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from manager.config import get_settings
from shared.utils.logger import get_logger

logger = get_logger("manager.rate_limiter")
settings = get_settings()

# Sliding window parameters
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_LIMIT = settings.RATE_LIMIT_DEFAULT  # 1000 req/min per user
AUTH_LIMIT = settings.RATE_LIMIT_AUTH  # 10 req/min on /auth/login by IP


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """Redis-backed sliding window rate limiter."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client is None:
            # If Redis is unavailable, allow the request through
            return await call_next(request)

        path = request.url.path
        now = time.time()
        window = DEFAULT_WINDOW_SECONDS

        # Determine the rate limit key and limit
        if "/auth/login" in path:
            # Rate limit by IP on login endpoints
            client_ip = _get_client_ip(request)
            key = f"ratelimit:auth:{client_ip}"
            limit = AUTH_LIMIT
        else:
            # Rate limit by user ID if authenticated, otherwise by IP
            user = getattr(request.state, "user", None)
            if user is not None:
                key = f"ratelimit:user:{user.user_id}"
            else:
                client_ip = _get_client_ip(request)
                key = f"ratelimit:ip:{client_ip}"
            limit = DEFAULT_LIMIT

        try:
            pipe = redis_client.pipeline()
            window_start = now - window

            # Remove expired entries from the sorted set
            pipe.zremrangebyscore(key, 0, window_start)
            # Add current request timestamp
            pipe.zadd(key, {str(now): now})
            # Count requests in the window
            pipe.zcard(key)
            # Set TTL on the key
            pipe.expire(key, window + 1)

            results = await pipe.execute()
            request_count = results[2]

            if request_count > limit:
                # Calculate when the oldest request in the window will expire
                oldest = await redis_client.zrange(key, 0, 0, withscores=True)
                if oldest:
                    retry_after = int(oldest[0][1] + window - now) + 1
                else:
                    retry_after = window

                retry_after = max(1, retry_after)

                logger.warning(
                    "rate limit exceeded",
                    key=key,
                    count=request_count,
                    limit=limit,
                    retry_after=retry_after,
                )

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after": retry_after,
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(now + retry_after)),
                    },
                )

            # Add rate limit headers to the response
            response = await call_next(request)
            remaining = max(0, limit - request_count)
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(int(now + window))
            return response

        except Exception as exc:
            # If Redis fails, allow the request through rather than blocking
            logger.error("rate limiter error, allowing request", error=str(exc))
            return await call_next(request)


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    if client:
        return client.host
    return "unknown"
