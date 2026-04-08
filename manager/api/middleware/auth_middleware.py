"""
CyberNest Manager -- JWT verification middleware.

Verifies Bearer token on every request, extracts user id + role, and attaches
them to request.state.user. Allows unauthenticated access to public paths.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from manager.config import get_settings
from manager.db.database import AsyncSessionLocal
from shared.utils.crypto import decode_jwt_token
from shared.utils.logger import get_logger

logger = get_logger("manager.auth")
settings = get_settings()

# Paths that do not require authentication
PUBLIC_PATHS: set[str] = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/health",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
}

# Prefixes that are public
PUBLIC_PREFIXES: tuple[str, ...] = (
    "/docs",
    "/redoc",
    "/openapi.json",
)


@dataclass
class AuthenticatedUser:
    """Attached to request.state.user after successful JWT verification."""
    user_id: uuid.UUID
    username: str
    role: str
    email: str


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that verifies JWT Bearer tokens."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Allow public endpoints through without auth
        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        # WebSocket connections handled separately
        if request.scope.get("type") == "websocket":
            return await call_next(request)

        auth_header: Optional[str] = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing or invalid Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Strip "Bearer "

        # Check if token is blacklisted in Redis
        try:
            redis_client = request.app.state.redis
            if redis_client:
                is_blacklisted = await redis_client.get(f"token:blacklist:{token}")
                if is_blacklisted:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Token has been revoked"},
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        except Exception:
            pass  # Redis unavailable -- proceed with JWT verification

        try:
            payload = decode_jwt_token(token, settings.JWT_SECRET)
        except ExpiredSignatureError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Token has expired"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWTError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token_type = payload.get("type", "access")
        if token_type != "access":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid token type"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            user_id = uuid.UUID(payload.get("sub", ""))
        except (ValueError, TypeError):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid token subject"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        request.state.user = AuthenticatedUser(
            user_id=user_id,
            username=payload.get("username", ""),
            role=payload.get("role", "readonly"),
            email=payload.get("email", ""),
        )

        return await call_next(request)


# ---------------------------------------------------------------------------
# FastAPI dependency-based auth (for use in route handlers)
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(request: Request) -> AuthenticatedUser:
    """FastAPI dependency to get the authenticated user from request state."""
    user: Optional[AuthenticatedUser] = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(*allowed_roles: str):
    """Return a FastAPI dependency that enforces role-based access control."""

    async def _check_role(
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return _check_role
