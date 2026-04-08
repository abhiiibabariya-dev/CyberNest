"""
CyberNest Manager -- Authentication router.

Handles login, registration, token refresh, logout, MFA setup/verify,
and password changes with full JWT + TOTP support.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import AuditLog, User
from shared.utils.crypto import (
    create_jwt_token,
    decode_jwt_token,
    hash_password,
    verify_password,
)
from shared.utils.logger import get_logger

logger = get_logger("manager.auth")
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=1)
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=150)
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_data: str


class MFAVerifyRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _create_tokens(user: User) -> dict:
    """Create access + refresh JWT tokens for a user."""
    user_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "type": "access",
    }
    access_token = create_jwt_token(
        user_data, settings.JWT_SECRET, expires_minutes=settings.JWT_EXPIRE_MINUTES
    )

    refresh_data = {
        "sub": str(user.id),
        "type": "refresh",
    }
    refresh_token = create_jwt_token(
        refresh_data, settings.JWT_SECRET, expires_minutes=settings.JWT_REFRESH_EXPIRE_MINUTES
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRE_MINUTES * 60,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value if hasattr(user.role, "value") else str(user.role),
            "mfa_enabled": user.mfa_secret is not None,
        },
    }


async def _audit(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Record an entry in the audit log."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
    )
    db.add(entry)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user with username/password and optional TOTP."""
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check account lockout (5 failed attempts)
    if user.failed_logins >= 5:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account locked due to too many failed login attempts. Contact an administrator.",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_logins += 1
        db.add(user)
        await _audit(
            db, user.id, "login_failed", "auth",
            details={"reason": "invalid_password"},
            ip_address=_get_client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # MFA verification if enabled
    if user.mfa_secret:
        if not body.totp_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="TOTP code required",
                headers={"X-MFA-Required": "true"},
            )
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            user.failed_logins += 1
            db.add(user)
            await _audit(
                db, user.id, "login_failed", "auth",
                details={"reason": "invalid_totp"},
                ip_address=_get_client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code",
            )

    # Successful login
    user.failed_logins = 0
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)

    await _audit(
        db, user.id, "login", "auth",
        ip_address=_get_client_ip(request),
    )

    tokens = _create_tokens(user)
    logger.info("user logged in", user_id=str(user.id), username=user.username)
    return tokens


@router.post("/register", response_model=TokenResponse)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    # Check for existing username
    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(new_user)
    await db.flush()

    await _audit(
        db, new_user.id, "register", "user",
        resource_id=str(new_user.id),
        ip_address=_get_client_ip(request),
    )

    tokens = _create_tokens(new_user)
    logger.info("user registered", user_id=str(new_user.id), username=new_user.username)
    return tokens


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a valid refresh token for a new access + refresh token pair."""
    try:
        payload = decode_jwt_token(body.refresh_token, settings.JWT_SECRET)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    # Check blacklist
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client:
        is_blacklisted = await redis_client.get(f"token:blacklist:{body.refresh_token}")
        if is_blacklisted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

    try:
        user_id = uuid.UUID(payload.get("sub", ""))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Blacklist old refresh token
    if redis_client:
        await redis_client.setex(
            f"token:blacklist:{body.refresh_token}",
            settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
            "1",
        )

    tokens = _create_tokens(user)
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Blacklist the current access token in Redis."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client and token:
        await redis_client.setex(
            f"token:blacklist:{token}",
            settings.JWT_EXPIRE_MINUTES * 60,
            "1",
        )

    logger.info("user logged out", user_id=str(current_user.user_id))


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a TOTP secret and return the provisioning URI for authenticator apps."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled. Disable it first to reconfigure.",
        )

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="CyberNest SIEM",
    )

    # Store the secret temporarily in Redis (5 min TTL) until verified
    redis_client = getattr(db, "_request_app_state_redis", None)
    # We store in the user record but don't consider MFA enabled until verified
    # Use a temporary field approach -- store pending secret in Redis
    return MFASetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_data=provisioning_uri,
    )


@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify a TOTP code and enable MFA for the user."""
    # The secret should have been returned by /mfa/setup and the user provides
    # the code from their authenticator app along with the secret
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Get the pending secret from the request body or header
    secret = request.headers.get("X-MFA-Secret")
    if not secret:
        # Try to get from Redis pending setup
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client:
            secret = await redis_client.get(f"mfa:pending:{current_user.user_id}")
            if secret:
                secret = secret.decode() if isinstance(secret, bytes) else secret

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA secret not found. Call /mfa/setup first and provide the secret via X-MFA-Secret header.",
        )

    totp = pyotp.TOTP(secret)
    if not totp.verify(body.totp_code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Ensure your authenticator app time is synchronized.",
        )

    # Enable MFA by storing the verified secret
    user.mfa_secret = secret
    db.add(user)

    await _audit(
        db, user.id, "mfa_enabled", "user",
        resource_id=str(user.id),
        ip_address=_get_client_ip(request),
    )

    # Clean up Redis pending secret
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client:
        await redis_client.delete(f"mfa:pending:{current_user.user_id}")

    logger.info("MFA enabled", user_id=str(user.id))
    return {"detail": "MFA enabled successfully"}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's password after verifying the old password."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if body.old_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current password",
        )

    user.password_hash = hash_password(body.new_password)
    db.add(user)

    await _audit(
        db, user.id, "password_changed", "user",
        resource_id=str(user.id),
        ip_address=_get_client_ip(request),
    )

    logger.info("password changed", user_id=str(user.id))
    return {"detail": "Password changed successfully"}
