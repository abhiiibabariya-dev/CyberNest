"""CyberNest — Authentication API routes."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import (
    hash_password, verify_password, create_access_token, get_current_user, require_admin,
)
from app.core.config import get_settings
from app.models.auth import User
from app.models.enums import UserRole
from app.schemas.auth import (
    UserCreate, UserResponse, UserUpdate, LoginRequest, TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(data: UserCreate, db: Annotated[AsyncSession, Depends(get_db)]):
    # Check uniqueness
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        hashed_password=hash_password(data.password),
        role=data.role,
        department=data.department,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    token = create_access_token(user.id, user.role.value)
    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@router.post("/logout")
async def logout(current_user: Annotated[User, Depends(get_current_user)]):
    # In a production system, blacklist the token in Redis
    return {"detail": "Logged out successfully"}
