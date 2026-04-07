"""CyberNest — Auth request/response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field
from app.models.enums import UserRole


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.ANALYST
    department: str | None = None


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_mfa_enabled: bool
    department: str | None
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    department: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
