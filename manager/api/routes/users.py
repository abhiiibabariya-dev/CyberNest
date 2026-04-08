"""
CyberNest Manager -- Users router.

Full user management with RBAC: list, create, get, update, delete, /me endpoint.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import AuditLog, User, UserRole
from shared.utils.crypto import hash_password
from shared.utils.logger import get_logger

logger = get_logger("manager.users")
settings = get_settings()

router = APIRouter(prefix="/users", tags=["Users"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=150)
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst")


class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=150)
    email: Optional[str] = Field(None, max_length=254)
    role: Optional[str] = None
    is_active: Optional[bool] = None


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------

@router.get("/me")
async def get_me(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the currently authenticated user's profile."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_dict(user)


@router.put("/me")
async def update_me(
    body: UserUpdateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the currently authenticated user's profile (cannot change own role)."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if body.username is not None:
        # Check uniqueness
        existing = await db.execute(
            select(User).where(and_(User.username == body.username, User.id != user.id))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already taken")
        user.username = body.username

    if body.email is not None:
        existing = await db.execute(
            select(User).where(and_(User.email == body.email, User.id != user.id))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already taken")
        user.email = body.email

    # Users cannot change their own role
    if body.role is not None:
        raise HTTPException(status_code=403, detail="Cannot change your own role")

    user.updated_at = datetime.now(timezone.utc)
    db.add(user)
    return _user_to_dict(user)


# ---------------------------------------------------------------------------
# Admin user management
# ---------------------------------------------------------------------------

@router.get("/")
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """List users (admin only)."""
    query = select(User)
    count_query = select(func.count(User.id))
    conditions = []

    if role:
        try:
            conditions.append(User.role == UserRole(role))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {role}")
    if is_active is not None:
        conditions.append(User.is_active == is_active)
    if search:
        conditions.append(
            User.username.ilike(f"%{search}%") | User.email.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(User.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    users = result.scalars().all()

    return {
        "items": [_user_to_dict(u) for u in users],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user (admin only)."""
    try:
        role = UserRole(body.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")

    # Prevent non-super_admins from creating super_admins
    if role == UserRole.super_admin and current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admins can create super admin accounts")

    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=role,
    )
    db.add(new_user)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="user",
        resource_id=str(new_user.id),
        details={"username": body.username, "role": body.role},
    )
    db.add(audit)

    return _user_to_dict(new_user)


@router.get("/{user_uuid}")
async def get_user(
    user_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Get user detail (admin only)."""
    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_dict(user)


@router.put("/{user_uuid}")
async def update_user(
    user_uuid: uuid.UUID,
    body: UserUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update a user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if body.username is not None:
        existing = await db.execute(
            select(User).where(and_(User.username == body.username, User.id != user_uuid))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already taken")
        user.username = body.username
        changes["username"] = body.username

    if body.email is not None:
        existing = await db.execute(
            select(User).where(and_(User.email == body.email, User.id != user_uuid))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already taken")
        user.email = body.email
        changes["email"] = body.email

    if body.role is not None:
        try:
            new_role = UserRole(body.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")

        if new_role == UserRole.super_admin and current_user.role != "super_admin":
            raise HTTPException(status_code=403, detail="Only super admins can assign super admin role")

        user.role = new_role
        changes["role"] = body.role

    if body.is_active is not None:
        # Prevent deactivating yourself
        if user_uuid == current_user.user_id and not body.is_active:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        user.is_active = body.is_active
        changes["is_active"] = body.is_active

    user.updated_at = datetime.now(timezone.utc)
    db.add(user)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="user",
        resource_id=str(user_uuid),
        details=changes,
    )
    db.add(audit)

    return _user_to_dict(user)


@router.delete("/{user_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (super admin only). Does not hard-delete."""
    if user_uuid == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)
    db.add(user)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="deactivate",
        resource_type="user",
        resource_id=str(user_uuid),
        details={"username": user.username},
    )
    db.add(audit)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_to_dict(u: User) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "email": u.email,
        "role": u.role.value if hasattr(u.role, "value") else str(u.role),
        "is_active": u.is_active,
        "mfa_enabled": u.mfa_secret is not None,
        "failed_logins": u.failed_logins,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "updated_at": u.updated_at.isoformat() if u.updated_at else None,
    }
