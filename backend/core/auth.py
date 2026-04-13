"""Authentication + tenant-scoped session."""
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from loguru import logger
from core.config import settings
from core.database import get_db
from core.models import User, Tenant, UserRole, AuditLog

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def get_tenant_by_ingest_token(token: str, db: Session) -> Optional[Tenant]:
    return db.execute(
        select(Tenant).where(Tenant.ingest_token == token, Tenant.is_active == True)
    ).scalar_one_or_none()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    username = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    q = select(User).where(User.username == username)
    if tenant_id:
        q = q.where(User.tenant_id == tenant_id)
    user = db.execute(q).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def get_current_tenant(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Tenant:
    if current_user.role == UserRole.SUPER_ADMIN:
        return None
    if not current_user.tenant_id:
        raise HTTPException(status_code=403, detail="User has no tenant assigned")
    tenant = db.execute(
        select(Tenant).where(Tenant.id == current_user.tenant_id, Tenant.is_active == True)
    ).scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found or suspended")
    return tenant

def require_role(*roles: UserRole):
    def checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {[r.value for r in roles]}")
        return current_user
    return checker

def audit(db, action, user, resource=None, resource_id=None, details=None, request=None):
    db.add(AuditLog(
        tenant_id=user.tenant_id, user_id=user.id, username=user.username,
        action=action, resource=resource, resource_id=resource_id,
        details=details or {},
        ip_address=request.client.host if request else None,
    ))
