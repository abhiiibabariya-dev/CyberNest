"""CyberNest — Audit logging middleware for compliance tracking."""

import uuid
from datetime import datetime

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import insert
import structlog

from app.core.database import AsyncSessionLocal
from app.models.auth import AuditLog

logger = structlog.get_logger()

# Methods and paths to audit
AUDITABLE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SKIP_PATHS = {"/health", "/api/v1/logs/ingest", "/api/v1/search", "/ws/"}


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.method in AUDITABLE_METHODS and not any(request.url.path.startswith(p) for p in SKIP_PATHS):
            try:
                user_id = getattr(request.state, "user_id", None) if hasattr(request, "state") else None
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        insert(AuditLog).values(
                            id=uuid.uuid4(),
                            user_id=user_id,
                            action=request.method,
                            resource_type=self._extract_resource(request.url.path),
                            resource_id=self._extract_id(request.url.path),
                            ip_address=request.client.host if request.client else None,
                            user_agent=request.headers.get("user-agent", "")[:512],
                            timestamp=datetime.utcnow(),
                        )
                    )
                    await session.commit()
            except Exception as e:
                logger.error("Audit log failed", error=str(e))

        return response

    def _extract_resource(self, path: str) -> str:
        parts = path.strip("/").split("/")
        # /api/v1/alerts/xxx -> alerts
        if len(parts) >= 3:
            return parts[2]
        return path

    def _extract_id(self, path: str) -> str | None:
        parts = path.strip("/").split("/")
        if len(parts) >= 4:
            return parts[3]
        return None
