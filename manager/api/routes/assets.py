"""
CyberNest Manager -- Assets router.

Full asset inventory management with CRUD and enrichment from ES
(events/alerts associated with asset).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, cast, func, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import Alert, Asset, AssetCriticality, AuditLog
from shared.utils.logger import get_logger

logger = get_logger("manager.assets")
settings = get_settings()

router = APIRouter(prefix="/assets", tags=["Assets"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AssetCreateRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    ip: Optional[str] = None
    mac: Optional[str] = None
    os: Optional[str] = Field(None, max_length=100)
    os_version: Optional[str] = Field(None, max_length=100)
    owner: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=255)
    criticality: str = Field(default="medium")
    role: Optional[str] = Field(None, max_length=100)
    tags: list[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)


class AssetUpdateRequest(BaseModel):
    hostname: Optional[str] = Field(None, max_length=255)
    ip: Optional[str] = None
    mac: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: Optional[str] = None
    role: Optional[str] = None
    tags: Optional[list[str]] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    vulnerability_count: Optional[int] = Field(None, ge=0)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.get("/")
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    criticality: Optional[str] = None,
    department: Optional[str] = None,
    search: Optional[str] = None,
    tag: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List assets with filters and pagination."""
    query = select(Asset)
    count_query = select(func.count(Asset.id))
    conditions = []

    if criticality:
        try:
            conditions.append(Asset.criticality == AssetCriticality(criticality))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid criticality: {criticality}")
    if department:
        conditions.append(Asset.department.ilike(f"%{department}%"))
    if search:
        conditions.append(
            Asset.hostname.ilike(f"%{search}%")
            | Asset.owner.ilike(f"%{search}%")
            | cast(Asset.ip, String).ilike(f"%{search}%")
        )
    if tag:
        conditions.append(Asset.tags.any(tag))

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(Asset.risk_score.desc(), Asset.hostname.asc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    assets = result.scalars().all()

    return {
        "items": [_asset_to_dict(a) for a in assets],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Create a new asset."""
    try:
        crit = AssetCriticality(body.criticality)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid criticality: {body.criticality}")

    asset = Asset(
        hostname=body.hostname,
        ip=body.ip,
        mac=body.mac,
        os=body.os,
        os_version=body.os_version,
        owner=body.owner,
        department=body.department,
        criticality=crit,
        role=body.role,
        tags=body.tags,
        risk_score=body.risk_score,
    )
    db.add(asset)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"hostname": body.hostname},
    )
    db.add(audit)

    return _asset_to_dict(asset)


@router.get("/{asset_uuid}")
async def get_asset(
    asset_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get asset detail."""
    result = await db.execute(select(Asset).where(Asset.id == asset_uuid))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.put("/{asset_uuid}")
async def update_asset(
    asset_uuid: uuid.UUID,
    body: AssetUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update an asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_uuid))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    if body.hostname is not None:
        asset.hostname = body.hostname
    if body.ip is not None:
        asset.ip = body.ip
    if body.mac is not None:
        asset.mac = body.mac
    if body.os is not None:
        asset.os = body.os
    if body.os_version is not None:
        asset.os_version = body.os_version
    if body.owner is not None:
        asset.owner = body.owner
    if body.department is not None:
        asset.department = body.department
    if body.criticality is not None:
        try:
            asset.criticality = AssetCriticality(body.criticality)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid criticality: {body.criticality}")
    if body.role is not None:
        asset.role = body.role
    if body.tags is not None:
        asset.tags = body.tags
    if body.risk_score is not None:
        asset.risk_score = body.risk_score
    if body.vulnerability_count is not None:
        asset.vulnerability_count = body.vulnerability_count

    asset.updated_at = datetime.now(timezone.utc)
    db.add(asset)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="asset",
        resource_id=str(asset_uuid),
    )
    db.add(audit)

    return _asset_to_dict(asset)


@router.delete("/{asset_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Delete an asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_uuid))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)


# ---------------------------------------------------------------------------
# Events and alerts for an asset
# ---------------------------------------------------------------------------

@router.get("/{asset_uuid}/events")
async def get_asset_events(
    asset_uuid: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get recent events for an asset from ES (matched by IP or hostname)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_uuid))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    events = []
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
        if es:
            should_clauses = []
            if asset.ip:
                should_clauses.append({"term": {"source.ip": str(asset.ip)}})
                should_clauses.append({"term": {"destination.ip": str(asset.ip)}})
            if asset.hostname:
                should_clauses.append({"term": {"host.hostname": asset.hostname}})

            if should_clauses:
                es_result = await es.search(
                    index=settings.ES_INDEX_EVENTS,
                    body={
                        "query": {
                            "bool": {"should": should_clauses, "minimum_should_match": 1}
                        },
                        "size": limit,
                        "sort": [{"@timestamp": {"order": "desc"}}],
                    },
                )
                events = [
                    hit["_source"] for hit in es_result.get("hits", {}).get("hits", [])
                ]
    except Exception as exc:
        logger.warning("failed to fetch asset events", error=str(exc))

    return {"asset_id": str(asset_uuid), "events": events, "count": len(events)}


@router.get("/{asset_uuid}/alerts")
async def get_asset_alerts(
    asset_uuid: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alerts associated with an asset (matched by IP)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_uuid))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not asset.ip:
        return {"asset_id": str(asset_uuid), "alerts": [], "count": 0}

    alerts_result = await db.execute(
        select(Alert)
        .where(
            (cast(Alert.source_ip, String) == str(asset.ip))
            | (cast(Alert.destination_ip, String) == str(asset.ip))
        )
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    alerts = alerts_result.scalars().all()

    return {
        "asset_id": str(asset_uuid),
        "alerts": [
            {
                "id": str(a.id),
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
        "count": len(alerts),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _asset_to_dict(a: Asset) -> dict:
    return {
        "id": str(a.id),
        "hostname": a.hostname,
        "ip": str(a.ip) if a.ip else None,
        "mac": str(a.mac) if a.mac else None,
        "os": a.os,
        "os_version": a.os_version,
        "owner": a.owner,
        "department": a.department,
        "criticality": a.criticality.value,
        "role": a.role,
        "tags": a.tags or [],
        "risk_score": a.risk_score,
        "vulnerability_count": a.vulnerability_count,
        "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }
