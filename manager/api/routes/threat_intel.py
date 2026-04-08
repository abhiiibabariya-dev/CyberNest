"""
CyberNest Manager -- Threat Intelligence router.

IOC lookup (Redis cache -> DB -> live API), bulk import CSV/STIX,
and feed management CRUD.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import (
    AuditLog,
    FeedType,
    IOCType,
    ThreatIntelFeed,
    ThreatIntelIOC,
)
from shared.utils.logger import get_logger

logger = get_logger("manager.threat_intel")
settings = get_settings()

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IOCLookupRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    ioc_type: Optional[str] = None


class IOCCreateRequest(BaseModel):
    ioc_type: str
    value: str = Field(..., min_length=1)
    source: str = Field(default="manual", max_length=255)
    confidence: int = Field(default=50, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class FeedCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    feed_type: str
    url: str
    api_key: Optional[str] = None
    is_enabled: bool = True
    fetch_interval_hours: int = Field(default=6, ge=1, le=168)
    config_json: dict = Field(default_factory=dict)


class FeedUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    url: Optional[str] = None
    api_key: Optional[str] = None
    is_enabled: Optional[bool] = None
    fetch_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    config_json: Optional[dict] = None


# ---------------------------------------------------------------------------
# IOC Lookup
# ---------------------------------------------------------------------------

@router.post("/lookup")
async def lookup_ioc(
    body: IOCLookupRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lookup an IOC value. Checks Redis cache first, then DB, then returns."""
    value = body.value.strip()
    cache_key = f"ioc:lookup:{value}"

    # 1. Check Redis cache
    try:
        from manager.main import app
        redis = getattr(app.state, "redis", None)
        if redis:
            cached = await redis.get(cache_key)
            if cached:
                result = json.loads(cached)
                result["source"] = "cache"
                return result
    except Exception:
        pass

    # 2. Check database
    query = select(ThreatIntelIOC).where(
        and_(
            ThreatIntelIOC.value == value,
            ThreatIntelIOC.is_active == True,
        )
    )
    if body.ioc_type:
        try:
            ioc_t = IOCType(body.ioc_type)
            query = query.where(ThreatIntelIOC.ioc_type == ioc_t)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IOC type: {body.ioc_type}")

    result_db = await db.execute(query)
    iocs = result_db.scalars().all()

    if iocs:
        # Update hit count
        for ioc in iocs:
            ioc.hit_count += 1
            ioc.last_seen_at = datetime.now(timezone.utc)
            db.add(ioc)

        result_data = {
            "found": True,
            "value": value,
            "matches": [_ioc_to_dict(ioc) for ioc in iocs],
            "source": "database",
        }

        # Cache the result for 5 minutes
        try:
            if redis:
                await redis.setex(cache_key, 300, json.dumps(result_data, default=str))
        except Exception:
            pass

        return result_data

    # 3. Not found
    return {
        "found": False,
        "value": value,
        "matches": [],
        "source": "database",
    }


@router.get("/iocs")
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    min_confidence: Optional[int] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List IOCs with filters."""
    query = select(ThreatIntelIOC)
    count_query = select(func.count(ThreatIntelIOC.id))
    conditions = []

    if ioc_type:
        try:
            conditions.append(ThreatIntelIOC.ioc_type == IOCType(ioc_type))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IOC type: {ioc_type}")
    if source:
        conditions.append(ThreatIntelIOC.source.ilike(f"%{source}%"))
    if is_active is not None:
        conditions.append(ThreatIntelIOC.is_active == is_active)
    if search:
        conditions.append(ThreatIntelIOC.value.ilike(f"%{search}%"))
    if min_confidence is not None:
        conditions.append(ThreatIntelIOC.confidence >= min_confidence)

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(ThreatIntelIOC.hit_count.desc(), ThreatIntelIOC.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    iocs = result.scalars().all()

    return {
        "items": [_ioc_to_dict(i) for i in iocs],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/iocs", status_code=status.HTTP_201_CREATED)
async def create_ioc(
    body: IOCCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Manually add an IOC."""
    try:
        ioc_t = IOCType(body.ioc_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type: {body.ioc_type}")

    # Check for duplicate
    existing = await db.execute(
        select(ThreatIntelIOC).where(
            and_(
                ThreatIntelIOC.value == body.value,
                ThreatIntelIOC.ioc_type == ioc_t,
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="IOC already exists",
        )

    ioc = ThreatIntelIOC(
        ioc_type=ioc_t,
        value=body.value,
        source=body.source,
        confidence=body.confidence,
        tags=body.tags,
        expires_at=body.expires_at,
    )
    db.add(ioc)
    await db.flush()

    return _ioc_to_dict(ioc)


@router.delete("/iocs/{ioc_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate an IOC."""
    result = await db.execute(select(ThreatIntelIOC).where(ThreatIntelIOC.id == ioc_uuid))
    ioc = result.scalar_one_or_none()
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.is_active = False
    ioc.updated_at = datetime.now(timezone.utc)
    db.add(ioc)


# ---------------------------------------------------------------------------
# Bulk Import
# ---------------------------------------------------------------------------

@router.post("/import/csv")
async def import_iocs_csv(
    file: UploadFile = File(...),
    source: str = Query(default="csv_import"),
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Bulk import IOCs from a CSV file.

    Expected CSV columns: ioc_type, value, confidence (optional), tags (optional, comma-separated)
    """
    content = await file.read()
    text = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    skipped = 0
    errors = []

    for row_num, row in enumerate(reader, start=2):
        ioc_type_str = row.get("ioc_type", "").strip()
        value = row.get("value", "").strip()

        if not ioc_type_str or not value:
            errors.append(f"Row {row_num}: missing ioc_type or value")
            continue

        try:
            ioc_t = IOCType(ioc_type_str)
        except ValueError:
            errors.append(f"Row {row_num}: invalid ioc_type '{ioc_type_str}'")
            continue

        # Check for duplicate
        existing = await db.execute(
            select(ThreatIntelIOC.id).where(
                and_(
                    ThreatIntelIOC.value == value,
                    ThreatIntelIOC.ioc_type == ioc_t,
                )
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        confidence = 50
        try:
            conf_str = row.get("confidence", "50").strip()
            if conf_str:
                confidence = max(0, min(100, int(conf_str)))
        except (ValueError, TypeError):
            pass

        tags_str = row.get("tags", "").strip()
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

        ioc = ThreatIntelIOC(
            ioc_type=ioc_t,
            value=value,
            source=source,
            confidence=confidence,
            tags=tags,
        )
        db.add(ioc)
        imported += 1

    audit = AuditLog(
        user_id=current_user.user_id,
        action="import_csv",
        resource_type="threat_intel",
        details={"imported": imported, "skipped": skipped, "errors": len(errors)},
    )
    db.add(audit)

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors[:50],  # Limit error messages
    }


@router.post("/import/stix")
async def import_iocs_stix(
    file: UploadFile = File(...),
    source: str = Query(default="stix_import"),
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Bulk import IOCs from a STIX 2.x JSON bundle."""
    content = await file.read()
    try:
        stix_data = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}")

    objects = stix_data.get("objects", [])
    if not objects:
        raise HTTPException(status_code=400, detail="No objects found in STIX bundle")

    imported = 0
    skipped = 0

    # Map STIX indicator patterns to IOC types
    type_map = {
        "ipv4-addr": IOCType.ip,
        "ipv6-addr": IOCType.ip,
        "domain-name": IOCType.domain,
        "url": IOCType.url,
        "file:hashes.MD5": IOCType.hash_md5,
        "file:hashes.'SHA-1'": IOCType.hash_sha1,
        "file:hashes.'SHA-256'": IOCType.hash_sha256,
        "email-addr": IOCType.email,
    }

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        name = obj.get("name", "")
        confidence_val = obj.get("confidence", 50)

        # Simple STIX pattern parser: extract value from patterns like
        # [ipv4-addr:value = '1.2.3.4']
        ioc_type = None
        value = None

        for stix_type, our_type in type_map.items():
            if stix_type in pattern:
                ioc_type = our_type
                # Extract value between quotes
                parts = pattern.split("'")
                if len(parts) >= 2:
                    value = parts[1]
                break

        if not ioc_type or not value:
            skipped += 1
            continue

        # Check for duplicate
        existing = await db.execute(
            select(ThreatIntelIOC.id).where(
                and_(
                    ThreatIntelIOC.value == value,
                    ThreatIntelIOC.ioc_type == ioc_type,
                )
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        # Extract tags from STIX labels
        labels = obj.get("labels", [])

        ioc = ThreatIntelIOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=min(100, max(0, confidence_val)) if isinstance(confidence_val, int) else 50,
            tags=labels if isinstance(labels, list) else [],
        )
        db.add(ioc)
        imported += 1

    audit = AuditLog(
        user_id=current_user.user_id,
        action="import_stix",
        resource_type="threat_intel",
        details={"imported": imported, "skipped": skipped},
    )
    db.add(audit)

    return {"imported": imported, "skipped": skipped}


# ---------------------------------------------------------------------------
# Feed Management
# ---------------------------------------------------------------------------

@router.get("/feeds")
async def list_feeds(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    is_enabled: Optional[bool] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List threat intel feeds."""
    query = select(ThreatIntelFeed)
    count_query = select(func.count(ThreatIntelFeed.id))

    if is_enabled is not None:
        query = query.where(ThreatIntelFeed.is_enabled == is_enabled)
        count_query = count_query.where(ThreatIntelFeed.is_enabled == is_enabled)

    query = query.order_by(ThreatIntelFeed.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    feeds = result.scalars().all()

    return {
        "items": [_feed_to_dict(f) for f in feeds],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/feeds", status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Create a new threat intel feed."""
    try:
        ft = FeedType(body.feed_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid feed type: {body.feed_type}")

    feed = ThreatIntelFeed(
        name=body.name,
        feed_type=ft,
        url=body.url,
        api_key=body.api_key,
        is_enabled=body.is_enabled,
        fetch_interval_hours=body.fetch_interval_hours,
        config_json=body.config_json,
    )
    db.add(feed)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="threat_intel_feed",
        resource_id=str(feed.id),
        details={"name": body.name, "type": body.feed_type},
    )
    db.add(audit)

    return _feed_to_dict(feed)


@router.get("/feeds/{feed_uuid}")
async def get_feed(
    feed_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get feed detail."""
    result = await db.execute(select(ThreatIntelFeed).where(ThreatIntelFeed.id == feed_uuid))
    feed = result.scalar_one_or_none()
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    return _feed_to_dict(feed)


@router.put("/feeds/{feed_uuid}")
async def update_feed(
    feed_uuid: uuid.UUID,
    body: FeedUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update a feed."""
    result = await db.execute(select(ThreatIntelFeed).where(ThreatIntelFeed.id == feed_uuid))
    feed = result.scalar_one_or_none()
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")

    if body.name is not None:
        feed.name = body.name
    if body.url is not None:
        feed.url = body.url
    if body.api_key is not None:
        feed.api_key = body.api_key
    if body.is_enabled is not None:
        feed.is_enabled = body.is_enabled
    if body.fetch_interval_hours is not None:
        feed.fetch_interval_hours = body.fetch_interval_hours
    if body.config_json is not None:
        feed.config_json = body.config_json

    feed.updated_at = datetime.now(timezone.utc)
    db.add(feed)

    return _feed_to_dict(feed)


@router.delete("/feeds/{feed_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(
    feed_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Delete a feed."""
    result = await db.execute(select(ThreatIntelFeed).where(ThreatIntelFeed.id == feed_uuid))
    feed = result.scalar_one_or_none()
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    await db.delete(feed)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ioc_to_dict(ioc: ThreatIntelIOC) -> dict:
    return {
        "id": str(ioc.id),
        "ioc_type": ioc.ioc_type.value,
        "value": ioc.value,
        "source": ioc.source,
        "confidence": ioc.confidence,
        "tags": ioc.tags or [],
        "is_active": ioc.is_active,
        "hit_count": ioc.hit_count,
        "first_seen_at": ioc.first_seen_at.isoformat() if ioc.first_seen_at else None,
        "last_seen_at": ioc.last_seen_at.isoformat() if ioc.last_seen_at else None,
        "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
    }


def _feed_to_dict(f: ThreatIntelFeed) -> dict:
    return {
        "id": str(f.id),
        "name": f.name,
        "feed_type": f.feed_type.value,
        "url": f.url,
        "is_enabled": f.is_enabled,
        "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
        "ioc_count": f.ioc_count,
        "fetch_interval_hours": f.fetch_interval_hours,
        "config_json": f.config_json,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }
