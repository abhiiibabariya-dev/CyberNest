"""CyberNest — Threat Intelligence API routes."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst
from app.models.auth import User
from app.models.threat_intel import IOCEntry, ThreatFeed
from app.models.enums import IOCType

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.post("/lookup")
async def lookup_ioc(
    value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Lookup an IOC value across all types in the threat intel database."""
    result = await db.execute(
        select(IOCEntry).where(IOCEntry.value == value, IOCEntry.is_active == True)
    )
    entries = result.scalars().all()

    if not entries:
        return {"found": False, "value": value, "results": []}

    return {
        "found": True,
        "value": value,
        "results": [
            {
                "ioc_type": e.ioc_type.value,
                "threat_score": e.threat_score,
                "confidence": e.confidence,
                "threat_type": e.threat_type,
                "malware_family": e.malware_family,
                "sources": e.sources,
                "source_count": e.source_count,
                "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                "tags": e.tags,
                "enrichment": e.enrichment,
            }
            for e in entries
        ],
    }


@router.get("/iocs")
async def list_iocs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    ioc_type: IOCType | None = None,
    threat_type: str | None = None,
    min_score: float | None = None,
    search: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
):
    query = (
        select(IOCEntry)
        .where(IOCEntry.is_active == True)
        .order_by(desc(IOCEntry.threat_score))
        .limit(limit).offset(offset)
    )
    if ioc_type:
        query = query.where(IOCEntry.ioc_type == ioc_type)
    if threat_type:
        query = query.where(IOCEntry.threat_type == threat_type)
    if min_score:
        query = query.where(IOCEntry.threat_score >= min_score)
    if search:
        query = query.where(IOCEntry.value.ilike(f"%{search}%"))

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/feeds")
async def list_feeds(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(ThreatFeed).order_by(ThreatFeed.name))
    return result.scalars().all()


@router.post("/feeds/{feed_id}/refresh")
async def refresh_feed(
    feed_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    # Trigger async refresh via Kafka
    from app.core.kafka import publish_event, Topics
    await publish_event(Topics.THREAT_INTEL, {
        "action": "refresh_feed",
        "feed_id": str(feed_id),
        "feed_url": feed.url,
        "feed_type": feed.feed_type,
    })
    return {"detail": f"Feed refresh triggered for {feed.name}"}
