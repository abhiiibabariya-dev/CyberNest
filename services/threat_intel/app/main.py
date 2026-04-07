"""
CyberNest Threat Intelligence Service — Feed ingestion, IOC database management,
and real-time IOC lookup for the parser/correlator pipeline.

Runs as a standalone service that:
1. Periodically fetches IOCs from all configured free feeds
2. Deduplicates and scores IOCs (multi-source confirmation raises score)
3. Stores in PostgreSQL with TTL-based expiry
4. Caches hot IOCs in Redis for fast lookup during log parsing
5. Exposes a Redis-based lookup interface for the parser service

Attacker coverage: C2 IPs, malware hashes, phishing URLs, botnet infrastructure
Defender value: Auto-enrichment of parsed events with threat context
"""

import asyncio
import os
from datetime import datetime, timedelta, timezone

import structlog
import redis.asyncio as redis_lib
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text

from app.config import get_settings
from app.feeds.abuse_ch import URLhausFeed, MalwareBazaarFeed, ThreatFoxFeed, FeodoTrackerFeed
from app.feeds.otx import OTXFeed
from app.feeds.emerging_threats import EmergingThreatsFeed, PhishTankFeed
from app.feeds.base import IOC

logger = structlog.get_logger()
settings = get_settings()


# IOC Redis cache prefix — used by parser for fast lookups
REDIS_IOC_PREFIX = "ti:ioc:"
REDIS_IOC_SET = "ti:ioc:all"


async def store_iocs(iocs: list[IOC], session: AsyncSession, redis_client: redis_lib.Redis):
    """Persist IOCs to PostgreSQL and cache in Redis.

    Deduplication: If IOC already exists, update score and source count.
    Multi-source confirmation: Each additional source raises confidence.
    """
    stored = 0
    updated = 0

    for ioc in iocs:
        try:
            # Check if IOC already exists
            result = await session.execute(
                text("SELECT id, source_count, sources, threat_score FROM threat_intel.ioc_entries WHERE ioc_type = :ioc_type AND value = :value"),
                {"ioc_type": ioc.ioc_type, "value": ioc.value}
            )
            existing = result.fetchone()

            expires_at = datetime.now(timezone.utc) + timedelta(days=ioc.ttl_days)

            if existing:
                # Update: increment source count, merge sources, recalculate score
                current_sources = existing[2] or []
                if ioc.source not in current_sources:
                    new_sources = current_sources + [ioc.source]
                    new_count = len(new_sources)
                    # Multi-source score boost: each source adds 10 points, capped at 100
                    boosted_score = min(100.0, max(existing[3] or 0, ioc.threat_score) + (new_count - 1) * 10)

                    await session.execute(
                        text("""
                            UPDATE threat_intel.ioc_entries
                            SET source_count = :count, sources = :sources, threat_score = :score,
                                last_seen = :now, expires_at = :expires, confidence = :confidence
                            WHERE id = :id
                        """),
                        {
                            "id": existing[0], "count": new_count, "sources": new_sources,
                            "score": boosted_score, "now": datetime.now(timezone.utc),
                            "expires": expires_at, "confidence": min(100.0, ioc.confidence + new_count * 5),
                        }
                    )
                    updated += 1
            else:
                # Insert new IOC
                await session.execute(
                    text("""
                        INSERT INTO threat_intel.ioc_entries
                        (id, ioc_type, value, description, threat_score, confidence,
                         source_count, sources, threat_type, malware_family, tags,
                         first_seen, last_seen, expires_at, is_active)
                        VALUES (gen_random_uuid(), :ioc_type, :value, :description, :score, :confidence,
                                1, :sources, :threat_type, :malware_family, :tags,
                                :first_seen, :last_seen, :expires, true)
                        ON CONFLICT (ioc_type, value) DO NOTHING
                    """),
                    {
                        "ioc_type": ioc.ioc_type, "value": ioc.value,
                        "description": ioc.description, "score": ioc.threat_score,
                        "confidence": ioc.confidence, "sources": [ioc.source],
                        "threat_type": ioc.threat_type, "malware_family": ioc.malware_family,
                        "tags": ioc.tags[:20], "first_seen": ioc.first_seen,
                        "last_seen": ioc.last_seen, "expires": expires_at,
                    }
                )
                stored += 1

            # Cache in Redis for fast lookup (used by parser)
            # Key: ti:ioc:<type>:<value> → threat_score
            redis_key = f"{REDIS_IOC_PREFIX}{ioc.ioc_type}:{ioc.value}"
            await redis_client.setex(redis_key, ioc.ttl_days * 86400, str(ioc.threat_score))

        except Exception as e:
            logger.debug("IOC store error", value=ioc.value, error=str(e))

    await session.commit()
    return stored, updated


async def expire_old_iocs(session: AsyncSession, redis_client: redis_lib.Redis):
    """Mark expired IOCs as inactive and remove from Redis cache."""
    result = await session.execute(
        text("""
            UPDATE threat_intel.ioc_entries
            SET is_active = false
            WHERE expires_at < :now AND is_active = true
            RETURNING ioc_type, value
        """),
        {"now": datetime.now(timezone.utc)}
    )
    expired = result.fetchall()
    await session.commit()

    # Remove from Redis
    for ioc_type, value in expired:
        await redis_client.delete(f"{REDIS_IOC_PREFIX}{ioc_type}:{value}")

    if expired:
        logger.info("Expired IOCs cleaned", count=len(expired))


async def run():
    """Main loop: fetch all feeds, store IOCs, repeat on interval."""
    logger.info("Starting CyberNest Threat Intelligence Service",
                refresh_interval=settings.FEED_REFRESH_INTERVAL)

    # Database
    engine = create_async_engine(settings.DATABASE_URL, pool_size=5)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Redis
    redis_client = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

    # Initialize feed providers
    feeds = [
        URLhausFeed(),
        MalwareBazaarFeed(),
        ThreatFoxFeed(),
        FeodoTrackerFeed(),
        EmergingThreatsFeed(),
        PhishTankFeed(),
    ]

    # Add OTX if API key configured
    if settings.OTX_API_KEY:
        feeds.append(OTXFeed(settings.OTX_API_KEY))

    logger.info("Configured feeds", count=len(feeds),
                names=[f.name for f in feeds])

    while True:
        total_stored = 0
        total_updated = 0
        total_errors = 0

        for feed in feeds:
            try:
                logger.info("Fetching feed", feed=feed.name)
                iocs = await feed.fetch()

                if iocs:
                    async with Session() as session:
                        stored, updated = await store_iocs(iocs, session, redis_client)
                        total_stored += stored
                        total_updated += updated
                        logger.info("Feed processed",
                                    feed=feed.name, fetched=len(iocs),
                                    stored=stored, updated=updated)
            except Exception as e:
                total_errors += 1
                logger.error("Feed fetch failed", feed=feed.name, error=str(e))

        # Expire old IOCs
        async with Session() as session:
            await expire_old_iocs(session, redis_client)

        # Update stats in Redis
        await redis_client.set("ti:stats:last_run", datetime.now(timezone.utc).isoformat())
        await redis_client.set("ti:stats:total_stored", str(total_stored))
        await redis_client.set("ti:stats:total_updated", str(total_updated))

        logger.info("Feed cycle complete",
                    stored=total_stored, updated=total_updated, errors=total_errors)

        # Sleep until next refresh
        await asyncio.sleep(settings.FEED_REFRESH_INTERVAL)


if __name__ == "__main__":
    asyncio.run(run())
