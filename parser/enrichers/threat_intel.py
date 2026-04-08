"""
CyberNest Threat Intelligence Enricher.

Checks source/destination IPs, domains, and file hashes against known IOC feeds.
Uses Redis as a fast-path cache with PostgreSQL as the authoritative store.
IOC cache is reloaded every 10 minutes.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Optional

import asyncpg
import redis.asyncio as redis

from shared.utils.logger import get_logger

logger = get_logger("parser.enricher.threat_intel")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://cybernest:cybernest@localhost:5432/cybernest",
)
IOC_CACHE_PREFIX = "cybernest:ioc:"
IOC_CACHE_TTL = int(os.environ.get("IOC_CACHE_TTL", "600"))  # 10 minutes
IOC_RELOAD_INTERVAL = int(os.environ.get("IOC_RELOAD_INTERVAL", "600"))  # 10 minutes


class ThreatIntelEnricher:
    """Threat intelligence enrichment with Redis cache and PostgreSQL backend."""

    def __init__(self) -> None:
        self._redis: Optional[redis.Redis] = None
        self._pg_pool: Optional[asyncpg.Pool] = None
        self._initialized = False
        self._last_reload: float = 0.0
        self._reload_lock = asyncio.Lock()
        self._reload_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """Initialize Redis and PostgreSQL connections."""
        if self._initialized:
            return

        self._initialized = True

        # Redis
        try:
            self._redis = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self._redis.ping()
            logger.info("threat_intel redis connected")
        except Exception as exc:
            logger.warning("threat_intel redis unavailable", error=str(exc))
            self._redis = None

        # PostgreSQL
        try:
            self._pg_pool = await asyncpg.create_pool(
                POSTGRES_DSN,
                min_size=1,
                max_size=5,
                command_timeout=10,
            )
            logger.info("threat_intel postgres connected")
        except Exception as exc:
            logger.warning("threat_intel postgres unavailable", error=str(exc))
            self._pg_pool = None

        # Start periodic reload task
        self._reload_task = asyncio.create_task(self._periodic_reload())

    async def close(self) -> None:
        """Clean up resources."""
        if self._reload_task:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            await self._redis.close()
        if self._pg_pool:
            await self._pg_pool.close()

    async def _periodic_reload(self) -> None:
        """Periodically reload IOCs from PostgreSQL into Redis cache."""
        while True:
            try:
                await asyncio.sleep(IOC_RELOAD_INTERVAL)
                await self._reload_cache()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("ioc cache reload failed", error=str(exc))

    async def _reload_cache(self) -> None:
        """Reload all active IOCs from PostgreSQL into Redis."""
        if not self._pg_pool or not self._redis:
            return

        async with self._reload_lock:
            now = time.time()
            if now - self._last_reload < IOC_RELOAD_INTERVAL / 2:
                return  # Avoid reload storms

            try:
                async with self._pg_pool.acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT ioc_type, ioc_value, severity, source, description,
                               first_seen, last_seen, tags, confidence
                        FROM threat_indicators
                        WHERE active = true
                          AND (expiry_at IS NULL OR expiry_at > NOW())
                    """)

                pipe = self._redis.pipeline()
                count = 0
                for row in rows:
                    ioc_type = row["ioc_type"]  # ip, domain, hash_md5, hash_sha256, url
                    ioc_value = row["ioc_value"].lower().strip()
                    cache_key = f"{IOC_CACHE_PREFIX}{ioc_type}:{ioc_value}"
                    ioc_data = {
                        "type": ioc_type,
                        "value": ioc_value,
                        "severity": row["severity"] or "medium",
                        "source": row["source"] or "unknown",
                        "description": row["description"] or "",
                        "first_seen": str(row["first_seen"]) if row["first_seen"] else None,
                        "last_seen": str(row["last_seen"]) if row["last_seen"] else None,
                        "tags": row["tags"] if row["tags"] else [],
                        "confidence": row["confidence"] or "medium",
                    }
                    pipe.setex(cache_key, IOC_CACHE_TTL, json.dumps(ioc_data))
                    count += 1

                if count > 0:
                    await pipe.execute()

                self._last_reload = now
                logger.info("ioc cache reloaded", count=count)

            except Exception as exc:
                logger.error("ioc cache reload error", error=str(exc))

    async def _check_redis(self, ioc_type: str, value: str) -> Optional[dict[str, Any]]:
        """Check Redis cache for an IOC."""
        if not self._redis:
            return None
        try:
            cache_key = f"{IOC_CACHE_PREFIX}{ioc_type}:{value.lower().strip()}"
            cached = await self._redis.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass
        return None

    async def _check_postgres(self, ioc_type: str, value: str) -> Optional[dict[str, Any]]:
        """Check PostgreSQL for an IOC on cache miss."""
        if not self._pg_pool:
            return None
        try:
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT ioc_type, ioc_value, severity, source, description,
                           first_seen, last_seen, tags, confidence
                    FROM threat_indicators
                    WHERE ioc_type = $1
                      AND LOWER(ioc_value) = LOWER($2)
                      AND active = true
                      AND (expiry_at IS NULL OR expiry_at > NOW())
                    LIMIT 1
                """, ioc_type, value.strip())

                if row:
                    ioc_data = {
                        "type": row["ioc_type"],
                        "value": row["ioc_value"],
                        "severity": row["severity"] or "medium",
                        "source": row["source"] or "unknown",
                        "description": row["description"] or "",
                        "first_seen": str(row["first_seen"]) if row["first_seen"] else None,
                        "last_seen": str(row["last_seen"]) if row["last_seen"] else None,
                        "tags": row["tags"] if row["tags"] else [],
                        "confidence": row["confidence"] or "medium",
                    }
                    # Cache the result
                    if self._redis:
                        try:
                            cache_key = f"{IOC_CACHE_PREFIX}{ioc_type}:{value.lower().strip()}"
                            await self._redis.setex(cache_key, IOC_CACHE_TTL, json.dumps(ioc_data))
                        except Exception:
                            pass
                    return ioc_data
        except Exception as exc:
            logger.debug("postgres ioc lookup failed", error=str(exc))
        return None

    async def check_indicator(self, ioc_type: str, value: str) -> Optional[dict[str, Any]]:
        """Check if a value is a known IOC.

        Args:
            ioc_type: One of 'ip', 'domain', 'hash_md5', 'hash_sha256', 'url'.
            value: The indicator value to check.

        Returns:
            IOC data dict if found, None otherwise.
        """
        if not value or value in ("-", "?", "N/A", "0.0.0.0"):
            return None

        # Check Redis first
        result = await self._check_redis(ioc_type, value)
        if result is not None:
            return result

        # Cache miss - check PostgreSQL
        result = await self._check_postgres(ioc_type, value)
        return result

    async def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Enrich an ECS event with threat intelligence data.

        Checks source/destination IPs, domains, and file hashes.
        Tags matched events with threat.indicator fields.

        Modifies event in place and returns it.
        """
        matches: list[dict[str, Any]] = []

        # Check source IP
        src_ip = (event.get("source") or {}).get("ip")
        if src_ip:
            ioc = await self.check_indicator("ip", src_ip)
            if ioc:
                matches.append(ioc)

        # Check destination IP
        dst_ip = (event.get("destination") or {}).get("ip")
        if dst_ip:
            ioc = await self.check_indicator("ip", dst_ip)
            if ioc:
                matches.append(ioc)

        # Check domains
        for domain_field in [
            (event.get("source") or {}).get("domain"),
            (event.get("destination") or {}).get("domain"),
            (event.get("url") or {}).get("domain"),
            (event.get("dns", {}) or {}).get("question", {}).get("name") if isinstance(event.get("dns"), dict) else None,
        ]:
            if domain_field:
                ioc = await self.check_indicator("domain", domain_field)
                if ioc:
                    matches.append(ioc)

        # Check file hashes
        file_hash = (event.get("file") or {}).get("hash") or {}
        if isinstance(file_hash, dict):
            for hash_type in ("sha256", "md5", "sha1"):
                hash_val = file_hash.get(hash_type)
                if hash_val:
                    ioc = await self.check_indicator(f"hash_{hash_type}", hash_val)
                    if ioc:
                        matches.append(ioc)

        # Apply threat intelligence to event
        if matches:
            # Use the highest-severity match
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
            matches.sort(key=lambda m: severity_order.get(m.get("severity", ""), 0), reverse=True)
            primary = matches[0]

            threat = event.setdefault("threat", {})
            threat["indicator"] = {
                "type": primary.get("type"),
                "description": primary.get("description"),
                "provider": primary.get("source"),
                "confidence": primary.get("confidence"),
                "first_seen": primary.get("first_seen"),
                "last_seen": primary.get("last_seen"),
            }

            # Set IP or domain on indicator
            if primary.get("type") == "ip":
                threat["indicator"]["ip"] = primary.get("value")
            elif primary.get("type") == "domain":
                threat["indicator"]["domain"] = primary.get("value")
            elif primary.get("type", "").startswith("hash_"):
                hash_type = primary["type"].replace("hash_", "")
                threat["indicator"][f"file.hash.{hash_type}"] = primary.get("value")

            # Tag event
            tags = event.setdefault("tags", [])
            if "threat-intel-match" not in tags:
                tags.append("threat-intel-match")

            # Elevate event severity if IOC match is high/critical
            if primary.get("severity") in ("high", "critical"):
                event_meta = event.setdefault("event", {})
                current_sev = event_meta.get("severity", 0)
                ioc_sev = 80 if primary["severity"] == "high" else 95
                event_meta["severity"] = max(current_sev, ioc_sev)

            # Add all matches as additional indicators
            if len(matches) > 1:
                threat["additional_indicators"] = [
                    {
                        "type": m.get("type"),
                        "value": m.get("value"),
                        "source": m.get("source"),
                        "severity": m.get("severity"),
                    }
                    for m in matches[1:]
                ]

        return event
