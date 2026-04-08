"""
CyberNest Asset Lookup Enricher.

Checks source/destination IPs against the PostgreSQL assets table to enrich
events with host information: name, OS, risk score, and criticality.
Uses Redis cache with 5-minute TTL.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import asyncpg
import redis.asyncio as redis

from shared.utils.logger import get_logger

logger = get_logger("parser.enricher.asset_lookup")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://cybernest:cybernest@localhost:5432/cybernest",
)
ASSET_CACHE_PREFIX = "cybernest:asset:"
ASSET_CACHE_TTL = int(os.environ.get("ASSET_CACHE_TTL", "300"))  # 5 minutes


class AssetLookupEnricher:
    """Asset enrichment from PostgreSQL with Redis caching."""

    def __init__(self) -> None:
        self._redis: Optional[redis.Redis] = None
        self._pg_pool: Optional[asyncpg.Pool] = None
        self._initialized = False

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
            logger.info("asset_lookup redis connected")
        except Exception as exc:
            logger.warning("asset_lookup redis unavailable", error=str(exc))
            self._redis = None

        # PostgreSQL
        try:
            self._pg_pool = await asyncpg.create_pool(
                POSTGRES_DSN,
                min_size=1,
                max_size=5,
                command_timeout=10,
            )
            logger.info("asset_lookup postgres connected")
        except Exception as exc:
            logger.warning("asset_lookup postgres unavailable", error=str(exc))
            self._pg_pool = None

    async def close(self) -> None:
        """Clean up resources."""
        if self._redis:
            await self._redis.close()
        if self._pg_pool:
            await self._pg_pool.close()

    async def _get_cached(self, ip: str) -> Optional[dict[str, Any]]:
        """Get cached asset data from Redis."""
        if not self._redis:
            return None
        try:
            cached = await self._redis.get(f"{ASSET_CACHE_PREFIX}{ip}")
            if cached:
                data = json.loads(cached)
                if "_empty" in data:
                    return {"_empty": True}
                return data
        except Exception:
            pass
        return None

    async def _set_cached(self, ip: str, data: Optional[dict[str, Any]]) -> None:
        """Cache asset data in Redis."""
        if not self._redis:
            return
        try:
            value = json.dumps(data) if data else '{"_empty": true}'
            await self._redis.setex(
                f"{ASSET_CACHE_PREFIX}{ip}",
                ASSET_CACHE_TTL,
                value,
            )
        except Exception:
            pass

    async def _lookup_postgres(self, ip: str) -> Optional[dict[str, Any]]:
        """Look up asset in PostgreSQL by IP address."""
        if not self._pg_pool:
            return None

        try:
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT
                        hostname,
                        ip_address,
                        os_name,
                        os_version,
                        os_family,
                        os_platform,
                        risk_score,
                        criticality,
                        department,
                        location,
                        owner,
                        asset_type,
                        tags,
                        last_seen,
                        status
                    FROM assets
                    WHERE ip_address = $1
                      AND status = 'active'
                    LIMIT 1
                """, ip)

                if row:
                    asset_data = {
                        "hostname": row["hostname"],
                        "ip_address": row["ip_address"],
                        "os_name": row["os_name"],
                        "os_version": row["os_version"],
                        "os_family": row["os_family"],
                        "os_platform": row["os_platform"],
                        "risk_score": float(row["risk_score"]) if row["risk_score"] is not None else None,
                        "criticality": row["criticality"],
                        "department": row["department"],
                        "location": row["location"],
                        "owner": row["owner"],
                        "asset_type": row["asset_type"],
                        "tags": row["tags"] if row["tags"] else [],
                        "last_seen": str(row["last_seen"]) if row["last_seen"] else None,
                    }

                    # Cache the result
                    await self._set_cached(ip, asset_data)
                    return asset_data

        except asyncpg.UndefinedTableError:
            logger.debug("assets table does not exist yet")
        except Exception as exc:
            logger.debug("asset postgres lookup failed", ip=ip, error=str(exc))

        return None

    async def lookup_ip(self, ip: str) -> Optional[dict[str, Any]]:
        """Look up asset information for an IP address.

        Args:
            ip: IP address to look up.

        Returns:
            Asset data dict if found, None otherwise.
        """
        if not ip or ip in ("-", "?", "N/A", "0.0.0.0"):
            return None

        # Check cache
        cached = await self._get_cached(ip)
        if cached is not None:
            if "_empty" in cached:
                return None
            return cached

        # Cache miss - check PostgreSQL
        result = await self._lookup_postgres(ip)

        # Cache negative result too
        if result is None:
            await self._set_cached(ip, None)

        return result

    def _apply_asset_to_host(self, host: dict[str, Any], asset: dict[str, Any]) -> None:
        """Apply asset data to ECS host fields."""
        if asset.get("hostname"):
            host["name"] = asset["hostname"]
            host["hostname"] = asset["hostname"]

        # OS information
        os_info: dict[str, Any] = {}
        if asset.get("os_name"):
            os_info["name"] = asset["os_name"]
        if asset.get("os_version"):
            os_info["version"] = asset["os_version"]
        if asset.get("os_family"):
            os_info["family"] = asset["os_family"]
        if asset.get("os_platform"):
            os_info["platform"] = asset["os_platform"]
        if os_info:
            host["os"] = os_info

        # Risk and criticality
        if asset.get("risk_score") is not None:
            host["risk_score"] = asset["risk_score"]
        if asset.get("criticality"):
            host["criticality"] = asset["criticality"]

        # Asset type
        if asset.get("asset_type"):
            host["type"] = asset["asset_type"]

    async def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Enrich an ECS event with asset information.

        Checks source.ip and destination.ip against the asset database.
        Populates host.name, host.os, host.risk_score, host.criticality.

        Modifies event in place and returns it.
        """
        # Enrich source IP
        src_ip = (event.get("source") or {}).get("ip")
        if src_ip:
            asset = await self.lookup_ip(src_ip)
            if asset:
                host = event.setdefault("host", {})
                self._apply_asset_to_host(host, asset)

                # Add asset metadata
                event.setdefault("cybernest", {})["source_asset"] = {
                    "hostname": asset.get("hostname"),
                    "criticality": asset.get("criticality"),
                    "risk_score": asset.get("risk_score"),
                    "department": asset.get("department"),
                    "owner": asset.get("owner"),
                }

                # Elevate event severity based on asset criticality
                if asset.get("criticality") in ("critical", "high"):
                    event_meta = event.setdefault("event", {})
                    current_sev = event_meta.get("severity", 0)
                    bump = 20 if asset["criticality"] == "critical" else 10
                    event_meta["severity"] = min(100, current_sev + bump)

                # Add tags
                tags = event.setdefault("tags", [])
                if "asset-enriched" not in tags:
                    tags.append("asset-enriched")
                if asset.get("criticality") in ("critical", "high"):
                    tag = f"asset-{asset['criticality']}"
                    if tag not in tags:
                        tags.append(tag)

        # Check destination IP for asset info too (less common but useful)
        dst_ip = (event.get("destination") or {}).get("ip")
        if dst_ip and dst_ip != src_ip:
            asset = await self.lookup_ip(dst_ip)
            if asset:
                event.setdefault("cybernest", {})["destination_asset"] = {
                    "hostname": asset.get("hostname"),
                    "criticality": asset.get("criticality"),
                    "risk_score": asset.get("risk_score"),
                    "department": asset.get("department"),
                    "owner": asset.get("owner"),
                }
                # If target is critical, also bump severity
                if asset.get("criticality") in ("critical", "high"):
                    event_meta = event.setdefault("event", {})
                    current_sev = event_meta.get("severity", 0)
                    bump = 15 if asset["criticality"] == "critical" else 5
                    event_meta["severity"] = min(100, current_sev + bump)

        return event
