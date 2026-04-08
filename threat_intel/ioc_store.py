"""IOC Store — CRUD operations against PostgreSQL with Redis hot cache."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import asyncpg
import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger("threat_intel.ioc_store")

REDIS_KEY_PREFIX = "cybernest:ioc"
REDIS_IOC_TTL = 3600  # 1 hour

# ── SQL statements ──────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id              BIGSERIAL PRIMARY KEY,
    ioc_type        TEXT        NOT NULL,
    ioc_value       TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    confidence      SMALLINT    NOT NULL DEFAULT 50,
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ioc_type, ioc_value, source)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON threat_intel_iocs (ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_expires    ON threat_intel_iocs (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_source     ON threat_intel_iocs (source);
"""

UPSERT_SQL = """
INSERT INTO threat_intel_iocs (ioc_type, ioc_value, source, confidence, tags, expires_at, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, now(), now())
ON CONFLICT (ioc_type, ioc_value, source) DO UPDATE SET
    confidence = GREATEST(threat_intel_iocs.confidence, EXCLUDED.confidence),
    tags       = ARRAY(
        SELECT DISTINCT unnest(threat_intel_iocs.tags || EXCLUDED.tags)
    ),
    last_seen   = now(),
    expires_at  = COALESCE(EXCLUDED.expires_at, threat_intel_iocs.expires_at),
    updated_at  = now()
RETURNING id, ioc_type, ioc_value, source, confidence, tags,
          first_seen, last_seen, expires_at, created_at, updated_at;
"""

LOOKUP_SQL = """
SELECT id, ioc_type, ioc_value, source, confidence, tags,
       first_seen, last_seen, expires_at, created_at, updated_at
FROM threat_intel_iocs
WHERE ioc_type = $1 AND ioc_value = $2
ORDER BY confidence DESC
LIMIT 1;
"""

DELETE_EXPIRED_SQL = """
DELETE FROM threat_intel_iocs
WHERE expires_at IS NOT NULL AND expires_at < now()
RETURNING id;
"""

STATS_SQL = """
SELECT
    (SELECT count(*) FROM threat_intel_iocs)::bigint                          AS total,
    (SELECT jsonb_object_agg(ioc_type, cnt)
       FROM (SELECT ioc_type, count(*)::bigint AS cnt
               FROM threat_intel_iocs GROUP BY ioc_type) sub)                 AS by_type,
    (SELECT jsonb_object_agg(source, cnt)
       FROM (SELECT source, count(*)::bigint AS cnt
               FROM threat_intel_iocs GROUP BY source) sub)                   AS by_source;
"""

ALL_IOCS_SQL = """
SELECT ioc_type, ioc_value, source, confidence, tags,
       first_seen, last_seen, expires_at
FROM threat_intel_iocs;
"""


def _ioc_cache_key(ioc_type: str, ioc_value: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{ioc_type}:{ioc_value}"


def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    d: dict[str, Any] = dict(row)
    for key, val in d.items():
        if isinstance(val, datetime):
            d[key] = val.isoformat()
    return d


class IOCStore:
    """Manages IOC persistence in PostgreSQL with a Redis read-through cache."""

    def __init__(self, pool: asyncpg.Pool, redis: aioredis.Redis) -> None:
        self._pool = pool
        self._redis = redis

    # ── Schema bootstrap ────────────────────────────────────────────────

    async def ensure_schema(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_TABLE_SQL)
        logger.info("ioc_store.schema_ensured")

    # ── Single IOC insert / upsert ──────────────────────────────────────

    async def add_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        source: str,
        confidence: int = 50,
        tags: list[str] | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        tags = tags or []
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                UPSERT_SQL,
                ioc_type,
                ioc_value,
                source,
                confidence,
                tags,
                expires_at,
            )
        ioc = _row_to_dict(row)
        await self._cache_set(ioc_type, ioc_value, ioc)
        logger.debug("ioc_store.add_ioc", type=ioc_type, value=ioc_value, source=source)
        return ioc

    # ── Bulk insert ─────────────────────────────────────────────────────

    async def bulk_add_iocs(self, iocs: list[dict[str, Any]]) -> int:
        """Batch upsert a list of IOC dicts. Returns count of rows affected."""
        if not iocs:
            return 0

        inserted = 0
        # Process in chunks of 500 to avoid overwhelming the connection
        chunk_size = 500
        for offset in range(0, len(iocs), chunk_size):
            chunk = iocs[offset : offset + chunk_size]
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    for ioc in chunk:
                        try:
                            row = await conn.fetchrow(
                                UPSERT_SQL,
                                ioc["type"],
                                ioc["value"],
                                ioc["source"],
                                ioc.get("confidence", 50),
                                ioc.get("tags", []),
                                ioc.get("expires_at"),
                            )
                            if row:
                                inserted += 1
                                await self._cache_set(
                                    ioc["type"], ioc["value"], _row_to_dict(row)
                                )
                        except Exception:
                            logger.exception(
                                "ioc_store.bulk_insert_error",
                                type=ioc.get("type"),
                                value=ioc.get("value"),
                            )
        logger.info("ioc_store.bulk_add_iocs", total=len(iocs), inserted=inserted)
        return inserted

    # ── Lookup (cache-first) ────────────────────────────────────────────

    async def lookup_ioc(
        self, ioc_type: str, ioc_value: str
    ) -> dict[str, Any] | None:
        # 1. Try Redis hot cache
        cached = await self._cache_get(ioc_type, ioc_value)
        if cached is not None:
            logger.debug("ioc_store.cache_hit", type=ioc_type, value=ioc_value)
            return cached

        # 2. Fall through to DB
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(LOOKUP_SQL, ioc_type, ioc_value)

        if row is None:
            return None

        ioc = _row_to_dict(row)
        await self._cache_set(ioc_type, ioc_value, ioc)
        logger.debug("ioc_store.cache_miss_db_hit", type=ioc_type, value=ioc_value)
        return ioc

    # ── Expiry cleanup ──────────────────────────────────────────────────

    async def delete_expired_iocs(self) -> int:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(DELETE_EXPIRED_SQL)
        count = len(rows)
        if count:
            logger.info("ioc_store.expired_deleted", count=count)
        return count

    # ── Statistics ──────────────────────────────────────────────────────

    async def get_ioc_stats(self) -> dict[str, Any]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(STATS_SQL)
        total = row["total"] or 0
        by_type = json.loads(row["by_type"]) if row["by_type"] else {}
        by_source = json.loads(row["by_source"]) if row["by_source"] else {}
        return {"total": total, "by_type": by_type, "by_source": by_source}

    # ── Cache warm-up ───────────────────────────────────────────────────

    async def warm_cache(self) -> int:
        """Load all IOCs from DB into Redis. Returns count loaded."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(ALL_IOCS_SQL)

        pipe = self._redis.pipeline(transaction=False)
        for row in rows:
            key = _ioc_cache_key(row["ioc_type"], row["ioc_value"])
            payload = json.dumps(_row_to_dict(row))
            pipe.setex(key, REDIS_IOC_TTL, payload)

        await pipe.execute()
        logger.info("ioc_store.cache_warmed", count=len(rows))
        return len(rows)

    # ── Redis helpers ───────────────────────────────────────────────────

    async def _cache_set(
        self, ioc_type: str, ioc_value: str, ioc: dict[str, Any]
    ) -> None:
        key = _ioc_cache_key(ioc_type, ioc_value)
        try:
            await self._redis.setex(key, REDIS_IOC_TTL, json.dumps(ioc))
        except Exception:
            logger.warning("ioc_store.cache_set_failed", key=key)

    async def _cache_get(
        self, ioc_type: str, ioc_value: str
    ) -> dict[str, Any] | None:
        key = _ioc_cache_key(ioc_type, ioc_value)
        try:
            raw = await self._redis.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            logger.warning("ioc_store.cache_get_failed", key=key)
        return None
