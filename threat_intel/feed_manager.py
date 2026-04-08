"""Feed Manager — orchestrates all threat intel feed fetches on a schedule."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import asyncpg
import structlog

from threat_intel.ioc_store import IOCStore
from threat_intel.feeds import otx_feed, abusech_feed, emergingthreats_feed

logger = structlog.get_logger("threat_intel.feed_manager")

# ── SQL for feed tracking ───────────────────────────────────────────────────

CREATE_FEEDS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    feed_name       TEXT PRIMARY KEY,
    last_fetched    TIMESTAMPTZ,
    last_status     TEXT        NOT NULL DEFAULT 'pending',
    iocs_total      BIGINT      NOT NULL DEFAULT 0,
    iocs_new        BIGINT      NOT NULL DEFAULT 0,
    error_message   TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

UPSERT_FEED_STATUS_SQL = """
INSERT INTO threat_intel_feeds (feed_name, last_fetched, last_status, iocs_total, iocs_new, error_message, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (feed_name) DO UPDATE SET
    last_fetched  = EXCLUDED.last_fetched,
    last_status   = EXCLUDED.last_status,
    iocs_total    = EXCLUDED.iocs_total,
    iocs_new      = EXCLUDED.iocs_new,
    error_message = EXCLUDED.error_message,
    updated_at    = now();
"""

GET_FEED_SQL = """
SELECT feed_name, last_fetched, last_status, iocs_total, iocs_new, error_message
FROM threat_intel_feeds
WHERE feed_name = $1;
"""


# ── Feed definitions ────────────────────────────────────────────────────────

FeedFetcher = Callable[..., Awaitable[list[dict[str, Any]]]]


class FeedDef:
    """Describes a single feed source."""

    __slots__ = ("name", "fetcher", "interval_seconds", "kwargs")

    def __init__(
        self,
        name: str,
        fetcher: FeedFetcher,
        interval_seconds: int = 21600,  # 6 hours
        **kwargs: Any,
    ) -> None:
        self.name = name
        self.fetcher = fetcher
        self.interval_seconds = interval_seconds
        self.kwargs = kwargs


class FeedManager:
    """Schedules, runs, deduplicates, and tracks all threat intel feeds."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        ioc_store: IOCStore,
        otx_api_key: str = "",
        default_interval: int = 21600,
    ) -> None:
        self._pool = pool
        self._store = ioc_store
        self._tasks: list[asyncio.Task[None]] = []
        self._running = False

        # Register all feeds
        self._feeds: list[FeedDef] = [
            FeedDef("otx", otx_feed.fetch, default_interval, api_key=otx_api_key),
            FeedDef("abusech", abusech_feed.fetch_all, default_interval),
            FeedDef("emergingthreats", emergingthreats_feed.fetch, default_interval),
        ]

    # ── Schema ──────────────────────────────────────────────────────────

    async def ensure_schema(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_FEEDS_TABLE_SQL)
        logger.info("feed_manager.schema_ensured")

    # ── Lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start background scheduler tasks for every feed + daily cleanup."""
        self._running = True
        for feed in self._feeds:
            task = asyncio.create_task(
                self._feed_loop(feed), name=f"feed:{feed.name}"
            )
            self._tasks.append(task)

        # Daily expired-IOC cleanup
        cleanup_task = asyncio.create_task(
            self._cleanup_loop(), name="feed:cleanup"
        )
        self._tasks.append(cleanup_task)
        logger.info(
            "feed_manager.started",
            feeds=[f.name for f in self._feeds],
        )

    async def stop(self) -> None:
        """Cancel all scheduled tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("feed_manager.stopped")

    # ── Run a single feed once (public, for manual triggers) ────────────

    async def run_feed(self, feed_name: str) -> dict[str, Any]:
        """Run a specific feed by name and return summary."""
        for feed in self._feeds:
            if feed.name == feed_name:
                return await self._execute_feed(feed)
        return {"error": f"unknown feed: {feed_name}"}

    # ── Internal loops ──────────────────────────────────────────────────

    async def _feed_loop(self, feed: FeedDef) -> None:
        """Repeatedly fetch a feed at its configured interval."""
        while self._running:
            try:
                await self._execute_feed(feed)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("feed_manager.loop_error", feed=feed.name)
            await asyncio.sleep(feed.interval_seconds)

    async def _cleanup_loop(self) -> None:
        """Delete expired IOCs once per day."""
        while self._running:
            try:
                deleted = await self._store.delete_expired_iocs()
                logger.info("feed_manager.cleanup_done", deleted=deleted)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("feed_manager.cleanup_error")
            await asyncio.sleep(86400)  # 24 hours

    # ── Core fetch + persist logic ──────────────────────────────────────

    async def _execute_feed(self, feed: FeedDef) -> dict[str, Any]:
        """Fetch a single feed, deduplicate, bulk-insert, and record status."""
        feed_name = feed.name
        logger.info("feed_manager.fetching", feed=feed_name)
        now = datetime.now(timezone.utc)

        try:
            raw_iocs = await feed.fetcher(**feed.kwargs)
        except Exception as exc:
            logger.error("feed_manager.fetch_error", feed=feed_name, error=str(exc))
            await self._update_feed_status(
                feed_name, now, "error", 0, 0, str(exc)
            )
            return {"feed": feed_name, "status": "error", "error": str(exc)}

        # Deduplicate within this batch on (type, value, source)
        seen: set[tuple[str, str, str]] = set()
        unique_iocs: list[dict[str, Any]] = []
        for ioc in raw_iocs:
            key = (ioc["type"], ioc["value"], ioc["source"])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        total = len(unique_iocs)
        new_count = 0
        if unique_iocs:
            new_count = await self._store.bulk_add_iocs(unique_iocs)

        await self._update_feed_status(
            feed_name, now, "ok", total, new_count, None
        )

        logger.info(
            "feed_manager.fetch_complete",
            feed=feed_name,
            total=total,
            new=new_count,
        )
        return {
            "feed": feed_name,
            "status": "ok",
            "total": total,
            "new": new_count,
        }

    # ── DB tracking helpers ─────────────────────────────────────────────

    async def _update_feed_status(
        self,
        feed_name: str,
        fetched_at: datetime,
        status: str,
        iocs_total: int,
        iocs_new: int,
        error_message: str | None,
    ) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                UPSERT_FEED_STATUS_SQL,
                feed_name,
                fetched_at,
                status,
                iocs_total,
                iocs_new,
                error_message,
            )

    async def get_feed_status(self, feed_name: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(GET_FEED_SQL, feed_name)
        if row is None:
            return None
        return dict(row)

    async def get_all_feed_statuses(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM threat_intel_feeds ORDER BY feed_name"
            )
        return [dict(r) for r in rows]
