"""Threat Intelligence service — main entry point.

Initializes DB pool, Redis connection, IOC store, feed manager.
Runs cache warm-up and starts the feed scheduler on startup.
Exposes a lightweight HTTP health-check on port 8084.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from typing import Any

import asyncpg
import redis.asyncio as aioredis
import structlog
from aiohttp import web

from threat_intel.ioc_store import IOCStore
from threat_intel.feed_manager import FeedManager

# ── Logging ─────────────────────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if os.getenv("LOG_FORMAT") == "console"
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        structlog.get_config().get("min_level", 0)
    ),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("threat_intel.main")

# ── Configuration (env vars) ────────────────────────────────────────────────

DB_DSN = os.getenv("THREAT_INTEL_DB_DSN", "postgresql://cybernest:cybernest@localhost:5432/cybernest")
REDIS_URL = os.getenv("THREAT_INTEL_REDIS_URL", "redis://localhost:6379/0")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
FEED_INTERVAL = int(os.getenv("FEED_INTERVAL_SECONDS", "21600"))  # 6h
HEALTH_PORT = int(os.getenv("THREAT_INTEL_PORT", "8084"))

# ── Globals (set during startup) ────────────────────────────────────────────

_pool: asyncpg.Pool | None = None
_redis: aioredis.Redis | None = None
_store: IOCStore | None = None
_feed_mgr: FeedManager | None = None


# ── Health check HTTP server ────────────────────────────────────────────────

async def _handle_health(request: web.Request) -> web.Response:
    """Return service health including IOC stats and feed statuses."""
    status: dict[str, Any] = {"service": "threat_intel", "status": "ok"}
    try:
        if _store:
            status["ioc_stats"] = await _store.get_ioc_stats()
        if _feed_mgr:
            feeds = await _feed_mgr.get_all_feed_statuses()
            status["feeds"] = feeds
    except Exception as exc:
        status["status"] = "degraded"
        status["error"] = str(exc)
    return web.json_response(status)


async def _handle_lookup(request: web.Request) -> web.Response:
    """GET /lookup?type=ip&value=1.2.3.4 — quick IOC lookup."""
    ioc_type = request.query.get("type", "")
    ioc_value = request.query.get("value", "")
    if not ioc_type or not ioc_value:
        return web.json_response(
            {"error": "query params 'type' and 'value' required"}, status=400
        )
    if _store is None:
        return web.json_response({"error": "store not initialized"}, status=503)

    result = await _store.lookup_ioc(ioc_type, ioc_value)
    if result is None:
        return web.json_response({"found": False}, status=404)
    return web.json_response({"found": True, "ioc": result})


async def _handle_stats(request: web.Request) -> web.Response:
    """GET /stats — IOC statistics."""
    if _store is None:
        return web.json_response({"error": "store not initialized"}, status=503)
    stats = await _store.get_ioc_stats()
    return web.json_response(stats)


async def _handle_refresh(request: web.Request) -> web.Response:
    """POST /refresh?feed=otx — manually trigger a feed refresh."""
    feed_name = request.query.get("feed", "")
    if not feed_name:
        return web.json_response({"error": "'feed' query param required"}, status=400)
    if _feed_mgr is None:
        return web.json_response({"error": "feed manager not initialized"}, status=503)
    result = await _feed_mgr.run_feed(feed_name)
    return web.json_response(result)


def _create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", _handle_health)
    app.router.add_get("/lookup", _handle_lookup)
    app.router.add_get("/stats", _handle_stats)
    app.router.add_post("/refresh", _handle_refresh)
    return app


# ── Startup / shutdown ──────────────────────────────────────────────────────

async def startup() -> None:
    global _pool, _redis, _store, _feed_mgr

    logger.info("main.starting", db_dsn=DB_DSN.split("@")[-1], redis=REDIS_URL)

    # 1. PostgreSQL connection pool
    _pool = await asyncpg.create_pool(
        dsn=DB_DSN, min_size=2, max_size=10, command_timeout=30
    )
    logger.info("main.db_connected")

    # 2. Redis connection
    _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    await _redis.ping()
    logger.info("main.redis_connected")

    # 3. IOC Store
    _store = IOCStore(pool=_pool, redis=_redis)
    await _store.ensure_schema()

    # 4. Warm cache from DB
    cached = await _store.warm_cache()
    logger.info("main.cache_warmed", cached=cached)

    # 5. Feed Manager
    _feed_mgr = FeedManager(
        pool=_pool,
        ioc_store=_store,
        otx_api_key=OTX_API_KEY,
        default_interval=FEED_INTERVAL,
    )
    await _feed_mgr.ensure_schema()
    await _feed_mgr.start()
    logger.info("main.feeds_scheduled")


async def shutdown() -> None:
    logger.info("main.shutting_down")
    if _feed_mgr:
        await _feed_mgr.stop()
    if _redis:
        await _redis.aclose()
    if _pool:
        await _pool.close()
    logger.info("main.shutdown_complete")


async def main() -> None:
    """Run startup, health-check server, and wait for termination."""
    await startup()

    app = _create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HEALTH_PORT)
    await site.start()
    logger.info("main.health_server_listening", port=HEALTH_PORT)

    # Wait for shutdown signal
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows does not support add_signal_handler
            pass

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await runner.cleanup()
        await shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
