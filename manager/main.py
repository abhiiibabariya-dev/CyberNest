"""
CyberNest Manager -- FastAPI Application Entry Point.

Registers all routers, middleware, WebSocket manager, startup/shutdown events,
health check, and metrics endpoint.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from manager.api.middleware.auth_middleware import JWTAuthMiddleware
from manager.api.middleware.rate_limiter import RateLimiterMiddleware
from manager.api.routes import (
    agents,
    alerts,
    assets,
    auth,
    cases,
    dashboard,
    playbooks,
    rules,
    search,
    threat_intel,
    users,
)
from manager.config import get_settings
from shared.utils.logger import get_logger

logger = get_logger("manager")
settings = get_settings()

# Track startup time for uptime calculation
_start_time: float = 0.0


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifecycle: initialize and tear down dependencies."""
    global _start_time
    _start_time = time.time()

    logger.info("starting CyberNest Manager API")

    # -- Initialize Redis ------------------------------------------------
    application.state.redis = None
    try:
        import redis.asyncio as aioredis
        application.state.redis = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=False,
            max_connections=50,
        )
        await application.state.redis.ping()
        logger.info("redis connected", url=settings.REDIS_URL)
    except Exception as exc:
        logger.warning("redis connection failed, running without cache", error=str(exc))
        application.state.redis = None

    # -- Initialize Elasticsearch ----------------------------------------
    application.state.es = None
    try:
        from elasticsearch import AsyncElasticsearch
        application.state.es = AsyncElasticsearch(
            hosts=[settings.ES_URL],
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        info = await application.state.es.info()
        logger.info(
            "elasticsearch connected",
            url=settings.ES_URL,
            version=info.get("version", {}).get("number", "unknown"),
        )
    except Exception as exc:
        logger.warning("elasticsearch connection failed", error=str(exc))
        application.state.es = None

    # -- Initialize Kafka producer (for audit, etc.) ---------------------
    application.state.kafka_producer = None
    try:
        from shared.utils.kafka_utils import KafkaProducerManager
        producer = KafkaProducerManager(settings.KAFKA_BOOTSTRAP)
        await producer.start()
        application.state.kafka_producer = producer
        logger.info("kafka producer connected", bootstrap=settings.KAFKA_BOOTSTRAP)
    except Exception as exc:
        logger.warning("kafka producer connection failed", error=str(exc))

    # -- Initialize database tables (dev mode) ---------------------------
    try:
        from manager.db.database import init_db
        await init_db()
        logger.info("database tables initialized")
    except Exception as exc:
        logger.warning("database init skipped (tables may already exist)", error=str(exc))

    # -- Start syslog receiver (background) ------------------------------
    syslog_task = None
    try:
        from manager.receiver.syslog_receiver import start_syslog_receiver
        syslog_task = asyncio.create_task(_start_syslog_safe())
    except Exception as exc:
        logger.warning("syslog receiver start failed", error=str(exc))

    # -- Start agent receiver (background) -------------------------------
    agent_task = None
    try:
        from manager.receiver.agent_receiver import start_agent_receiver
        agent_task = asyncio.create_task(
            start_agent_receiver(redis_client=application.state.redis)
        )
    except Exception as exc:
        logger.warning("agent receiver start failed", error=str(exc))

    logger.info(
        "CyberNest Manager API started",
        host=settings.API_HOST,
        port=settings.API_PORT,
    )

    yield  # Application is running

    # -- Shutdown --------------------------------------------------------
    logger.info("shutting down CyberNest Manager API")

    if syslog_task:
        syslog_task.cancel()
        try:
            await syslog_task
        except asyncio.CancelledError:
            pass

    if agent_task:
        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass

    if application.state.kafka_producer:
        try:
            await application.state.kafka_producer.stop()
        except Exception:
            pass

    if application.state.es:
        try:
            await application.state.es.close()
        except Exception:
            pass

    if application.state.redis:
        try:
            await application.state.redis.close()
        except Exception:
            pass

    logger.info("CyberNest Manager API stopped")


async def _start_syslog_safe():
    """Start syslog receiver, catching errors to not crash the app."""
    try:
        from manager.receiver.syslog_receiver import start_syslog_receiver
        await start_syslog_receiver()
    except Exception as exc:
        logger.warning("syslog receiver error", error=str(exc))


# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberNest SIEM + SOAR Manager API",
    description="Central management API for the CyberNest SIEM + SOAR platform. "
    "Handles agents, alerts, cases, rules, playbooks, threat intel, assets, and user management.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware (order matters: outermost first)
# ---------------------------------------------------------------------------

# CORS
cors_origins = settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiter
app.add_middleware(RateLimiterMiddleware)

# JWT auth
app.add_middleware(JWTAuthMiddleware)


# ---------------------------------------------------------------------------
# Request timing middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = round((time.time() - start) * 1000, 2)
    response.headers["X-Response-Time-Ms"] = str(elapsed)
    return response


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

PREFIX = "/api/v1"

app.include_router(auth.router, prefix=PREFIX)
app.include_router(users.router, prefix=PREFIX)
app.include_router(alerts.router, prefix=PREFIX)
app.include_router(agents.router, prefix=PREFIX)
app.include_router(rules.router, prefix=PREFIX)
app.include_router(cases.router, prefix=PREFIX)
app.include_router(search.router, prefix=PREFIX)
app.include_router(dashboard.router, prefix=PREFIX)
app.include_router(playbooks.router, prefix=PREFIX)
app.include_router(threat_intel.router, prefix=PREFIX)
app.include_router(assets.router, prefix=PREFIX)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint verifying all dependencies."""
    checks = {
        "service": "cybernest-manager",
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(time.time() - _start_time, 1) if _start_time else 0,
        "dependencies": {},
    }

    overall_healthy = True

    # PostgreSQL
    try:
        from manager.db.database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            from sqlalchemy import text
            await db.execute(text("SELECT 1"))
        checks["dependencies"]["postgresql"] = {"status": "healthy"}
    except Exception as exc:
        checks["dependencies"]["postgresql"] = {"status": "unhealthy", "error": str(exc)}
        overall_healthy = False

    # Redis
    try:
        if app.state.redis:
            await app.state.redis.ping()
            checks["dependencies"]["redis"] = {"status": "healthy"}
        else:
            checks["dependencies"]["redis"] = {"status": "unavailable"}
    except Exception as exc:
        checks["dependencies"]["redis"] = {"status": "unhealthy", "error": str(exc)}

    # Elasticsearch
    try:
        if app.state.es:
            await app.state.es.ping()
            checks["dependencies"]["elasticsearch"] = {"status": "healthy"}
        else:
            checks["dependencies"]["elasticsearch"] = {"status": "unavailable"}
    except Exception as exc:
        checks["dependencies"]["elasticsearch"] = {"status": "unhealthy", "error": str(exc)}

    # Kafka
    try:
        if app.state.kafka_producer and app.state.kafka_producer.is_started:
            checks["dependencies"]["kafka"] = {"status": "healthy"}
        else:
            checks["dependencies"]["kafka"] = {"status": "unavailable"}
    except Exception as exc:
        checks["dependencies"]["kafka"] = {"status": "unhealthy", "error": str(exc)}

    if not overall_healthy:
        checks["status"] = "degraded"

    status_code = 200 if overall_healthy else 503
    return JSONResponse(content=checks, status_code=status_code)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@app.get("/metrics", tags=["System"])
async def metrics():
    """Basic metrics endpoint for monitoring."""
    uptime = round(time.time() - _start_time, 1) if _start_time else 0

    # Connected agents
    try:
        from manager.receiver.agent_receiver import get_connected_agents
        connected_agents = len(get_connected_agents())
    except Exception:
        connected_agents = 0

    # DB stats
    db_stats = {}
    try:
        from manager.db.database import AsyncSessionLocal
        from manager.db.models import Alert, Agent, Case, Rule, User
        from sqlalchemy import func, select

        async with AsyncSessionLocal() as db:
            for model, name in [
                (User, "users"),
                (Agent, "agents"),
                (Alert, "alerts"),
                (Case, "cases"),
                (Rule, "rules"),
            ]:
                result = await db.execute(select(func.count(model.id)))
                db_stats[name] = result.scalar() or 0
    except Exception:
        pass

    return {
        "service": "cybernest-manager",
        "uptime_seconds": uptime,
        "connected_agents": connected_agents,
        "db_counts": db_stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Run with uvicorn
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "manager.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=4,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
    )
