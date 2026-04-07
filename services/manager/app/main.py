"""
CyberNest Manager — Central API Server
Enterprise SIEM + SOAR Platform
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.core.config import get_settings
from app.core.database import init_db, engine
from app.core.kafka import close_kafka_producer
from app.core.redis import close_redis
from app.core.elasticsearch import close_es
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.audit import AuditMiddleware

# API Routers
from app.api.v1.auth.routes import router as auth_router
from app.api.v1.agents.routes import router as agents_router
from app.api.v1.events.routes import router as events_router
from app.api.v1.alerts.routes import router as alerts_router
from app.api.v1.rules.routes import router as rules_router
from app.api.v1.cases.routes import router as cases_router
from app.api.v1.playbooks.routes import router as playbooks_router
from app.api.v1.dashboard.routes import router as dashboard_router
from app.api.v1.threat_intel.routes import router as threat_intel_router
from app.api.v1.users.routes import router as users_router
from app.api.websocket import router as ws_router

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberNest Manager", env=settings.CYBERNEST_ENV)
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down CyberNest Manager")
    await close_kafka_producer()
    await close_redis()
    await close_es()
    await engine.dispose()


app = FastAPI(
    title="CyberNest — Enterprise SIEM + SOAR",
    description="Unified Security Information & Event Management + Security Orchestration, Automation & Response",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Middleware (order matters — outermost runs first)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.CYBERNEST_ENV == "development" else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)

# Mount API routers under /api/v1
app.include_router(auth_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(playbooks_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")

# WebSocket routes
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": settings.SERVICE_NAME,
        "version": "1.0.0",
        "environment": settings.CYBERNEST_ENV,
    }


@app.get("/")
async def root():
    return {
        "name": "CyberNest",
        "description": "Enterprise SIEM + SOAR Platform",
        "version": "1.0.0",
        "docs": "/api/docs",
        "api_base": "/api/v1",
    }
