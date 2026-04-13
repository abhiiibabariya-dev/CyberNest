"""CyberNest SIEM+SOAR — Multi-Tenant Entry Point"""
import asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from loguru import logger
from core.database import init_db
from core.config import settings
from api.routes import router as api_router
from api.ws import router as ws_router
from siem.detection import load_rules

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 55)
    logger.info("  CyberNest SIEM+SOAR v1.0 — Multi-Tenant")
    logger.info("=" * 55)
    await init_db()
    rules = load_rules()
    logger.info(f"[DB] Ready | [DETECTION] {len(rules)} rules loaded")
    logger.info(f"[VT]  VirusTotal:  {'configured' if settings.VIRUSTOTAL_API_KEY else 'set CYBERNEST_VIRUSTOTAL_API_KEY'}")
    logger.info(f"[AI]  AbuseIPDB:   {'configured' if settings.ABUSEIPDB_API_KEY else 'set CYBERNEST_ABUSEIPDB_API_KEY'}")
    logger.info(f"[SL]  Slack:       {'configured' if settings.SLACK_WEBHOOK_URL else 'set CYBERNEST_SLACK_WEBHOOK_URL'}")
    logger.info(f"[FW]  Firewall:    {settings.FIREWALL_TYPE}")
    if os.getenv("CYBERNEST_SYSLOG_ENABLED","false").lower() == "true":
        from siem.syslog_listener import start_syslog_listeners
        asyncio.create_task(start_syslog_listeners())
        logger.info(f"[SYSLOG] UDP:{settings.SYSLOG_UDP_PORT} TCP:{settings.SYSLOG_TCP_PORT}")
    logger.info("[READY] http://localhost:8000  |  docs: /api/docs")
    yield
    logger.info("[SHUTDOWN] CyberNest shutting down")

app = FastAPI(title="CyberNest SIEM+SOAR", version="1.0.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url="/api/redoc")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/ws")

dashboard_dist = os.path.join(os.path.dirname(__file__), "..", "dashboard", "dist")
if os.path.exists(dashboard_dist):
    app.mount("/", StaticFiles(directory=dashboard_dist, html=True), name="dashboard")
