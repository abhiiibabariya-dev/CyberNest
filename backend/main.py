"""CyberNest - SIEM + SOAR Platform"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from core.database import init_db
from api.routes import router as api_router
from api.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CyberNest",
    description="Unified SIEM + SOAR Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/ws")

# Serve frontend
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
