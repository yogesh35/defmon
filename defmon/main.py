"""DefMon — FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from prometheus_fastapi_instrumentator import Instrumentator

from defmon.config import get_settings
from defmon.pipeline import DefmonPipeline

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown logic."""
    logger.info(f"🛡️ {settings.app_name} v{settings.version} starting up")
    pipeline = DefmonPipeline()
    pipeline_task = asyncio.create_task(pipeline.run())

    yield

    pipeline.stop()
    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        logger.info("DefMon runtime pipeline stopped")

    logger.info(f"🛡️ {settings.app_name} shutting down")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Enterprise Website Security Monitoring & Automated Incident Response",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint — returns 200 if API is running."""
    return {"status": "healthy", "service": settings.app_name, "version": settings.version}

# Add Prometheus Monitoring
Instrumentator().instrument(app).expose(app)


# Register API Routers
from defmon.api import auth_router, alerts_router, incidents_router, logs_router, metrics_router, ws_router, admin_router, audit_router, overview_router, reports_router, senders_router

app.include_router(auth_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")
app.include_router(overview_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(senders_router, prefix="/api")
app.include_router(ws_router, prefix="/api")
