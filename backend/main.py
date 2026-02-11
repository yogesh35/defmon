"""Defmon — FastAPI application entry point."""
import asyncio
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.core.database import init_db, async_session
from backend.core.config import LOG_FILE, AUTH_LOG_FILE, APP_LOG_FILE
from backend.core.models import LogEntry, User
from backend.core.auth import hash_password
from backend.detection.engine import DetectionEngine
from backend.soar.playbooks import execute_playbook
from backend.collectors.log_collector import LogCollector
from backend.api.routes import router, websocket_endpoint
from backend.api.websocket import ws_manager
from backend.utils.geoip import geoip_lookup
from backend.utils.threat_intel import enrich_alert, init_threat_intel

app = FastAPI(title="Defmon", version="1.0.0",
              description="Website Security Monitoring & Automated Response — SIEM + SOAR")
app.include_router(router)

# Globals
detection_engine = DetectionEngine()

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "frontend", "static")

# Serve static files
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.websocket("/ws/live-feed")
async def ws_live(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
    except Exception:
        await ws_manager.disconnect(ws)


@app.on_event("startup")
async def startup():
    await init_db()

    # Initialize threat intelligence
    count = init_threat_intel()
    print(f"🛡️ Defmon — Loaded {count} threat intelligence indicators")

    # Seed blocked IPs from config
    from backend.core.config import SEED_BLACKLIST
    from backend.core.models import BlockedIP
    from sqlalchemy import select
    async with async_session() as session:
        for ip in SEED_BLACKLIST:
            existing = await session.execute(select(BlockedIP).where(BlockedIP.ip == ip))
            if not existing.scalar_one_or_none():
                session.add(BlockedIP(ip=ip, reason="Seed blacklist", severity="critical"))
        await session.commit()

    # Seed default admin and analyst users
    async with async_session() as session:
        existing = await session.execute(select(User).where(User.username == "admin"))
        if not existing.scalar_one_or_none():
            session.add(User(
                username="admin",
                password_hash=hash_password("admin123"),
                role="admin",
                full_name="Administrator",
                email="admin@defmon.local",
            ))
            session.add(User(
                username="analyst",
                password_hash=hash_password("analyst123"),
                role="analyst",
                full_name="SOC Analyst",
                email="analyst@defmon.local",
            ))
            await session.commit()
            print("👤 Default users created: admin/admin123, analyst/analyst123")

    # Start log collector in background
    asyncio.create_task(_run_collector())


async def _run_collector():
    """Background task: tail log files → detect → respond → broadcast."""
    collector = LogCollector({
        "access": LOG_FILE,
        "auth": AUTH_LOG_FILE,
        "app": APP_LOG_FILE,
    })

    async def on_log(parsed_log):
        geo = geoip_lookup(parsed_log.source_ip)

        # 1. Store log entry
        async with async_session() as session:
            entry = LogEntry(
                timestamp=parsed_log.timestamp,
                source_ip=parsed_log.source_ip,
                method=parsed_log.method,
                url=parsed_log.url,
                status_code=parsed_log.status_code,
                user_agent=parsed_log.user_agent,
                body=parsed_log.body,
                log_source=parsed_log.log_source,
                raw_line=parsed_log.raw_line,
                country=geo["country"],
                city=geo["city"],
                latitude=geo["latitude"],
                longitude=geo["longitude"],
            )
            session.add(entry)
            await session.commit()

        # 2. Run detection
        alerts = await detection_engine.analyze(parsed_log)

        # 3. For each alert → enrich with threat intel → SOAR playbook → broadcast
        for alert_data in alerts:
            alert_data["country"] = geo["country"]
            alert_data["latitude"] = geo["latitude"]
            alert_data["longitude"] = geo["longitude"]

            # Enrich with threat intelligence
            enrich_alert(alert_data)

            async with async_session() as session:
                result = await execute_playbook(session, alert_data, detection_engine)

            # Broadcast to dashboard
            await ws_manager.broadcast({
                "type": "alert",
                "data": {
                    **result,
                    "timestamp": str(parsed_log.timestamp),
                    "description": alert_data["description"],
                    "country": geo["country"],
                    "latitude": geo["latitude"],
                    "longitude": geo["longitude"],
                    "mitre_technique": alert_data.get("mitre_technique"),
                },
            })

    await collector.tail(on_log)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
