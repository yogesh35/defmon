"""DefMon reporting API for downloadable SOC snapshots."""

import csv
from io import StringIO
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import Alert, AuditLog, Incident, IncidentStatus, User, UserRole

reports_router = APIRouter(prefix="/reports", tags=["Reports"])
allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])


async def _build_daily_report(db: AsyncSession) -> dict:
    now = datetime.utcnow()
    since = now - timedelta(hours=24)

    summary = {
        "alerts_24h": int(await db.scalar(select(func.count(Alert.id)).where(Alert.timestamp >= since)) or 0),
        "critical_24h": int(await db.scalar(select(func.count(Alert.id)).where(Alert.timestamp >= since, Alert.severity == "Critical")) or 0),
        "open_incidents": int(await db.scalar(select(func.count(Incident.id)).where(Incident.status == IncidentStatus.OPEN)) or 0),
        "actions_24h": int(await db.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.timestamp >= since,
                AuditLog.actor == "SOAR",
            )
        ) or 0),
    }

    recent_incidents_rows = (await db.execute(
        select(Incident).order_by(desc(Incident.created_at)).limit(20)
    )).scalars().all()

    recent_actions_rows = (await db.execute(
        select(AuditLog)
        .where(AuditLog.actor == "SOAR")
        .order_by(desc(AuditLog.timestamp))
        .limit(50)
    )).scalars().all()

    return {
        "report_type": "defmon_daily_soc_report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": "last_24_hours",
        "summary": summary,
        "recent_incidents": [
            {
                "case_id": str(i.case_id),
                "status": i.status.value if hasattr(i.status, "value") else str(i.status),
                "severity": i.severity.value if hasattr(i.severity, "value") else str(i.severity),
                "description": i.description,
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "closed_at": i.closed_at.isoformat() if i.closed_at else None,
            }
            for i in recent_incidents_rows
        ],
        "recent_actions": [
            {
                "action": a.action,
                "actor": a.actor,
                "target": a.target,
                "details": a.details,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in recent_actions_rows
        ],
    }


@reports_router.get("/daily")
async def get_daily_report(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
):
    """Return a daily SOC report payload as JSON."""
    payload = await _build_daily_report(db)
    return JSONResponse(content=payload)


@reports_router.get("/daily/download")
async def download_daily_report(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
):
    """Download a daily SOC report as a CSV file."""
    payload = await _build_daily_report(db)
    filename = f"defmon_daily_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "field", "value", "timestamp", "case_id", "status", "severity", "description", "actor", "target", "details"])

    writer.writerow(["report", "report_type", payload["report_type"], "", "", "", "", "", "", "", ""])
    writer.writerow(["report", "generated_at", payload["generated_at"], "", "", "", "", "", "", "", ""])
    writer.writerow(["report", "window", payload["window"], "", "", "", "", "", "", "", ""])

    for key, value in payload["summary"].items():
        writer.writerow(["summary", key, value, "", "", "", "", "", "", "", ""])

    for incident in payload["recent_incidents"]:
        writer.writerow([
            "incident",
            "",
            "",
            incident.get("created_at") or "",
            incident.get("case_id") or "",
            incident.get("status") or "",
            incident.get("severity") or "",
            incident.get("description") or "",
            "",
            "",
            "",
        ])

    for action in payload["recent_actions"]:
        writer.writerow([
            "action",
            action.get("action") or "",
            "",
            action.get("timestamp") or "",
            "",
            "",
            "",
            "",
            action.get("actor") or "",
            action.get("target") or "",
            action.get("details") or "",
        ])

    body = output.getvalue()

    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
