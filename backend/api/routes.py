"""FastAPI REST & WebSocket API routes."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session
from backend.core.models import Alert, Incident, LogEntry, BlockedIP, ResponseAction
from backend.api.websocket import ws_manager

router = APIRouter(prefix="/api")


# ── Alerts ───────────────────────────────────────────────────────────────────
@router.get("/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
):
    q = select(Alert).order_by(desc(Alert.timestamp))
    if severity:
        q = q.where(Alert.severity == severity)
    if status:
        q = q.where(Alert.status == status)
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    if rule_id:
        q = q.where(Alert.rule_id == rule_id)
    q = q.limit(limit).offset(offset)
    result = await session.execute(q)
    alerts = result.scalars().all()
    return [_alert_dict(a) for a in alerts]


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return {"error": "not found"}
    return _alert_dict(alert)


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, body: dict, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return {"error": "not found"}
    for field in ("status", "analyst_notes"):
        if field in body:
            setattr(alert, field, body[field])
    await session.commit()
    return _alert_dict(alert)


# ── Incidents ────────────────────────────────────────────────────────────────
@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
):
    q = select(Incident).order_by(desc(Incident.created_at))
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    q = q.limit(limit).offset(offset)
    result = await session.execute(q)
    return [_incident_dict(i) for i in result.scalars().all()]


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        return {"error": "not found"}
    return _incident_dict(inc)


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, body: dict, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        return {"error": "not found"}
    for field in ("status", "analyst_notes", "severity"):
        if field in body:
            setattr(inc, field, body[field])
    inc.updated_at = datetime.utcnow()
    await session.commit()
    return _incident_dict(inc)


# ── Logs ─────────────────────────────────────────────────────────────────────
@router.get("/logs")
async def search_logs(
    source_ip: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    url_contains: Optional[str] = None,
    log_source: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
):
    q = select(LogEntry).order_by(desc(LogEntry.timestamp))
    if source_ip:
        q = q.where(LogEntry.source_ip == source_ip)
    if method:
        q = q.where(LogEntry.method == method)
    if status_code:
        q = q.where(LogEntry.status_code == status_code)
    if url_contains:
        q = q.where(LogEntry.url.contains(url_contains))
    if log_source:
        q = q.where(LogEntry.log_source == log_source)
    q = q.limit(limit).offset(offset)
    result = await session.execute(q)
    return [_log_dict(l) for l in result.scalars().all()]


# ── Blocked IPs ──────────────────────────────────────────────────────────────
@router.get("/blocked-ips")
async def list_blocked_ips(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(BlockedIP).order_by(desc(BlockedIP.blocked_at)))
    return [
        {"id": b.id, "ip": b.ip, "reason": b.reason,
         "blocked_at": str(b.blocked_at), "severity": b.severity}
        for b in result.scalars().all()
    ]


@router.delete("/blocked-ips/{ip}")
async def unblock_ip(ip: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(BlockedIP).where(BlockedIP.ip == ip))
    entry = result.scalar_one_or_none()
    if not entry:
        return {"error": "not found"}
    await session.delete(entry)
    await session.commit()
    return {"status": "unblocked", "ip": ip}


# ── Response Actions ─────────────────────────────────────────────────────────
@router.get("/response-actions")
async def list_response_actions(
    limit: int = Query(100, le=500),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(ResponseAction).order_by(desc(ResponseAction.timestamp)).limit(limit)
    )
    return [
        {"id": r.id, "timestamp": str(r.timestamp), "action_type": r.action_type,
         "target": r.target, "detail": r.detail, "alert_id": r.alert_id,
         "incident_id": r.incident_id, "status": r.status}
        for r in result.scalars().all()
    ]


# ── Notification Logs ────────────────────────────────────────────────────────
@router.get("/notifications")
async def get_notification_logs(
    channel: Optional[str] = None,
    limit: int = Query(50, le=500),
):
    """Return recent notifications from all channels with raw log samples."""
    import json
    from backend.core.config import DATA_DIR

    files = {
        "notifications": DATA_DIR / "logs" / "notifications.log",
        "slack":         DATA_DIR / "logs" / "slack_webhooks.log",
        "email":         DATA_DIR / "logs" / "email_outbox.log",
        "syslog":        DATA_DIR / "logs" / "syslog_cef.log",
    }

    results = {}
    for name, path in files.items():
        if channel and channel != name:
            continue
        if not path.exists():
            results[name] = []
            continue
        lines = path.read_text().strip().split("\n")
        lines = [l for l in lines if l.strip()]
        lines = lines[-limit:]  # most recent
        lines.reverse()

        if name == "email":
            # Split emails by separator
            full = path.read_text()
            emails = full.split("=" * 60)
            entries = []
            for i in range(0, len(emails) - 1, 3):
                block = ("=" * 60).join(emails[i:i+3])
                if block.strip():
                    entries.append(block.strip())
            results[name] = entries[-limit:][::-1]
        elif name in ("notifications", "slack"):
            parsed = []
            for l in lines:
                try:
                    parsed.append(json.loads(l))
                except json.JSONDecodeError:
                    parsed.append({"raw": l})
            results[name] = parsed
        else:
            results[name] = lines

    return results


# ── Raw Log Viewer ───────────────────────────────────────────────────────────
@router.get("/raw-logs/{log_type}")
async def get_raw_logs(
    log_type: str,
    lines: int = Query(50, le=500),
):
    """Return the tail of a raw log file so analysts can see exact contents.

    log_type: access | auth | app | notifications | slack | email | syslog
    """
    from backend.core.config import DATA_DIR

    log_files = {
        "access":        DATA_DIR / "logs" / "access.log",
        "auth":          DATA_DIR / "logs" / "auth.log",
        "app":           DATA_DIR / "logs" / "app.log",
        "notifications": DATA_DIR / "logs" / "notifications.log",
        "slack":         DATA_DIR / "logs" / "slack_webhooks.log",
        "email":         DATA_DIR / "logs" / "email_outbox.log",
        "syslog":        DATA_DIR / "logs" / "syslog_cef.log",
    }

    path = log_files.get(log_type)
    if not path or not path.exists():
        return {"error": f"Unknown log type: {log_type}", "available": list(log_files.keys())}

    all_lines = path.read_text().strip().split("\n")
    all_lines = [l for l in all_lines if l.strip()]
    tail = all_lines[-lines:]

    return {
        "log_type": log_type,
        "file": str(path),
        "total_lines": len(all_lines),
        "showing": len(tail),
        "lines": tail,
    }


# ── Stats (dashboard) ────────────────────────────────────────────────────────
@router.get("/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    # Total counts
    total_logs = (await session.execute(select(func.count(LogEntry.id)))).scalar() or 0
    total_alerts = (await session.execute(select(func.count(Alert.id)))).scalar() or 0
    open_alerts = (await session.execute(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )).scalar() or 0
    total_incidents = (await session.execute(select(func.count(Incident.id)))).scalar() or 0
    open_incidents = (await session.execute(
        select(func.count(Incident.id)).where(Incident.status == "open")
    )).scalar() or 0
    total_blocked = (await session.execute(select(func.count(BlockedIP.id)))).scalar() or 0

    # Alerts by severity
    sev_q = await session.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in sev_q.all()}

    # Alerts by rule
    rule_q = await session.execute(
        select(Alert.rule_id, func.count(Alert.id)).group_by(Alert.rule_id).order_by(desc(func.count(Alert.id)))
    )
    by_rule = {row[0]: row[1] for row in rule_q.all()}

    # Top attacking IPs
    ip_q = await session.execute(
        select(Alert.source_ip, func.count(Alert.id)).group_by(Alert.source_ip)
        .order_by(desc(func.count(Alert.id))).limit(10)
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in ip_q.all()]

    # Recent alerts (last 20)
    recent_q = await session.execute(
        select(Alert).order_by(desc(Alert.timestamp)).limit(20)
    )
    recent_alerts = [_alert_dict(a) for a in recent_q.scalars().all()]

    # Geo data for map
    geo_q = await session.execute(
        select(Alert.source_ip, Alert.country, Alert.latitude, Alert.longitude,
               Alert.severity, func.count(Alert.id))
        .where(Alert.latitude.isnot(None))
        .group_by(Alert.source_ip, Alert.country, Alert.latitude, Alert.longitude, Alert.severity)
        .limit(200)
    )
    geo_points = [
        {"ip": r[0], "country": r[1], "lat": r[2], "lng": r[3],
         "severity": r[4], "count": r[5]}
        for r in geo_q.all()
    ]

    # Timeline (alerts per minute, last 30 minutes)
    timeline_q = await session.execute(
        select(Alert.timestamp).order_by(desc(Alert.timestamp)).limit(500)
    )
    timestamps = [row[0] for row in timeline_q.all()]
    timeline = _bucket_timestamps(timestamps)

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "total_blocked": total_blocked,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "top_ips": top_ips,
        "recent_alerts": recent_alerts,
        "geo_points": geo_points,
        "timeline": timeline,
    }


# ── WebSocket endpoint ───────────────────────────────────────────────────────
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _alert_dict(a: Alert) -> dict:
    return {
        "id": a.id, "timestamp": str(a.timestamp), "rule_id": a.rule_id,
        "rule_name": a.rule_name, "severity": a.severity,
        "risk_score": a.risk_score, "source_ip": a.source_ip,
        "description": a.description, "evidence": a.evidence,
        "mitre_tactic": a.mitre_tactic, "mitre_technique": a.mitre_technique,
        "mitre_name": a.mitre_name, "status": a.status,
        "incident_id": a.incident_id, "analyst_notes": a.analyst_notes,
        "country": a.country, "latitude": a.latitude, "longitude": a.longitude,
    }


def _incident_dict(i: Incident) -> dict:
    return {
        "id": i.id, "created_at": str(i.created_at),
        "updated_at": str(i.updated_at), "title": i.title,
        "severity": i.severity, "status": i.status,
        "description": i.description, "analyst_notes": i.analyst_notes,
        "source_ip": i.source_ip, "attack_type": i.attack_type,
        "mitre_tactic": i.mitre_tactic, "mitre_technique": i.mitre_technique,
    }


def _log_dict(l: LogEntry) -> dict:
    return {
        "id": l.id, "timestamp": str(l.timestamp), "source_ip": l.source_ip,
        "method": l.method, "url": l.url, "status_code": l.status_code,
        "user_agent": l.user_agent, "log_source": l.log_source,
        "country": l.country,
    }


def _bucket_timestamps(timestamps: list, buckets: int = 30) -> list[dict]:
    """Group timestamps into minute-buckets for the timeline chart."""
    if not timestamps:
        return []
    from collections import Counter
    counts = Counter()
    for ts in timestamps:
        key = ts.strftime("%H:%M") if hasattr(ts, "strftime") else str(ts)[:16]
        counts[key] += 1
    sorted_keys = sorted(counts.keys())[-buckets:]
    return [{"time": k, "count": counts[k]} for k in sorted_keys]
