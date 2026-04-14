"""DefMon Alerts API points."""

import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import Alert, User, UserRole

alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])

# Viewers, analysts, and admins can read alerts
allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])
allow_write = RoleChecker([UserRole.ANALYST, UserRole.ADMIN])


class AlertStatusUpdateRequest(BaseModel):
    status: str


@alerts_router.get("")
async def get_alerts(
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Retrieve chronologically ordered alerts."""
    result = await db.execute(
        select(Alert)
        .order_by(desc(Alert.timestamp))
        .offset(offset)
        .limit(limit)
    )
    alerts = result.scalars().all()
    # Pydantic serialization is better, but returning mapped dicts is okay
    return [
        {
            "id": a.id,
            "alert_id": str(a.alert_id),
            "timestamp": a.timestamp.isoformat(),
            "ip": a.ip,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "description": a.description,
            "risk_score": a.risk_score,
            "tags": a.tags,
            "status": a.status,
        }
        for a in alerts
    ]


@alerts_router.get("/summary")
async def get_alerts_summary(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    """Get Critical/High/Medium/Low counts from the last 24 hours."""
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    
    result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.timestamp >= twenty_four_hours_ago)
        .group_by(Alert.severity)
    )
    counts = {
        (severity.value if hasattr(severity, "value") else severity): count
        for severity, count in result.all()
    }
    
    return {
        "Critical": counts.get("Critical", 0),
        "High": counts.get("High", 0),
        "Medium": counts.get("Medium", 0),
        "Low": counts.get("Low", 0),
    }


@alerts_router.get("/top-offenders")
async def get_top_offenders(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Top 10 attacker IPs by alert count in the last 24 hours."""
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    
    result = await db.execute(
        select(Alert.ip, func.count(Alert.id).label("total_alerts"))
        .where(Alert.timestamp >= twenty_four_hours_ago)
        .group_by(Alert.ip)
        .order_by(desc("total_alerts"))
        .limit(10)
    )
    
    offenders = []
    for ip, count in result.all():
        offenders.append({
            "ip": ip,
            "alerts": count
        })
    return offenders


@alerts_router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdateRequest,
    user: User = Depends(allow_write),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update alert triage status (acknowledged or resolved)."""
    allowed_statuses = {"acknowledged", "resolved"}
    next_status = payload.status.strip().lower()
    if next_status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="status must be one of: acknowledged, resolved",
        )

    try:
        parsed_alert_id = uuid.UUID(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid alert_id") from exc

    result = await db.execute(select(Alert).where(Alert.alert_id == parsed_alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert.status = next_status
    await db.flush()

    return {
        "alert_id": str(alert.alert_id),
        "status": alert.status,
    }
