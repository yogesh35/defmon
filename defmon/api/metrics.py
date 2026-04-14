"""DefMon Metrics API endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import Alert, Incident, IncidentStatus, User, UserRole

metrics_router = APIRouter(prefix="/metrics", tags=["Metrics"])

allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])


@metrics_router.get("")
async def get_metrics(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Calculate Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR).
    
    MTTD = Alert.created_at - Alert.timestamp
    MTTR = Incident.closed_at - Incident.created_at
    """
    # 1. Calculate MTTD
    result_alerts = await db.execute(
        select(Alert).limit(1000)  # Evaluate bounding past N alerts for performance
    )
    alerts = result_alerts.scalars().all()
    
    mttd_values = [
            max((a.created_at.replace(tzinfo=None) - a.timestamp.replace(tzinfo=None)).total_seconds(), 0)
            for a in alerts if a.created_at and a.timestamp
    ]
    mttd_seconds = round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else None

    # 2. Calculate MTTR
    result_incidents = await db.execute(
        select(Incident).where(Incident.status == IncidentStatus.CLOSED).limit(1000)
    )
    closed_incidents = result_incidents.scalars().all()
    
    mttr_values = [
            max((i.closed_at.replace(tzinfo=None) - i.created_at.replace(tzinfo=None)).total_seconds(), 0)
            for i in closed_incidents if i.closed_at and i.created_at
    ]
    mttr_seconds = round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else None

    return {
        "mttd_seconds": mttd_seconds,
        "mttr_seconds": mttr_seconds,
        "mttd_samples": len(mttd_values),
        "mttr_samples": len(mttr_values),
    }
