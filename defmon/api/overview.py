"""DefMon executive overview API endpoint."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import Alert, AuditLog, BlockedIP, Incident, IncidentStatus, User, UserRole

overview_router = APIRouter(prefix="/overview", tags=["Overview"])
allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])


@overview_router.get("")
async def get_overview(
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return an executive SOC overview for the last 24 hours."""
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)

    alerts_24h = await db.scalar(
        select(func.count(Alert.id)).where(Alert.timestamp >= twenty_four_hours_ago)
    ) or 0

    critical_24h = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.timestamp >= twenty_four_hours_ago,
            Alert.severity == "Critical",
        )
    ) or 0

    open_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.OPEN)
    ) or 0

    blocked_ips = await db.scalar(select(func.count(BlockedIP.id))) or 0

    actions_24h = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= twenty_four_hours_ago)
    ) or 0

    top_rule_row = (await db.execute(
        select(Alert.rule_id, func.count(Alert.id).label("count"))
        .where(Alert.timestamp >= twenty_four_hours_ago)
        .group_by(Alert.rule_id)
        .order_by(desc("count"))
        .limit(1)
    )).first()

    top_attacker_row = (await db.execute(
        select(Alert.ip, func.count(Alert.id).label("count"))
        .where(Alert.timestamp >= twenty_four_hours_ago)
        .group_by(Alert.ip)
        .order_by(desc("count"))
        .limit(1)
    )).first()

    response_per_alert = round((actions_24h / alerts_24h), 2) if alerts_24h else 0.0

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "alerts_24h": int(alerts_24h),
        "critical_24h": int(critical_24h),
        "open_incidents": int(open_incidents),
        "blocked_ips": int(blocked_ips),
        "actions_24h": int(actions_24h),
        "response_per_alert": response_per_alert,
        "top_rule": {
            "rule_id": top_rule_row[0],
            "count": int(top_rule_row[1]),
        } if top_rule_row else None,
        "top_attacker": {
            "ip": top_attacker_row[0],
            "count": int(top_attacker_row[1]),
        } if top_attacker_row else None,
    }
