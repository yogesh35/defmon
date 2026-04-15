"""DefMon audit API endpoints for SOAR action visibility."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import AuditLog, User, UserRole

audit_router = APIRouter(prefix="/audit", tags=["Audit"])
allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])


@audit_router.get("")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return latest SOAR response actions from immutable audit log."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.actor == "SOAR")
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
    )
    rows = result.scalars().all()

    return [
        {
            "id": row.id,
            "action": row.action,
            "actor": row.actor,
            "target": row.target,
            "details": row.details,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]
