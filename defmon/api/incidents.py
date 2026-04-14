"""DefMon Incidents API endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import Alert, Incident, IncidentStatus, SeverityLevel, User, UserRole

incidents_router = APIRouter(prefix="/incidents", tags=["Incidents"])

allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])
allow_write = RoleChecker([UserRole.ANALYST, UserRole.ADMIN])


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatus


@incidents_router.get("")
async def get_incidents(
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity_filter: Optional[SeverityLevel] = Query(None, alias="severity"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Retrieve paginated incidents, optionally filtering by status and severity."""
    query = select(Incident).options(selectinload(Incident.alert)).order_by(desc(Incident.created_at))
    
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if severity_filter:
        query = query.where(Incident.severity == severity_filter)
        
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    return [
        {
            "id": i.id,
            "case_id": str(i.case_id),
            "status": i.status,
            "severity": i.severity,
            "description": i.description,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "closed_at": i.closed_at.isoformat() if i.closed_at else None,
            "alert": {
                "alert_id": str(i.alert.alert_id),
                "ip": i.alert.ip,
                "rule_id": i.alert.rule_id,
            } if i.alert else None
        }
        for i in incidents
    ]


@incidents_router.get("/{case_id}")
async def get_incident(
    case_id: str,
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get full details for a specific incident tracker."""
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alert))
        .where(Incident.case_id == case_id)
    )
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        
    return {
        "id": incident.id,
        "case_id": str(incident.case_id),
        "status": incident.status,
        "severity": incident.severity,
        "description": incident.description,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        "alert": {
            "alert_id": str(incident.alert.alert_id),
            "timestamp": incident.alert.timestamp.isoformat(),
            "ip": incident.alert.ip,
            "rule_id": incident.alert.rule_id,
            "severity": incident.alert.severity,
            "description": incident.alert.description,
            "risk_score": incident.alert.risk_score,
            "tags": incident.alert.tags,
            "raw_event": incident.alert.raw_event
        } if incident.alert else None
    }


@incidents_router.patch("/{case_id}/status")
async def update_incident_status(
    case_id: str,
    payload: IncidentStatusUpdateRequest,
    user: User = Depends(allow_write),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update incident status with minimal lifecycle transitions."""
    allowed_statuses = {IncidentStatus.OPEN, IncidentStatus.CLOSED}
    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="status must be one of: open, closed",
        )

    try:
        parsed_case_id = uuid.UUID(case_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid case_id") from exc

    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alert))
        .where(Incident.case_id == parsed_case_id)
    )
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident.status = payload.status
    if payload.status == IncidentStatus.CLOSED:
        incident.closed_at = datetime.now(timezone.utc)
    else:
        incident.closed_at = None

    incident.updated_at = datetime.now(timezone.utc)
    await db.flush()

    return {
        "case_id": str(incident.case_id),
        "status": incident.status,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
    }
