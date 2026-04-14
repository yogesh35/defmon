"""DefMon sender management and remote ingest endpoints."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.api.websocket import manager
from defmon.database import get_db
from defmon.detection.engine import DetectionEngine, Alert as DetectionAlert
from defmon.models import (
    Alert,
    AuditLog,
    LogEntry,
    LogSender,
    SeverityLevel,
    User,
    UserRole,
)
from defmon.parser import LogParser
from defmon.soar.playbooks import get_playbook_engine
from defmon.utils.threat_intel import ThreatIntelService

senders_router = APIRouter(prefix="/senders", tags=["Senders"])
allow_admin = RoleChecker([UserRole.ADMIN])

_parser = LogParser()
_detector = DetectionEngine()
_intel = ThreatIntelService()
_playbook = get_playbook_engine()


class CreateSenderRequest(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    description: str = Field(default="", max_length=500)
    allowed_ip: str | None = Field(default=None, max_length=45)


class ToggleBlockRequest(BaseModel):
    is_blocked: bool
    reason: str = Field(default="", max_length=500)


class ToggleActiveRequest(BaseModel):
    is_active: bool


class IngestRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=2000)


class IngestResponse(BaseModel):
    sender_id: str
    sender_name: str
    accepted_lines: int
    rejected_lines: int
    generated_alerts: int
    malicious_lines: int
    normal_lines: int


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _new_sender_id() -> str:
    return f"snd_{secrets.token_hex(8)}"


def _new_api_key() -> str:
    return f"dmsk_{secrets.token_urlsafe(32)}"


def _to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _to_severity(value: str) -> SeverityLevel:
    try:
        return SeverityLevel(value)
    except ValueError:
        return SeverityLevel.LOW


async def _write_audit(
    db: AsyncSession,
    action: str,
    actor: str,
    target: str,
    details: str,
) -> None:
    db.add(
        AuditLog(
            action=action,
            actor=actor,
            target=target,
            details=details,
            timestamp=datetime.utcnow(),
        )
    )


def _serialize_sender(sender: LogSender) -> dict:
    return {
        "id": sender.id,
        "name": sender.name,
        "description": sender.description,
        "allowed_ip": sender.allowed_ip,
        "is_active": sender.is_active,
        "is_blocked": sender.is_blocked,
        "block_reason": sender.block_reason,
        "created_by": sender.created_by,
        "created_at": sender.created_at.isoformat() if sender.created_at else None,
        "updated_at": sender.updated_at.isoformat() if sender.updated_at else None,
        "last_seen_at": sender.last_seen_at.isoformat() if sender.last_seen_at else None,
        "last_log_preview": sender.last_log_preview,
    }


@senders_router.get("")
async def list_senders(
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    rows = await db.execute(select(LogSender).order_by(desc(LogSender.created_at)))
    return [_serialize_sender(sender) for sender in rows.scalars().all()]


@senders_router.post("", status_code=status.HTTP_201_CREATED)
async def create_sender(
    payload: CreateSenderRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    existing = await db.execute(select(LogSender).where(LogSender.name == payload.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Sender name already exists")

    raw_key = _new_api_key()
    sender = LogSender(
        id=_new_sender_id(),
        name=payload.name,
        description=payload.description,
        api_key_hash=_hash_api_key(raw_key),
        allowed_ip=payload.allowed_ip,
        is_active=True,
        is_blocked=False,
        block_reason="",
        created_by=user.username,
    )
    db.add(sender)
    await db.flush()

    await _write_audit(
        db,
        action="SENDER_CREATED",
        actor=user.username,
        target=sender.id,
        details=f"name={sender.name}",
    )

    return {"sender": _serialize_sender(sender), "api_key": raw_key}


@senders_router.patch("/{sender_id}/block")
async def block_or_unblock_sender(
    sender_id: str,
    payload: ToggleBlockRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(LogSender).where(LogSender.id == sender_id))
    sender = result.scalar_one_or_none()
    if sender is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")

    sender.is_blocked = payload.is_blocked
    sender.block_reason = payload.reason if payload.is_blocked else ""
    await db.flush()

    await _write_audit(
        db,
        action="SENDER_BLOCKED" if payload.is_blocked else "SENDER_UNBLOCKED",
        actor=user.username,
        target=sender.id,
        details=sender.block_reason or "manual toggle",
    )

    return {"sender": _serialize_sender(sender)}


@senders_router.patch("/{sender_id}/active")
async def set_sender_active(
    sender_id: str,
    payload: ToggleActiveRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(LogSender).where(LogSender.id == sender_id))
    sender = result.scalar_one_or_none()
    if sender is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")

    sender.is_active = payload.is_active
    await db.flush()

    await _write_audit(
        db,
        action="SENDER_ACTIVATED" if payload.is_active else "SENDER_DEACTIVATED",
        actor=user.username,
        target=sender.id,
        details=f"name={sender.name}",
    )

    return {"sender": _serialize_sender(sender)}


@senders_router.post("/{sender_id}/revoke-key")
async def revoke_sender_key(
    sender_id: str,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(LogSender).where(LogSender.id == sender_id))
    sender = result.scalar_one_or_none()
    if sender is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")

    raw_key = _new_api_key()
    sender.api_key_hash = _hash_api_key(raw_key)
    sender.updated_at = datetime.utcnow()
    await db.flush()

    await _write_audit(
        db,
        action="SENDER_KEY_REVOKED",
        actor=user.username,
        target=sender.id,
        details=f"name={sender.name}",
    )

    return {"sender": _serialize_sender(sender), "api_key": raw_key}


@senders_router.delete("/{sender_id}")
async def delete_sender(
    sender_id: str,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(LogSender).where(LogSender.id == sender_id))
    sender = result.scalar_one_or_none()
    if sender is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")

    await _write_audit(
        db,
        action="SENDER_DELETED",
        actor=user.username,
        target=sender.id,
        details=f"name={sender.name}",
    )
    await db.delete(sender)
    return {"deleted": True, "sender_id": sender_id}


@senders_router.post("/ingest", response_model=IngestResponse)
async def ingest_remote_logs(
    payload: IngestRequest,
    request: Request,
    sender_id: str = Query(..., description="Sender ID issued by admin"),
    sender_key: str = Query(..., description="Sender API key issued by admin"),
    db: AsyncSession = Depends(get_db),
) -> IngestResponse:
    row = await db.execute(select(LogSender).where(LogSender.id == sender_id))
    sender = row.scalar_one_or_none()
    if sender is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown sender")

    if sender.api_key_hash != _hash_api_key(sender_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sender key")

    if not sender.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sender is inactive")

    if sender.is_blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sender is blocked")

    source_ip = request.client.host if request.client else None
    if sender.allowed_ip and source_ip and sender.allowed_ip != source_ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sender IP not allowed")

    accepted = 0
    rejected = 0
    generated_alerts = 0
    malicious_lines = 0
    normal_lines = 0

    for line in payload.lines:
        event = _parser.parse_line(line)
        if event is None:
            rejected += 1
            continue

        accepted += 1
        intel = await _intel.lookup_ip(event.ip)
        alerts = await _detector.analyze(event, threat_intel_score=float(intel.confidence_score))
        is_malicious = len(alerts) > 0
        if is_malicious:
            malicious_lines += 1
        else:
            normal_lines += 1

        db.add(
            LogEntry(
                timestamp=_to_naive_utc(event.timestamp),
                ip=event.ip,
                method=event.method,
                uri=event.uri,
                status_code=event.status_code,
                bytes_sent=event.bytes_sent,
                user_agent=event.user_agent,
                referrer=event.referrer,
                raw_line=event.raw_line,
                sender_id=sender.id,
                sender_name=sender.name,
                classification="malicious" if is_malicious else "normal",
                is_malicious=is_malicious,
                created_at=datetime.utcnow(),
            )
        )

        for alert in alerts:
            generated_alerts += 1
            merged_tags = list(dict.fromkeys([*alert.tags, *intel.tags]))
            db_alert = Alert(
                alert_id=uuid.UUID(alert.alert_id),
                timestamp=_to_naive_utc(alert.timestamp),
                ip=alert.ip,
                rule_id=alert.rule_id,
                severity=_to_severity(alert.severity),
                description=alert.description,
                raw_event=alert.raw_event,
                risk_score=alert.risk_score,
                tags=merged_tags,
                status="new",
                created_at=datetime.utcnow(),
            )
            db.add(db_alert)
            await db.flush()

            playbook_result = await _playbook.execute(alert=alert, session=db)
            incident = playbook_result.get("incident")

            await manager.broadcast(
                {
                    "type": "alert",
                    "alert": {
                        "alert_id": alert.alert_id,
                        "timestamp": alert.timestamp.isoformat(),
                        "ip": alert.ip,
                        "rule_id": alert.rule_id,
                        "severity": alert.severity,
                        "description": alert.description,
                        "risk_score": alert.risk_score,
                        "tags": merged_tags,
                        "status": "new",
                    },
                    "incident_case_id": str(incident.case_id) if incident else None,
                }
            )

    sender.last_seen_at = datetime.utcnow()
    if accepted > 0:
        sender.last_log_preview = payload.lines[-1][:300]

    await _write_audit(
        db,
        action="SENDER_INGEST",
        actor=sender.name,
        target=sender.id,
        details=(
            f"accepted={accepted}, rejected={rejected}, alerts={generated_alerts}, "
            f"malicious={malicious_lines}, normal={normal_lines}"
        ),
    )

    return IngestResponse(
        sender_id=sender.id,
        sender_name=sender.name,
        accepted_lines=accepted,
        rejected_lines=rejected,
        generated_alerts=generated_alerts,
        malicious_lines=malicious_lines,
        normal_lines=normal_lines,
    )
