"""DefMon SOAR Actions — automated response functions for security incidents.

All actions write an audit log entry BEFORE performing the action to maintain
an immutable audit trail. Each function is async and interacts with the database
via SQLAlchemy async sessions.

Actions:
- block_ip: Block an IP address in the database (and optionally system-level).
- lock_account: Lock a user account in the database.
- create_incident: Create an incident record linked to an alert.
- send_alert_notification: POST alert to a webhook URL.
"""

import os
import uuid
from datetime import datetime
from typing import Optional

import httpx
from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.config import get_settings
from defmon.models import AuditLog, BlockedIP, Incident, IncidentStatus, SeverityLevel, User


# Import Alert from detection engine (the dataclass, not the ORM model)
from defmon.detection.engine import Alert


# ---------------------------------------------------------------------------
# Audit Trail Helper
# ---------------------------------------------------------------------------
async def _write_audit_log(
    session: AsyncSession,
    action: str,
    target: str,
    details: str = "",
) -> None:
    """Write an immutable audit log entry BEFORE executing the action.

    Args:
        session: Active database session.
        action: Action being performed (e.g., 'block_ip', 'lock_account').
        target: Target of the action (e.g., IP address, username).
        details: Optional additional context.
    """
    audit_entry = AuditLog(
        action=action,
        actor="SOAR",
        target=target,
        details=details,
        timestamp=datetime.utcnow(),
    )
    session.add(audit_entry)
    await session.flush()
    logger.info(f"Audit log: action={action}, actor=SOAR, target={target}")


# ---------------------------------------------------------------------------
# block_ip
# ---------------------------------------------------------------------------
async def block_ip(ip: str, session: AsyncSession, reason: str = "") -> None:
    """Block an IP address by writing to the blocked_ips table.

    If config flag use_system_block=true and process is root, also appends
    to /etc/hosts.deny for system-level blocking.

    Writes audit log BEFORE performing the action.

    Args:
        ip: IP address to block.
        session: Active database session.
        reason: Optional reason for blocking.
    """
    # Audit trail FIRST
    await _write_audit_log(
        session,
        action="block_ip",
        target=ip,
        details=f"Reason: {reason}" if reason else "Automated SOAR block",
    )

    # Check if IP is already blocked
    result = await session.execute(
        select(BlockedIP).where(BlockedIP.ip == ip)
    )
    existing = result.scalar_one_or_none()

    if existing:
        logger.info(f"IP {ip} is already blocked — skipping DB insert")
    else:
        blocked = BlockedIP(
            ip=ip,
            reason=reason or "Automated SOAR block",
            blocked_at=datetime.utcnow(),
            blocked_by="SOAR",
        )
        session.add(blocked)
        await session.flush()
        logger.info(f"Blocked IP {ip} in database")

    # System-level blocking (optional)
    settings = get_settings()
    soar_config = settings.soar_config
    if soar_config.get("use_system_block", False):
        try:
            if os.getuid() == 0:  # Check if root
                with open("/etc/hosts.deny", "a") as f:
                    f.write(f"ALL: {ip}\n")
                logger.info(f"Added {ip} to /etc/hosts.deny")
            else:
                logger.warning(
                    f"Cannot write to /etc/hosts.deny — process is not root"
                )
        except (AttributeError, OSError) as e:
            # os.getuid() not available on Windows, or file write error
            logger.warning(f"System-level block failed for {ip}: {e}")


# ---------------------------------------------------------------------------
# lock_account
# ---------------------------------------------------------------------------
async def lock_account(username: str, session: AsyncSession) -> None:
    """Lock a user account by setting is_locked=True in the database.

    Writes audit log BEFORE performing the action.

    Args:
        username: Username to lock.
        session: Active database session.
    """
    # Audit trail FIRST
    await _write_audit_log(
        session,
        action="lock_account",
        target=username,
        details="Automated SOAR account lock due to security alert",
    )

    # Update user record
    result = await session.execute(
        update(User)
        .where(User.username == username)
        .values(is_locked=True)
        .returning(User.id)
    )
    updated = result.scalar_one_or_none()

    if updated:
        logger.info(f"Locked user account: {username}")
    else:
        logger.warning(f"User account not found for locking: {username}")


# ---------------------------------------------------------------------------
# create_incident
# ---------------------------------------------------------------------------
async def create_incident(alert: Alert, session: AsyncSession) -> Incident:
    """Create an Incident record linked to an alert.

    Writes audit log BEFORE performing the action.

    Args:
        alert: Alert dataclass from the detection engine.
        session: Active database session.

    Returns:
        Created Incident ORM object.
    """
    case_id = uuid.uuid4()

    # Audit trail FIRST
    await _write_audit_log(
        session,
        action="create_incident",
        target=str(case_id),
        details=f"Alert: {alert.alert_id}, Rule: {alert.rule_id}, IP: {alert.ip}",
    )

    # Map severity string to enum
    severity_map = {
        "Critical": SeverityLevel.CRITICAL,
        "High": SeverityLevel.HIGH,
        "Medium": SeverityLevel.MEDIUM,
        "Low": SeverityLevel.LOW,
    }
    severity_enum = severity_map.get(alert.severity, SeverityLevel.LOW)

    incident = Incident(
        case_id=case_id,
        alert_id=uuid.UUID(alert.alert_id),
        status=IncidentStatus.OPEN,
        severity=severity_enum,
        description=(
            f"Auto-generated incident for {alert.rule_id}: {alert.description}"
        ),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    session.add(incident)
    await session.flush()

    logger.info(
        f"Created incident {case_id} for alert {alert.alert_id} "
        f"(rule={alert.rule_id}, severity={alert.severity})"
    )
    return incident


# ---------------------------------------------------------------------------
# send_alert_notification
# ---------------------------------------------------------------------------
async def send_alert_notification(alert: Alert, session: AsyncSession) -> None:
    """Send alert notification by POSTing JSON to the configured webhook URL.

    Fails silently with a Loguru warning if WEBHOOK_URL is unset.
    Writes audit log BEFORE performing the action.

    Args:
        alert: Alert dataclass from the detection engine.
        session: Active database session.
    """
    webhook_url = os.getenv("WEBHOOK_URL", "")

    # Audit trail FIRST
    await _write_audit_log(
        session,
        action="send_alert_notification",
        target=webhook_url or "no_webhook",
        details=f"Alert: {alert.alert_id}, Severity: {alert.severity}",
    )

    if not webhook_url:
        logger.warning(
            "WEBHOOK_URL not set — skipping alert notification for "
            f"alert {alert.alert_id}"
        )
        return

    payload = {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp.isoformat(),
        "ip": alert.ip,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "description": alert.description,
        "risk_score": alert.risk_score,
        "tags": alert.tags,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
        logger.info(
            f"Alert notification sent for {alert.alert_id} "
            f"to {webhook_url} (status={response.status_code})"
        )
    except httpx.TimeoutException:
        logger.warning(
            f"Webhook timeout sending alert {alert.alert_id} to {webhook_url}"
        )
    except httpx.HTTPStatusError as e:
        logger.warning(
            f"Webhook HTTP error for alert {alert.alert_id}: "
            f"{e.response.status_code}"
        )
    except Exception as e:
        logger.warning(
            f"Webhook unexpected error for alert {alert.alert_id}: {e}"
        )
