"""SOAR response actions — the hands of the platform.

Every action is logged to the response_actions table for full auditability.
The notification engine dispatches alerts to console, log file, Slack, email,
and syslog CEF channels.
"""
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.core.models import BlockedIP, LockedAccount, ResponseAction
from backend.soar.notifications import send_notification


async def block_ip(session: AsyncSession, ip: str, reason: str,
                   alert_id: str = None, severity: str = None) -> bool:
    """Simulate blocking an IP via firewall / fail2ban.

    Returns True if newly blocked, False if already blocked.
    """
    existing = await session.execute(select(BlockedIP).where(BlockedIP.ip == ip))
    if existing.scalar_one_or_none():
        return False

    session.add(BlockedIP(ip=ip, reason=reason, alert_id=alert_id, severity=severity))
    session.add(ResponseAction(
        action_type="block_ip",
        target=ip,
        detail=f"Blocked IP via firewall simulation: {reason}",
        alert_id=alert_id,
    ))
    await session.commit()
    return True


async def add_to_blacklist_db(session: AsyncSession, ip: str, reason: str,
                              alert_id: str = None) -> None:
    """Add IP to the persistent blacklist."""
    session.add(ResponseAction(
        action_type="blacklist",
        target=ip,
        detail=f"Added to blacklist DB: {reason}",
        alert_id=alert_id,
    ))
    await session.commit()


async def send_alert_notification(session: AsyncSession, alert_data: dict,
                                  alert_id: str = None,
                                  context: dict = None) -> dict:
    """Dispatch alert through all notification channels.

    Sends to: console, log_file, slack, email, syslog CEF.
    Records each delivery in the response_actions table.
    """
    ctx = context or {}
    ctx["alert_id"] = alert_id

    # Dispatch through notification engine
    results = await send_notification(alert_data, context=ctx)

    # Record each channel delivery as a response action
    channels_delivered = [ch for ch, r in results.items() if r["status"] == "delivered"]
    channels_str = ", ".join(channels_delivered)

    msg = (
        f"[{alert_data['severity'].upper()}] {alert_data['rule_name']} | "
        f"IP: {alert_data['source_ip']} | "
        f"Notified via: {channels_str}"
    )
    session.add(ResponseAction(
        action_type="notify",
        target=channels_str,
        detail=msg,
        alert_id=alert_id,
    ))
    await session.commit()
    return results


async def log_response_action(session: AsyncSession, action_type: str,
                              target: str, detail: str,
                              alert_id: str = None, incident_id: str = None):
    session.add(ResponseAction(
        action_type=action_type,
        target=target,
        detail=detail,
        alert_id=alert_id,
        incident_id=incident_id,
    ))
    await session.commit()


async def lock_account(session: AsyncSession, username: str, source_ip: str,
                       reason: str, alert_id: str = None) -> bool:
    """Lock a compromised user account.

    Returns True if newly locked, False if already locked.
    """
    existing = await session.execute(
        select(LockedAccount).where(
            LockedAccount.username == username,
            LockedAccount.status == "locked",
        )
    )
    if existing.scalar_one_or_none():
        return False

    session.add(LockedAccount(
        username=username,
        source_ip=source_ip,
        reason=reason,
        alert_id=alert_id,
    ))
    session.add(ResponseAction(
        action_type="lock_account",
        target=username,
        detail=f"Locked account '{username}' — {reason}",
        alert_id=alert_id,
    ))
    await session.commit()
    return True
