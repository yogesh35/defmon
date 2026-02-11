"""SOAR Playbooks — automated response workflows triggered by alert severity.

Each playbook is a sequence of actions. The playbook runner selects the
appropriate playbook based on alert severity and executes every step.
"""
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.models import Alert, Incident
from backend.soar.actions import (
    block_ip,
    add_to_blacklist_db,
    send_alert_notification,
    log_response_action,
    lock_account,
)


# ── Playbook definitions ─────────────────────────────────────────────────────

PLAYBOOKS = {
    "critical": {
        "name": "Critical Threat Response",
        "steps": ["notify", "block_ip", "blacklist", "lock_account", "create_incident"],
        "description": "Immediate block + blacklist + lock accounts + incident ticket for critical threats",
    },
    "high": {
        "name": "High Threat Response",
        "steps": ["notify", "block_ip", "lock_account", "create_incident"],
        "description": "Block IP, lock compromised accounts, and create incident for high-severity threats",
    },
    "medium": {
        "name": "Medium Threat Response",
        "steps": ["notify", "create_incident"],
        "description": "Notify SOC and create investigation ticket",
    },
    "low": {
        "name": "Low Threat Response",
        "steps": ["notify"],
        "description": "Log and notify for awareness",
    },
}


async def execute_playbook(session: AsyncSession, alert_data: dict,
                           detection_engine) -> dict:
    """Run the playbook for a given alert. Returns summary of actions taken."""
    severity = alert_data.get("severity", "low")
    playbook = PLAYBOOKS.get(severity, PLAYBOOKS["low"])

    # Persist the alert
    alert = Alert(**alert_data)
    session.add(alert)
    await session.flush()  # get alert.id

    actions_taken = []
    incident_id = None

    for step in playbook["steps"]:
        if step == "notify":
            notify_ctx = {
                "actions_taken": list(actions_taken),
                "incident_id": incident_id,
                "playbook": playbook["name"],
            }
            await send_alert_notification(session, alert_data,
                                          alert_id=alert.id, context=notify_ctx)
            actions_taken.append("notification_sent")

        elif step == "block_ip":
            blocked = await block_ip(
                session, alert_data["source_ip"],
                reason=alert_data["description"],
                alert_id=alert.id,
                severity=severity,
            )
            if blocked:
                detection_engine.add_to_blacklist(alert_data["source_ip"])
                actions_taken.append("ip_blocked")
            else:
                actions_taken.append("ip_already_blocked")

        elif step == "blacklist":
            await add_to_blacklist_db(
                session, alert_data["source_ip"],
                reason=alert_data["description"],
                alert_id=alert.id,
            )
            detection_engine.add_to_blacklist(alert_data["source_ip"])
            actions_taken.append("ip_blacklisted")

        elif step == "create_incident":
            incident = Incident(
                id=str(uuid.uuid4()),
                title=f"[{severity.upper()}] {alert_data['rule_name']} from {alert_data['source_ip']}",
                severity=severity,
                description=alert_data["description"],
                source_ip=alert_data["source_ip"],
                attack_type=alert_data["rule_id"],
                mitre_tactic=alert_data.get("mitre_tactic"),
                mitre_technique=alert_data.get("mitre_technique"),
            )
            session.add(incident)
            await session.flush()
            alert.incident_id = incident.id
            incident_id = incident.id
            await log_response_action(
                session, "create_ticket", alert_data["source_ip"],
                f"Incident {incident.id[:8]}… created",
                alert_id=alert.id, incident_id=incident.id,
            )
            actions_taken.append("incident_created")

        elif step == "lock_account":
            # Lock accounts targeted by brute-force or credential attacks
            if alert_data.get("rule_id") in ("brute_force", "sql_injection"):
                target_user = _extract_target_user(alert_data)
                if target_user:
                    locked = await lock_account(
                        session, target_user, alert_data["source_ip"],
                        reason=alert_data["description"],
                        alert_id=alert.id,
                    )
                    if locked:
                        actions_taken.append("account_locked")
                    else:
                        actions_taken.append("account_already_locked")

    await session.commit()

    return {
        "alert_id": alert.id,
        "incident_id": incident_id,
        "playbook": playbook["name"],
        "actions_taken": actions_taken,
        "severity": severity,
        "source_ip": alert_data["source_ip"],
        "rule_name": alert_data["rule_name"],
    }


def _extract_target_user(alert_data: dict) -> str | None:
    """Extract the targeted username from alert evidence/description."""
    evidence = alert_data.get("evidence", "")
    # Try to extract username from auth log evidence
    import re
    m = re.search(r"for (\w+) from", evidence)
    if m:
        return m.group(1)
    # Try common patterns
    m = re.search(r"username[=:](\w+)", evidence)
    if m:
        return m.group(1)
    # Default for brute force alerts
    if alert_data.get("rule_id") == "brute_force":
        return "admin"
    return None
