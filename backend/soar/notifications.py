"""Notification Engine — multi-channel alert delivery system.

Supports multiple notification channels, each with its own formatter
and delivery mechanism. All notifications are persisted to DB and to
a dedicated log file for forensic review.

Channels:
  - console   : Colored terminal output (always on)
  - log_file  : Appends to data/logs/notifications.log
  - slack     : Simulated Slack webhook (writes JSON payload)
  - email     : Simulated email (writes .eml-style output)
  - syslog    : Simulated syslog CEF format
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from backend.core.config import DATA_DIR, MITRE_MAP

# ── Paths ─────────────────────────────────────────────────────────────────────
NOTIFY_LOG = DATA_DIR / "logs" / "notifications.log"
SLACK_LOG = DATA_DIR / "logs" / "slack_webhooks.log"
EMAIL_LOG = DATA_DIR / "logs" / "email_outbox.log"
SYSLOG_LOG = DATA_DIR / "logs" / "syslog_cef.log"

# Ensure files exist
for f in [NOTIFY_LOG, SLACK_LOG, EMAIL_LOG, SYSLOG_LOG]:
    f.parent.mkdir(parents=True, exist_ok=True)
    f.touch(exist_ok=True)

# ── ANSI colors for console output ───────────────────────────────────────────
_COLORS = {
    "critical": "\033[1;97;41m",  # white on red
    "high":     "\033[1;93;43m",  # yellow on orange
    "medium":   "\033[1;30;43m",  # black on yellow
    "low":      "\033[1;30;42m",  # black on green
    "info":     "\033[1;37;44m",  # white on blue
    "reset":    "\033[0m",
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── Channel: Console ─────────────────────────────────────────────────────────
def notify_console(alert_data: dict, context: dict = None) -> str:
    """Print a color-coded alert to the terminal."""
    sev = alert_data.get("severity", "info")
    color = _COLORS.get(sev, _COLORS["info"])
    reset = _COLORS["reset"]
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")

    mitre = ""
    if alert_data.get("mitre_technique"):
        mitre = f" [{alert_data['mitre_technique']}]"

    actions = ""
    if context and context.get("actions_taken"):
        actions = f" → {', '.join(context['actions_taken'])}"

    msg = (
        f"{color} {sev.upper():>8} {reset} "
        f"{emoji} {alert_data.get('rule_name', 'Unknown Rule')}"
        f"{mitre}\n"
        f"           IP: {alert_data.get('source_ip', '?')}"
        f"  |  {alert_data.get('description', '')}"
        f"{actions}\n"
    )
    print(msg, flush=True)
    return msg


# ── Channel: Log File ────────────────────────────────────────────────────────
def notify_log_file(alert_data: dict, context: dict = None) -> str:
    """Append a structured log line to notifications.log."""
    entry = {
        "timestamp": _now_iso(),
        "channel": "log_file",
        "severity": alert_data.get("severity"),
        "rule_id": alert_data.get("rule_id"),
        "rule_name": alert_data.get("rule_name"),
        "source_ip": alert_data.get("source_ip"),
        "description": alert_data.get("description"),
        "mitre_technique": alert_data.get("mitre_technique"),
        "mitre_tactic": alert_data.get("mitre_tactic"),
        "risk_score": alert_data.get("risk_score"),
        "country": alert_data.get("country"),
        "actions_taken": context.get("actions_taken") if context else [],
        "alert_id": context.get("alert_id") if context else None,
        "incident_id": context.get("incident_id") if context else None,
    }
    line = json.dumps(entry, default=str)
    with open(NOTIFY_LOG, "a") as f:
        f.write(line + "\n")
    return line


# ── Channel: Slack Webhook (simulated) ───────────────────────────────────────
def notify_slack(alert_data: dict, context: dict = None) -> str:
    """Simulate a Slack incoming webhook POST.

    In production, replace with:
        httpx.post(SLACK_WEBHOOK_URL, json=payload)
    """
    sev = alert_data.get("severity", "info").upper()
    emoji = _SEVERITY_EMOJI.get(alert_data.get("severity", "info"), "⚪")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} [{sev}] {alert_data.get('rule_name', 'Alert')}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source IP:*\n`{alert_data.get('source_ip', '?')}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev} (score: {alert_data.get('risk_score', 0)})"},
                {"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{alert_data.get('mitre_technique', 'N/A')} — {alert_data.get('mitre_name', '')}"},
                {"type": "mrkdwn", "text": f"*Country:*\n{alert_data.get('country', '?')}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{alert_data.get('description', '')}"}
        },
    ]

    if context and context.get("actions_taken"):
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*SOAR Actions:*\n• " + "\n• ".join(context["actions_taken"])}
        })

    if context and context.get("incident_id"):
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Incident: `{context['incident_id'][:8]}…` | Alert: `{context.get('alert_id', '?')[:8]}…`"}
            ]
        })

    payload = {
        "channel": "#soc-alerts",
        "username": "Defmon-Bot",
        "icon_emoji": ":shield:",
        "blocks": blocks,
    }

    line = json.dumps({"timestamp": _now_iso(), "webhook_payload": payload}, default=str)
    with open(SLACK_LOG, "a") as f:
        f.write(line + "\n")
    return line


# ── Channel: Email (simulated) ──────────────────────────────────────────────
def notify_email(alert_data: dict, context: dict = None) -> str:
    """Simulate sending an email alert to the SOC team.

    In production, replace with smtplib or an email API (SendGrid, SES).
    """
    sev = alert_data.get("severity", "info").upper()
    ts = _now_iso()

    actions_text = "None"
    if context and context.get("actions_taken"):
        actions_text = ", ".join(context["actions_taken"])

    incident_text = "N/A"
    if context and context.get("incident_id"):
        incident_text = context["incident_id"]

    email = (
        f"From: siem-noreply@company.local\n"
        f"To: soc-team@company.local\n"
        f"Subject: [{sev}] {alert_data.get('rule_name', 'Security Alert')} — {alert_data.get('source_ip', '?')}\n"
        f"Date: {ts}\n"
        f"X-Priority: {'1 (Highest)' if sev in ('CRITICAL','HIGH') else '3 (Normal)'}\n"
        f"Content-Type: text/plain; charset=utf-8\n"
        f"\n"
        f"{'='*60}\n"
        f"  SECURITY ALERT — {sev}\n"
        f"{'='*60}\n"
        f"\n"
        f"Rule:          {alert_data.get('rule_name', '?')}\n"
        f"Rule ID:       {alert_data.get('rule_id', '?')}\n"
        f"Severity:      {sev} (risk score: {alert_data.get('risk_score', 0)})\n"
        f"Source IP:     {alert_data.get('source_ip', '?')}\n"
        f"Country:       {alert_data.get('country', '?')}\n"
        f"Timestamp:     {ts}\n"
        f"\n"
        f"MITRE ATT&CK:  {alert_data.get('mitre_tactic', 'N/A')} / "
        f"{alert_data.get('mitre_technique', 'N/A')} — {alert_data.get('mitre_name', '')}\n"
        f"\n"
        f"Description:\n"
        f"  {alert_data.get('description', 'No description')}\n"
        f"\n"
        f"Evidence (truncated):\n"
        f"  {str(alert_data.get('evidence', ''))[:300]}\n"
        f"\n"
        f"SOAR Actions:  {actions_text}\n"
        f"Incident ID:   {incident_text}\n"
        f"\n"
        f"{'='*60}\n"
        f"  This is an automated alert from Defmon SIEM+SOAR\n"
        f"{'='*60}\n"
        f"\n"
    )

    with open(EMAIL_LOG, "a") as f:
        f.write(email)
    return email


# ── Channel: Syslog CEF (simulated) ─────────────────────────────────────────
def notify_syslog_cef(alert_data: dict, context: dict = None) -> str:
    """Write a CEF (Common Event Format) syslog line.

    Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
    """
    sev_map = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
    cef_sev = sev_map.get(alert_data.get("severity", "info"), 1)

    extensions = (
        f"src={alert_data.get('source_ip', '?')} "
        f"msg={alert_data.get('description', '?')} "
        f"cs1={alert_data.get('mitre_technique', 'N/A')} cs1Label=MITRE_Technique "
        f"cs2={alert_data.get('mitre_tactic', 'N/A')} cs2Label=MITRE_Tactic "
        f"cs3={alert_data.get('country', '?')} cs3Label=Country "
        f"cn1={alert_data.get('risk_score', 0)} cn1Label=RiskScore"
    )

    line = (
        f"CEF:0|Defmon|SOAR|1.0|{alert_data.get('rule_id', '?')}|"
        f"{alert_data.get('rule_name', '?')}|{cef_sev}|{extensions}"
    )

    with open(SYSLOG_LOG, "a") as f:
        f.write(f"{_now_iso()} {line}\n")
    return line


# ── Notification Engine (orchestrator) ───────────────────────────────────────

# Registry of active channels
_CHANNELS = {
    "console":  notify_console,
    "log_file": notify_log_file,
    "slack":    notify_slack,
    "email":    notify_email,
    "syslog":   notify_syslog_cef,
}


def get_channels():
    """Return list of active notification channel names."""
    return list(_CHANNELS.keys())


async def send_notification(alert_data: dict, context: dict = None,
                            channels: list[str] = None) -> dict:
    """Dispatch an alert to all (or specified) notification channels.

    Args:
        alert_data: Detection alert dict (rule_id, severity, source_ip, etc.)
        context:    SOAR context (alert_id, incident_id, actions_taken)
        channels:   Optional list of channel names to use (defaults to all)

    Returns:
        dict mapping channel_name → success/failure
    """
    if channels is None:
        channels = list(_CHANNELS.keys())

    results = {}
    for ch_name in channels:
        handler = _CHANNELS.get(ch_name)
        if not handler:
            results[ch_name] = {"status": "error", "detail": "unknown channel"}
            continue
        try:
            handler(alert_data, context)
            results[ch_name] = {"status": "delivered"}
        except Exception as e:
            results[ch_name] = {"status": "error", "detail": str(e)}

    return results
