"""SQLAlchemy ORM models — the single source of truth for the DB schema.

Tables
------
log_entries      – every normalized log event
alerts           – detection-engine findings
incidents        – case-management tickets
blocked_ips      – IPs currently blocked
response_actions – audit trail of SOAR actions
"""
import datetime, uuid
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, ForeignKey, Index,
)
from sqlalchemy.orm import relationship
from backend.core.database import Base


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.datetime.utcnow()


# ── Log Entry ────────────────────────────────────────────────────────────────
class LogEntry(Base):
    __tablename__ = "log_entries"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=_now, index=True)
    source_ip     = Column(String(45), index=True)            # IPv4/IPv6
    method        = Column(String(10))
    url           = Column(Text)
    status_code   = Column(Integer)
    user_agent    = Column(Text)
    body          = Column(Text, nullable=True)                # POST body
    log_source    = Column(String(30), default="access")       # access / auth / app
    raw_line      = Column(Text)
    country       = Column(String(5), nullable=True)
    city          = Column(String(100), nullable=True)
    latitude      = Column(Float, nullable=True)
    longitude     = Column(Float, nullable=True)

    __table_args__ = (
        Index("ix_log_ts_ip", "timestamp", "source_ip"),
    )


# ── Alert ────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id            = Column(String(36), primary_key=True, default=_uuid)
    timestamp     = Column(DateTime, default=_now, index=True)
    rule_id       = Column(String(50), index=True)             # e.g. "sql_injection"
    rule_name     = Column(String(120))
    severity      = Column(String(10), index=True)             # critical/high/medium/low
    risk_score    = Column(Float, default=0)
    source_ip     = Column(String(45), index=True)
    description   = Column(Text)
    evidence      = Column(Text)                               # raw log / payload
    mitre_tactic  = Column(String(60), nullable=True)
    mitre_technique = Column(String(20), nullable=True)
    mitre_name    = Column(String(120), nullable=True)
    status        = Column(String(20), default="open")         # open / investigating / closed
    incident_id   = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    country       = Column(String(5), nullable=True)
    latitude      = Column(Float, nullable=True)
    longitude     = Column(Float, nullable=True)

    incident      = relationship("Incident", back_populates="alerts")


# ── Incident (case management) ───────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id            = Column(String(36), primary_key=True, default=_uuid)
    created_at    = Column(DateTime, default=_now)
    updated_at    = Column(DateTime, default=_now, onupdate=_now)
    title         = Column(String(200))
    severity      = Column(String(10))
    status        = Column(String(20), default="open")         # open / investigating / mitigated / closed
    description   = Column(Text)
    analyst_notes = Column(Text, nullable=True)
    source_ip     = Column(String(45), nullable=True)
    attack_type   = Column(String(50), nullable=True)
    mitre_tactic  = Column(String(60), nullable=True)
    mitre_technique = Column(String(20), nullable=True)

    alerts        = relationship("Alert", back_populates="incident")


# ── Blocked IP ───────────────────────────────────────────────────────────────
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    ip            = Column(String(45), unique=True, index=True)
    reason        = Column(Text)
    blocked_at    = Column(DateTime, default=_now)
    alert_id      = Column(String(36), nullable=True)
    severity      = Column(String(10), nullable=True)


# ── Response Action (audit trail) ────────────────────────────────────────────
class ResponseAction(Base):
    __tablename__ = "response_actions"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=_now, index=True)
    action_type   = Column(String(40))                         # block_ip / blacklist / alert / ticket
    target        = Column(String(120))                        # IP, email, etc.
    detail        = Column(Text)
    alert_id      = Column(String(36), nullable=True)
    incident_id   = Column(String(36), nullable=True)
    status        = Column(String(20), default="completed")
