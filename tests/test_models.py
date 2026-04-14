"""Tests for DefMon database models — validates ORM schema definitions."""

import uuid
from datetime import datetime

import pytest


class TestSeverityLevel:
    """Tests for the SeverityLevel enum."""

    def test_critical_value(self):
        """Critical severity enum must have correct string value."""
        from defmon.models import SeverityLevel
        assert SeverityLevel.CRITICAL.value == "Critical"

    def test_high_value(self):
        """High severity enum must have correct string value."""
        from defmon.models import SeverityLevel
        assert SeverityLevel.HIGH.value == "High"

    def test_medium_value(self):
        """Medium severity enum must have correct string value."""
        from defmon.models import SeverityLevel
        assert SeverityLevel.MEDIUM.value == "Medium"

    def test_low_value(self):
        """Low severity enum must have correct string value."""
        from defmon.models import SeverityLevel
        assert SeverityLevel.LOW.value == "Low"

    def test_severity_is_string_enum(self):
        """SeverityLevel must be a string enum for JSON serialization."""
        from defmon.models import SeverityLevel
        assert isinstance(SeverityLevel.CRITICAL, str)


class TestIncidentStatus:
    """Tests for the IncidentStatus enum."""

    def test_open_value(self):
        from defmon.models import IncidentStatus
        assert IncidentStatus.OPEN.value == "open"

    def test_in_progress_value(self):
        from defmon.models import IncidentStatus
        assert IncidentStatus.IN_PROGRESS.value == "in_progress"

    def test_closed_value(self):
        from defmon.models import IncidentStatus
        assert IncidentStatus.CLOSED.value == "closed"


class TestUserRole:
    """Tests for the UserRole enum."""

    def test_admin_role(self):
        from defmon.models import UserRole
        assert UserRole.ADMIN.value == "admin"

    def test_analyst_role(self):
        from defmon.models import UserRole
        assert UserRole.ANALYST.value == "analyst"

    def test_viewer_role(self):
        from defmon.models import UserRole
        assert UserRole.VIEWER.value == "viewer"


class TestLogEntryModel:
    """Tests for the LogEntry SQLAlchemy model."""

    def test_tablename(self):
        """LogEntry table name must be 'log_entries'."""
        from defmon.models import LogEntry
        assert LogEntry.__tablename__ == "log_entries"

    def test_required_columns_exist(self):
        """LogEntry must define all required columns."""
        from defmon.models import LogEntry
        column_names = {c.name for c in LogEntry.__table__.columns}
        required = {"id", "timestamp", "ip", "method", "uri", "status_code",
                     "bytes_sent", "user_agent", "referrer", "raw_line", "created_at"}
        assert required.issubset(column_names)

    def test_ip_supports_ipv6(self):
        """IP column must support IPv6 addresses (max 45 chars)."""
        from defmon.models import LogEntry
        ip_col = LogEntry.__table__.columns["ip"]
        assert ip_col.type.length >= 45


class TestAlertModel:
    """Tests for the Alert SQLAlchemy model."""

    def test_tablename(self):
        from defmon.models import Alert
        assert Alert.__tablename__ == "alerts"

    def test_required_columns_exist(self):
        from defmon.models import Alert
        column_names = {c.name for c in Alert.__table__.columns}
        required = {"id", "alert_id", "timestamp", "ip", "rule_id", "severity",
                     "description", "raw_event", "risk_score", "tags", "status"}
        assert required.issubset(column_names)

    def test_alert_id_is_uuid(self):
        """alert_id must be a UUID type for unique identification."""
        from defmon.models import Alert
        from sqlalchemy.dialects.postgresql import UUID as PG_UUID
        col = Alert.__table__.columns["alert_id"]
        assert isinstance(col.type, PG_UUID)


class TestIncidentModel:
    """Tests for the Incident SQLAlchemy model."""

    def test_tablename(self):
        from defmon.models import Incident
        assert Incident.__tablename__ == "incidents"

    def test_required_columns_exist(self):
        from defmon.models import Incident
        column_names = {c.name for c in Incident.__table__.columns}
        required = {"id", "case_id", "alert_id", "status", "severity",
                     "description", "created_at", "updated_at", "closed_at"}
        assert required.issubset(column_names)

    def test_foreign_key_to_alerts(self):
        """Incident.alert_id must reference alerts.alert_id via foreign key."""
        from defmon.models import Incident
        alert_id_col = Incident.__table__.columns["alert_id"]
        fk_targets = [fk.target_fullname for fk in alert_id_col.foreign_keys]
        assert "alerts.alert_id" in fk_targets


class TestBlockedIPModel:
    """Tests for the BlockedIP SQLAlchemy model."""

    def test_tablename(self):
        from defmon.models import BlockedIP
        assert BlockedIP.__tablename__ == "blocked_ips"

    def test_required_columns_exist(self):
        from defmon.models import BlockedIP
        column_names = {c.name for c in BlockedIP.__table__.columns}
        required = {"id", "ip", "reason", "blocked_at", "blocked_by"}
        assert required.issubset(column_names)

    def test_ip_is_unique(self):
        """IP column in blocked_ips must enforce uniqueness."""
        from defmon.models import BlockedIP
        ip_col = BlockedIP.__table__.columns["ip"]
        assert ip_col.unique is True


class TestAuditLogModel:
    """Tests for the AuditLog SQLAlchemy model."""

    def test_tablename(self):
        from defmon.models import AuditLog
        assert AuditLog.__tablename__ == "audit_log"

    def test_required_columns_exist(self):
        from defmon.models import AuditLog
        column_names = {c.name for c in AuditLog.__table__.columns}
        required = {"id", "action", "actor", "target", "details", "timestamp"}
        assert required.issubset(column_names)

    def test_default_actor_is_soar(self):
        """Default actor must be 'SOAR' for automated actions."""
        from defmon.models import AuditLog
        actor_col = AuditLog.__table__.columns["actor"]
        assert actor_col.default.arg == "SOAR"


class TestUserModel:
    """Tests for the User SQLAlchemy model."""

    def test_tablename(self):
        from defmon.models import User
        assert User.__tablename__ == "users"

    def test_required_columns_exist(self):
        from defmon.models import User
        column_names = {c.name for c in User.__table__.columns}
        required = {"id", "username", "hashed_password", "role", "is_active",
                     "is_locked", "created_at", "last_login"}
        assert required.issubset(column_names)

    def test_username_is_unique(self):
        """Username must enforce uniqueness."""
        from defmon.models import User
        username_col = User.__table__.columns["username"]
        assert username_col.unique is True

    def test_is_locked_default_false(self):
        """is_locked must default to False."""
        from defmon.models import User
        col = User.__table__.columns["is_locked"]
        assert col.default.arg is False


class TestBaseModel:
    """Tests for the declarative base."""

    def test_base_has_metadata(self):
        """Base must expose metadata for Alembic autogenerate."""
        from defmon.models import Base
        assert Base.metadata is not None

    def test_all_tables_registered(self):
        """All 6 model tables must be registered on the Base metadata."""
        from defmon.models import Base
        table_names = set(Base.metadata.tables.keys())
        expected = {"log_entries", "alerts", "incidents", "blocked_ips", "audit_log", "users"}
        assert expected.issubset(table_names)
