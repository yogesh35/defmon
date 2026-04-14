"""initial schema — all DefMon foundation tables

Revision ID: 001_initial
Revises: None
Create Date: 2024-10-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all DefMon foundation tables."""

    # --- log_entries ---
    op.create_table(
        "log_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("uri", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("bytes_sent", sa.Integer(), server_default="0"),
        sa.Column("user_agent", sa.Text(), server_default=""),
        sa.Column("referrer", sa.Text(), server_default=""),
        sa.Column("raw_line", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_log_entries_timestamp", "log_entries", ["timestamp"])
    op.create_index("ix_log_entries_ip", "log_entries", ["ip"])

    # --- severity enum ---
    severity_enum = sa.Enum("Critical", "High", "Medium", "Low", name="severitylevel")
    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("rule_id", sa.String(50), nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("raw_event", sa.Text(), server_default=""),
        sa.Column("risk_score", sa.Float(), server_default="0.0"),
        sa.Column("tags", ARRAY(sa.String()), server_default="{}"),
        sa.Column("status", sa.String(20), server_default="new"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_ip", "alerts", ["ip"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])

    # --- incident status enum ---
    incident_enum = sa.Enum("open", "in_progress", "closed", name="incidentstatus")
    # --- incidents ---
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", UUID(as_uuid=True), nullable=False),
        sa.Column("status", incident_enum, server_default="open"),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.alert_id"]),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])

    # --- blocked_ips ---
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("reason", sa.Text(), server_default=""),
        sa.Column("blocked_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("blocked_by", sa.String(50), server_default="SOAR"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip"),
    )
    op.create_index("ix_blocked_ips_ip", "blocked_ips", ["ip"])

    # --- audit_log ---
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor", sa.String(50), nullable=False, server_default="SOAR"),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("details", sa.Text(), server_default=""),
        sa.Column("timestamp", sa.DateTime(), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])

    # --- user role enum ---
    role_enum = sa.Enum("admin", "analyst", "viewer", name="userrole")
    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", role_enum, server_default="viewer", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("is_locked", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_username", "users", ["username"])


def downgrade() -> None:
    """Drop all DefMon foundation tables."""
    op.drop_table("users")
    op.drop_table("audit_log")
    op.drop_table("blocked_ips")
    op.drop_table("incidents")
    op.drop_table("alerts")
    op.drop_table("log_entries")

    # Drop enums
    sa.Enum(name="userrole").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="incidentstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="severitylevel").drop(op.get_bind(), checkfirst=True)
