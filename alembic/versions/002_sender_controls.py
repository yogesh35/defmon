"""add sender controls and received log metadata

Revision ID: 002_sender_controls
Revises: 001_initial
Create Date: 2026-04-14

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "002_sender_controls"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("log_entries", sa.Column("sender_id", sa.String(length=64), nullable=True))
    op.add_column("log_entries", sa.Column("sender_name", sa.String(length=100), nullable=True))
    op.create_index("ix_log_entries_sender_id", "log_entries", ["sender_id"])
    op.create_index("ix_log_entries_sender_name", "log_entries", ["sender_name"])

    op.create_table(
        "log_senders",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=True),
        sa.Column("api_key_hash", sa.String(length=128), nullable=False),
        sa.Column("allowed_ip", sa.String(length=45), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_blocked", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("block_reason", sa.Text(), server_default="", nullable=True),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_log_preview", sa.Text(), server_default="", nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_log_senders_name", "log_senders", ["name"])


def downgrade() -> None:
    op.drop_index("ix_log_senders_name", table_name="log_senders")
    op.drop_table("log_senders")

    op.drop_index("ix_log_entries_sender_name", table_name="log_entries")
    op.drop_index("ix_log_entries_sender_id", table_name="log_entries")
    op.drop_column("log_entries", "sender_name")
    op.drop_column("log_entries", "sender_id")
