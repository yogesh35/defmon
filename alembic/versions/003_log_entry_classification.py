"""add explicit normal/malicious classification for log entries

Revision ID: 003_log_entry_classification
Revises: 002_sender_controls
Create Date: 2026-04-14

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "003_log_entry_classification"
down_revision: Union[str, None] = "002_sender_controls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "log_entries",
        sa.Column("classification", sa.String(length=16), server_default="normal", nullable=False),
    )
    op.add_column(
        "log_entries",
        sa.Column("is_malicious", sa.Boolean(), server_default="false", nullable=False),
    )
    op.create_index("ix_log_entries_classification", "log_entries", ["classification"])
    op.create_index("ix_log_entries_is_malicious", "log_entries", ["is_malicious"])


def downgrade() -> None:
    op.drop_index("ix_log_entries_is_malicious", table_name="log_entries")
    op.drop_index("ix_log_entries_classification", table_name="log_entries")
    op.drop_column("log_entries", "is_malicious")
    op.drop_column("log_entries", "classification")
