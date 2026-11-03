"""Share password login rate limits across API workers.

Revision ID: 0010_shared_login_rate_limits
Revises: 0009_evidence_attachment_scope
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_shared_login_rate_limits"
down_revision = "0009_evidence_attachment_scope"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_rate_limit_entries",
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("attempt_times_us", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_hash", name=op.f("pk_login_rate_limit_entries")),
    )
    op.create_index(
        "ix_login_rate_limit_entries_updated",
        "login_rate_limit_entries",
        ["updated_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_login_rate_limit_entries_updated", table_name="login_rate_limit_entries")
    op.drop_table("login_rate_limit_entries")
