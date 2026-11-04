"""Track agreed retest deadlines for findings.

Revision ID: 0012_overview_risk_trends
Revises: 0011_workspace_settings
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_overview_risk_trends"
down_revision = "0011_workspace_settings"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("retest_due_at", sa.DateTime(timezone=True)))
    op.create_index(
        "ix_findings_workspace_retest_due",
        "findings",
        ["workspace_id", "retest_due_at"],
    )


def downgrade():
    op.drop_index("ix_findings_workspace_retest_due", table_name="findings")
    op.drop_column("findings", "retest_due_at")
