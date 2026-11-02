"""Add password hashes for browser email/password sessions.

Revision ID: 0007_password_sessions
Revises: 0006_reports
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_password_sessions"
down_revision = "0006_reports"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("users", "password_hash")
