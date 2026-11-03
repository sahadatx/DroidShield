"""Persist allowlisted workspace presentation settings.

Revision ID: 0011_workspace_settings
Revises: 0010_shared_login_rate_limits
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_workspace_settings"
down_revision = "0010_shared_login_rate_limits"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workspace_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("display_timezone", sa.String(length=64), nullable=False),
        sa.Column("date_format", sa.String(length=16), nullable=False),
        sa.Column("default_report_template", sa.String(length=16), nullable=False),
        sa.Column("report_branding_name", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "length(trim(display_timezone)) > 0 AND length(display_timezone) <= 64",
            name=op.f("ck_workspace_settings_timezone_required"),
        ),
        sa.CheckConstraint(
            "date_format IN ('iso', 'dmy', 'mdy')",
            name=op.f("ck_workspace_settings_date_format"),
        ),
        sa.CheckConstraint(
            "default_report_template IN ('executive', 'technical', 'combined')",
            name=op.f("ck_workspace_settings_report_template"),
        ),
        sa.CheckConstraint(
            "report_branding_name IS NULL OR length(trim(report_branding_name)) > 0",
            name=op.f("ck_workspace_settings_branding_name"),
        ),
        sa.CheckConstraint("revision >= 1", name=op.f("ck_workspace_settings_revision_positive")),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            ondelete="RESTRICT",
            name=op.f("fk_workspace_settings_workspace_id_workspaces"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "updated_by"],
            ["users.workspace_id", "users.id"],
            ondelete="RESTRICT",
            name="fk_user_updated_by",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workspace_settings")),
        sa.UniqueConstraint("workspace_id", name="workspace_unique"),
    )
    op.create_index(
        op.f("ix_workspace_settings_workspace_id"),
        "workspace_settings",
        ["workspace_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_workspace_settings_workspace_id"), table_name="workspace_settings")
    op.drop_table("workspace_settings")
