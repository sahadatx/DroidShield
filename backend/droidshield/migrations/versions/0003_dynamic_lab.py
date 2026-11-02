"""Controlled dynamic sessions and exclusive disposable device leases.

Revision ID: 0003_dynamic_lab
Revises: 0002_analysis_worker
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_dynamic_lab"
down_revision = "0002_analysis_worker"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dynamic_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.String(128), nullable=False),
        sa.Column("scenario", sa.String(32), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("configuration_snapshot", sa.JSON(), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(64), nullable=True),
        sa.Column("cancellation_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_dynamic_sessions"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_dynamic_workspace_id"),
        sa.UniqueConstraint("job_id", name="uq_dynamic_sessions_job_id"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "artifact_id", "job_id"],
            [
                "analysis_jobs.workspace_id",
                "analysis_jobs.assessment_id",
                "analysis_jobs.artifact_id",
                "analysis_jobs.id",
            ],
            name="fk_dynamic_job_origin",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("scenario IN ('launch_observe', 'package_inspection')", name="scenario"),
        sa.CheckConstraint("timeout_seconds BETWEEN 10 AND 120", name="timeout"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status"
        ),
    )
    for column in ("workspace_id", "project_id", "assessment_id"):
        op.create_index(f"ix_dynamic_sessions_{column}", "dynamic_sessions", [column])
    op.create_index("ix_dynamic_status_created", "dynamic_sessions", ["status", "created_at"])
    op.create_table(
        "dynamic_device_leases",
        sa.Column("device_id", sa.String(128), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("worker_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantined", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("device_id", name="pk_dynamic_device_leases"),
        sa.UniqueConstraint("session_id", name="uq_dynamic_device_leases_session_id"),
        sa.ForeignKeyConstraint(["session_id"], ["dynamic_sessions.id"], ondelete="RESTRICT"),
    )


def downgrade():
    op.drop_table("dynamic_device_leases")
    op.drop_table("dynamic_sessions")
