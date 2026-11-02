"""Protected static analysis jobs, leases and immutable normalized results.

Revision ID: 0002_analysis_worker
Revises: 0001_initial
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_analysis_worker"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.add_column(sa.Column("worker_id", sa.Uuid(), nullable=True))
        for name in ("started_at", "completed_at", "heartbeat_at", "lease_expires_at"):
            batch.add_column(sa.Column(name, sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.create_check_constraint("attempt_count_nonnegative", "attempt_count >= 0")
        batch.create_unique_constraint(
            "uq_jobs_result_origin", ["workspace_id", "assessment_id", "artifact_id", "id"]
        )
        batch.create_index("ix_jobs_status_lease", ["status", "lease_expires_at"])

    sha_check = "artifact_sha256"
    for character in "0123456789abcdef":
        sha_check = f"replace({sha_check}, '{character}', '')"
    op.create_table(
        "analysis_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("engine_version", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("indicators_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_analysis_results"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_results_workspace_id"),
        sa.UniqueConstraint("job_id", name="uq_results_job_id"),
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
            name="fk_results_job_origin",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("schema_version >= 1", name="schema_version_positive"),
        sa.CheckConstraint("length(trim(engine_version)) > 0", name="engine_version_required"),
        sa.CheckConstraint(
            f"length(artifact_sha256) = 64 AND {sha_check} = ''",
            name="artifact_sha256_lower_hex",
        ),
    )
    for column in ("workspace_id", "project_id", "assessment_id"):
        op.create_index(f"ix_analysis_results_{column}", "analysis_results", [column])
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(f"""CREATE TRIGGER analysis_results_deny_{action.lower()}
                BEFORE {action} ON analysis_results BEGIN
                SELECT RAISE(ABORT, 'Historical records are immutable'); END""")
    elif op.get_bind().dialect.name == "postgresql":
        op.execute("""CREATE TRIGGER analysis_results_deny_change
            BEFORE UPDATE OR DELETE ON analysis_results
            FOR EACH ROW EXECUTE FUNCTION droidshield_deny_history_change()""")
        op.execute("""CREATE TRIGGER analysis_results_deny_truncate
            BEFORE TRUNCATE ON analysis_results
            FOR EACH STATEMENT EXECUTE FUNCTION droidshield_deny_history_change()""")


def downgrade():
    op.drop_table("analysis_results")
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.drop_index("ix_jobs_status_lease")
        batch.drop_constraint("uq_jobs_result_origin", type_="unique")
        batch.drop_constraint(op.f("ck_analysis_jobs_attempt_count_nonnegative"), type_="check")
        for column in (
            "attempt_count",
            "lease_expires_at",
            "heartbeat_at",
            "completed_at",
            "started_at",
            "worker_id",
        ):
            batch.drop_column(column)
