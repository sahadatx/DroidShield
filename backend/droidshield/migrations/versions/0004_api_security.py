"""Scoped HTTPS API targets, fenced execution and expanded controlled lab scenarios.

Revision ID: 0004_api_security
Revises: 0003_dynamic_lab
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_api_security"
down_revision = "0003_dynamic_lab"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "uq_jobs_api_origin", "analysis_jobs", ["workspace_id", "assessment_id", "id"], unique=True
    )
    op.create_table(
        "api_targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("endpoints", sa.JSON(), nullable=False),
        sa.Column("excluded_endpoints", sa.JSON(), nullable=False),
        sa.Column("auth_method", sa.String(16), nullable=False),
        sa.Column("primary_secret_ref", sa.String(128), nullable=True),
        sa.Column("secondary_secret_ref", sa.String(128), nullable=True),
        sa.Column("requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("test_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("test_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_api_targets"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_api_targets_workspace_id"),
        sa.UniqueConstraint("assessment_id", name="uq_api_targets_assessment_id"),
        sa.UniqueConstraint(
            "workspace_id", "project_id", "assessment_id", "id", name="uq_api_targets_origin"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(trim(name)) > 0", name="name_required"),
        sa.CheckConstraint(
            "auth_method IN ('none', 'bearer', 'api_key', 'cookie')", name="auth_method"
        ),
        sa.CheckConstraint("requests_per_minute BETWEEN 1 AND 120", name="rate_limit"),
        sa.CheckConstraint("test_window_end > test_window_start", name="test_window"),
    )
    for column in ("workspace_id", "project_id", "assessment_id"):
        op.create_index(f"ix_api_targets_{column}", "api_targets", [column])
    op.create_table(
        "api_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("configuration_snapshot", sa.JSON(), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(64), nullable=True),
        sa.Column("cancellation_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_api_executions"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_api_executions_workspace_id"),
        sa.UniqueConstraint("job_id", name="uq_api_executions_job_id"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id", "target_id"],
            [
                "api_targets.workspace_id",
                "api_targets.project_id",
                "api_targets.assessment_id",
                "api_targets.id",
            ],
            name="fk_api_execution_target_origin",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "job_id"],
            ["analysis_jobs.workspace_id", "analysis_jobs.assessment_id", "analysis_jobs.id"],
            name="fk_api_execution_job_origin",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status"
        ),
    )
    for column in ("workspace_id", "project_id", "assessment_id"):
        op.create_index(f"ix_api_executions_{column}", "api_executions", [column])
    op.create_index("ix_api_executions_status_created", "api_executions", ["status", "created_at"])
    _scenario_constraint(
        "scenario IN ('launch_observe', 'package_inspection', 'frida_observe', 'proxy_observe')"
    )
    _guards()


def _scenario_constraint(expression):
    # Rebuild the sole referencing lease table around SQLite batch replacement.
    # Its rows, active owners and quarantine flags are retained transactionally.
    if op.get_bind().dialect.name == "sqlite":
        bind = op.get_bind()
        bind.exec_driver_sql(
            "CREATE TEMPORARY TABLE droidshield_lease_backup AS SELECT * FROM dynamic_device_leases"
        )
        op.drop_table("dynamic_device_leases")
        with op.batch_alter_table("dynamic_sessions") as batch:
            batch.drop_constraint(op.f("ck_dynamic_sessions_scenario"), type_="check")
            batch.create_check_constraint(
                "scenario",
                expression,
            )
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
        bind.exec_driver_sql(
            "INSERT INTO dynamic_device_leases SELECT * FROM droidshield_lease_backup"
        )
        bind.exec_driver_sql("DROP TABLE droidshield_lease_backup")
    else:
        op.drop_constraint(op.f("ck_dynamic_sessions_scenario"), "dynamic_sessions", type_="check")
        op.create_check_constraint(
            "scenario",
            "dynamic_sessions",
            expression,
        )


def _guards():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            bind.exec_driver_sql(
                f"CREATE TRIGGER api_targets_immutable_{action.lower()} BEFORE {action} ON api_targets BEGIN SELECT RAISE(ABORT, 'API targets are immutable'); END"
            )
        bind.exec_driver_sql(
            "CREATE TRIGGER api_result_write_once BEFORE UPDATE ON api_executions WHEN OLD.result_json IS NOT NULL BEGIN SELECT RAISE(ABORT, 'API results are immutable'); END"
        )
        bind.exec_driver_sql(
            "CREATE TRIGGER api_result_no_delete BEFORE DELETE ON api_executions WHEN OLD.result_json IS NOT NULL BEGIN SELECT RAISE(ABORT, 'API results are immutable'); END"
        )
    else:
        bind.exec_driver_sql(
            "CREATE FUNCTION droidshield_api_target_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'API targets are immutable'; END $$"
        )
        bind.exec_driver_sql(
            "CREATE TRIGGER api_targets_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON api_targets FOR EACH STATEMENT EXECUTE FUNCTION droidshield_api_target_immutable()"
        )
        bind.exec_driver_sql(
            "CREATE FUNCTION droidshield_api_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.result_json IS NOT NULL THEN RAISE EXCEPTION 'API results are immutable'; END IF; IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$"
        )
        bind.exec_driver_sql(
            "CREATE TRIGGER api_result_write_once BEFORE UPDATE OR DELETE ON api_executions FOR EACH ROW EXECUTE FUNCTION droidshield_api_result_immutable()"
        )
        bind.exec_driver_sql(
            "CREATE TRIGGER api_result_no_truncate BEFORE TRUNCATE ON api_executions FOR EACH STATEMENT EXECUTE FUNCTION droidshield_api_target_immutable()"
        )


def downgrade():
    bind = op.get_bind()
    # Existing 0.3 data can round-trip when none of this revision's features
    # have been used. Never silently erase new target/result/instrumentation
    # history or invalidate a retained Frida/proxy session.
    has_history = any(
        bind.execute(sa.text(statement)).scalar_one() > 0
        for statement in (
            "SELECT count(*) FROM api_targets",
            "SELECT count(*) FROM api_executions",
            "SELECT count(*) FROM dynamic_sessions WHERE scenario IN ('frida_observe', 'proxy_observe')",
        )
    )
    if has_history:
        raise RuntimeError(
            "API or instrumentation history requires a reviewed backup before downgrade"
        )
    op.drop_table("api_executions")
    op.drop_table("api_targets")
    if bind.dialect.name == "postgresql":
        bind.exec_driver_sql("DROP FUNCTION droidshield_api_result_immutable()")
        bind.exec_driver_sql("DROP FUNCTION droidshield_api_target_immutable()")
    op.drop_index("uq_jobs_api_origin", table_name="analysis_jobs")
    _scenario_constraint("scenario IN ('launch_observe', 'package_inspection')")
