"""Immutable reviewed client report versions and protected exports.

Revision ID: 0006_reports
Revises: 0005_delivery_workflow
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_reports"
down_revision = "0005_delivery_workflow"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "uq_reports_project_origin", "reports", ["workspace_id", "project_id", "id"], unique=True
    )
    op.create_index(
        "uq_reports_assessment_origin",
        "reports",
        ["workspace_id", "project_id", "assessment_id", "id"],
        unique=True,
    )
    op.create_table(
        "report_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_report_snapshots"),
        sa.UniqueConstraint("report_id", name="uq_report_snapshots_report_id"),
        sa.UniqueConstraint(
            "assessment_id", "version", name="uq_report_snapshots_assessment_version"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id", "report_id"],
            ["reports.workspace_id", "reports.project_id", "reports.assessment_id", "reports.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("version >= 1", name="version_positive"),
        sa.CheckConstraint("length(sha256) = 64", name="sha256_length"),
    )
    for field in ("workspace_id", "project_id", "assessment_id"):
        op.create_index(f"ix_report_snapshots_{field}", "report_snapshots", [field])
    op.create_table(
        "report_exports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(8), nullable=False),
        sa.Column("storage_ref", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_report_exports"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "report_id"],
            ["reports.workspace_id", "reports.project_id", "reports.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("format IN ('pdf', 'json')", name="format"),
        sa.CheckConstraint("file_size > 0 AND file_size <= 16777216", name="bounded_file_size"),
        sa.CheckConstraint("length(sha256) = 64", name="sha256_length"),
    )
    for field in ("workspace_id", "project_id", "report_id"):
        op.create_index(f"ix_report_exports_{field}", "report_exports", [field])
    _guards()


def _guards():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        for table in ("report_snapshots", "report_exports"):
            for action in ("UPDATE", "DELETE"):
                bind.exec_driver_sql(
                    f"CREATE TRIGGER {table}_immutable_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'Report history is immutable'); END"
                )
        bind.exec_driver_sql(
            "CREATE TRIGGER reports_frozen_fields BEFORE UPDATE ON reports WHEN OLD.workspace_id != NEW.workspace_id OR OLD.project_id != NEW.project_id OR OLD.assessment_id != NEW.assessment_id OR OLD.title != NEW.title OR OLD.template != NEW.template OR OLD.version != NEW.version OR OLD.filters != NEW.filters OR OLD.branding != NEW.branding OR OLD.author_id != NEW.author_id OR OLD.created_at != NEW.created_at OR (OLD.approved_at IS NOT NULL AND (NEW.reviewer_id IS NOT OLD.reviewer_id OR NEW.approved_at IS NOT OLD.approved_at OR NEW.status NOT IN ('approved','exported'))) BEGIN SELECT RAISE(ABORT, 'Report identity and release are immutable'); END"
        )
    else:
        bind.exec_driver_sql(
            "CREATE FUNCTION droidshield_report_history_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Report history is immutable'; END $$"
        )
        for table in ("report_snapshots", "report_exports"):
            bind.exec_driver_sql(
                f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION droidshield_report_history_immutable()"
            )
        bind.exec_driver_sql(
            "CREATE FUNCTION droidshield_report_frozen_fields() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ROW(OLD.workspace_id,OLD.project_id,OLD.assessment_id,OLD.title,OLD.template,OLD.version,OLD.filters::text,OLD.branding::text,OLD.author_id,OLD.created_at) IS DISTINCT FROM ROW(NEW.workspace_id,NEW.project_id,NEW.assessment_id,NEW.title,NEW.template,NEW.version,NEW.filters::text,NEW.branding::text,NEW.author_id,NEW.created_at) OR (OLD.approved_at IS NOT NULL AND (NEW.reviewer_id IS DISTINCT FROM OLD.reviewer_id OR NEW.approved_at IS DISTINCT FROM OLD.approved_at OR NEW.status NOT IN ('approved','exported'))) THEN RAISE EXCEPTION 'Report identity and release are immutable'; END IF; RETURN NEW; END $$"
        )
        bind.exec_driver_sql(
            "CREATE TRIGGER reports_frozen_fields BEFORE UPDATE ON reports FOR EACH ROW EXECUTE FUNCTION droidshield_report_frozen_fields()"
        )


def downgrade():
    bind = op.get_bind()
    if bind.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM report_snapshots) OR EXISTS(SELECT 1 FROM report_exports)"
        )
    ).scalar():
        raise RuntimeError("Report history exists; refusing a destructive downgrade")
    if bind.dialect.name == "sqlite":
        bind.exec_driver_sql("DROP TRIGGER reports_frozen_fields")
    else:
        bind.exec_driver_sql("DROP TRIGGER reports_frozen_fields ON reports")
        bind.exec_driver_sql("DROP FUNCTION droidshield_report_frozen_fields()")
    op.drop_table("report_exports")
    op.drop_table("report_snapshots")
    if bind.dialect.name != "sqlite":
        bind.exec_driver_sql("DROP FUNCTION droidshield_report_history_immutable()")
    op.drop_index("uq_reports_assessment_origin", table_name="reports")
    op.drop_index("uq_reports_project_origin", table_name="reports")
