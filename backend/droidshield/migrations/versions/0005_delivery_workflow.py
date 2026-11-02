"""Reviewed analyst work, private evidence and versioned mobile coverage.

Revision ID: 0005_delivery_workflow
Revises: 0004_api_security
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_delivery_workflow"
down_revision = "0004_api_security"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "projects",
        sa.Column(
            "platform",
            sa.String(16),
            sa.CheckConstraint("platform IN ('android', 'ios')", name=op.f("ck_projects_platform")),
            server_default="android",
            nullable=False,
        ),
    )
    # Add checks as table constraints in the same batch. Reflecting adjacent
    # SQLite inline CHECK clauses can merge their names in SQLAlchemy's parser.
    with op.batch_alter_table("retests") as batch:
        batch.add_column(sa.Column("revision", sa.Integer(), server_default="1", nullable=False))
        batch.add_column(sa.Column("review_decision", sa.String(16), nullable=True))
        batch.alter_column("new_artifact_id", existing_type=sa.Uuid(), nullable=True)
        batch.create_check_constraint("revision_positive", "revision >= 1")
        batch.create_check_constraint(
            "review_decision", "review_decision IS NULL OR review_decision IN ('approve', 'reject')"
        )
        batch.create_check_constraint(
            "mobile_artifact_required", "new_artifact_id IS NOT NULL OR method = 'api'"
        )
    op.execute("UPDATE retests SET review_decision = 'approve' WHERE reviewer_id IS NOT NULL")
    op.create_table(
        "assessment_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column("artifact_id", sa.Uuid(), nullable=True),
        sa.Column("release_ref", sa.String(200), nullable=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("artifact_ref", sa.String(2048), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("tool", sa.String(128), nullable=False),
        sa.Column("tool_version", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(2000), nullable=False),
        sa.Column("redaction_count", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_evidence"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_assessment_evidence_workspace_id"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "finding_id", "assessment_id"],
            [
                "findings.workspace_id",
                "findings.project_id",
                "findings.id",
                "findings.assessment_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("platform IN ('android', 'ios')", name="platform"),
        sa.CheckConstraint("file_size BETWEEN 1 AND 262144", name="file_size"),
        sa.CheckConstraint("redaction_count >= 0", name="redaction_count"),
        sa.CheckConstraint(
            "length(sha256) = 64 AND " + _hex_check("sha256") + " = ''", name="sha256_lower_hex"
        ),
    )
    op.create_table(
        "test_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("case_snapshot", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("environment", sa.String(2000), nullable=False),
        sa.Column("tool", sa.String(128), nullable=False),
        sa.Column("tool_version", sa.String(128), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("contributors", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_test_executions"),
        sa.UniqueConstraint("assessment_id", "case_id", name="uq_test_executions_case"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "operator_id"],
            ["users.workspace_id", "users.id"],
            name="fk_user_operator_id",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("platform IN ('android', 'ios')", name="platform"),
        sa.CheckConstraint("status IN ('not_run', 'pass', 'fail', 'na', 'blocked')", name="status"),
        sa.CheckConstraint("revision >= 1", name="revision_positive"),
    )
    for table in ("assessment_evidence", "test_executions"):
        for column in ("workspace_id", "project_id", "assessment_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
    _guard()


def _hex_check(column):
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return expression


def _guard():
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER ds_evidence_{action.lower()} BEFORE {action} ON assessment_evidence BEGIN SELECT RAISE(ABORT, 'assessment evidence is immutable'); END"
            )
    else:
        op.execute(
            "CREATE FUNCTION ds_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'assessment evidence is immutable'; END $$"
        )
        op.execute(
            "CREATE TRIGGER ds_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON assessment_evidence FOR EACH STATEMENT EXECUTE FUNCTION ds_evidence_immutable()"
        )


def downgrade():
    bind = op.get_bind()
    for table in ("assessment_evidence", "test_executions", "retests"):
        if bind.scalar(sa.text(f"SELECT COUNT(*) FROM {table}")):
            raise RuntimeError("Refusing to discard analyst delivery or retest history")
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER ds_evidence_update")
        op.execute("DROP TRIGGER ds_evidence_delete")
    else:
        op.execute("DROP TRIGGER ds_evidence_immutable ON assessment_evidence")
        op.execute("DROP FUNCTION ds_evidence_immutable()")
    op.drop_table("test_executions")
    op.drop_table("assessment_evidence")
    with op.batch_alter_table("retests") as batch:
        batch.drop_constraint(op.f("ck_retests_mobile_artifact_required"), type_="check")
        batch.drop_constraint(op.f("ck_retests_review_decision"), type_="check")
        batch.drop_constraint(op.f("ck_retests_revision_positive"), type_="check")
        batch.alter_column("new_artifact_id", existing_type=sa.Uuid(), nullable=False)
        batch.drop_column("review_decision")
        batch.drop_column("revision")
    op.drop_column("projects", "platform")
