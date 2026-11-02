"""Add immutable protected screenshot attachments to analyst evidence.

Revision ID: 0008_evidence_attachments
Revises: 0007_password_sessions
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_evidence_attachments"
down_revision = "0007_password_sessions"
branch_labels = None
depends_on = None


def upgrade():
    sha_characters_removed = "sha256"
    for character in "0123456789abcdef":
        sha_characters_removed = f"replace({sha_characters_removed}, '{character}', '')"
    op.create_table(
        "evidence_attachments",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("storage_ref", sa.String(length=2048), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "evidence_id"],
            ["assessment_evidence.workspace_id", "assessment_evidence.id"],
            name="fk_evidence_attachments_workspace_id_assessment_evidence",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_evidence_attachments"),
        sa.CheckConstraint(
            "file_size BETWEEN 1 AND 8388608", name="ck_evidence_attachments_file_size"
        ),
        sa.CheckConstraint(
            "length(trim(storage_ref)) > 0", name="ck_evidence_attachments_storage_ref_required"
        ),
        sa.CheckConstraint("media_type = 'image/png'", name="ck_evidence_attachments_media_type"),
        sa.CheckConstraint(
            "display_name = 'screenshot.png'", name="ck_evidence_attachments_display_name"
        ),
        sa.CheckConstraint(
            f"length(sha256) = 64 AND {sha_characters_removed} = ''",
            name="ck_evidence_attachments_sha256_lower_hex",
        ),
    )
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER ds_evidence_attachment_{action.lower()} "
                f"BEFORE {action} ON evidence_attachments BEGIN "
                "SELECT RAISE(ABORT, 'evidence attachments are immutable'); END"
            )
    else:
        op.execute(
            "CREATE FUNCTION ds_evidence_attachment_immutable() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'evidence attachments are immutable'; END $$"
        )
        op.execute(
            "CREATE TRIGGER ds_evidence_attachment_immutable BEFORE UPDATE OR DELETE OR TRUNCATE "
            "ON evidence_attachments FOR EACH STATEMENT "
            "EXECUTE FUNCTION ds_evidence_attachment_immutable()"
        )


def downgrade():
    if op.get_bind().dialect.name == "sqlite":
        op.execute("DROP TRIGGER ds_evidence_attachment_update")
        op.execute("DROP TRIGGER ds_evidence_attachment_delete")
    else:
        op.execute("DROP TRIGGER ds_evidence_attachment_immutable ON evidence_attachments")
        op.execute("DROP FUNCTION ds_evidence_attachment_immutable()")
    op.drop_table("evidence_attachments")
