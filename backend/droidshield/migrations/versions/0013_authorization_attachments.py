"""Add immutable, privately stored authorization evidence attachments.

Revision ID: 0013_authorization_attachments
Revises: 0012_overview_risk_trends
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_authorization_attachments"
down_revision = "0012_overview_risk_trends"
branch_labels = None
depends_on = None


def _immutable_guards():
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER ds_authorization_attachment_{action.lower()} "
                f"BEFORE {action} ON authorization_attachments BEGIN "
                "SELECT RAISE(ABORT, 'authorization attachments are immutable'); END"
            )
    else:
        op.execute(
            "CREATE FUNCTION ds_authorization_attachment_immutable() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
            "'authorization attachments are immutable'; END $$"
        )
        op.execute(
            "CREATE TRIGGER ds_authorization_attachment_immutable "
            "BEFORE UPDATE OR DELETE OR TRUNCATE ON authorization_attachments "
            "FOR EACH STATEMENT EXECUTE FUNCTION ds_authorization_attachment_immutable()"
        )


def upgrade():
    sha_characters_removed = "sha256"
    for character in "0123456789abcdef":
        sha_characters_removed = f"replace({sha_characters_removed}, '{character}', '')"
    op.create_table(
        "authorization_attachments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("storage_ref", sa.String(length=96), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_authorization_attachments_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "project_id", "authorization_id"],
            ["authorizations.workspace_id", "authorizations.project_id", "authorizations.id"],
            name="fk_authorization_attachments_workspace_id_authorizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "created_by"],
            ["users.workspace_id", "users.id"],
            name="fk_user_created_by",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authorization_attachments"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_authorization_attachments_workspace_id"),
        sa.CheckConstraint(
            "file_size BETWEEN 1 AND 8388608", name="ck_authorization_attachments_file_size"
        ),
        sa.CheckConstraint(
            "length(trim(storage_ref)) > 0",
            name="ck_authorization_attachments_storage_ref_required",
        ),
        sa.CheckConstraint(
            f"length(sha256) = 64 AND {sha_characters_removed} = ''",
            name="ck_authorization_attachments_sha256_lower_hex",
        ),
        sa.CheckConstraint(
            "media_type IN ('application/pdf', 'image/png', 'image/jpeg')",
            name="ck_authorization_attachments_media_type",
        ),
        sa.CheckConstraint(
            "length(trim(display_name)) BETWEEN 1 AND 120",
            name="ck_authorization_attachments_display_name",
        ),
    )
    op.create_index(
        "ix_authorization_attachments_workspace_id",
        "authorization_attachments",
        ["workspace_id"],
    )
    op.create_index(
        "ix_authorization_attachments_owner",
        "authorization_attachments",
        ["workspace_id", "project_id", "authorization_id"],
    )
    _immutable_guards()


def downgrade():
    if op.get_bind().scalar(sa.text("SELECT COUNT(*) FROM authorization_attachments")):
        raise RuntimeError("Refusing to discard client authorization attachments")
    if op.get_bind().dialect.name == "sqlite":
        op.execute("DROP TRIGGER ds_authorization_attachment_update")
        op.execute("DROP TRIGGER ds_authorization_attachment_delete")
    else:
        op.execute(
            "DROP TRIGGER ds_authorization_attachment_immutable ON authorization_attachments"
        )
        op.execute("DROP FUNCTION ds_authorization_attachment_immutable()")
    op.drop_index("ix_authorization_attachments_owner", table_name="authorization_attachments")
    op.drop_index(
        "ix_authorization_attachments_workspace_id", table_name="authorization_attachments"
    )
    op.drop_table("authorization_attachments")
