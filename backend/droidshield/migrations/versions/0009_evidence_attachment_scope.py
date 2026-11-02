"""Constrain attachment rows to a workspace and index their owner.

Revision ID: 0009_evidence_attachment_scope
Revises: 0008_evidence_attachments
"""

from alembic import op

revision = "0009_evidence_attachment_scope"
down_revision = "0008_evidence_attachments"
branch_labels = None
depends_on = None


def _sqlite_immutability_triggers():
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER ds_evidence_attachment_{action.lower()} "
            f"BEFORE {action} ON evidence_attachments BEGIN "
            "SELECT RAISE(ABORT, 'evidence attachments are immutable'); END"
        )


def upgrade():
    if op.get_bind().dialect.name == "sqlite":
        op.execute("DROP TRIGGER ds_evidence_attachment_update")
        op.execute("DROP TRIGGER ds_evidence_attachment_delete")
        with op.batch_alter_table("evidence_attachments") as batch:
            batch.create_foreign_key(
                "fk_evidence_attachments_workspace_id_workspaces",
                "workspaces",
                ["workspace_id"],
                ["id"],
                ondelete="RESTRICT",
            )
        _sqlite_immutability_triggers()
    else:
        op.create_foreign_key(
            "fk_evidence_attachments_workspace_id_workspaces",
            "evidence_attachments",
            "workspaces",
            ["workspace_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    op.create_index(
        "ix_evidence_attachments_workspace_id", "evidence_attachments", ["workspace_id"]
    )


def downgrade():
    op.drop_index("ix_evidence_attachments_workspace_id", table_name="evidence_attachments")
    if op.get_bind().dialect.name == "sqlite":
        op.execute("DROP TRIGGER ds_evidence_attachment_update")
        op.execute("DROP TRIGGER ds_evidence_attachment_delete")
        with op.batch_alter_table("evidence_attachments") as batch:
            batch.drop_constraint(
                "fk_evidence_attachments_workspace_id_workspaces", type_="foreignkey"
            )
        _sqlite_immutability_triggers()
    else:
        op.drop_constraint(
            "fk_evidence_attachments_workspace_id_workspaces",
            "evidence_attachments",
            type_="foreignkey",
        )
