"""Store Android long version codes without narrowing.

Revision ID: 0014_android_long_version_code
Revises: 0013_authorization_attachments
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_android_long_version_code"
down_revision = "0013_authorization_attachments"
branch_labels = None
depends_on = None


def _alter_type(existing_type: sa.types.TypeEngine, target_type: sa.types.TypeEngine) -> None:
    if op.get_bind().dialect.name == "sqlite":
        # SQLite INTEGER already stores signed 64-bit values; rebuilding this
        # immutable, heavily referenced table would add risk without widening
        # its actual storage capacity.
        return
    op.alter_column(
        "app_artifacts",
        "version_code",
        existing_type=existing_type,
        type_=target_type,
        existing_nullable=True,
    )


def upgrade() -> None:
    _alter_type(sa.Integer(), sa.BigInteger())


def downgrade() -> None:
    bind = op.get_bind()
    has_wide_values = bind.execute(
        sa.text("SELECT 1 FROM app_artifacts WHERE version_code > :maximum LIMIT 1"),
        {"maximum": 2**31 - 1},
    ).first()
    if has_wide_values:
        raise RuntimeError("Cannot downgrade while full Android version codes are stored")
    _alter_type(sa.BigInteger(), sa.Integer())
