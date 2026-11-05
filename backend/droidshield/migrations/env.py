from alembic import context
from sqlalchemy import BigInteger, Integer

from droidshield import report_models  # noqa: F401
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.models import Base

config = context.config
target_metadata = Base.metadata
url = config.attributes.get("database_url") or Settings().database_url


def _compare_type(context_, inspected_column, metadata_column, inspected_type, metadata_type):
    # SQLite INTEGER already stores signed 64-bit values. Old migrated SQLite
    # schemas can retain INTEGER while the model declares BIGINT; this is the
    # same storage capacity and intentionally needs no table rebuild.
    if (
        context_.dialect.name == "sqlite"
        and inspected_column.name == "version_code"
        and metadata_column.table.name == "app_artifacts"
        and isinstance(inspected_type, Integer)
        and isinstance(metadata_type, BigInteger)
    ):
        return False
    return None


if context.is_offline_mode():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = build_engine(url)
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, compare_type=_compare_type
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
