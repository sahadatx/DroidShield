from alembic import context

from droidshield import report_models  # noqa: F401
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.models import Base

config = context.config
target_metadata = Base.metadata
url = config.attributes.get("database_url") or Settings().database_url

if context.is_offline_mode():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = build_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
