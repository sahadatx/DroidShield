from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def build_engine(url: str, *, read_only: bool = False) -> Engine:
    parsed = make_url(url)
    options = {"pool_pre_ping": True}
    if parsed.get_backend_name() == "postgresql":
        options["pool_timeout"] = 5
        options["connect_args"] = {}
        if "connect_timeout" not in parsed.query:
            options["connect_args"]["connect_timeout"] = 5
        if read_only:
            options["connect_args"]["options"] = "-c default_transaction_read_only=on"
    if parsed.get_backend_name() == "sqlite":
        options["connect_args"] = {"check_same_thread": False}
        if not parsed.database or parsed.database == ":memory:":
            if read_only:
                raise ValueError("A backup verification database must be a persistent file")
            options["poolclass"] = StaticPool
        else:
            database = Path(parsed.database).expanduser().resolve()
            if read_only:
                if not database.is_file():
                    raise ValueError("The backup database file does not exist")
                parsed = parsed.set(
                    database=f"file:{database}", query={"mode": "ro", "uri": "true"}
                )
            else:
                database.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(parsed, **options)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def sqlite_constraints(connection, _record):
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if read_only:
                connection.execute("PRAGMA query_only=ON")

        @event.listens_for(engine, "begin")
        def sqlite_serialized_transactions(connection):
            # SQLite ignores SELECT FOR UPDATE. Serialize development writes
            # before any reads so queue and revoke cannot race on stale permits.
            connection.exec_driver_sql("BEGIN" if read_only else "BEGIN IMMEDIATE")

    elif read_only:

        @event.listens_for(engine, "begin")
        def postgresql_read_only_transaction(connection):
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")

    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_session(request):
    # Kept framework independent; API dependency supplies its typed Request wrapper.
    with request.app.state.session_factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
