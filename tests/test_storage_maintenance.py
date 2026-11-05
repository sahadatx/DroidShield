import hashlib
import io
import os
import sqlite3
import sys
import time
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from droidshield.config import Settings
from droidshield.db import build_engine, session_factory
from droidshield.models import AppArtifact
from droidshield.storage import Storage
from droidshield.storage_maintenance import cleanup_apply, cleanup_plan, verify_backup
from tests.test_api import api as _api
from tests.test_api import make_project

api = _api


def _artifact(api, root: Path):
    project = make_project(api)
    store = Storage(root)
    staged = store.stage(io.BytesIO(b"verified backup artifact"), 1024)
    reference = store.publish(staged)
    digest, size = staged.sha256, staged.file_size
    staged.close()
    with Session(api.engine) as session:
        session.add(
            AppArtifact(
                workspace_id=api.workspaces["main"],
                project_id=UUID(project["id"]),
                sha256=digest,
                storage_ref=reference,
                original_filename="sample.apk",
                file_size=size,
                build_type="unknown",
                metadata_json={},
                created_by=api.users["admin"],
            )
        )
        session.commit()
    return store, reference, digest, size


def test_backup_verification_checks_referenced_bytes_and_reports_corruption(api, tmp_path):
    storage_root = tmp_path / "backup-store"
    store, reference, digest, size = _artifact(api, storage_root)
    with Session(api.engine) as session:
        result = verify_backup(session, storage_root)
    assert result["consistent"] is True
    assert result["checked"] == 1
    assert result["failed"] == 0
    assert result["namespaces"]["artifacts"] == {"checked": 1, "failed": 0}
    assert result["namespaces"]["report_exports"] == {"checked": 0, "failed": 0}

    path = store._path(reference)
    path.chmod(0o600)
    path.write_bytes(b"tampered backup artifact")
    with Session(api.engine) as session:
        result = verify_backup(session, storage_root)
    assert result["consistent"] is False
    assert result["failed"] == 1
    assert digest == hashlib.sha256(b"verified backup artifact").hexdigest()
    assert size == len(b"verified backup artifact")


def test_cleanup_preview_and_apply_cover_all_stores_without_deleting_references(api, tmp_path):
    storage_root = tmp_path / "live-store"
    artifact_store, artifact_ref, _, _ = _artifact(api, storage_root)
    old = time.time() - 7200
    os.utime(artifact_store._path(artifact_ref), (old, old))
    other_stores = (
        Storage(storage_root / "evidence"),
        Storage(storage_root / "evidence-attachments"),
        Storage(
            storage_root / "authorization-attachments",
            reference_prefix="authdoc",
            object_suffix=".bin",
        ),
        Storage(storage_root / "reports"),
    )
    orphan_paths = []
    for index, store in enumerate(other_stores):
        staged = store.stage(io.BytesIO(f"orphan-{index}".encode()), 1024)
        reference = store.publish(staged)
        staged.close()
        path = store._path(reference)
        os.utime(path, (old, old))
        orphan_paths.append(path)

    threshold = time.time() - 3600
    with Session(api.engine) as session:
        preview = cleanup_plan(session, storage_root, threshold)
    assert preview == {
        "artifacts": 0,
        "evidence": 1,
        "evidence_screenshots": 1,
        "authorization_documents": 1,
        "report_exports": 1,
    }
    assert all(path.exists() for path in orphan_paths)

    with Session(api.engine) as session:
        removed = cleanup_apply(session, storage_root, threshold)
    assert sum(removed.values()) == 4
    assert all(not path.exists() for path in orphan_paths)
    assert artifact_store._path(artifact_ref).exists()


def test_cleanup_cli_is_preview_only_until_explicit_typed_approval(
    api, monkeypatch, capsys, tmp_path
):
    from droidshield import cli

    storage_root = tmp_path / "cli-store"
    store = Storage(storage_root)
    staged = store.stage(io.BytesIO(b"old orphan"), 1024)
    reference = store.publish(staged)
    staged.close()
    old = time.time() - 7200
    path = store._path(reference)
    os.utime(path, (old, old))
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url="sqlite://",
        storage_root=storage_root,
    )
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "build_engine", lambda *_args, **_kwargs: api.engine)
    monkeypatch.setattr(api.engine, "dispose", lambda: None)
    monkeypatch.setattr(sys, "argv", ["droidshield", "cleanup-storage", "--older-than-hours", "1"])
    cli.main()
    assert path.exists()
    assert "total=1" in capsys.readouterr().out

    monkeypatch.setattr(
        sys,
        "argv",
        ["droidshield", "cleanup-storage", "--older-than-hours", "1", "--apply"],
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "wrong approval")
    with pytest.raises(SystemExit) as cancelled:
        cli.main()
    assert cancelled.value.code == 2
    assert path.exists()

    monkeypatch.setattr("builtins.input", lambda _prompt: "DELETE OLD UNREFERENCED STORAGE")
    cli.main()
    assert not path.exists()


def test_cleanup_preview_does_not_create_missing_namespaces(api, tmp_path):
    storage_root = tmp_path / "missing-store"
    with Session(api.engine) as session:
        result = cleanup_plan(session, storage_root, time.time() - 3600)
    assert set(result.values()) == {0}
    assert not storage_root.exists()


def test_backup_verification_cli_opens_restored_database_read_only(monkeypatch, capsys, tmp_path):
    from droidshield import cli
    from droidshield.models import Base

    backup_database = tmp_path / "empty-backup.sqlite"
    backup_url = f"sqlite:///{backup_database}"
    source_engine = build_engine(backup_url)
    Base.metadata.create_all(source_engine)
    source_engine.dispose()
    backup_storage = tmp_path / "backup-storage"
    backup_storage.mkdir(mode=0o700)
    monkeypatch.setenv("DROIDSHIELD_BACKUP_DATABASE_URL", backup_url)
    monkeypatch.setattr(
        cli,
        "Settings",
        lambda: Settings(
            _env_file=None,
            environment="test",
            database_url="sqlite://",
            storage_root=tmp_path / "workspace-storage",
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["droidshield", "verify-backup", "--storage-root", str(backup_storage)],
    )

    cli.main()

    output = capsys.readouterr().out
    assert "Backup verification: CONSISTENT" in output
    assert "references checked=0; failures=0" in output
    assert not (tmp_path / "workspace-storage").exists()


def test_read_only_sqlite_backup_engine_never_creates_or_mutates_database(tmp_path):
    missing = tmp_path / "missing-backup.sqlite"
    with pytest.raises(ValueError, match="does not exist"):
        build_engine(f"sqlite:///{missing}", read_only=True)
    assert not missing.exists()

    database = tmp_path / "backup.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE proof (value TEXT NOT NULL)")
    connection.execute("INSERT INTO proof VALUES ('backup')")
    connection.commit()
    connection.close()

    engine = build_engine(f"sqlite:///{database}", read_only=True)
    try:
        with session_factory(engine)() as session:
            assert session.execute(text("SELECT value FROM proof")).scalar_one() == "backup"
            with pytest.raises(OperationalError):
                session.execute(text("INSERT INTO proof VALUES ('changed')"))
                session.commit()
    finally:
        engine.dispose()

    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM proof").fetchone()[0] == 1
    connection.close()


def test_read_only_postgres_engine_accepts_explicit_connect_timeout():
    engine = build_engine(
        "postgresql+psycopg://backup:ignored@127.0.0.1/droidshield?connect_timeout=2",
        read_only=True,
    )
    try:
        assert engine.dialect.name == "postgresql"
    finally:
        engine.dispose()
