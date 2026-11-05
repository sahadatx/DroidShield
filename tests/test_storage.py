import io
import os
import time

import pytest
from pydantic import ValidationError

from droidshield.config import Settings
from droidshield.storage import Storage, StorageError


def test_verified_snapshot_matches_original_and_cleans_up(tmp_path):
    store = Storage(tmp_path / "protected")
    staged = store.stage(io.BytesIO(b"test artifact bytes"), 100)
    reference = store.publish(staged)
    staged.close()
    with store.verified_copy(reference, staged.sha256, staged.file_size) as snapshot:
        assert snapshot.read_bytes() == b"test artifact bytes"
        assert snapshot.stat().st_mode & 0o077 == 0
    assert not snapshot.exists()
    assert not list(store.staging.iterdir())
    with store.open_artifact(reference) as original:
        assert original.read() == b"test artifact bytes"


@pytest.mark.parametrize(
    "data,maximum,code", [(b"", 100, "invalid_apk"), (b"x" * 10, 9, "upload_too_large")]
)
def test_stage_rejects_empty_and_oversized_files_without_leaks(tmp_path, data, maximum, code):
    store = Storage(tmp_path)
    with pytest.raises(StorageError) as error:
        store.stage(io.BytesIO(data), maximum)
    assert error.value.code == code
    assert not list(store.staging.iterdir())


def test_symlink_and_fifo_are_not_readable_as_artifacts(tmp_path, monkeypatch):
    store = Storage(tmp_path / "protected")
    reference = "apk:" + "a" * 32
    path = store.objects / ("a" * 32 + ".apk")
    target = tmp_path / "private"
    target.write_bytes(b"not an artifact")
    path.symlink_to(target)
    with pytest.raises(StorageError):
        store.open_artifact(reference)
    path.unlink()
    os.mkfifo(path)
    actual_open = os.open

    def nonblocking_open(name, flags, *args, **kwargs):
        if name == path:
            assert flags & os.O_NONBLOCK
        return actual_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", nonblocking_open)
    with pytest.raises(StorageError):
        store.open_artifact(reference)


@pytest.mark.parametrize(
    "reference", ["../../secret", "/etc/passwd", "apk:../x", "apk:" + "f" * 31]
)
def test_storage_references_cannot_choose_paths(tmp_path, reference):
    with pytest.raises(StorageError):
        Storage(tmp_path).open_artifact(reference)


def test_tampered_original_fails_digest_check_and_cleans_snapshot(tmp_path):
    store = Storage(tmp_path)
    staged = store.stage(io.BytesIO(b"original"), 100)
    reference = store.publish(staged)
    staged.close()
    path = store.objects / (reference[4:] + ".apk")
    path.chmod(0o600)
    path.write_bytes(b"tampered")
    with (
        pytest.raises(StorageError) as error,
        store.verified_copy(reference, staged.sha256, staged.file_size),
    ):
        pytest.fail("A modified artifact must not be exposed")
    assert error.value.code == "artifact_integrity_failed"
    assert not list(store.staging.iterdir())


def test_cleanup_retains_referenced_and_fresh_objects(tmp_path):
    store = Storage(tmp_path)
    old = time.time() - 7200
    refs = []
    for _ in range(3):
        staged = store.stage(io.BytesIO(b"bytes"), 100)
        refs.append(store.publish(staged))
        staged.close()
    for reference in refs[:2]:
        os.utime(store.objects / (reference[4:] + ".apk"), (old, old))
    pending = store.stage(io.BytesIO(b"unfinished"), 100)
    os.utime(pending.path, (old, old))
    assert store.clean_orphans({refs[0]}, time.time() - 3600) == 2
    assert (store.objects / (refs[0][4:] + ".apk")).exists()
    assert not (store.objects / (refs[1][4:] + ".apk")).exists()
    assert (store.objects / (refs[2][4:] + ".apk")).exists()
    assert not pending.path.exists()


def test_custom_private_namespace_keeps_reference_checks_and_cleanup(tmp_path):
    store = Storage(
        tmp_path / "authorization-attachments", reference_prefix="authdoc", object_suffix=".bin"
    )
    staged = store.stage(io.BytesIO(b"approval bytes"), 100)
    reference = store.publish(staged)
    staged.close()
    path = store._path(reference)
    old = time.time() - 7200
    os.utime(path, (old, old))
    assert store.clean_orphans({reference}, time.time() - 3600) == 0
    assert path.exists()
    assert store.clean_orphans(set(), time.time() - 3600) == 1
    assert not path.exists()


@pytest.mark.parametrize(
    "path", ["/usr/local/share/droidshield", "/usr/lib/droidshield", "/lib/droidshield"]
)
def test_storage_and_sqlite_cannot_be_placed_inside_exposed_runtimes(path):
    with pytest.raises(StorageError):
        Storage(path)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, storage_root=path)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url=f"sqlite:///{path}/db.sqlite")
