"""Protected local object store. References are opaque; clients never choose paths."""

import hashlib
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4


class StorageError(Exception):
    def __init__(self, code: str = "storage_unavailable"):
        self.code = code
        super().__init__("Protected artifact storage operation failed")


@dataclass(frozen=True)
class StagedFile:
    path: Path
    sha256: str
    file_size: int

    def close(self) -> None:
        self.path.unlink(missing_ok=True)


class Storage:
    def __init__(self, root: Path | str):
        self.root = Path(root).absolute()
        visible_runtime = {Path(path).resolve() for path in ("/usr", "/lib", "/lib64")}
        if any(self.root.resolve().is_relative_to(path) for path in visible_runtime):
            raise StorageError("storage_unavailable")
        self.objects = self.root / "objects"
        self.staging = self.root / "staging"
        try:
            for directory in [self.root, self.objects, self.staging]:
                if directory.is_symlink():
                    raise StorageError()
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                if not directory.is_dir() or directory.stat().st_uid != os.getuid():
                    raise StorageError()
                directory.chmod(0o700)
        except OSError as exc:
            raise StorageError() from exc

    def stage(self, source: BinaryIO, max_bytes: int) -> StagedFile:
        descriptor, name = tempfile.mkstemp(prefix="upload-", suffix=".apk", dir=self.staging)
        path = Path(name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as destination:
                while chunk := source.read(64 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise StorageError("upload_too_large")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if not size:
                raise StorageError("invalid_apk")
            path.chmod(0o400)
            return StagedFile(path, digest.hexdigest(), size)
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise StorageError() from exc
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _path(self, storage_ref: str) -> Path:
        if not re.fullmatch(r"apk:[0-9a-f]{32}", storage_ref):
            raise StorageError("artifact_integrity_failed")
        return self.objects / (storage_ref[4:] + ".apk")

    def publish(self, staged: StagedFile) -> str:
        reference = "apk:" + uuid4().hex
        path = self._path(reference)
        try:
            # link is exclusive and atomic on this filesystem. Staging is private
            # and an object becomes visible only after inspection has succeeded.
            os.link(staged.path, path, follow_symlinks=False)
            with self.open_artifact(reference) as source:
                os.fsync(source.fileno())
            directory_fd = os.open(self.objects, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise StorageError() from exc
        return reference

    def discard(self, storage_ref: str) -> None:
        self._path(storage_ref).unlink(missing_ok=True)

    def open_artifact(self, storage_ref: str) -> BinaryIO:
        try:
            descriptor = os.open(
                self._path(storage_ref), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            )
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise StorageError("artifact_integrity_failed")
            return os.fdopen(descriptor, "rb")
        except OSError as exc:
            raise StorageError("artifact_integrity_failed") from exc

    @contextmanager
    def verified_copy(self, storage_ref: str, sha256: str, size: int) -> Iterator[Path]:
        directory = Path(tempfile.mkdtemp(prefix="snapshot-", dir=self.staging))
        path = directory / "app.apk"
        copy = None
        try:
            with self.open_artifact(storage_ref) as source:
                if os.fstat(source.fileno()).st_size != size:
                    raise StorageError("artifact_integrity_failed")
                try:
                    copy = self.stage(source, size)
                except StorageError as exc:
                    raise StorageError("artifact_integrity_failed") from exc
            if copy.file_size != size or copy.sha256 != sha256:
                copy.close()
                raise StorageError("artifact_integrity_failed")
            copy.path.rename(path)
            yield path
        except OSError as exc:
            raise StorageError("artifact_integrity_failed") from exc
        finally:
            if copy:
                copy.close()
            shutil.rmtree(directory, ignore_errors=True)

    def clean_orphans(self, referenced: set[str], older_than: float) -> int:
        """Trusted CLI maintenance; never remove a referenced object or fresh upload."""
        count = 0
        for path in self.objects.iterdir():
            if not re.fullmatch(r"[0-9a-f]{32}\.apk", path.name):
                continue
            if "apk:" + path.stem in referenced:
                continue
            if not path.is_symlink() and path.is_file() and path.stat().st_mtime < older_than:
                path.unlink()
                count += 1
        for path in self.staging.iterdir():
            if path.is_symlink() or path.stat().st_mtime >= older_than:
                continue
            if path.is_file() and path.name.startswith("upload-"):
                path.unlink()
                count += 1
            elif path.is_dir() and path.name.startswith("snapshot-"):
                shutil.rmtree(path)
                count += 1
        return count
