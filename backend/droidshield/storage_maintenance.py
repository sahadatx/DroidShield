"""Read-only backup verification and approved stale-object cleanup helpers."""

from itertools import chain
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield.models import (
    AppArtifact,
    AssessmentEvidence,
    AuthorizationAttachment,
    EvidenceAttachment,
)
from droidshield.report_models import ReportExport
from droidshield.storage import Storage, StorageError


def _namespaces(root: Path):
    return (
        ("artifacts", root, "apk", ".apk", AppArtifact, "storage_ref"),
        ("evidence", root / "evidence", "apk", ".apk", AssessmentEvidence, "artifact_ref"),
        (
            "evidence_screenshots",
            root / "evidence-attachments",
            "apk",
            ".apk",
            EvidenceAttachment,
            "storage_ref",
        ),
        (
            "authorization_documents",
            root / "authorization-attachments",
            "authdoc",
            ".bin",
            AuthorizationAttachment,
            "storage_ref",
        ),
        ("report_exports", root / "reports", "apk", ".apk", ReportExport, "storage_ref"),
    )


def _references(session: Session, model, reference_column):
    statement = select(
        getattr(model, reference_column), model.sha256, model.file_size
    ).execution_options(yield_per=1000)
    return session.execute(statement)


def cleanup_plan(session: Session, storage_root: Path, older_than: float) -> dict[str, int]:
    """Return stale candidate counts, never deleting referenced or fresh data."""
    counts = {}
    for name, root, prefix, suffix, model, reference_column in _namespaces(storage_root):
        references = {row[0] for row in _references(session, model, reference_column)}
        if not root.exists() and not references:
            counts[name] = 0
            continue
        store = Storage(root, reference_prefix=prefix, object_suffix=suffix, create=False)
        counts[name] = store.stale_unreferenced_count(references, older_than)
    return counts


def cleanup_apply(session: Session, storage_root: Path, older_than: float) -> dict[str, int]:
    """Remove only stale, unreferenced files in each known private namespace."""
    counts = {}
    for name, root, prefix, suffix, model, reference_column in _namespaces(storage_root):
        references = {row[0] for row in _references(session, model, reference_column)}
        if not root.exists() and not references:
            counts[name] = 0
            continue
        store = Storage(root, reference_prefix=prefix, object_suffix=suffix, create=False)
        counts[name] = store.clean_orphans(references, older_than)
    return counts


def verify_backup(session: Session, storage_root: Path) -> dict[str, object]:
    """Verify each immutable database reference against a read-only storage copy."""
    namespaces = {}
    for name, root, prefix, suffix, model, reference_column in _namespaces(storage_root):
        checked = 0
        failed = 0
        rows = _references(session, model, reference_column)
        first = next(rows, None)
        if first is not None:
            try:
                store = Storage(root, reference_prefix=prefix, object_suffix=suffix, create=False)
            except StorageError:
                remaining = sum(1 for _ in rows)
                checked = failed = 1 + remaining
            else:
                for storage_ref, sha256, size in chain((first,), rows):
                    checked += 1
                    try:
                        store.verify(storage_ref, sha256, size)
                    except StorageError:
                        failed += 1
        namespaces[name] = {"checked": checked, "failed": failed}
    total_checked = sum(item["checked"] for item in namespaces.values())
    total_failed = sum(item["failed"] for item in namespaces.values())
    return {
        "consistent": total_failed == 0,
        "checked": total_checked,
        "failed": total_failed,
        "namespaces": namespaces,
    }
