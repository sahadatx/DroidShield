"""Job lifecycle security tests; APK parser and isolation have separate real tests."""

import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from droidshield import services, worker
from droidshield.analysis_contract import LIMITATIONS
from droidshield.apk_engine import analyze
from droidshield.cli import migrate
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.models import (
    AnalysisJob,
    AnalysisResult,
    Assessment,
    AuditEvent,
    Authorization,
    Base,
    Finding,
    Project,
    ProjectAccess,
    User,
)
from droidshield.sandbox import SandboxCancelled, SandboxError
from droidshield.storage import StorageError
from tests.test_api import isolated_test_engine
from tests.test_concurrency import seed_queueable_assessment


def engine_output():
    output = {
        "schema_version": 1,
        "engine_version": "droidshield-manifest-2",
        "sha256": "a" * 64,
        "file_size": 100,
        "metadata": {
            "package_name": "test.app",
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
            "permissions": [],
            "application": {
                "debuggable": True,
                "uses_cleartext_traffic": None,
                "allow_backup": None,
                "test_only": None,
            },
            "components": [],
            "signing_certificate": None,
        },
        "indicators": [],
        "limitations": list(LIMITATIONS),
    }
    output["indicators"] = analyze(output["metadata"])
    return output


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    url = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL", f"sqlite:///{tmp_path / 'worker.db'}")
    with isolated_test_engine(url) as engine:
        Base.metadata.create_all(engine)
        user_id, authorization_id, assessment_id = seed_queueable_assessment(engine)
        with Session(engine) as session:
            actor = session.get(User, user_id)
            services.queue_assessment(
                services.Context(session, actor, "test-worker-queue"), assessment_id, 1
            )
            session.commit()
            job_id = session.scalar(select(AnalysisJob.id))
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=url,
            storage_root=tmp_path / "protected",
        )
        apk = tmp_path / "snapshot.apk"
        apk.write_bytes(b"test snapshot")
        calls = []

        class TestStorage:
            def __init__(self, root):
                assert root == settings.storage_root

            @contextmanager
            def verified_copy(self, reference, sha256, size):
                assert reference == "protected/app.apk"
                assert sha256 == "a" * 64 and size == 100
                yield apk

        class TestSandbox:
            def __init__(self, configuration):
                assert configuration is settings

            def run(self, path, mode="analyze", should_cancel=None):
                calls.append(path)
                assert mode == "analyze" and not should_cancel()
                return engine_output()

        monkeypatch.setattr(worker, "Storage", TestStorage)
        monkeypatch.setattr(worker, "Sandbox", TestSandbox)
        yield engine, settings, job_id, assessment_id, authorization_id, calls


def test_scan_success_creates_atomic_unreviewed_findings_with_provenance(jobs):
    engine, settings, job_id, assessment_id, _, calls = jobs
    assert worker.run_once(settings, engine)
    assert not worker.run_once(settings, engine)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assessment = session.get(Assessment, assessment_id)
        result = session.scalar(select(AnalysisResult))
        finding = session.scalar(select(Finding))
        assert job.status == "completed" and job.attempt_count == 1
        assert job.started_at and job.completed_at and job.heartbeat_at
        assert job.worker_id and job.lease_expires_at is None
        assert assessment.status == "needs_review" and assessment.completed_at is None
        assert result.job_id == job_id and result.artifact_sha256 == "a" * 64
        assert result.indicators_json[0]["rule_id"] == "MANIFEST_DEBUGGABLE"
        assert finding.verification_status == "unreviewed" and finding.remediation_status == "open"
        assert finding.evidence_provenance["analysis_result_id"] == str(result.id)
        assert finding.evidence_provenance["artifact_sha256"] == "a" * 64
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert job.configuration_snapshot["execution"]
        audit = session.scalars(select(AuditEvent).where(AuditEvent.resource_id == job_id)).all()
        assert {event.action for event in audit} == {
            "analysis_job.claimed",
            "analysis_job.completed",
        }
        assert all(event.actor_id is None for event in audit)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "change,reason",
    [
        ("expired", "authorization_invalid"),
        ("scope", "authorization_invalid"),
        ("disabled", "operator_access_revoked"),
        ("viewer", "operator_access_revoked"),
        ("inactive", "project_inactive"),
        ("snapshot", "execution_snapshot_invalid"),
        ("artifact", "artifact_integrity_failed"),
    ],
)
def test_claim_revalidates_prerequisites_without_invoking_parser(jobs, change, reason):
    engine, settings, job_id, assessment_id, authorization_id, calls = jobs
    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)
        permit = session.get(Authorization, authorization_id)
        if change == "expired":
            permit.valid_until = datetime.now(UTC) - timedelta(seconds=1)
        elif change == "scope":
            permit.exclusions = ["package:test.app"]
        elif change in {"disabled", "viewer"}:
            actor = session.get(User, assessment.created_by)
            if change == "disabled":
                actor.status = "disabled"
            else:
                actor.role = "VIEWER"
        elif change == "inactive":
            session.get(Project, assessment.project_id).status = "on_hold"
        elif change == "snapshot":
            job = session.get(AnalysisJob, job_id)
            job.configuration_snapshot = {
                **job.configuration_snapshot,
                "requested_targets": ["package:other.app"],
            }
        elif change == "artifact":
            for record in (assessment, session.get(AnalysisJob, job_id)):
                record.configuration_snapshot = {
                    **record.configuration_snapshot,
                    "artifact_sha256": "b" * 64,
                }
        session.commit()
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.status == "failed" and job.failure_reason == reason
        assert job.attempt_count == 0 and job.completed_at
        assert session.get(Assessment, assessment_id).status == "failed"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
    assert calls == []


@pytest.mark.parametrize("action", ["revoke", "expire", "disable", "cancel"])
def test_running_scan_stops_when_authorization_or_access_is_withdrawn(jobs, monkeypatch, action):
    engine, settings, job_id, assessment_id, authorization_id, _ = jobs

    def interrupted_scan(self, path, mode, should_cancel):
        with Session(engine) as session:
            assessment = session.get(Assessment, assessment_id)
            actor = session.get(User, assessment.created_by)
            context = services.Context(session, actor, "test-stop-worker")
            permit = session.get(Authorization, authorization_id)
            if action == "revoke":
                services.revoke_authorization(
                    context, authorization_id, permit.revision, "Approval withdrawn"
                )
            elif action == "expire":
                permit.valid_until = datetime.now(UTC) - timedelta(seconds=1)
            elif action == "disable":
                actor.status = "disabled"
            else:
                services.cancel_assessment(
                    context, assessment_id, assessment.revision, "Stop testing"
                )
            session.commit()
        assert should_cancel()
        raise SandboxCancelled()

    monkeypatch.setattr(worker.Sandbox, "run", interrupted_scan)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).status == "cancelled"
        assert session.get(Assessment, assessment_id).status == "cancelled"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_expired_lease_fails_safely_and_stale_worker_cannot_publish(jobs, monkeypatch):
    engine, settings, job_id, assessment_id, _, _ = jobs

    def lease_lost(self, path, mode, should_cancel):
        with Session(engine) as session:
            session.get(AnalysisJob, job_id).lease_expires_at = datetime.now(UTC) - timedelta(
                seconds=1
            )
            session.commit()
        assert should_cancel()
        # Even an engine ignoring cancellation must not publish output.
        return engine_output()

    monkeypatch.setattr(worker.Sandbox, "run", lease_lost)
    assert worker.run_once(settings, engine)
    assert worker.run_once(settings, engine)
    assert not worker.run_once(settings, engine)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.status == "failed" and job.failure_reason == "worker_lease_expired"
        assert job.attempt_count == 1
        assert session.get(Assessment, assessment_id).status == "failed"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0


def test_changed_claim_token_fences_out_original_worker(jobs, monkeypatch):
    engine, settings, job_id, _, _, _ = jobs
    new_worker = uuid4()

    def token_lost(self, path, mode, should_cancel):
        with Session(engine) as session:
            session.get(AnalysisJob, job_id).worker_id = new_worker
            session.commit()
        assert should_cancel()
        return engine_output()

    monkeypatch.setattr(worker.Sandbox, "run", token_lost)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.worker_id == new_worker and job.status == "running"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0


def test_concurrent_worker_cannot_execute_claimed_job_twice(jobs, monkeypatch):
    engine, settings, _, _, _, calls = jobs
    entered, release = Event(), Event()

    def waiting_scan(self, path, mode, should_cancel):
        calls.append(path)
        entered.set()
        assert release.wait(timeout=10)
        assert not should_cancel()
        return engine_output()

    monkeypatch.setattr(worker.Sandbox, "run", waiting_scan)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(worker.run_once, settings, engine)
        try:
            assert entered.wait(timeout=10)
            assert not worker.run_once(settings, engine)
        finally:
            release.set()
        assert first.result(timeout=10)
    assert len(calls) == 1


def test_engine_failure_never_persists_partial_evidence_or_error_details(jobs, monkeypatch):
    engine, settings, job_id, _, _, _ = jobs

    def failed_scan(self, path, mode, should_cancel):
        raise SandboxError("analysis_timeout")

    monkeypatch.setattr(worker.Sandbox, "run", failed_scan)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).failure_reason == "analysis_timeout"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_storage_integrity_failure_prevents_parser_execution(jobs, monkeypatch):
    engine, settings, job_id, _, _, calls = jobs

    @contextmanager
    def tampered_copy(self, *args):
        raise StorageError("artifact_integrity_failed")
        yield  # pragma: no cover

    monkeypatch.setattr(worker.Storage, "verified_copy", tampered_copy)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).failure_reason == "artifact_integrity_failed"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
    assert calls == []


def test_final_authorization_gate_discards_results_even_without_engine_callback(jobs, monkeypatch):
    engine, settings, job_id, _, authorization_id, _ = jobs

    def withdrawn_after_scan(self, path, mode, should_cancel):
        with Session(engine) as session:
            permit = session.get(Authorization, authorization_id)
            permit.valid_until = datetime.now(UTC) - timedelta(seconds=1)
            session.commit()
        return engine_output()

    monkeypatch.setattr(worker.Sandbox, "run", withdrawn_after_scan)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).status == "cancelled"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_findings_and_normalized_results_roll_back_together(jobs):
    engine, settings, job_id, _, _, _ = jobs

    def reject_finding(*args):
        raise ValueError("Private database diagnostic")

    event.listen(Finding, "before_insert", reject_finding)
    try:
        assert worker.run_once(settings, engine)
    finally:
        event.remove(Finding, "before_insert", reject_finding)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.status == "failed" and job.failure_reason == "analysis_failed"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
        assert "Private" not in str(session.scalars(select(AuditEvent.source_metadata)).all())


def test_engine_cannot_substitute_a_different_artifact_digest(jobs, monkeypatch):
    engine, settings, job_id, _, _, _ = jobs

    def substituted_artifact(self, path, mode, should_cancel):
        output = engine_output()
        output["sha256"] = "b" * 64
        return output

    monkeypatch.setattr(worker.Sandbox, "run", substituted_artifact)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).failure_reason == "engine_result_invalid"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0


def test_running_worker_revalidates_nonowner_project_grants(jobs, monkeypatch):
    engine, settings, job_id, assessment_id, _, _ = jobs
    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)
        analyst = User(
            workspace_id=assessment.workspace_id,
            email="operator@example.test",
            full_name="Operator",
            role="SECURITY_ANALYST",
        )
        session.add(analyst)
        session.flush()
        grant = ProjectAccess(
            workspace_id=assessment.workspace_id,
            project_id=assessment.project_id,
            user_id=analyst.id,
            created_by=assessment.created_by,
        )
        session.add(grant)
        assessment.created_by = analyst.id
        session.flush()
        grant_id = grant.id
        session.commit()

    def grant_withdrawn(self, path, mode, should_cancel):
        with Session(engine) as session:
            session.delete(session.get(ProjectAccess, grant_id))
            session.commit()
        assert should_cancel()
        return engine_output()

    monkeypatch.setattr(worker.Sandbox, "run", grant_withdrawn)
    assert worker.run_once(settings, engine)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.status == "cancelled" and job.cancellation_reason == "operator_access_revoked"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0


@pytest.mark.parametrize("moment", ["before_copy", "during_scan", "after_scan"])
def test_worker_shutdown_cancels_claim_without_publishing(jobs, monkeypatch, moment):
    engine, settings, job_id, assessment_id, _, calls = jobs
    stop = Event()
    if moment == "before_copy":
        original = worker._claim

        def stop_after_claim(*args):
            claimed = original(*args)
            stop.set()
            return claimed

        monkeypatch.setattr(worker, "_claim", stop_after_claim)
    else:

        def interrupted(self, path, mode, should_cancel):
            stop.set()
            if moment == "during_scan":
                assert should_cancel()
                raise SandboxCancelled()
            return engine_output()

        monkeypatch.setattr(worker.Sandbox, "run", interrupted)
    assert worker.run_once(settings, engine, should_stop=stop.is_set)
    with Session(engine) as session:
        job = session.get(AnalysisJob, job_id)
        assert job.status == "cancelled" and job.cancellation_reason == "worker_shutdown"
        assert session.get(Assessment, assessment_id).status == "cancelled"
        assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
    if moment == "before_copy":
        assert calls == []


def test_stopped_worker_leaves_unclaimed_queue_untouched(jobs):
    engine, settings, job_id, _, _, calls = jobs
    assert not worker.run_once(settings, engine, should_stop=lambda: True)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).status == "queued"
    assert calls == []


def test_migrated_results_reject_changes_to_persisted_evidence(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'immutable.db'}",
        storage_root=tmp_path / "artifacts",
    )
    migrate(settings)
    engine = build_engine(settings.database_url)
    try:
        user_id, _, assessment_id = seed_queueable_assessment(engine)
        with Session(engine) as session:
            services.queue_assessment(
                services.Context(session, session.get(User, user_id), "test-immutable-result"),
                assessment_id,
                1,
            )
            session.commit()

        @contextmanager
        def snapshot(self, *args):
            yield tmp_path / "isolated.apk"

        monkeypatch.setattr(worker.Storage, "verified_copy", snapshot)
        monkeypatch.setattr(worker.Sandbox, "run", lambda *args, **kwargs: engine_output())
        assert worker.run_once(settings, engine)
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(AnalysisResult)) == 1
        for statement in ("UPDATE analysis_results SET id = id", "DELETE FROM analysis_results"):
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(text(statement))
    finally:
        engine.dispose()


def test_api_queue_is_left_for_a_future_capable_worker(jobs):
    engine, settings, job_id, assessment_id, _, calls = jobs
    with Session(engine) as session:
        session.get(Assessment, assessment_id).assessment_type = "api"
        session.commit()
    assert not worker.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(AnalysisJob, job_id).status == "queued"
    assert calls == []
