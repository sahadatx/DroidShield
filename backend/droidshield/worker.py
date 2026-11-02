"""Lease-based static analysis orchestration; queue rows never execute themselves.

Every database transaction is short. No database locks are held while parsing an
APK, and the subprocess cancellation callback renews the lease only after checking
the current authorization, account, project grant, scope and artifact identity.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import or_, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from droidshield.analysis_contract import ENGINE_VERSION, DexAnalysisResult
from droidshield.analysis_contract import AnalysisResult as EngineResult
from droidshield.auth import utc
from droidshield.config import Settings
from droidshield.db import build_engine, session_factory
from droidshield.models import (
    AnalysisJob,
    AnalysisResult,
    AppArtifact,
    Assessment,
    AuditEvent,
    Authorization,
    Client,
    Finding,
    Project,
    ProjectAccess,
    User,
)
from droidshield.sandbox import Sandbox, SandboxCancelled, SandboxError
from droidshield.storage import Storage, StorageError

_SCOPE_KEYS = (
    "requested_targets",
    "authorization_id",
    "authorization_revision",
    "approved_targets",
    "exclusions",
    "valid_from",
    "valid_until",
    "artifact_sha256",
    "engine",
    "proxy_targets",
)

ENGINE_VERSIONS = {
    "manifest": ENGINE_VERSION,
    "dex": "droidshield-dex-1",
    "mobsf": "droidshield-mobsf-1",
}


@dataclass(frozen=True)
class Claim:
    job_id: UUID
    worker_id: UUID
    storage_ref: str
    sha256: str
    file_size: int
    engine: str = "manifest"
    metadata: dict | None = None


def _locked(session: Session, job_id: UUID, *, skip: bool = False):
    """Use the same authorization → assessment → job order as revoke/cancel."""
    if session.bind.dialect.name == "postgresql":
        # A busy or unavailable control database must not stall the cancellation
        # monitor indefinitely. The sandbox also has an independent watchdog.
        session.execute(text("SET LOCAL lock_timeout = '2s'"))
        session.execute(text("SET LOCAL statement_timeout = '5s'"))
    origin = session.execute(
        select(Assessment.id, Assessment.authorization_id, Assessment.workspace_id)
        .join(AnalysisJob, AnalysisJob.assessment_id == Assessment.id)
        .where(AnalysisJob.id == job_id)
    ).first()
    if origin is None:
        return None
    permit = session.scalar(
        select(Authorization)
        .where(
            Authorization.id == origin.authorization_id,
            Authorization.workspace_id == origin.workspace_id,
        )
        .with_for_update(skip_locked=skip)
    )
    if permit is None:
        return None
    assessment = session.scalar(
        select(Assessment).where(Assessment.id == origin.id).with_for_update(skip_locked=skip)
    )
    if assessment is None:
        return None
    job = session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id).with_for_update(skip_locked=skip)
    )
    return (permit, assessment, job) if job is not None else None


def _prerequisite(
    session: Session,
    permit: Authorization,
    assessment: Assessment,
    job: AnalysisJob,
    *,
    assessment_type: str = "static",
) -> tuple[str | None, AppArtifact | None]:
    """Return only fixed reason codes. Never include attacker-controlled data."""
    now = datetime.now(UTC)
    snapshot = assessment.configuration_snapshot
    if (
        assessment.assessment_type != assessment_type
        or job.workspace_id != assessment.workspace_id
        or job.artifact_id != assessment.artifact_id
        or assessment.authorization_id != permit.id
        or permit.workspace_id != assessment.workspace_id
        or permit.project_id != assessment.project_id
        or any(snapshot.get(key) != job.configuration_snapshot.get(key) for key in _SCOPE_KEYS)
        or (
            assessment_type == "static"
            and snapshot.get("engine", "manifest") not in ENGINE_VERSIONS
        )
    ):
        return "execution_snapshot_invalid", None
    if (
        permit.status != "verified"
        or not (utc(permit.valid_from) <= now < utc(permit.valid_until))
        or snapshot.get("authorization_id") != str(permit.id)
        or snapshot.get("authorization_revision") != permit.revision
        or snapshot.get("approved_targets") != permit.approved_targets
        or snapshot.get("exclusions") != permit.exclusions
        or snapshot.get("valid_from") != utc(permit.valid_from).isoformat()
        or snapshot.get("valid_until") != utc(permit.valid_until).isoformat()
    ):
        return "authorization_invalid", None
    project = session.scalar(
        select(Project).where(
            Project.id == assessment.project_id, Project.workspace_id == assessment.workspace_id
        )
    )
    client = (
        session.scalar(
            select(Client).where(
                Client.id == project.client_id, Client.workspace_id == assessment.workspace_id
            )
        )
        if project is not None
        else None
    )
    user = session.scalar(
        select(User).where(
            User.id == assessment.created_by, User.workspace_id == assessment.workspace_id
        )
    )
    if project is None or client is None or project.status != "active" or client.status != "active":
        return "project_inactive", None
    if user is None or user.status != "active" or user.role not in {"ADMIN", "SECURITY_ANALYST"}:
        return "operator_access_revoked", None
    if user.role != "ADMIN" and project.created_by != user.id:
        grant = session.scalar(
            select(ProjectAccess.id).where(
                ProjectAccess.workspace_id == assessment.workspace_id,
                ProjectAccess.project_id == project.id,
                ProjectAccess.user_id == user.id,
            )
        )
        if grant is None:
            return "operator_access_revoked", None
    artifact = session.scalar(
        select(AppArtifact).where(
            AppArtifact.id == assessment.artifact_id,
            AppArtifact.workspace_id == assessment.workspace_id,
            AppArtifact.project_id == project.id,
        )
    )
    if artifact is None or snapshot.get("artifact_sha256") != artifact.sha256:
        return "artifact_integrity_failed", None
    if (
        project.platform != "android"
        or artifact.metadata_json.get("artifact_format", "apk") != "apk"
    ):
        return "target_scope_invalid", None
    target = f"package:{project.package_id}"
    additional = snapshot.get("proxy_targets", []) if assessment_type == "dynamic" else []
    if (
        not isinstance(additional, list)
        or len(additional) > 10
        or any(not isinstance(item, str) or not item.startswith("https://") for item in additional)
    ):
        return "target_scope_invalid", None
    from droidshield.services import is_excluded

    requested = [target, *additional]
    if (
        artifact.metadata_json.get("package_name") != project.package_id
        or snapshot.get("requested_targets") != requested
        or any(item not in permit.approved_targets for item in requested)
        or any(
            is_excluded(item, exclusion) for item in requested for exclusion in permit.exclusions
        )
    ):
        return "target_scope_invalid", None
    return None, artifact


def _audit(session: Session, job: AnalysisJob, action: str, *, reason: str | None = None):
    session.add(
        AuditEvent(
            workspace_id=job.workspace_id,
            actor_id=None,
            action=f"analysis_job.{action}",
            resource_type="analysis_job",
            resource_id=job.id,
            result="failure" if action == "failed" else "success",
            request_id=f"worker-{job.worker_id or uuid4()}",
            source_metadata={"channel": "worker", **({"reason": reason} if reason else {})},
        )
    )


def _terminal(
    session: Session,
    assessment: Assessment,
    job: AnalysisJob,
    reason: str,
    *,
    cancelled: bool = False,
):
    now = datetime.now(UTC)
    status = "cancelled" if cancelled else "failed"
    job.status = status
    job.completed_at = now
    job.lease_expires_at = None
    if cancelled:
        job.cancellation_reason = reason
    else:
        job.failure_reason = reason
    if assessment.status in {"queued", "running"}:
        assessment.status = status
        if cancelled:
            assessment.cancelled_at = now
            assessment.cancellation_reason = reason
        else:
            assessment.completed_at = now
            assessment.failure_reason = reason
    _audit(session, job, status, reason=reason)


def _claim(settings: Settings, engine: Engine) -> tuple[bool, Claim | None]:
    factory = session_factory(engine)
    now = datetime.now(UTC)
    with factory() as session:
        candidates = session.scalars(
            select(AnalysisJob.id)
            .join(Assessment, Assessment.id == AnalysisJob.assessment_id)
            .where(
                Assessment.assessment_type == "static",
                or_(
                    AnalysisJob.status == "queued",
                    (AnalysisJob.status == "running")
                    & or_(
                        AnalysisJob.lease_expires_at.is_(None), AnalysisJob.lease_expires_at <= now
                    ),
                ),
            )
            .order_by(AnalysisJob.created_at, AnalysisJob.id)
            .limit(25)
        ).all()
    for job_id in candidates:
        with factory.begin() as session:
            locked = _locked(session, job_id, skip=True)
            if locked is None:
                continue
            permit, assessment, job = locked
            if job.status == "running":
                if job.lease_expires_at is None or utc(job.lease_expires_at) <= datetime.now(UTC):
                    _terminal(session, assessment, job, "worker_lease_expired")
                    return True, None
                continue
            if job.status != "queued":
                continue
            if assessment.status != "queued":
                _terminal(
                    session,
                    assessment,
                    job,
                    "assessment_not_queued",
                    cancelled=assessment.status == "cancelled",
                )
                return True, None
            reason, artifact = _prerequisite(session, permit, assessment, job)
            if reason is not None:
                _terminal(session, assessment, job, reason)
                return True, None
            execution = {
                key: value
                for key, value in settings.model_dump(mode="json").items()
                if (
                    key.startswith(("analysis_", "apk_", "dex_"))
                    or key in {"max_apk_bytes", "mobsf_timeout_seconds", "mobsf_max_report_bytes"}
                )
                and not key.endswith(("path", "root"))
            }
            now = datetime.now(UTC)
            job.worker_id = uuid4()
            job.status = "running"
            job.started_at = now
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
            job.attempt_count += 1
            job.configuration_snapshot = {**job.configuration_snapshot, "execution": execution}
            selected = assessment.configuration_snapshot.get("engine", "manifest")
            job.tool_versions = {f"static_{selected}": ENGINE_VERSIONS[selected]}
            assessment.status = "running"
            assessment.started_at = now
            assessment.configuration_snapshot = {
                **assessment.configuration_snapshot,
                "execution": execution,
            }
            assessment.tool_versions = dict(job.tool_versions)
            _audit(session, job, "claimed")
            return True, Claim(
                job.id,
                job.worker_id,
                artifact.storage_ref,
                artifact.sha256,
                artifact.file_size,
                selected,
                dict(artifact.metadata_json),
            )
    return False, None


def _owns(job: AnalysisJob, claim: Claim) -> bool:
    return (
        job.status == "running"
        and job.worker_id == claim.worker_id
        and job.lease_expires_at is not None
        and utc(job.lease_expires_at) > datetime.now(UTC)
    )


def _monitor(settings: Settings, engine: Engine, claim: Claim) -> bool:
    """True means terminate the parser immediately and discard its output."""
    with session_factory(engine).begin() as session:
        locked = _locked(session, claim.job_id)
        if locked is None:
            return True
        permit, assessment, job = locked
        if not _owns(job, claim):
            return True
        reason, _ = _prerequisite(session, permit, assessment, job)
        if assessment.status != "running" or reason is not None:
            _terminal(session, assessment, job, reason or "assessment_cancelled", cancelled=True)
            return True
        now = datetime.now(UTC)
        if (
            job.heartbeat_at is None
            or (now - utc(job.heartbeat_at)).total_seconds() >= settings.worker_heartbeat_seconds
        ):
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    return False


def _failed(engine: Engine, claim: Claim, reason: str, *, cancelled: bool = False):
    with session_factory(engine).begin() as session:
        locked = _locked(session, claim.job_id)
        if locked is not None:
            _, assessment, job = locked
            if _owns(job, claim):
                _terminal(session, assessment, job, reason, cancelled=cancelled)


def _publish(engine: Engine, claim: Claim, output: dict[str, Any]):
    if claim.engine == "dex":
        validated = DexAnalysisResult.model_validate(output)
    elif claim.engine == "mobsf":
        from droidshield.mobsf import MobSFAnalysisResult

        validated = MobSFAnalysisResult.model_validate(output)
    else:
        validated = EngineResult.model_validate(output)
    output = validated.model_dump(mode="json")
    with session_factory(engine).begin() as session:
        locked = _locked(session, claim.job_id)
        if locked is None:
            return
        permit, assessment, job = locked
        if not _owns(job, claim):
            return
        reason, artifact = _prerequisite(session, permit, assessment, job)
        if assessment.status != "running" or reason is not None:
            _terminal(session, assessment, job, reason or "assessment_cancelled", cancelled=True)
            return
        if (
            output.get("sha256") != claim.sha256
            or output.get("file_size") != claim.file_size
            or output.get("engine_version") != ENGINE_VERSIONS[claim.engine]
            or output.get("schema_version") != {"manifest": 1, "dex": 2, "mobsf": 3}[claim.engine]
            or output.get("metadata", {}).get("package_name")
            != artifact.metadata_json.get("package_name")
        ):
            _terminal(session, assessment, job, "engine_result_invalid")
            return
        result = AnalysisResult(
            workspace_id=assessment.workspace_id,
            project_id=assessment.project_id,
            assessment_id=assessment.id,
            artifact_id=artifact.id,
            job_id=job.id,
            engine_version=output["engine_version"],
            schema_version=output["schema_version"],
            metadata_json={
                **output["metadata"],
                **{
                    f"_{key}": output[key]
                    for key in ("dex_summary", "mobsf_summary")
                    if key in output
                },
            },
            indicators_json=output["indicators"],
            limitations_json=output["limitations"],
            artifact_sha256=claim.sha256,
        )
        session.add(result)
        session.flush()
        for indicator in output["indicators"]:
            session.add(
                Finding(
                    workspace_id=assessment.workspace_id,
                    project_id=assessment.project_id,
                    assessment_id=assessment.id,
                    artifact_id=artifact.id,
                    title=indicator["title"],
                    description=indicator["description"],
                    affected_component=indicator["affected_component"],
                    category=indicator["rule_id"],
                    severity=indicator["severity"],
                    verification_status="unreviewed",
                    remediation_status="open",
                    reproduction_steps=indicator["reproduction_steps"],
                    impact=indicator["impact"],
                    remediation=indicator["remediation"],
                    evidence_provenance={
                        "source": f"static_{claim.engine}",
                        "analysis_result_id": str(result.id),
                        "job_id": str(job.id),
                        "rule_id": indicator["rule_id"],
                        "artifact_sha256": claim.sha256,
                        "engine_version": ENGINE_VERSIONS[claim.engine],
                        "evidence": indicator["evidence"],
                    },
                    created_by=assessment.created_by,
                )
            )
        job.status = "completed"
        job.completed_at = datetime.now(UTC)
        job.lease_expires_at = None
        assessment.status = "needs_review"
        _audit(session, job, "completed")


def run_once(
    settings: Settings,
    engine: Engine | None = None,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> bool:
    """Handle one static job (including stale/invalid jobs); False means idle.

    Other assessment types are reserved for their scoped workers. An expired
    lease fails safely; this worker never retries a scan.
    """
    if should_stop is not None and should_stop():
        return False
    owned_engine = engine is None
    engine = engine or build_engine(settings.database_url)
    try:
        handled, claim = _claim(settings, engine)
        if claim is None:
            return handled

        def cancelled() -> bool:
            if should_stop is not None and should_stop():
                _failed(engine, claim, "worker_shutdown", cancelled=True)
                return True
            return _monitor(settings, engine, claim)

        try:
            if cancelled():
                return True
            with Storage(settings.storage_root).verified_copy(
                claim.storage_ref, claim.sha256, claim.file_size
            ) as path:
                if cancelled():
                    return True
                if claim.engine == "mobsf":
                    from droidshield.mobsf import MobSF

                    output = MobSF(settings).run(
                        path, metadata=claim.metadata, should_cancel=cancelled
                    )
                elif claim.engine == "dex":
                    output = Sandbox(settings).run(
                        path, mode="analyze", engine="dex", should_cancel=cancelled
                    )
                else:
                    output = Sandbox(settings).run(path, mode="analyze", should_cancel=cancelled)
            if cancelled():
                return True
            _publish(engine, claim, output)
        except SandboxCancelled:
            _failed(engine, claim, "execution_cancelled", cancelled=True)
        except SandboxError as error:
            _failed(engine, claim, error.code)
        except StorageError as error:
            reason = (
                "artifact_integrity_failed"
                if error.code == "artifact_integrity_failed"
                else "storage_unavailable"
            )
            _failed(engine, claim, reason)
        except Exception:
            # Storage and parser failures cannot disclose paths or raw input and
            # must not strand a live job. The fenced transaction owns publication.
            _failed(engine, claim, "analysis_failed")
        return True
    finally:
        if owned_engine:
            engine.dispose()
