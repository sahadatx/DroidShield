"""Authorized disposable-emulator sessions; queued rows never run application code."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.engine import Engine

from droidshield import services as svc
from droidshield.api_common import Ctx, Idem, Limit, Offset
from droidshield.auth import utc
from droidshield.db import build_engine, session_factory
from droidshield.errors import DomainError, conflict, not_found
from droidshield.frida_runtime import FridaLab
from droidshield.frida_runtime import configuration as frida_configuration
from droidshield.lab import (
    ENGINE_VERSION,
    AdbLab,
    LabCancelled,
    LabError,
    LabResult,
    configured_devices,
)
from droidshield.models import AnalysisJob, DynamicDeviceLease, DynamicSession, User
from droidshield.proxy_contract import PROXY_VERSION
from droidshield.schemas import ResponseModel
from droidshield.storage import Storage, StorageError
from droidshield.worker import _audit, _locked, _prerequisite, _terminal

router = APIRouter(prefix="/api/v1", tags=["Dynamic Testing"])


class DynamicCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    revision: int = Field(ge=1)
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    scenario: Literal["launch_observe", "package_inspection", "frida_observe", "proxy_observe"]
    proxy_targets: list[str] = Field(default_factory=list, max_length=10)
    timeout_seconds: int = Field(default=90, ge=10, le=120)
    notes: str | None = Field(default=None, max_length=20000)

    @model_validator(mode="after")
    def scenario_configuration(self):
        if self.scenario == "proxy_observe" and not self.proxy_targets:
            raise ValueError("Approved proxy targets are required")
        if self.scenario != "proxy_observe" and self.proxy_targets:
            raise ValueError("Proxy targets are only valid for proxy observation")
        return self


class DynamicCancel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    reason: str = Field(min_length=1, max_length=2000)


class DynamicOut(ResponseModel):
    id: UUID
    assessment_id: UUID
    artifact_id: UUID
    device_id: str
    scenario: str
    proxy_targets: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices(
            "proxy_targets", AliasPath("configuration_snapshot", "proxy_targets")
        ),
    )
    timeout_seconds: int
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    failure_reason: str | None
    cancellation_reason: str | None
    result_json: LabResult | None


def lookup(ctx: svc.Context, resource_id: UUID) -> DynamicSession:
    record = ctx.session.scalar(
        select(DynamicSession).where(
            DynamicSession.id == resource_id,
            DynamicSession.workspace_id == ctx.workspace_id,
            DynamicSession.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if record is None:
        raise not_found()
    return record


def _device(settings, device_id: str) -> dict | None:
    return next((item for item in configured_devices(settings) if item["id"] == device_id), None)


def create(ctx: svc.Context, assessment_id: UUID, data: DynamicCreate, settings) -> DynamicSession:
    svc.require_writer(ctx)
    record = svc.assessment(ctx, assessment_id)
    if record.assessment_type != "dynamic":
        raise conflict("Dynamic sessions require a Dynamic assessment")
    try:
        device = _device(settings, data.device_id)
    except LabError as exc:
        raise DomainError(
            503, "lab_unavailable", "Disposable lab configuration is unavailable"
        ) from exc
    if device is None:
        raise conflict("Choose an administrator-configured disposable lab")
    if data.timeout_seconds > settings.dynamic_timeout_seconds:
        raise conflict("Session timeout exceeds the configured lab limit")
    if record.status in {"draft", "awaiting_authorization"}:
        record = svc.queue_assessment(ctx, assessment_id, data.revision)
    else:
        # Same permit → assessment → job lock ordering as revocation/worker.
        job_id = ctx.session.scalar(
            select(AnalysisJob.id).where(AnalysisJob.assessment_id == record.id)
        )
        locked = _locked(ctx.session, job_id) if job_id else None
        if locked is None:
            raise conflict("Queue the authorized assessment before starting a session")
        _, record, _ = locked
        svc.check_revision(record, data.revision)
    job = ctx.session.scalar(select(AnalysisJob).where(AnalysisJob.assessment_id == assessment_id))
    if record.status != "queued" or job is None or job.status != "queued":
        raise conflict("The assessment is not queued for runtime testing")
    locked = _locked(ctx.session, job.id)
    if locked is None:
        raise conflict("Verified authorization is required")
    permit, record, job = locked
    observer_snapshot = {}
    try:
        if data.scenario == "frida_observe":
            observer_snapshot["frida_configuration"] = frida_configuration(settings)
        elif data.scenario == "proxy_observe":
            from droidshield.proxy import proxy_configuration, validate_proxy_targets

            proxy_targets = validate_proxy_targets(
                data.proxy_targets,
                record.configuration_snapshot.get("requested_targets", []),
                permit.approved_targets,
                permit.exclusions,
                svc.project(ctx, record.project_id).package_id,
            )
            observer_snapshot = {
                "proxy_targets": proxy_targets,
                "proxy_configuration": proxy_configuration(settings),
            }
            record.configuration_snapshot = {
                **record.configuration_snapshot,
                "proxy_targets": proxy_targets,
            }
            job.configuration_snapshot = {
                **job.configuration_snapshot,
                "proxy_targets": proxy_targets,
            }
    except LabError as exc:
        raise DomainError(
            503, "lab_unavailable", "The selected observation engine is unavailable"
        ) from exc
    reason, artifact = _prerequisite(ctx.session, permit, record, job, assessment_type="dynamic")
    if reason:
        raise conflict("Current authorization, scope and artifact must permit runtime testing")
    if ctx.session.scalar(select(DynamicSession.id).where(DynamicSession.job_id == job.id)):
        raise conflict("This assessment already has a runtime session")
    lease = ctx.session.get(DynamicDeviceLease, device["id"])
    if lease is None:
        ctx.session.add(DynamicDeviceLease(device_id=device["id"]))
    elif lease.quarantined:
        raise conflict("This device requires administrator reprovisioning")
    session = DynamicSession(
        workspace_id=ctx.workspace_id,
        project_id=record.project_id,
        assessment_id=record.id,
        artifact_id=artifact.id,
        job_id=job.id,
        device_id=device["id"],
        scenario=data.scenario,
        timeout_seconds=data.timeout_seconds,
        notes=data.notes,
        created_by=ctx.user.id,
        status="queued",
        configuration_snapshot={
            "lab_device": device,
            "engine_version": ENGINE_VERSION,
            **observer_snapshot,
        },
    )
    ctx.session.add(session)
    ctx.session.flush()
    svc.audit(ctx, "dynamic_session.created", "dynamic_session", session.id)
    return session


@router.get("/assessments/{assessment_id}/dynamic-sessions")
def list_sessions(
    assessment_id: UUID,
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    status: Literal["queued", "running", "completed", "failed", "cancelled"] | None = None,
    scenario: Literal["launch_observe", "package_inspection", "frida_observe", "proxy_observe"]
    | None = None,
):
    svc.assessment(ctx, assessment_id)
    query = select(DynamicSession).where(
        DynamicSession.assessment_id == assessment_id,
        DynamicSession.workspace_id == ctx.workspace_id,
    )
    if status:
        query = query.where(DynamicSession.status == status)
    if scenario:
        query = query.where(DynamicSession.scenario == scenario)
    items, total = svc.paginate(
        ctx,
        query.order_by(DynamicSession.created_at.desc(), DynamicSession.id),
        limit,
        offset,
    )
    return {
        "items": [DynamicOut.model_validate(item) for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/assessments/{assessment_id}/dynamic-sessions", response_model=DynamicOut, status_code=201
)
def create_session(assessment_id: UUID, ctx: Ctx, data: DynamicCreate, key: Idem, request: Request):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"dynamic.create:{assessment_id}",
        data,
        lambda rid: lookup(ctx, rid),
        lambda: create(ctx, assessment_id, data, request.app.state.settings),
    )


@router.get("/dynamic-sessions/{session_id}", response_model=DynamicOut)
def session_detail(session_id: UUID, ctx: Ctx):
    return lookup(ctx, session_id)


def _cancel(ctx: svc.Context, session_id: UUID, reason: str) -> DynamicSession:
    item = lookup(ctx, session_id)
    joblock = _locked(ctx.session, item.job_id)
    if joblock is None:
        raise conflict("Session authorization is unavailable")
    _, assessment, _ = joblock
    item = ctx.session.scalar(
        select(DynamicSession).where(DynamicSession.id == item.id).with_for_update()
    )
    if item.status not in {"queued", "running"}:
        raise conflict("Only queued or running sessions can be cancelled")
    svc.cancel_assessment(ctx, assessment.id, assessment.revision, reason)
    item.status = "cancelled"
    item.cancellation_reason = "operator_cancelled"
    item.completed_at = datetime.now(UTC)
    svc.audit(ctx, "dynamic_session.cancelled", "dynamic_session", item.id)
    return item


@router.post("/dynamic-sessions/{session_id}/cancel", response_model=DynamicOut)
def cancel_session(session_id: UUID, ctx: Ctx, data: DynamicCancel, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"dynamic.cancel:{session_id}",
        data,
        lambda rid: lookup(ctx, rid),
        lambda: _cancel(ctx, session_id, data.reason),
    )


@dataclass(frozen=True)
class Claim:
    session_id: UUID
    job_id: UUID
    worker_id: UUID
    device: dict
    package: str
    storage_ref: str
    sha256: str
    file_size: int
    scenario: str
    timeout: int
    proxy_targets: tuple[str, ...] = ()


def _session_lock(session, session_id):
    origin = session.get(DynamicSession, session_id)
    if origin is None:
        return None
    locked = _locked(session, origin.job_id)
    if locked is None:
        return None
    item = session.scalar(
        select(DynamicSession).where(DynamicSession.id == session_id).with_for_update()
    )
    lease = session.scalar(
        select(DynamicDeviceLease)
        .where(DynamicDeviceLease.device_id == item.device_id)
        .with_for_update()
    )
    return (*locked, item, lease)


def _lease_owned(lease, claim):
    return (
        lease is not None
        and lease.session_id == claim.session_id
        and lease.worker_id == claim.worker_id
        and lease.expires_at is not None
        and utc(lease.expires_at) > datetime.now(UTC)
        and not lease.quarantined
    )


def _session_reason(session, permit, assessment, job, item, settings):
    reason, artifact = _prerequisite(session, permit, assessment, job, assessment_type="dynamic")
    if reason:
        return reason, None
    creator = session.get(User, item.created_by)
    if (
        creator is None
        or creator.workspace_id != item.workspace_id
        or creator.status != "active"
        or creator.role not in {"ADMIN", "SECURITY_ANALYST"}
        or session.scalar(
            svc.visible_projects(svc.Context(session, creator, "dynamic-worker")).where(
                svc.Project.id == item.project_id
            )
        )
        is None
    ):
        return "operator_access_revoked", None
    if (
        _device(settings, item.device_id) != item.configuration_snapshot.get("lab_device")
        or item.configuration_snapshot.get("engine_version") != ENGINE_VERSION
    ):
        return "lab_configuration_changed", None
    try:
        if item.scenario == "frida_observe":
            if item.configuration_snapshot.get("frida_configuration") != frida_configuration(
                settings
            ):
                return "lab_configuration_changed", None
        elif item.scenario == "proxy_observe":
            from droidshield.proxy import proxy_configuration, validate_proxy_targets

            targets = validate_proxy_targets(
                item.configuration_snapshot.get("proxy_targets", []),
                assessment.configuration_snapshot.get("requested_targets", []),
                permit.approved_targets,
                permit.exclusions,
                artifact.metadata_json["package_name"],
            )
            if targets != job.configuration_snapshot.get(
                "proxy_targets"
            ) or item.configuration_snapshot.get("proxy_configuration") != proxy_configuration(
                settings
            ):
                return "lab_configuration_changed", None
    except LabError:
        return "lab_configuration_changed", None
    return None, artifact


def _mark(session, assessment, job, item, reason, *, cancelled=False):
    if job.status in {"queued", "running"}:
        _terminal(session, assessment, job, reason, cancelled=cancelled)
    item.status = "cancelled" if cancelled or job.status == "cancelled" else "failed"
    item.completed_at = datetime.now(UTC)
    if item.status == "cancelled":
        item.cancellation_reason = reason
    else:
        item.failure_reason = reason


def _claim(settings, engine):
    factory = session_factory(engine)
    now = datetime.now(UTC)
    with factory() as session:
        ids = session.scalars(
            select(DynamicSession.id)
            .where(DynamicSession.status.in_(["queued", "running"]))
            .order_by(DynamicSession.created_at, DynamicSession.id)
            .limit(25)
        ).all()
    for session_id in ids:
        with factory.begin() as session:
            locked = _session_lock(session, session_id)
            if locked is None:
                continue
            permit, assessment, job, item, lease = locked
            if item.status == "running":
                # API cancellation clears the job lease while its live owner
                # still needs the separate device lease to remove its own APK.
                # Do not quarantine underneath that cleanup attempt.
                if lease is None or lease.expires_at is None or utc(lease.expires_at) <= now:
                    _mark(
                        session,
                        assessment,
                        job,
                        item,
                        "worker_lease_expired",
                        cancelled=job.status == "cancelled",
                    )
                    if lease is not None:
                        lease.quarantined = True
                    return True, None
                continue
            if item.status != "queued":
                continue
            if assessment.status != "queued" or job.status != "queued":
                _mark(
                    session,
                    assessment,
                    job,
                    item,
                    "assessment_cancelled",
                    cancelled=job.status == "cancelled",
                )
                return True, None
            reason, artifact = _session_reason(session, permit, assessment, job, item, settings)
            if reason or lease is None or lease.quarantined:
                _mark(session, assessment, job, item, reason or "device_quarantined")
                return True, None
            if lease.session_id is not None:
                if lease.expires_at is None or utc(lease.expires_at) <= now:
                    lease.quarantined = True
                    _mark(session, assessment, job, item, "device_quarantined")
                    return True, None
                continue
            token = uuid4()
            now = datetime.now(UTC)
            job.status = item.status = assessment.status = "running"
            job.worker_id = token
            job.started_at = item.started_at = assessment.started_at = now
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
            job.attempt_count += 1
            versions = {"dynamic": ENGINE_VERSION}
            if item.scenario == "frida_observe":
                versions["frida"] = item.configuration_snapshot["frida_configuration"]["version"]
            elif item.scenario == "proxy_observe":
                versions["proxy"] = PROXY_VERSION
            job.tool_versions = versions
            assessment.tool_versions = dict(job.tool_versions)
            lease.session_id, lease.worker_id, lease.expires_at = (
                item.id,
                token,
                job.lease_expires_at,
            )
            _audit(session, job, "claimed")
            return True, Claim(
                item.id,
                job.id,
                token,
                item.configuration_snapshot["lab_device"],
                artifact.metadata_json["package_name"],
                artifact.storage_ref,
                artifact.sha256,
                artifact.file_size,
                item.scenario,
                item.timeout_seconds,
                tuple(item.configuration_snapshot.get("proxy_targets", [])),
            )
    return False, None


def _monitor(settings, engine, claim):
    with session_factory(engine).begin() as session:
        locked = _session_lock(session, claim.session_id)
        if locked is None:
            return True
        permit, assessment, job, item, lease = locked
        if not _lease_owned(lease, claim):
            return True
        if job.worker_id != claim.worker_id or job.status != "running" or item.status != "running":
            return True
        if job.lease_expires_at is None or utc(job.lease_expires_at) <= datetime.now(UTC):
            return True
        reason, _ = _session_reason(session, permit, assessment, job, item, settings)
        if reason or assessment.status != "running":
            _mark(session, assessment, job, item, reason or "assessment_cancelled", cancelled=True)
            return True
        now = datetime.now(UTC)
        if (
            job.heartbeat_at is None
            or (now - utc(job.heartbeat_at)).total_seconds() >= settings.worker_heartbeat_seconds
        ):
            job.heartbeat_at = now
            job.lease_expires_at = lease.expires_at = now + timedelta(
                seconds=settings.worker_lease_seconds
            )
    return False


def _owns_device(engine, claim):
    with session_factory(engine)() as session:
        return _lease_owned(session.get(DynamicDeviceLease, claim.device["id"]), claim)


def _finish(
    settings, engine, claim, *, output=None, reason=None, cancelled=False, quarantine=False
):
    with session_factory(engine).begin() as session:
        locked = _session_lock(session, claim.session_id)
        if locked is None:
            return
        permit, assessment, job, item, lease = locked
        if not _lease_owned(lease, claim):
            return
        # A concurrent API cancellation has already changed the AnalysisJob.
        if job.worker_id != claim.worker_id:
            return
        if output is not None:
            issue, _ = _session_reason(session, permit, assessment, job, item, settings)
            if (
                job.status != "running"
                or item.status != "running"
                or assessment.status != "running"
                or job.lease_expires_at is None
                or utc(job.lease_expires_at) <= datetime.now(UTC)
                or issue
            ):
                reason, cancelled = issue or "assessment_cancelled", True
            else:
                result = LabResult.model_validate(output)
                if item.scenario == "frida_observe":
                    expected = item.configuration_snapshot["frida_configuration"]
                    if (
                        result.frida is None
                        or not result.pid_observed
                        or result.traffic is not None
                        or result.frida.version != expected["version"]
                        or result.frida.observation_seconds != expected["duration"]
                    ):
                        raise LabError("frida_output_invalid")
                elif item.scenario == "proxy_observe":
                    if (
                        result.traffic is None
                        or result.frida is not None
                        or any(
                            observation.target_index >= len(claim.proxy_targets)
                            for observation in result.traffic.observations
                        )
                    ):
                        raise LabError("proxy_output_invalid")
                elif result.frida is not None or result.traffic is not None:
                    raise LabError("dynamic_output_invalid")
                item.result_json = result.model_dump(mode="json")
                item.status = job.status = "completed"
                item.completed_at = job.completed_at = datetime.now(UTC)
                job.lease_expires_at = None
                assessment.status = "needs_review"
                _audit(session, job, "completed")
        if reason:
            _mark(session, assessment, job, item, reason, cancelled=cancelled)
        lease.quarantined = quarantine
        lease.session_id = lease.worker_id = lease.expires_at = None


def run_once(
    settings, engine: Engine | None = None, *, should_stop: Callable[[], bool] | None = None
) -> bool:
    """Run one controlled Dynamic session; Static/API/Full jobs are untouched."""
    if should_stop and should_stop():
        return False
    owned = engine is None
    engine = engine or build_engine(settings.database_url)
    try:
        handled, claim = _claim(settings, engine)
        if claim is None:
            return handled

        # A proxy's request thread and the ADB owner both monitor this attempt.
        # SQLite's in-memory StaticPool shares one DB-API connection, so even
        # independent Sessions must not overlap their control transactions.
        control_lock = threading.RLock()

        def cancelled():
            with control_lock:
                return bool((should_stop and should_stop()) or _monitor(settings, engine, claim))

        def owns_device():
            with control_lock:
                return _owns_device(engine, claim)

        def finish(**kwargs):
            with control_lock:
                _finish(settings, engine, claim, **kwargs)

        try:
            if cancelled():
                raise LabCancelled()
            with Storage(settings.storage_root).verified_copy(
                claim.storage_ref, claim.sha256, claim.file_size
            ) as path:
                if claim.scenario == "frida_observe":
                    lab = FridaLab(settings, claim.device)
                elif claim.scenario == "proxy_observe":
                    from droidshield.proxy import ProxyLab

                    lab = ProxyLab(settings, claim.device, targets=claim.proxy_targets)
                else:
                    lab = AdbLab(settings, claim.device)
                output = lab.run(
                    path,
                    claim.package,
                    claim.scenario,
                    claim.timeout,
                    should_cancel=cancelled,
                    owns_device=owns_device,
                )
            if cancelled():
                raise LabCancelled()
            finish(output=output)
        except LabCancelled:
            finish(reason="execution_cancelled", cancelled=True)
        except LabError as exc:
            finish(reason=exc.code, quarantine=True)
        except StorageError:
            finish(reason="artifact_integrity_failed")
        except Exception:
            finish(reason="dynamic_failed", quarantine=True)
        return True
    finally:
        if owned:
            engine.dispose()
