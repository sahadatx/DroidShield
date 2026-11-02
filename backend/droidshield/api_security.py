"""Scoped, leased, non-destructive HTTPS API assessment workflow."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.engine import Engine

from droidshield import services as svc
from droidshield.api import Ctx, Idem, Limit, Offset
from droidshield.api_secrets import SecretError, list_references, resolve
from droidshield.api_transport import HTTPSProbe, RequestCancelled, TransportError
from droidshield.auth import utc
from droidshield.db import build_engine, session_factory
from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import (
    AnalysisJob,
    APIExecution,
    APITarget,
    Client,
    Finding,
    User,
)
from droidshield.schemas import validate_target
from droidshield.worker import _audit, _locked, _terminal

ENGINE_VERSION = "droidshield-api-1"
LIMITATIONS = [
    "Only exact approved GET and HEAD endpoints are requested; redirects are never followed.",
    "Status codes and bounded response comparisons are observations, not proof of an authorization vulnerability.",
    "No injection, brute force, state-changing requests, OpenAPI execution, or general API coverage is performed.",
    "Response bodies, credential values, raw headers and body digests are not retained; analyst review is required.",
]
router = APIRouter(prefix="/api/v1", tags=["API Security"])


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class Endpoint(Strict):
    url: str = Field(min_length=1, max_length=2048)
    method: Literal["GET", "HEAD"] = "GET"
    expect_authentication: bool = False

    @field_validator("url")
    @classmethod
    def exact_https(cls, value):
        result = validate_target(value)
        if result.startswith(("package:", "bundle:")):
            raise ValueError("Choose an exact HTTPS endpoint")
        return result


class TargetCreate(Strict):
    name: str = Field(min_length=1, max_length=200)
    endpoints: list[Endpoint] = Field(min_length=1, max_length=20)
    excluded_endpoints: list[str] = Field(default_factory=list, max_length=100)
    auth_method: Literal["none", "bearer", "api_key", "cookie"] = "none"
    primary_secret_ref: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    secondary_secret_ref: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    requests_per_minute: int = Field(default=30, ge=1, le=120)
    test_window_start: AwareDatetime = Field(strict=False)
    test_window_end: AwareDatetime = Field(strict=False)

    @field_validator("test_window_start", "test_window_end", mode="before")
    @classmethod
    def explicit_datetimes(cls, value):
        if not isinstance(value, (str, datetime)):
            raise ValueError("Use an offset-aware date and time")
        return value

    @field_validator("excluded_endpoints")
    @classmethod
    def exclusions(cls, values):
        return [Endpoint.exact_https(value) for value in values]

    @model_validator(mode="after")
    def coherent(self):
        if self.test_window_end <= self.test_window_start:
            raise ValueError("Test window end must follow start")
        if len({(item.url, item.method) for item in self.endpoints}) != len(self.endpoints):
            raise ValueError("Duplicate endpoint methods are not allowed")
        if len(set(self.excluded_endpoints)) != len(self.excluded_endpoints):
            raise ValueError("Duplicate exclusions are not allowed")
        if any(
            svc.is_excluded(item.url, excluded)
            for item in self.endpoints
            for excluded in self.excluded_endpoints
        ):
            raise ValueError("Requested endpoints overlap an exclusion")
        if self.auth_method == "none":
            if (
                self.primary_secret_ref
                or self.secondary_secret_ref
                or any(item.expect_authentication for item in self.endpoints)
            ):
                raise ValueError(
                    "Protected endpoint comparisons require configured authentication references"
                )
        elif not self.primary_secret_ref:
            raise ValueError("Choose a project-bound primary secret reference")
        if self.secondary_secret_ref and self.secondary_secret_ref == self.primary_secret_ref:
            raise ValueError("Account comparison requires distinct references")
        return self


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    assessment_id: UUID
    project_id: UUID
    name: str
    endpoints: list[Endpoint]
    excluded_endpoints: list[str]
    auth_method: str
    primary_secret_ref: str | None
    secondary_secret_ref: str | None
    requests_per_minute: int
    test_window_start: datetime
    test_window_end: datetime
    created_at: datetime

    @field_validator("test_window_start", "test_window_end", "created_at")
    @classmethod
    def utc_timestamps(cls, value):
        return utc(value)


class Execute(Strict):
    revision: int = Field(ge=1)


class Cancel(Strict):
    reason: str = Field(min_length=1, max_length=2000)


class ProbeResult(Strict):
    status: int = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=262144)
    truncated: bool
    hsts_present: bool
    content_type_present: bool
    tls_verified: Literal[True] = True


class EndpointResult(Strict):
    endpoint_index: int = Field(ge=0, le=19)
    method: Literal["GET", "HEAD"]
    anonymous: ProbeResult
    primary: ProbeResult | None = None
    secondary: ProbeResult | None = None
    comparison: Literal[
        "not_run", "same_bounded_response", "different_bounded_response", "inconclusive"
    ]
    unexpected_anonymous_success: bool


class APIResult(Strict):
    engine_version: Literal["droidshield-api-1"] = ENGINE_VERSION
    requests_sent: int = Field(ge=1, le=120)
    endpoints: list[EndpointResult] = Field(min_length=1, max_length=20)
    requires_review: Literal[True] = True
    limitations: list[str]

    @model_validator(mode="after")
    def coherent(self):
        if [item.endpoint_index for item in self.endpoints] != list(range(len(self.endpoints))):
            raise ValueError("Endpoint observations must be ordered and unique")
        if (
            sum(1 + bool(item.primary) + bool(item.secondary) for item in self.endpoints)
            != self.requests_sent
        ):
            raise ValueError("Request count must match observations")
        for item in self.endpoints:
            if item.secondary and not item.primary:
                raise ValueError("Secondary comparison requires a primary observation")
            if item.unexpected_anonymous_success and not (
                item.primary
                and 200 <= item.anonymous.status < 300
                and 200 <= item.primary.status < 300
            ):
                raise ValueError(
                    "Unexpected anonymous success requires successful comparison responses"
                )
            if item.comparison != "not_run" and not item.secondary:
                raise ValueError("Account comparison requires two observations")
        return self

    @field_validator("limitations")
    @classmethod
    def fixed_limitations(cls, value):
        if value != LIMITATIONS:
            raise ValueError("Expected fixed API coverage limitations")
        return value


class ExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    assessment_id: UUID
    target_id: UUID
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    failure_reason: str | None
    cancellation_reason: str | None
    result_json: APIResult | None

    @field_validator("created_at", "started_at", "completed_at")
    @classmethod
    def utc_timestamps(cls, value):
        return utc(value) if value is not None else None


def target(ctx, resource_id):
    item = ctx.session.scalar(
        select(APITarget).where(
            APITarget.id == resource_id,
            APITarget.workspace_id == ctx.workspace_id,
            APITarget.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if item is None:
        raise not_found()
    return item


def execution(ctx, resource_id):
    item = ctx.session.scalar(
        select(APIExecution).where(
            APIExecution.id == resource_id,
            APIExecution.workspace_id == ctx.workspace_id,
            APIExecution.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if item is None:
        raise not_found()
    return item


def _refs(settings, item):
    resolve(settings, item.primary_secret_ref, item.workspace_id, item.project_id, item.auth_method)
    if item.secondary_secret_ref:
        resolve(
            settings,
            item.secondary_secret_ref,
            item.workspace_id,
            item.project_id,
            item.auth_method,
        )


def create_target(ctx, assessment_id, data, settings):
    svc.require_writer(ctx)
    assessment = svc.assessment(ctx, assessment_id, lock=True)
    if assessment.assessment_type != "api" or assessment.status not in {
        "draft",
        "awaiting_authorization",
    }:
        raise conflict("API target configuration requires a draft API assessment")
    if ctx.session.scalar(select(APITarget.id).where(APITarget.assessment_id == assessment_id)):
        raise conflict("This assessment already has an immutable API target configuration")
    if any(
        item.url not in assessment.configuration_snapshot.get("requested_targets", [])
        for item in data.endpoints
    ):
        raise conflict("Every endpoint must be an exact requested assessment target")
    item = APITarget(
        workspace_id=ctx.workspace_id,
        project_id=assessment.project_id,
        assessment_id=assessment.id,
        created_by=ctx.user.id,
        **data.model_dump(mode="python"),
    )
    item.endpoints = [endpoint.model_dump() for endpoint in data.endpoints]
    try:
        _refs(settings, item)
    except SecretError as exc:
        raise DomainError(
            422,
            "secret_reference_unavailable",
            "Choose a configured authentication reference for this project",
        ) from exc
    ctx.session.add(item)
    ctx.session.flush()
    svc.audit(ctx, "api_target.created", "api_target", item.id)
    return item


@router.get("/projects/{project_id}/api-secret-refs")
def references(project_id: UUID, ctx: Ctx, request: Request):
    svc.project(ctx, project_id)
    try:
        return {"items": list_references(request.app.state.settings, ctx.workspace_id, project_id)}
    except SecretError as exc:
        raise DomainError(
            503, "secret_store_unavailable", "Protected authentication references are unavailable"
        ) from exc


@router.get("/assessments/{assessment_id}/api-targets")
def targets(
    assessment_id: UUID,
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    auth_method: Literal["none", "bearer", "api_key", "cookie"] | None = None,
):
    svc.assessment(ctx, assessment_id)
    query = select(APITarget).where(
        APITarget.workspace_id == ctx.workspace_id,
        APITarget.assessment_id == assessment_id,
    )
    if auth_method:
        query = query.where(APITarget.auth_method == auth_method)
    items, total = svc.paginate(
        ctx,
        query.order_by(APITarget.created_at.desc(), APITarget.id),
        limit,
        offset,
    )
    return {
        "items": [TargetOut.model_validate(item) for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/assessments/{assessment_id}/api-targets", response_model=TargetOut, status_code=201)
def target_create(assessment_id: UUID, ctx: Ctx, data: TargetCreate, key: Idem, request: Request):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"api-target.create:{assessment_id}",
        data,
        lambda rid: target(ctx, rid),
        lambda: create_target(ctx, assessment_id, data, request.app.state.settings),
    )


@router.get("/api-targets/{target_id}", response_model=TargetOut)
def target_detail(target_id: UUID, ctx: Ctx):
    return target(ctx, target_id)


def _target_snapshot(item):
    data = TargetOut.model_validate(item).model_dump(mode="json", exclude={"created_at"})
    data["test_window_start"] = utc(item.test_window_start).isoformat()
    data["test_window_end"] = utc(item.test_window_end).isoformat()
    return data


def _policy(settings):
    ca_path = getattr(settings, "api_ca_bundle", None)
    ca_digest = None
    if ca_path is not None:
        try:
            with open(ca_path, "rb") as stream:
                bundle = stream.read(524289)
            if len(bundle) > 524288:
                raise ValueError("CA bundle exceeds its budget")
            ca_digest = hashlib.sha256(bundle).hexdigest()
        except (OSError, ValueError) as exc:
            raise DomainError(
                503, "api_configuration_unavailable", "API trust configuration is unavailable"
            ) from exc
    return {
        "allowed_networks": sorted(settings.api_allowed_networks),
        "timeout_seconds": settings.api_timeout_seconds,
        "request_timeout_seconds": settings.api_request_timeout_seconds,
        "max_response_bytes": settings.api_max_response_bytes,
        "max_requests": settings.api_max_requests,
        "ca_bundle_sha256": ca_digest,
        "engine_version": ENGINE_VERSION,
    }


def execute(ctx, target_id, revision, settings):
    svc.require_writer(ctx)
    item = target(ctx, target_id)
    assessment = svc.assessment(ctx, item.assessment_id)
    if assessment.assessment_type != "api":
        raise conflict("API execution requires an API assessment")
    if assessment.status in {"draft", "awaiting_authorization"}:
        assessment = svc.queue_assessment(ctx, assessment.id, revision)
    else:
        svc.check_revision(assessment, revision)
    job = ctx.session.scalar(select(AnalysisJob).where(AnalysisJob.assessment_id == assessment.id))
    if job is None:
        raise conflict("Queue the authorized API assessment before execution")
    locked = _locked(ctx.session, job.id)
    if locked is None:
        raise conflict("Verified authorization is required")
    permit, assessment, job = locked
    if assessment.status != "queued" or job.status != "queued":
        raise conflict("This assessment is not queued for API testing")
    if ctx.session.scalar(select(APIExecution.id).where(APIExecution.job_id == job.id)):
        raise conflict("This assessment already has an API execution")
    count = len(item.endpoints) * (
        1 + bool(item.primary_secret_ref) + bool(item.secondary_secret_ref)
    )
    if count > settings.api_max_requests:
        raise conflict("Endpoint probes exceed the configured request budget")
    if (count - 1) * 60 / item.requests_per_minute >= settings.api_timeout_seconds:
        raise conflict("Choose a rate and endpoint count that fit the configured execution timeout")
    output = APIExecution(
        workspace_id=ctx.workspace_id,
        project_id=item.project_id,
        assessment_id=assessment.id,
        target_id=item.id,
        job_id=job.id,
        created_by=ctx.user.id,
        status="queued",
        configuration_snapshot={"target": _target_snapshot(item), "policy": _policy(settings)},
    )
    reason = _reason(ctx.session, permit, assessment, job, output, item, settings)
    if reason:
        raise conflict(
            "Current authorization, endpoint scope, account references and test window must permit API testing"
        )
    ctx.session.add(output)
    ctx.session.flush()
    svc.audit(ctx, "api_execution.created", "api_execution", output.id)
    return output


@router.post("/api-targets/{target_id}/execute", response_model=ExecutionOut, status_code=201)
def start_execution(target_id: UUID, ctx: Ctx, data: Execute, key: Idem, request: Request):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"api.execute:{target_id}",
        data,
        lambda rid: execution(ctx, rid),
        lambda: execute(ctx, target_id, data.revision, request.app.state.settings),
    )


@router.get("/assessments/{assessment_id}/api-executions")
def executions(
    assessment_id: UUID,
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    status: Literal["queued", "running", "completed", "failed", "cancelled"] | None = None,
):
    svc.assessment(ctx, assessment_id)
    query = select(APIExecution).where(
        APIExecution.workspace_id == ctx.workspace_id,
        APIExecution.assessment_id == assessment_id,
    )
    if status:
        query = query.where(APIExecution.status == status)
    items, total = svc.paginate(
        ctx,
        query.order_by(APIExecution.created_at.desc(), APIExecution.id),
        limit,
        offset,
    )
    return {
        "items": [ExecutionOut.model_validate(item) for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api-executions/{execution_id}", response_model=ExecutionOut)
def execution_detail(execution_id: UUID, ctx: Ctx):
    return execution(ctx, execution_id)


def cancel(ctx, execution_id, reason):
    item = execution(ctx, execution_id)
    locked = _locked(ctx.session, item.job_id)
    if locked is None:
        raise conflict("Execution authorization is unavailable")
    _, assessment, _ = locked
    item = ctx.session.scalar(
        select(APIExecution).where(APIExecution.id == item.id).with_for_update()
    )
    if item.status not in {"queued", "running"}:
        raise conflict("Only queued or running API executions can be cancelled")
    svc.cancel_assessment(ctx, assessment.id, assessment.revision, reason)
    item.status, item.cancellation_reason, item.completed_at = (
        "cancelled",
        "operator_cancelled",
        datetime.now(UTC),
    )
    svc.audit(ctx, "api_execution.cancelled", "api_execution", item.id)
    return item


@router.post("/api-executions/{execution_id}/cancel", response_model=ExecutionOut)
def cancel_execution(execution_id: UUID, ctx: Ctx, data: Cancel, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"api.cancel:{execution_id}",
        data,
        lambda rid: execution(ctx, rid),
        lambda: cancel(ctx, execution_id, data.reason),
    )


def _reason(session, permit, assessment, job, output, item, settings):
    now = datetime.now(UTC)
    snapshot = assessment.configuration_snapshot
    keys = (
        "requested_targets",
        "authorization_id",
        "authorization_revision",
        "approved_targets",
        "exclusions",
        "valid_from",
        "valid_until",
        "artifact_sha256",
        "engine",
    )
    if (
        assessment.assessment_type != "api"
        or job.workspace_id != assessment.workspace_id
        or output.workspace_id != assessment.workspace_id
        or output.project_id != assessment.project_id
        or item.assessment_id != assessment.id
        or item.project_id != assessment.project_id
        or item.workspace_id != assessment.workspace_id
        or output.target_id != item.id
        or any(snapshot.get(key) != job.configuration_snapshot.get(key) for key in keys)
        or output.configuration_snapshot
        != {"target": _target_snapshot(item), "policy": _policy(settings)}
    ):
        return "execution_snapshot_invalid"
    if (
        permit.id != assessment.authorization_id
        or permit.workspace_id != assessment.workspace_id
        or permit.project_id != assessment.project_id
        or permit.status != "verified"
        or not utc(permit.valid_from) <= now < utc(permit.valid_until)
        or snapshot.get("authorization_id") != str(permit.id)
        or snapshot.get("authorization_revision") != permit.revision
        or snapshot.get("approved_targets") != permit.approved_targets
        or snapshot.get("exclusions") != permit.exclusions
        or snapshot.get("valid_from") != utc(permit.valid_from).isoformat()
        or snapshot.get("valid_until") != utc(permit.valid_until).isoformat()
    ):
        return "authorization_invalid"
    if not utc(item.test_window_start) <= now < utc(item.test_window_end):
        return "test_window_inactive"
    project = session.get(svc.Project, assessment.project_id)
    client = session.get(Client, project.client_id) if project else None
    if (
        project is None
        or client is None
        or project.workspace_id != assessment.workspace_id
        or client.workspace_id != assessment.workspace_id
        or project.status != "active"
        or client.status != "active"
    ):
        return "project_inactive"
    for actor_id in {assessment.created_by, output.created_by, item.created_by}:
        actor = session.get(User, actor_id)
        if (
            actor is None
            or actor.workspace_id != assessment.workspace_id
            or actor.status != "active"
            or actor.role not in {"ADMIN", "SECURITY_ANALYST"}
            or session.scalar(
                svc.visible_projects(svc.Context(session, actor, "api-worker")).where(
                    svc.Project.id == project.id
                )
            )
            is None
        ):
            return "operator_access_revoked"
    endpoints = [endpoint["url"] for endpoint in item.endpoints]
    requested = snapshot.get("requested_targets", [])
    if not endpoints or any(
        url not in requested
        or url not in permit.approved_targets
        or any(
            svc.is_excluded(url, exclusion)
            for exclusion in permit.exclusions + item.excluded_endpoints
        )
        for url in endpoints
    ):
        return "target_scope_invalid"
    try:
        contract = {key: getattr(item, key) for key in TargetCreate.model_fields}
        contract["test_window_start"] = utc(item.test_window_start)
        contract["test_window_end"] = utc(item.test_window_end)
        TargetCreate.model_validate(contract)
        _refs(settings, item)
    except Exception:
        return "target_configuration_invalid"
    return None


@dataclass(frozen=True)
class Claim:
    execution_id: UUID
    job_id: UUID
    worker_id: UUID
    workspace_id: UUID
    project_id: UUID
    target: dict


def _lock(session, execution_id):
    output = session.get(APIExecution, execution_id)
    if output is None:
        return None
    locked = _locked(session, output.job_id)
    if locked is None:
        return None
    output = session.scalar(
        select(APIExecution).where(APIExecution.id == output.id).with_for_update()
    )
    item = session.get(APITarget, output.target_id)
    return (*locked, output, item) if item else None


def _mark(session, assessment, job, output, reason, cancelled=False):
    if job.status in {"queued", "running"}:
        _terminal(session, assessment, job, reason, cancelled=cancelled)
    output.status = "cancelled" if cancelled or job.status == "cancelled" else "failed"
    output.completed_at = datetime.now(UTC)
    if output.status == "cancelled":
        output.cancellation_reason = reason
    else:
        output.failure_reason = reason


def _claim(settings, engine):
    factory = session_factory(engine)
    with factory() as session:
        ids = session.scalars(
            select(APIExecution.id)
            .where(APIExecution.status.in_(["queued", "running"]))
            .order_by(APIExecution.created_at, APIExecution.id)
            .limit(25)
        ).all()
    for resource_id in ids:
        with factory.begin() as session:
            locked = _lock(session, resource_id)
            if locked is None:
                continue
            permit, assessment, job, output, item = locked
            if output.status == "running":
                if job.status == "cancelled":
                    _mark(session, assessment, job, output, "assessment_cancelled", True)
                    return True, None
                if job.lease_expires_at is None or utc(job.lease_expires_at) <= datetime.now(UTC):
                    _mark(session, assessment, job, output, "worker_lease_expired")
                    return True, None
                continue
            if output.status != "queued":
                continue
            if assessment.status != "queued" or job.status != "queued":
                _mark(
                    session,
                    assessment,
                    job,
                    output,
                    "assessment_cancelled",
                    job.status == "cancelled",
                )
                return True, None
            reason = _reason(session, permit, assessment, job, output, item, settings)
            if reason:
                _mark(session, assessment, job, output, reason)
                return True, None
            token, now = uuid4(), datetime.now(UTC)
            job.status = output.status = assessment.status = "running"
            job.worker_id, job.heartbeat_at = token, now
            job.started_at = output.started_at = assessment.started_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
            job.attempt_count += 1
            job.tool_versions = assessment.tool_versions = {"api": ENGINE_VERSION}
            _audit(session, job, "claimed")
            return True, Claim(
                output.id,
                job.id,
                token,
                output.workspace_id,
                output.project_id,
                _target_snapshot(item),
            )
    return False, None


def _monitor(settings, engine, claim):
    with session_factory(engine).begin() as session:
        locked = _lock(session, claim.execution_id)
        if locked is None:
            return True
        permit, assessment, job, output, item = locked
        if (
            job.worker_id != claim.worker_id
            or job.status != "running"
            or output.status != "running"
            or job.lease_expires_at is None
            or utc(job.lease_expires_at) <= datetime.now(UTC)
        ):
            return True
        reason = _reason(session, permit, assessment, job, output, item, settings)
        if reason or assessment.status != "running":
            _mark(session, assessment, job, output, reason or "assessment_cancelled", True)
            return True
        now = datetime.now(UTC)
        if (
            job.heartbeat_at is None
            or (now - utc(job.heartbeat_at)).total_seconds() >= settings.worker_heartbeat_seconds
        ):
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    return False


def _finish(settings, engine, claim, *, result=None, reason=None, cancelled=False):
    with session_factory(engine).begin() as session:
        locked = _lock(session, claim.execution_id)
        if locked is None:
            return
        permit, assessment, job, output, item = locked
        if job.worker_id != claim.worker_id or output.status not in {"running", "cancelled"}:
            return
        if result is not None:
            issue = _reason(session, permit, assessment, job, output, item, settings)
            if (
                issue
                or job.status != "running"
                or output.status != "running"
                or assessment.status != "running"
                or job.lease_expires_at is None
                or utc(job.lease_expires_at) <= datetime.now(UTC)
            ):
                reason, cancelled = issue or "assessment_cancelled", True
            else:
                safe = APIResult.model_validate(result).model_dump(mode="json")
                output.result_json = safe
                output.status = job.status = "completed"
                output.completed_at = job.completed_at = datetime.now(UTC)
                job.lease_expires_at = None
                assessment.status = "needs_review"
                _audit(session, job, "completed")
                for observation in safe["endpoints"]:
                    if observation["unexpected_anonymous_success"]:
                        session.add(
                            Finding(
                                workspace_id=output.workspace_id,
                                project_id=output.project_id,
                                assessment_id=output.assessment_id,
                                artifact_id=None,
                                title="Protected endpoint returned success without credentials",
                                description="The configured protected endpoint returned a successful HTTP status to an anonymous request and to the configured primary account. A public response or login page can produce the same observation; inspect expected access policy before confirming.",
                                affected_component=f"Approved API endpoint #{observation['endpoint_index'] + 1}",
                                category="api_access_control",
                                severity="medium",
                                verification_status="unreviewed",
                                remediation_status="open",
                                reproduction_steps="Compare the approved endpoint anonymously and with the primary project account, and verify the actual response against the documented access policy.",
                                impact="Potential anonymous access requires analyst verification; HTTP success alone does not establish sensitive data exposure.",
                                remediation="Require the intended authentication and resource authorization for protected responses; confirm expected public endpoints with the client.",
                                evidence_provenance={
                                    "source": "api",
                                    "api_execution_id": str(output.id),
                                    "api_target_id": str(item.id),
                                    "job_id": str(job.id),
                                    "engine_version": ENGINE_VERSION,
                                    "endpoint_index": observation["endpoint_index"],
                                    "anonymous_status": observation["anonymous"]["status"],
                                    "primary_status": observation["primary"]["status"],
                                },
                                created_by=output.created_by,
                            )
                        )
        if reason:
            _mark(session, assessment, job, output, reason, cancelled)


def _safe_probe(observation):
    return ProbeResult(
        status=observation.status,
        response_bytes=observation.response_bytes,
        truncated=observation.truncated,
        hsts_present=observation.hsts_present,
        content_type_present=observation.content_type_present,
        tls_verified=observation.tls_verified,
    ).model_dump()


def run_once(
    settings, engine: Engine | None = None, *, should_stop: Callable[[], bool] | None = None
) -> bool:
    if should_stop and should_stop():
        return False
    owned = engine is None
    engine = engine or build_engine(settings.database_url)
    try:
        handled, claim = _claim(settings, engine)
        if claim is None:
            return handled
        deadline = time.monotonic() + settings.api_timeout_seconds

        def stopped():
            return bool((should_stop and should_stop()) or _monitor(settings, engine, claim))

        try:
            probe = HTTPSProbe(settings)
            results, count, next_at = [], 0, 0.0
            for index, endpoint in enumerate(claim.target["endpoints"]):
                observations = []
                refs = (
                    [None]
                    + (
                        [claim.target["primary_secret_ref"]]
                        if claim.target["primary_secret_ref"]
                        else []
                    )
                    + (
                        [claim.target["secondary_secret_ref"]]
                        if claim.target["secondary_secret_ref"]
                        else []
                    )
                )
                for reference in refs:
                    while time.monotonic() < next_at:
                        if time.monotonic() >= deadline:
                            raise TransportError("execution_timeout")
                        if stopped():
                            raise RequestCancelled()
                        time.sleep(max(0, min(0.1, next_at - time.monotonic())))
                    if time.monotonic() >= deadline:
                        raise TransportError("execution_timeout")
                    if stopped():
                        raise RequestCancelled()
                    if count >= settings.api_max_requests:
                        raise TransportError("request_budget_exceeded")
                    headers = (
                        resolve(
                            settings,
                            reference,
                            claim.workspace_id,
                            claim.project_id,
                            claim.target["auth_method"],
                        )
                        if reference
                        else {}
                    )
                    # The immediately preceding monitor revalidates the exact URL,
                    # authorization revision, project grant and current window.
                    observations.append(
                        probe.request(
                            endpoint["url"],
                            endpoint["method"],
                            headers,
                            should_cancel=stopped,
                            deadline=deadline,
                        )
                    )
                    count += 1
                    next_at = time.monotonic() + 60 / claim.target["requests_per_minute"]
                anonymous = observations[0]
                primary = observations[1] if len(observations) > 1 else None
                secondary = observations[2] if len(observations) > 2 else None
                comparison = "not_run"
                if primary and secondary:
                    comparison = (
                        "inconclusive"
                        if primary.truncated or secondary.truncated or endpoint["method"] == "HEAD"
                        else "same_bounded_response"
                        if (primary.status, primary.body_digest)
                        == (secondary.status, secondary.body_digest)
                        else "different_bounded_response"
                    )
                results.append(
                    EndpointResult(
                        endpoint_index=index,
                        method=endpoint["method"],
                        anonymous=_safe_probe(anonymous),
                        primary=_safe_probe(primary) if primary else None,
                        secondary=_safe_probe(secondary) if secondary else None,
                        comparison=comparison,
                        unexpected_anonymous_success=bool(
                            endpoint["expect_authentication"]
                            and primary
                            and 200 <= anonymous.status < 300
                            and 200 <= primary.status < 300
                        ),
                    ).model_dump()
                )
            if time.monotonic() >= deadline:
                raise TransportError("execution_timeout")
            if stopped():
                raise RequestCancelled()
            _finish(
                settings,
                engine,
                claim,
                result=APIResult(
                    requests_sent=count, endpoints=results, limitations=LIMITATIONS
                ).model_dump(),
            )
        except RequestCancelled:
            _finish(settings, engine, claim, reason="execution_cancelled", cancelled=True)
        except TransportError as exc:
            _finish(settings, engine, claim, reason=exc.code)
        except SecretError:
            _finish(settings, engine, claim, reason="secret_reference_unavailable")
        except Exception:
            _finish(settings, engine, claim, reason="api_execution_failed")
        return True
    finally:
        if owned:
            engine.dispose()
