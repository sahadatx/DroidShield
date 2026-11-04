"""Assessment, authorization, finding, and workspace reporting routes."""

import csv
import io
import json
import re
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response
from sqlalchemy import Date, cast, func, or_, select

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import Ctx, Idem, Limit, Offset, page
from droidshield.auth import utc
from droidshield.errors import DomainError, not_found
from droidshield.models import (
    AnalysisJob,
    AnalysisResult,
    APIExecution,
    APITarget,
    AppArtifact,
    Assessment,
    AssessmentEvidence,
    AuditEvent,
    Authorization,
    Client,
    DynamicSession,
    Evidence,
    Finding,
    Project,
    Report,
    Retest,
    TestExecution,
)

router = APIRouter()
MAX_AUDIT_EXPORT_RECORDS = 10_000
MAX_AUDIT_EXPORT_BYTES = 10 * 1024 * 1024
AUDIT_EXPORT_SOURCE_KEYS = {
    "channel",
    "method",
    "route",
    "role",
    "status",
    "revoked_sessions",
    "revision",
    "changed_fields",
    "format",
    "record_count",
    "filters",
}
OVERVIEW_ACTIVITY_LIMIT = 10


def _audit_event_query(
    ctx,
    *,
    action,
    resource_type,
    result,
    actor_id,
    resource_id,
    date_from,
    date_to,
):
    svc.require_admin(ctx)
    if date_from and date_to and date_from > date_to:
        raise DomainError(422, "validation_error", "Start date must be on or before end date")
    query = select(AuditEvent).where(AuditEvent.workspace_id == ctx.workspace_id)
    if action:
        query = query.where(AuditEvent.action == action)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if result:
        query = query.where(AuditEvent.result == result)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)
    if resource_id:
        query = query.where(AuditEvent.resource_id == resource_id)
    if date_from:
        query = query.where(AuditEvent.created_at >= datetime.combine(date_from, time.min, UTC))
    if date_to:
        query = query.where(AuditEvent.created_at <= datetime.combine(date_to, time.max, UTC))
    return query


def _audit_export_source(source):
    """Export only bounded, non-secret audit context with a strict field allowlist."""
    if not isinstance(source, dict):
        return {}
    output = {}
    for key in sorted(AUDIT_EXPORT_SOURCE_KEYS):
        if key not in source:
            continue
        value = source[key]
        if (
            key == "channel"
            and isinstance(value, str)
            and value
            in {
                "api",
                "worker",
                "trusted_local_cli",
            }
        ):
            output[key] = value
        elif (
            key == "method"
            and isinstance(value, str)
            and value
            in {
                "GET",
                "POST",
                "PATCH",
                "password",
                "password_session",
            }
        ):
            output[key] = value
        elif key == "route" and isinstance(value, str):
            safe_route = re.sub(r"[^a-zA-Z0-9_/{}/.:-]", "", value)[:256]
            if safe_route:
                output[key] = safe_route
        elif (
            key == "role"
            and isinstance(value, str)
            and value
            in {
                "ADMIN",
                "SECURITY_ANALYST",
                "VIEWER",
            }
        ):
            output[key] = value
        elif key == "status" and isinstance(value, str) and value in {"active", "disabled"}:
            output[key] = value
        elif key in {"revision", "revoked_sessions", "record_count"}:
            if (type(value) is int and value >= 0) or (
                isinstance(value, str) and value.isdecimal()
            ):
                output[key] = str(value)
        elif key in {"changed_fields", "filters"} and isinstance(value, (list, str)):
            items = value.split(",") if isinstance(value, str) else value
            safe_values = sorted(
                {
                    item.strip()
                    for item in items
                    if isinstance(item, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item.strip())
                }
            )
            if safe_values:
                output[key] = ", ".join(safe_values[:32])
        elif key == "format" and isinstance(value, str) and value in {"csv", "json"}:
            output[key] = value
    return output


def _overview_activity(ctx, project_ids, assessment_ids, date_from, date_to):
    """Return recent events only when their resource belongs to visible scope."""
    client_ids = select(Project.client_id).where(
        Project.workspace_id == ctx.workspace_id,
        Project.id.in_(project_ids),
    )
    finding_ids = select(Finding.id).where(
        Finding.workspace_id == ctx.workspace_id,
        Finding.assessment_id.in_(assessment_ids),
    )
    scoped_resources = or_(
        (AuditEvent.resource_type == "client") & AuditEvent.resource_id.in_(client_ids),
        (AuditEvent.resource_type == "project") & AuditEvent.resource_id.in_(project_ids),
        (AuditEvent.resource_type == "authorization")
        & AuditEvent.resource_id.in_(
            select(Authorization.id).where(
                Authorization.workspace_id == ctx.workspace_id,
                Authorization.project_id.in_(project_ids),
            )
        ),
        (AuditEvent.resource_type == "assessment") & AuditEvent.resource_id.in_(assessment_ids),
        (AuditEvent.resource_type == "app_artifact")
        & AuditEvent.resource_id.in_(
            select(AppArtifact.id).where(
                AppArtifact.workspace_id == ctx.workspace_id,
                AppArtifact.project_id.in_(project_ids),
            )
        ),
        (AuditEvent.resource_type == "analysis_job")
        & AuditEvent.resource_id.in_(
            select(AnalysisJob.id).where(
                AnalysisJob.workspace_id == ctx.workspace_id,
                AnalysisJob.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "dynamic_session")
        & AuditEvent.resource_id.in_(
            select(DynamicSession.id).where(
                DynamicSession.workspace_id == ctx.workspace_id,
                DynamicSession.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "finding") & AuditEvent.resource_id.in_(finding_ids),
        (AuditEvent.resource_type == "evidence")
        & AuditEvent.resource_id.in_(
            select(Evidence.id).where(
                Evidence.workspace_id == ctx.workspace_id,
                Evidence.finding_id.in_(finding_ids),
            )
        ),
        (AuditEvent.resource_type == "evidence")
        & AuditEvent.resource_id.in_(
            select(AssessmentEvidence.id).where(
                AssessmentEvidence.workspace_id == ctx.workspace_id,
                AssessmentEvidence.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "test_execution")
        & AuditEvent.resource_id.in_(
            select(TestExecution.id).where(
                TestExecution.workspace_id == ctx.workspace_id,
                TestExecution.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "report")
        & AuditEvent.resource_id.in_(
            select(Report.id).where(
                Report.workspace_id == ctx.workspace_id,
                Report.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "retest")
        & AuditEvent.resource_id.in_(
            select(Retest.id).where(
                Retest.workspace_id == ctx.workspace_id,
                Retest.original_assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "api_target")
        & AuditEvent.resource_id.in_(
            select(APITarget.id).where(
                APITarget.workspace_id == ctx.workspace_id,
                APITarget.assessment_id.in_(assessment_ids),
            )
        ),
        (AuditEvent.resource_type == "api_execution")
        & AuditEvent.resource_id.in_(
            select(APIExecution.id).where(
                APIExecution.workspace_id == ctx.workspace_id,
                APIExecution.assessment_id.in_(assessment_ids),
            )
        ),
    )
    query = select(AuditEvent).where(
        AuditEvent.workspace_id == ctx.workspace_id,
        scoped_resources,
    )
    if date_from:
        query = query.where(AuditEvent.created_at >= datetime.combine(date_from, time.min, UTC))
    if date_to:
        query = query.where(AuditEvent.created_at <= datetime.combine(date_to, time.max, UTC))
    events = ctx.session.scalars(
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id).limit(OVERVIEW_ACTIVITY_LIMIT)
    ).all()
    return [
        {
            "id": event.id,
            "timestamp": utc(event.created_at),
            "actor_id": event.actor_id,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "result": event.result,
        }
        for event in events
    ]


def _audit_export_record(item):
    return {
        "id": str(item.id),
        "timestamp": utc(item.created_at).isoformat().replace("+00:00", "Z"),
        "actor_id": str(item.actor_id) if item.actor_id else None,
        "action": item.action,
        "resource_type": item.resource_type,
        "resource_id": str(item.resource_id) if item.resource_id else None,
        "result": item.result,
        "request_id": item.request_id,
        "source": _audit_export_source(item.source_metadata),
    }


def _csv_safe_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@router.get("/capabilities", tags=["Workspace"])
def capabilities(request: Request, ctx: Ctx):
    from droidshield.lab import LabError, configured_devices

    settings = request.app.state.settings
    try:
        devices = configured_devices(settings)
    except LabError as exc:
        raise DomainError(503, "lab_unavailable", "Lab configuration is unavailable") from exc

    from droidshield.frida_runtime import configuration as frida_configuration
    from droidshield.proxy import proxy_configuration

    def configured(check):
        try:
            check(settings)
            return bool(devices)
        except LabError:
            return False

    return {
        "engines": {
            "manifest": {"configured": True},
            "dex": {"configured": True},
            "mobsf": {"configured": bool(settings.mobsf_url and settings.mobsf_api_key)},
        },
        "dynamic": {
            "configured": bool(devices),
            "devices": [
                {key: d[key] for key in ("id", "label", "android_version")} for d in devices
            ],
            "max_timeout_seconds": settings.dynamic_timeout_seconds,
            "frida": {"configured": configured(frida_configuration)},
            "proxy": {"configured": configured(proxy_configuration)},
        },
        "api": {
            "configured": True,
            "methods": ["GET", "HEAD"],
            "auth_methods": ["none", "bearer", "api_key", "cookie"],
            "max_requests": settings.api_max_requests,
            "max_timeout_seconds": settings.api_timeout_seconds,
        },
        "max_apk_bytes": settings.max_apk_bytes,
        "artifact_intake": {
            "formats": ["apk", "aab", "ipa"],
            "platforms": ["android", "ios"],
            "automated_execution_formats": ["apk"],
        },
        "delivery": {
            "manual_engagements": True,
            "independent_review": True,
            "reports": ["pdf", "json"],
            "cvss_base_versions": ["4.0", "3.1"],
            "retesting": True,
        },
    }


@router.get("/findings", response_model=s.Page[s.FindingSummaryOut], tags=["Findings"])
def findings(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    project_id: UUID | None = None,
    client_id: UUID | None = None,
    assessment_id: UUID | None = None,
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    verification_status: Literal["unreviewed", "confirmed", "false_positive", "needs_more_evidence"]
    | None = None,
    remediation_status: Literal["open", "in_progress", "fixed", "accepted_risk", "retest_required"]
    | None = None,
):
    if client_id:
        svc.client(ctx, client_id)
    query = select(Finding).where(
        Finding.workspace_id == ctx.workspace_id,
        Finding.project_id.in_(svc.visible_projects(ctx)),
    )
    for field, value in (
        (Finding.project_id, project_id),
        (Finding.assessment_id, assessment_id),
        (Finding.severity, severity),
        (Finding.verification_status, verification_status),
        (Finding.remediation_status, remediation_status),
    ):
        if value is not None:
            query = query.where(field == value)
    if client_id:
        query = query.where(
            Finding.project_id.in_(
                select(Project.id).where(
                    Project.workspace_id == ctx.workspace_id,
                    Project.client_id == client_id,
                    Project.id.in_(svc.visible_projects(ctx)),
                )
            )
        )
    if q:
        query = query.where(
            or_(
                Finding.title.icontains(q, autoescape=True),
                Finding.affected_component.icontains(q, autoescape=True),
            )
        )
    return page(
        ctx,
        query.order_by(Finding.created_at.desc(), Finding.id),
        s.FindingSummaryOut,
        limit,
        offset,
    )


@router.get("/findings/{finding_id}", response_model=s.FindingDetailOut, tags=["Findings"])
def finding_detail(finding_id: UUID, ctx: Ctx):
    record = ctx.session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.workspace_id == ctx.workspace_id,
            Finding.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if record is None:
        raise not_found()
    return record


@router.get("/assessments/{assessment_id}/job", response_model=s.AnalysisJobOut, tags=["Analysis"])
def assessment_job(assessment_id: UUID, ctx: Ctx):
    svc.assessment(ctx, assessment_id)
    record = ctx.session.scalar(
        select(AnalysisJob).where(
            AnalysisJob.assessment_id == assessment_id, AnalysisJob.workspace_id == ctx.workspace_id
        )
    )
    if record is None:
        raise not_found()
    return record


@router.get(
    "/assessments/{assessment_id}/analysis", response_model=s.AnalysisOut, tags=["Analysis"]
)
def assessment_analysis(assessment_id: UUID, ctx: Ctx):
    svc.assessment(ctx, assessment_id)
    record = ctx.session.scalar(
        select(AnalysisResult).where(
            AnalysisResult.assessment_id == assessment_id,
            AnalysisResult.workspace_id == ctx.workspace_id,
        )
    )
    if record is None:
        raise not_found()
    return record


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=s.Page[s.FindingSummaryOut],
    tags=["Findings"],
)
def assessment_findings(assessment_id: UUID, ctx: Ctx, limit: Limit = 25, offset: Offset = 0):
    svc.assessment(ctx, assessment_id)
    return page(
        ctx,
        select(Finding)
        .where(
            Finding.assessment_id == assessment_id,
            Finding.workspace_id == ctx.workspace_id,
        )
        .order_by(Finding.created_at.desc(), Finding.id),
        s.FindingSummaryOut,
        limit,
        offset,
    )


@router.get(
    "/projects/{project_id}/authorizations",
    response_model=s.Page[s.AuthorizationOut],
    tags=["Authorizations"],
)
def authorizations(project_id: UUID, ctx: Ctx, limit: Limit = 25, offset: Offset = 0):
    svc.project(ctx, project_id)
    query = select(Authorization).where(
        Authorization.project_id == project_id, Authorization.workspace_id == ctx.workspace_id
    )
    return page(
        ctx,
        query.order_by(Authorization.created_at.desc(), Authorization.id),
        s.AuthorizationOut,
        limit,
        offset,
    )


@router.post(
    "/projects/{project_id}/authorizations",
    response_model=s.AuthorizationOut,
    status_code=201,
    tags=["Authorizations"],
)
def create_authorization(project_id: UUID, ctx: Ctx, data: s.AuthorizationCreate, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"authorization.create:{project_id}",
        data,
        lambda rid: svc.authorization(ctx, rid),
        lambda: svc.create_authorization(ctx, project_id, data),
    )


@router.post(
    "/authorizations/{authorization_id}/verify",
    response_model=s.AuthorizationOut,
    tags=["Authorizations"],
)
def verify_authorization(authorization_id: UUID, ctx: Ctx, data: s.AuthorizationVerify, key: Idem):
    svc.require_admin(ctx)
    return svc.once(
        ctx,
        key,
        f"authorization.verify:{authorization_id}",
        data,
        lambda rid: svc.authorization(ctx, rid),
        lambda: svc.verify_authorization(ctx, authorization_id, data.revision),
    )


@router.post(
    "/authorizations/{authorization_id}/revoke",
    response_model=s.AuthorizationOut,
    tags=["Authorizations"],
)
def revoke_authorization(authorization_id: UUID, ctx: Ctx, data: s.AuthorizationRevoke, key: Idem):
    svc.require_admin(ctx)
    return svc.once(
        ctx,
        key,
        f"authorization.revoke:{authorization_id}",
        data,
        lambda rid: svc.authorization(ctx, rid),
        lambda: svc.revoke_authorization(ctx, authorization_id, data.revision, data.reason),
    )


@router.get("/assessments", response_model=s.Page[s.AssessmentOut], tags=["Assessments"])
def assessments(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    project_id: UUID | None = None,
    client_id: UUID | None = None,
    status: s.AssessmentStatus | None = None,
    assessment_type: s.AssessmentType | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    if date_from and date_to and date_from > date_to:
        raise DomainError(422, "validation_error", "Start date must be on or before end date")
    if client_id:
        svc.client(ctx, client_id)
    query = select(Assessment).where(
        Assessment.project_id.in_(svc.visible_projects(ctx)),
        Assessment.workspace_id == ctx.workspace_id,
    )
    if project_id:
        query = query.where(Assessment.project_id == project_id)
    if client_id:
        query = query.where(
            Assessment.project_id.in_(
                select(Project.id).where(
                    Project.workspace_id == ctx.workspace_id,
                    Project.client_id == client_id,
                    Project.id.in_(svc.visible_projects(ctx)),
                )
            )
        )
    if status:
        query = query.where(Assessment.status == status)
    if assessment_type:
        query = query.where(Assessment.assessment_type == assessment_type)
    if q:
        query = query.where(Assessment.name.icontains(q, autoescape=True))
    if date_from:
        query = query.where(Assessment.created_at >= datetime.combine(date_from, time.min, UTC))
    if date_to:
        query = query.where(Assessment.created_at <= datetime.combine(date_to, time.max, UTC))
    return page(
        ctx,
        query.order_by(Assessment.created_at.desc(), Assessment.id),
        s.AssessmentOut,
        limit,
        offset,
    )


@router.post("/assessments", response_model=s.AssessmentOut, status_code=201, tags=["Assessments"])
def create_assessment(ctx: Ctx, data: s.AssessmentCreate, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        "assessment.create",
        data,
        lambda rid: svc.assessment(ctx, rid),
        lambda: svc.create_assessment(ctx, data),
    )


@router.get("/assessments/{assessment_id}", response_model=s.AssessmentOut, tags=["Assessments"])
def assessment_detail(assessment_id: UUID, ctx: Ctx):
    return svc.assessment(ctx, assessment_id)


@router.patch("/assessments/{assessment_id}", response_model=s.AssessmentOut, tags=["Assessments"])
def update_assessment(assessment_id: UUID, ctx: Ctx, data: s.AssessmentUpdate):
    return svc.update_assessment(ctx, assessment_id, data)


@router.post(
    "/assessments/{assessment_id}/submit", response_model=s.AssessmentOut, tags=["Assessments"]
)
def submit_assessment(assessment_id: UUID, ctx: Ctx, data: s.AssessmentSubmit, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"assessment.submit:{assessment_id}",
        data,
        lambda rid: svc.assessment(ctx, rid),
        lambda: svc.submit_assessment(ctx, assessment_id, data.revision),
    )


@router.post(
    "/assessments/{assessment_id}/queue", response_model=s.AssessmentOut, tags=["Assessments"]
)
def queue_assessment(assessment_id: UUID, ctx: Ctx, data: s.AssessmentQueue, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"assessment.queue:{assessment_id}",
        data,
        lambda rid: svc.assessment(ctx, rid),
        lambda: svc.queue_assessment(ctx, assessment_id, data.revision),
    )


@router.post(
    "/assessments/{assessment_id}/cancel", response_model=s.AssessmentOut, tags=["Assessments"]
)
def cancel_assessment(assessment_id: UUID, ctx: Ctx, data: s.AssessmentCancel, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"assessment.cancel:{assessment_id}",
        data,
        lambda rid: svc.assessment(ctx, rid),
        lambda: svc.cancel_assessment(ctx, assessment_id, data.revision, data.reason),
    )


@router.get("/overview", response_model=s.OverviewOut, tags=["Overview"])
def overview(
    ctx: Ctx,
    project_id: UUID | None = None,
    client_id: UUID | None = None,
    assessment_type: s.AssessmentType | None = None,
    assessment_status: s.AssessmentStatus | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    trend_days: Annotated[int, Query(ge=7, le=90)] = 30,
):
    if date_from and date_to and date_from > date_to:
        raise DomainError(422, "validation_error", "Start date must be on or before end date")

    projects = svc.visible_projects(ctx)
    if client_id:
        svc.client(ctx, client_id)
    if project_id and not ctx.session.scalar(
        select(Project.id).where(
            Project.workspace_id == ctx.workspace_id,
            Project.id == project_id,
            Project.id.in_(projects),
        )
    ):
        raise not_found()

    project_scope = [
        Project.workspace_id == ctx.workspace_id,
        Project.id.in_(projects),
    ]
    if project_id:
        project_scope.append(Project.id == project_id)
    if client_id:
        project_scope.append(Project.client_id == client_id)
    if date_from:
        project_scope.append(Project.created_at >= datetime.combine(date_from, time.min, UTC))
    if date_to:
        project_scope.append(Project.created_at <= datetime.combine(date_to, time.max, UTC))
    project_ids = select(Project.id).where(*project_scope)

    assessment_scope = [
        Assessment.workspace_id == ctx.workspace_id,
        Assessment.project_id.in_(project_ids),
    ]
    if assessment_type:
        assessment_scope.append(Assessment.assessment_type == assessment_type)
    if assessment_status:
        assessment_scope.append(Assessment.status == assessment_status)
    if date_from:
        assessment_scope.append(Assessment.created_at >= datetime.combine(date_from, time.min, UTC))
    if date_to:
        assessment_scope.append(Assessment.created_at <= datetime.combine(date_to, time.max, UTC))
    assessment_ids = select(Assessment.id).where(*assessment_scope)

    count_project_scope = list(project_scope)
    if assessment_type or assessment_status:
        count_project_scope.append(
            Project.id.in_(select(Assessment.project_id).where(*assessment_scope))
        )
    count_project_ids = select(Project.id).where(*count_project_scope)

    def created_between(model):
        filters = []
        if date_from:
            filters.append(model.created_at >= datetime.combine(date_from, time.min, UTC))
        if date_to:
            filters.append(model.created_at <= datetime.combine(date_to, time.max, UTC))
        return filters

    def grouped_counts(model, field, *filters):
        rows = ctx.session.execute(
            select(field, func.count()).select_from(model).where(*filters).group_by(field)
        ).all()
        return dict(rows)

    client_query = svc.client_query(ctx)
    if project_id or client_id or assessment_type or assessment_status:
        client_query = client_query.where(
            Client.id.in_(select(Project.client_id).where(Project.id.in_(count_project_ids)))
        )
    client_query = client_query.where(*created_between(Client))
    client_scope = client_query.with_only_columns(Client.id).subquery()
    client_status = grouped_counts(
        Client,
        Client.status,
        Client.id.in_(select(client_scope.c.id)),
        Client.workspace_id == ctx.workspace_id,
    )
    project_status = grouped_counts(Project, Project.status, *count_project_scope)
    assessment_counts = grouped_counts(Assessment, Assessment.status, *assessment_scope)
    artifact_format = func.coalesce(AppArtifact.metadata_json["artifact_format"].as_string(), "apk")
    artifact_formats = grouped_counts(
        AppArtifact,
        artifact_format,
        AppArtifact.workspace_id == ctx.workspace_id,
        AppArtifact.project_id.in_(project_ids),
        *created_between(AppArtifact),
    )
    finding_rows = ctx.session.execute(
        select(
            Finding.severity,
            Finding.verification_status,
            Finding.remediation_status,
            func.count(),
        )
        .where(
            Finding.workspace_id == ctx.workspace_id,
            Finding.project_id.in_(project_ids),
            Finding.assessment_id.in_(assessment_ids),
            *created_between(Finding),
        )
        .group_by(Finding.severity, Finding.verification_status, Finding.remediation_status)
    ).all()
    total_findings = sum(row[3] for row in finding_rows)
    confirmed_findings = sum(row[3] for row in finding_rows if row[1] == "confirmed")
    unreviewed_findings = sum(row[3] for row in finding_rows if row[1] == "unreviewed")
    severity = {level: 0 for level in ["critical", "high", "medium", "low", "info"]}
    for level, verification, remediation, amount in finding_rows:
        if verification == "confirmed" and remediation != "fixed":
            severity[level] += amount

    trend_end = datetime.now(UTC).date()
    trend_start = trend_end - timedelta(days=trend_days - 1)
    trend_window_start = datetime.combine(trend_start, time.min, UTC)
    trend_window_end = datetime.combine(trend_end + timedelta(days=1), time.min, UTC)
    trend_project_scope = [
        Project.workspace_id == ctx.workspace_id,
        Project.id.in_(projects),
    ]
    if project_id:
        trend_project_scope.append(Project.id == project_id)
    if client_id:
        trend_project_scope.append(Project.client_id == client_id)
    trend_project_ids = select(Project.id).where(*trend_project_scope)
    trend_assessment_scope = [
        Assessment.workspace_id == ctx.workspace_id,
        Assessment.project_id.in_(trend_project_ids),
    ]
    if assessment_type:
        trend_assessment_scope.append(Assessment.assessment_type == assessment_type)
    if assessment_status:
        trend_assessment_scope.append(Assessment.status == assessment_status)
    if ctx.session.bind.dialect.name == "postgresql":
        trend_day = cast(func.timezone("UTC", Finding.created_at), Date)
    else:
        trend_day = func.date(Finding.created_at)
    trend_rows = ctx.session.execute(
        select(trend_day, Finding.severity, func.count())
        .where(
            Finding.workspace_id == ctx.workspace_id,
            Finding.project_id.in_(trend_project_ids),
            Finding.assessment_id.in_(select(Assessment.id).where(*trend_assessment_scope)),
            Finding.verification_status == "confirmed",
            Finding.remediation_status != "fixed",
            Finding.created_at >= trend_window_start,
            Finding.created_at < trend_window_end,
        )
        .group_by(trend_day, Finding.severity)
    ).all()
    trend_counts = {
        trend_start + timedelta(days=offset): {level: 0 for level in severity}
        for offset in range(trend_days)
    }
    for day, level, amount in trend_rows:
        if isinstance(day, str):
            day = date.fromisoformat(day)
        trend_counts[day][level] = amount
    risk_trend = [
        {"date": day, **counts, "total": sum(counts.values())}
        for day, counts in trend_counts.items()
    ]
    overdue_retests = (
        ctx.session.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.workspace_id == ctx.workspace_id,
                Finding.project_id.in_(project_ids),
                Finding.assessment_id.in_(assessment_ids),
                Finding.verification_status == "confirmed",
                Finding.remediation_status == "retest_required",
                Finding.retest_due_at.is_not(None),
                Finding.retest_due_at < datetime.now(UTC),
                *created_between(Finding),
            )
        )
        or 0
    )
    report_status = grouped_counts(
        Report,
        Report.status,
        Report.workspace_id == ctx.workspace_id,
        Report.project_id.in_(project_ids),
        Report.assessment_id.in_(assessment_ids),
        *created_between(Report),
    )
    retest_rows = ctx.session.execute(
        select(Retest.review_decision, Retest.result, func.count())
        .where(
            Retest.workspace_id == ctx.workspace_id,
            Retest.project_id.in_(project_ids),
            Retest.original_assessment_id.in_(assessment_ids),
            *created_between(Retest),
        )
        .group_by(Retest.review_decision, Retest.result)
    ).all()
    total_retests = sum(row[2] for row in retest_rows)
    retests_awaiting_review = sum(row[2] for row in retest_rows if row[0] is None)
    retests_approved = sum(row[2] for row in retest_rows if row[0] == "approve")
    retests_rejected = sum(row[2] for row in retest_rows if row[0] == "reject")
    retests_pass = sum(row[2] for row in retest_rows if row[1] == "pass")
    retests_fail = sum(row[2] for row in retest_rows if row[1] == "fail")
    dynamic_status = grouped_counts(
        DynamicSession,
        DynamicSession.status,
        DynamicSession.workspace_id == ctx.workspace_id,
        DynamicSession.project_id.in_(project_ids),
        DynamicSession.assessment_id.in_(assessment_ids),
        *created_between(DynamicSession),
    )
    api_status = grouped_counts(
        APIExecution,
        APIExecution.status,
        APIExecution.workspace_id == ctx.workspace_id,
        APIExecution.project_id.in_(project_ids),
        APIExecution.assessment_id.in_(assessment_ids),
        *created_between(APIExecution),
    )
    artifact_count = sum(artifact_formats.values())
    pending_assessment_reviews = assessment_counts.get("needs_review", 0)
    pending_report_reviews = report_status.get("awaiting_review", 0)
    pending_retest_reviews = retests_awaiting_review
    return {
        "total_clients": sum(client_status.values()),
        "active_clients": client_status.get("active", 0),
        "archived_clients": client_status.get("archived", 0),
        "total_projects": sum(project_status.values()),
        "active_projects": project_status.get("active", 0),
        "on_hold_projects": project_status.get("on_hold", 0),
        "archived_projects": project_status.get("archived", 0),
        "total_assessments": sum(assessment_counts.values()),
        "in_progress": assessment_counts.get("queued", 0) + assessment_counts.get("running", 0),
        "queued_assessments": assessment_counts.get("queued", 0),
        "completed_assessments": assessment_counts.get("completed", 0),
        "failed_assessments": assessment_counts.get("failed", 0),
        "open_findings": sum(severity.values()),
        "total_artifacts": artifact_count,
        "artifact_formats": {key: artifact_formats.get(key, 0) for key in ["apk", "aab", "ipa"]},
        "total_findings": total_findings,
        "confirmed_findings": confirmed_findings,
        "unreviewed_findings": unreviewed_findings,
        "critical_findings": severity["critical"],
        "high_findings": severity["high"],
        "severity": severity,
        "pending_reviews": pending_assessment_reviews,
        "total_reports": sum(report_status.values()),
        "reports_awaiting_review": report_status.get("awaiting_review", 0),
        "reports_approved": report_status.get("approved", 0),
        "reports_exported": report_status.get("exported", 0),
        "total_retests": total_retests,
        "retests_awaiting_review": retests_awaiting_review,
        "retests_approved": retests_approved,
        "retests_rejected": retests_rejected,
        "retests_pass": retests_pass,
        "retests_fail": retests_fail,
        "total_dynamic_sessions": sum(dynamic_status.values()),
        "dynamic_sessions_queued": dynamic_status.get("queued", 0),
        "dynamic_sessions_running": dynamic_status.get("running", 0),
        "dynamic_sessions_completed": dynamic_status.get("completed", 0),
        "dynamic_sessions_failed": dynamic_status.get("failed", 0),
        "total_api_targets": ctx.session.scalar(
            select(func.count())
            .select_from(APITarget)
            .where(
                APITarget.workspace_id == ctx.workspace_id,
                APITarget.project_id.in_(project_ids),
                APITarget.assessment_id.in_(assessment_ids),
                *created_between(APITarget),
            )
        )
        or 0,
        "total_api_executions": sum(api_status.values()),
        "api_executions_queued": api_status.get("queued", 0),
        "api_executions_running": api_status.get("running", 0),
        "api_executions_completed": api_status.get("completed", 0),
        "api_executions_failed": api_status.get("failed", 0),
        "recent_activity": _overview_activity(
            ctx, count_project_ids, assessment_ids, date_from, date_to
        ),
        "pending_actions": {
            "assessment_reviews": pending_assessment_reviews,
            "report_reviews": pending_report_reviews,
            "retest_reviews": pending_retest_reviews,
            "total": (pending_assessment_reviews + pending_report_reviews + pending_retest_reviews),
        },
        "risk_trend": risk_trend,
        "overdue_retests": overdue_retests,
    }


@router.get("/audit-events", response_model=s.AuditEventsPageOut, tags=["Audit"])
def audit_events(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    action: Annotated[str | None, Query(max_length=128)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
    result: Literal["success", "failure"] | None = None,
    actor_id: UUID | None = None,
    resource_id: UUID | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    query = _audit_event_query(
        ctx,
        action=action,
        resource_type=resource_type,
        result=result,
        actor_id=actor_id,
        resource_id=resource_id,
        date_from=date_from,
        date_to=date_to,
    )
    summary = dict(
        ctx.session.execute(
            query.with_only_columns(AuditEvent.result, func.count())
            .group_by(AuditEvent.result)
            .order_by(None)
        ).all()
    )
    items, total = svc.paginate(
        ctx, query.order_by(AuditEvent.created_at.desc(), AuditEvent.id), limit, offset
    )
    return {
        "items": [
            {
                "id": item.id,
                "timestamp": utc(item.created_at),
                "actor_id": item.actor_id,
                "action": item.action,
                "resource_type": item.resource_type,
                "resource_id": item.resource_id,
                "result": item.result,
                "request_id": item.request_id,
                "source": item.source_metadata,
            }
            for item in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "summary": {"success": summary.get("success", 0), "failure": summary.get("failure", 0)},
    }


@router.get(
    "/audit-events/export",
    tags=["Audit"],
    responses={
        200: {"content": {"application/json": {}, "text/csv": {}}},
        413: {"description": "The filtered export exceeds the record or byte limit."},
    },
)
def export_audit_events(
    ctx: Ctx,
    export_format: Annotated[Literal["csv", "json"], Query(alias="format")],
    action: Annotated[str | None, Query(max_length=128)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
    result: Literal["success", "failure"] | None = None,
    actor_id: UUID | None = None,
    resource_id: UUID | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    query = _audit_event_query(
        ctx,
        action=action,
        resource_type=resource_type,
        result=result,
        actor_id=actor_id,
        resource_id=resource_id,
        date_from=date_from,
        date_to=date_to,
    )
    events = ctx.session.scalars(
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id).limit(
            MAX_AUDIT_EXPORT_RECORDS + 1
        )
    ).all()
    if len(events) > MAX_AUDIT_EXPORT_RECORDS:
        raise DomainError(
            413,
            "export_too_large",
            f"Narrow the filters to export at most {MAX_AUDIT_EXPORT_RECORDS:,} audit events.",
        )
    records = [_audit_export_record(event) for event in events]
    if export_format == "json":
        content = json.dumps(
            {
                "exported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "total": len(records),
                "items": records,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        media_type = "application/json"
    else:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        columns = (
            "id",
            "timestamp",
            "actor_id",
            "action",
            "resource_type",
            "resource_id",
            "result",
            "request_id",
            "source",
        )
        writer.writerow(columns)
        for record in records:
            row = [
                json.dumps(
                    record["source"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                if column == "source"
                else record[column]
                for column in columns
            ]
            writer.writerow([_csv_safe_cell(value) for value in row])
        content = output.getvalue().encode("utf-8")
        media_type = "text/csv"
    if len(content) > MAX_AUDIT_EXPORT_BYTES:
        raise DomainError(
            413,
            "export_too_large",
            f"Narrow the filters to keep the export under {MAX_AUDIT_EXPORT_BYTES // (1024 * 1024)} MiB.",
        )

    active_filters = sorted(
        name
        for name, value in (
            ("action", action),
            ("resource_type", resource_type),
            ("result", result),
            ("actor_id", actor_id),
            ("resource_id", resource_id),
            ("date_from", date_from),
            ("date_to", date_to),
        )
        if value is not None
    )
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.workspace_id,
            actor_id=ctx.user.id,
            action="audit.exported",
            resource_type="audit_events",
            resource_id=None,
            result="success",
            request_id=ctx.request_id,
            source_metadata={
                "channel": "api",
                "format": export_format,
                "record_count": str(len(records)),
                "filters": ", ".join(active_filters),
            },
        )
    )
    ctx.session.commit()
    extension = "json" if export_format == "json" else "csv"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="droidshield-audit-export.{extension}"',
            "Cache-Control": "no-store",
        },
    )
