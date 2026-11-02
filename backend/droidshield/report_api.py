"""Authenticated client deliverable and CVSS calculation HTTP boundary."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from starlette.background import BackgroundTask

from droidshield import report_schemas as s
from droidshield import reports as svc
from droidshield import services
from droidshield.api import Ctx, Idem, Limit, Offset, page
from droidshield.cvss_scoring import score_cvss
from droidshield.errors import DomainError
from droidshield.models import Report
from droidshield.report_models import ReportExport
from droidshield.schemas import Page
from droidshield.storage import StorageError

router = APIRouter(prefix="/api/v1", tags=["Deliverables"])


@router.post("/cvss/score", response_model=s.CVSSOut)
def calculate_cvss(data: s.CVSSRequest, ctx: Ctx):
    try:
        return score_cvss(data.vector)
    except ValueError as exc:
        raise DomainError(422, "validation_error", str(exc)) from exc


@router.get("/reports", response_model=Page[s.ReportOut])
def list_reports(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    project_id: UUID | None = None,
    assessment_id: UUID | None = None,
    status: Literal["draft", "awaiting_review", "approved", "exported"] | None = None,
    template: Literal["executive", "technical", "combined"] | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
):
    query = select(Report).where(
        Report.workspace_id == ctx.workspace_id,
        Report.project_id.in_(services.visible_projects(ctx)),
    )
    for field, value in (
        (Report.project_id, project_id),
        (Report.assessment_id, assessment_id),
        (Report.status, status),
        (Report.template, template),
    ):
        if value is not None:
            query = query.where(field == value)
    if q:
        query = query.where(Report.title.icontains(q, autoescape=True))
    return page(
        ctx, query.order_by(Report.created_at.desc(), Report.id), s.ReportOut, limit, offset
    )


@router.post("/assessments/{assessment_id}/reports", response_model=s.ReportOut, status_code=201)
def create_report(
    assessment_id: UUID, data: s.ReportCreate, request: Request, ctx: Ctx, idempotency_key: Idem
):
    services.require_writer(ctx)
    return services.once(
        ctx,
        idempotency_key,
        f"report.create:{assessment_id}",
        data,
        lambda key: svc.report(ctx, key),
        lambda: svc.create(ctx, assessment_id, data, request.app.state.settings),
    )


@router.get("/reports/{report_id}", response_model=s.ReportDetailOut)
def read_report(report_id: UUID, ctx: Ctx):
    record = svc.report(ctx, report_id)
    frozen = svc.snapshot(ctx, record)
    return {
        **s.ReportOut.model_validate(record).model_dump(),
        "snapshot": frozen.snapshot_json,
        "snapshot_sha256": frozen.sha256,
    }


@router.post("/reports/{report_id}/release", response_model=s.ReportOut)
def release_report(report_id: UUID, data: s.ReportRelease, ctx: Ctx, idempotency_key: Idem):
    services.require_admin(ctx)
    return services.once(
        ctx,
        idempotency_key,
        f"report.release:{report_id}",
        data,
        lambda key: svc.report(ctx, key),
        lambda: svc.release(ctx, report_id),
    )


@router.get("/reports/{report_id}/exports", response_model=Page[s.ReportExportOut])
def list_exports(report_id: UUID, ctx: Ctx, limit: Limit = 25, offset: Offset = 0):
    record = svc.report(ctx, report_id)
    query = select(ReportExport).where(
        ReportExport.report_id == record.id,
        ReportExport.workspace_id == ctx.workspace_id,
        ReportExport.project_id == record.project_id,
    )
    return page(
        ctx,
        query.order_by(ReportExport.created_at.desc(), ReportExport.id),
        s.ReportExportOut,
        limit,
        offset,
    )


@router.post("/reports/{report_id}/exports", response_model=s.ReportExportOut, status_code=201)
def export_report(
    report_id: UUID, data: s.ReportExportCreate, request: Request, ctx: Ctx, idempotency_key: Idem
):
    services.require_writer(ctx)
    return services.once(
        ctx,
        idempotency_key,
        f"report.export:{report_id}",
        data,
        lambda key: svc.export_record(ctx, key),
        lambda: svc.export(ctx, report_id, data.format, request.app.state.settings),
    )


@router.get("/report-exports/{export_id}/download")
def download_export(export_id: UUID, request: Request, ctx: Ctx):
    record = svc.export_record(ctx, export_id)
    report = svc.report(ctx, record.report_id)
    copy = None
    try:
        copy = svc.store(request.app.state.settings).verified_copy(
            record.storage_ref, record.sha256, record.file_size
        )
        path = copy.__enter__()
        services.audit(ctx, "report.downloaded", "report", report.id)
        ctx.session.commit()
        return FileResponse(
            path,
            media_type="application/pdf" if record.format == "pdf" else "application/json",
            filename=f"DroidShield-report-v{report.version}.{record.format}",
            headers={"X-Content-SHA256": record.sha256},
            background=BackgroundTask(copy.__exit__, None, None, None),
        )
    except StorageError as exc:
        raise DomainError(
            409, "report_integrity_failed", "Report file integrity check failed"
        ) from exc
    except BaseException:
        if copy:
            copy.__exit__(None, None, None)
        raise
