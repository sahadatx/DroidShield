"""HTTP boundary for analyst-entered work and reviewed deliverables."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import select

from droidshield import delivery as svc
from droidshield import delivery_schemas as ds
from droidshield import evidence_uploads
from droidshield import schemas as s
from droidshield import services as base
from droidshield.api import Ctx, Idem, Limit, Offset, page
from droidshield.methodology import library
from droidshield.models import AssessmentEvidence, Retest

router = APIRouter(prefix="/api/v1", tags=["Analyst workflow"])


@router.get("/methodology")
def methodology(ctx: Ctx):
    return library()


@router.post("/assessments/{assessment_id}/manual-start", response_model=s.AssessmentOut)
def manual_start(assessment_id: UUID, ctx: Ctx, data: ds.ManualStart, key: Idem):
    base.require_writer(ctx)
    return base.once(
        ctx,
        key,
        f"assessment.manual_start:{assessment_id}",
        data,
        lambda rid: base.assessment(ctx, rid),
        lambda: svc.manual_start(ctx, assessment_id, data),
    )


@router.post("/assessments/{assessment_id}/manual-finish", response_model=s.AssessmentOut)
def manual_finish(assessment_id: UUID, ctx: Ctx, data: ds.ManualFinish, key: Idem):
    base.require_writer(ctx)
    return base.once(
        ctx,
        key,
        f"assessment.manual_finish:{assessment_id}",
        data,
        lambda rid: base.assessment(ctx, rid),
        lambda: svc.manual_finish(ctx, assessment_id, data),
    )


@router.post("/assessments/{assessment_id}/review", response_model=s.AssessmentOut)
def review_assessment(assessment_id: UUID, ctx: Ctx, data: ds.AssessmentReview, key: Idem):
    base.require_admin(ctx)
    return base.once(
        ctx,
        key,
        f"assessment.review:{assessment_id}",
        data,
        lambda rid: base.assessment(ctx, rid),
        lambda: svc.review_assessment(ctx, assessment_id, data),
    )


@router.get("/assessments/{assessment_id}/coverage")
def coverage(assessment_id: UUID, ctx: Ctx):
    return svc.coverage(ctx, assessment_id)


@router.put("/assessments/{assessment_id}/coverage/{case_id}", response_model=ds.ExecutionOut)
def record_test(assessment_id: UUID, case_id: str, ctx: Ctx, data: ds.CoverageUpdate):
    return svc.update_coverage(ctx, assessment_id, case_id, data)


@router.get("/assessments/{assessment_id}/evidence", response_model=s.Page[ds.EvidenceOut])
def evidence_list(assessment_id: UUID, ctx: Ctx, limit: Limit = 25, offset: Offset = 0):
    base.assessment(ctx, assessment_id)
    query = (
        select(AssessmentEvidence)
        .where(
            AssessmentEvidence.assessment_id == assessment_id,
            AssessmentEvidence.workspace_id == ctx.workspace_id,
        )
        .order_by(AssessmentEvidence.created_at.desc(), AssessmentEvidence.id)
    )
    return page(ctx, query, ds.EvidenceOut, limit, offset)


@router.post(
    "/assessments/{assessment_id}/evidence", response_model=ds.EvidenceOut, status_code=201
)
def create_evidence(
    assessment_id: UUID, ctx: Ctx, data: ds.EvidenceCreate, key: Idem, request: Request
):
    base.require_writer(ctx)
    return base.once(
        ctx,
        key,
        f"evidence.create:{assessment_id}",
        data,
        lambda rid: svc.evidence(ctx, rid),
        lambda: svc.create_evidence(ctx, assessment_id, data, request.app.state.settings),
    )


@router.post(
    "/assessments/{assessment_id}/evidence-attachments",
    response_model=ds.EvidenceOut,
    status_code=201,
)
async def create_evidence_attachment(assessment_id: UUID, ctx: Ctx, key: Idem, request: Request):
    base.require_writer(ctx)
    return await evidence_uploads.ingest(request, ctx, assessment_id, key)


@router.get("/evidence/{evidence_id}", response_model=ds.EvidenceOut)
def evidence_detail(evidence_id: UUID, ctx: Ctx):
    return svc.evidence(ctx, evidence_id)


@router.get("/evidence/{evidence_id}/content")
def evidence_content(evidence_id: UUID, ctx: Ctx, request: Request):
    record = svc.evidence(ctx, evidence_id)
    base.audit(ctx, "evidence.read", "evidence", record.id)
    if record.attachment is not None:
        attachment = record.attachment
        content = svc.get_evidence_attachment(request.app.state.settings, record)
        return Response(
            content,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="DroidShield-evidence-{record.id}.png"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
                "X-Content-SHA256": attachment.sha256,
            },
        )
    content = svc.get_evidence_content(request.app.state.settings, record)
    return Response(
        content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{record.id}.txt"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )


@router.post(
    "/assessments/{assessment_id}/findings", response_model=s.FindingDetailOut, status_code=201
)
def create_finding(assessment_id: UUID, ctx: Ctx, data: ds.FindingCreate, key: Idem):
    base.require_writer(ctx)
    return base.once(
        ctx,
        key,
        f"finding.create:{assessment_id}",
        data,
        lambda rid: svc.finding(ctx, rid),
        lambda: svc.create_finding(ctx, assessment_id, data),
    )


@router.patch("/findings/{finding_id}", response_model=s.FindingDetailOut)
def update_finding(finding_id: UUID, ctx: Ctx, data: ds.FindingUpdate):
    return svc.update_finding(ctx, finding_id, data)


@router.post("/findings/{finding_id}/review", response_model=s.FindingDetailOut)
def review_finding(finding_id: UUID, ctx: Ctx, data: ds.FindingReview, key: Idem, request: Request):
    base.require_admin(ctx)
    return base.once(
        ctx,
        key,
        f"finding.review:{finding_id}",
        data,
        lambda rid: svc.finding(ctx, rid),
        lambda: svc.review_finding(ctx, finding_id, data, request.app.state.settings),
    )


@router.get("/retests", response_model=s.Page[ds.RetestOut])
def retests(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    project_id: UUID | None = None,
    finding_id: UUID | None = None,
    assessment_id: UUID | None = None,
    method: Literal["static", "dynamic", "api", "manual"] | None = None,
    result: Literal["pass", "fail", "inconclusive", "not_reproducible"] | None = None,
    review_status: Literal["awaiting_review", "approved", "rejected"] | None = None,
):
    query = select(Retest).where(
        Retest.workspace_id == ctx.workspace_id, Retest.project_id.in_(base.visible_projects(ctx))
    )
    if project_id:
        query = query.where(Retest.project_id == project_id)
    if finding_id:
        query = query.where(Retest.finding_id == finding_id)
    if assessment_id:
        query = query.where(Retest.original_assessment_id == assessment_id)
    if method:
        query = query.where(Retest.method == method)
    if result:
        query = query.where(Retest.result == result)
    if review_status == "awaiting_review":
        query = query.where(Retest.review_decision.is_(None))
    elif review_status == "approved":
        query = query.where(Retest.review_decision == "approve")
    elif review_status == "rejected":
        query = query.where(Retest.review_decision == "reject")
    return page(
        ctx, query.order_by(Retest.created_at.desc(), Retest.id), ds.RetestOut, limit, offset
    )


@router.post("/findings/{finding_id}/retests", response_model=ds.RetestOut, status_code=201)
def create_retest(finding_id: UUID, ctx: Ctx, data: ds.RetestCreate, key: Idem):
    base.require_writer(ctx)
    return base.once(
        ctx,
        key,
        f"retest.create:{finding_id}",
        data,
        lambda rid: svc.retest(ctx, rid),
        lambda: svc.create_retest(ctx, finding_id, data),
    )


@router.get("/retests/{retest_id}", response_model=ds.RetestOut)
def retest_detail(retest_id: UUID, ctx: Ctx):
    return svc.retest(ctx, retest_id)


@router.post("/retests/{retest_id}/review", response_model=ds.RetestOut)
def review_retest(retest_id: UUID, ctx: Ctx, data: ds.RetestReview, key: Idem, request: Request):
    base.require_admin(ctx)
    return base.once(
        ctx,
        key,
        f"retest.review:{retest_id}",
        data,
        lambda rid: svc.retest(ctx, rid),
        lambda: svc.review_retest(ctx, retest_id, data, request.app.state.settings),
    )
