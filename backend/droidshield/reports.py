"""Client-scoped, reviewed, immutable security assessment deliverables."""

from __future__ import annotations

import hashlib
import io
import json
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select

from droidshield import services as svc
from droidshield.auth import utc
from droidshield.config import Settings
from droidshield.cvss_scoring import validate_cvss
from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import (
    AnalysisJob,
    AnalysisResult,
    AppArtifact,
    Authorization,
    Client,
    Finding,
    Report,
    Retest,
    User,
)
from droidshield.report_models import ReportExport, ReportSnapshot
from droidshield.report_schemas import ReportCreate
from droidshield.storage import Storage, StorageError

MAX_EXPORT_BYTES = 16 * 1024**2
MAX_SNAPSHOT_BYTES = 2 * 1024**2
ORDER = {value: index for index, value in enumerate(("critical", "high", "medium", "low", "info"))}
ALIGNMENT_NOTICE = (
    "This assessment documents security testing and evidence within its stated scope. "
    "MASVS/Mobile Top 10 and NIST SP 800-115 references describe testing alignment. "
    "The report is not a SOC 2, ISO 27001, HIPAA, PCI DSS or Google Play certification, "
    "and does not guarantee the absence of vulnerabilities. Untested controls remain Not Run."
)


def canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def report(ctx: svc.Context, resource_id: UUID, *, lock=False) -> Report:
    query = select(Report).where(
        Report.id == resource_id,
        Report.workspace_id == ctx.workspace_id,
        Report.project_id.in_(svc.visible_projects(ctx)),
    )
    value = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if value is None:
        raise not_found()
    return value


def snapshot(ctx: svc.Context, record: Report) -> ReportSnapshot:
    value = ctx.session.scalar(
        select(ReportSnapshot).where(
            ReportSnapshot.report_id == record.id,
            ReportSnapshot.workspace_id == ctx.workspace_id,
            ReportSnapshot.project_id == record.project_id,
            ReportSnapshot.assessment_id == record.assessment_id,
        )
    )
    if value is None or hashlib.sha256(canonical(value.snapshot_json)).hexdigest() != value.sha256:
        raise DomainError(409, "report_integrity_failed", "Report snapshot integrity check failed")
    return value


def _time(value):
    return utc(value).isoformat() if value is not None else None


def create(ctx: svc.Context, assessment_id: UUID, data: ReportCreate, settings: Settings) -> Report:
    from droidshield.delivery import coverage, get_evidence_content, sanitize_evidence
    from droidshield.models import AssessmentEvidence

    svc.require_writer(ctx)
    for narrative in (
        data.title,
        data.executive_summary,
        data.limitations,
        data.branding_name or "",
    ):
        clean, redactions = sanitize_evidence(narrative)
        if redactions or clean != narrative:
            raise DomainError(
                422,
                "sensitive_content",
                "Remove credentials and control characters from report narratives",
            )
    assessment = svc.assessment(ctx, assessment_id, lock=True)
    if assessment.status != "completed" or assessment.reviewer_id is None:
        raise conflict("Complete the independent assessment review before creating a report")
    project = svc.project(ctx, assessment.project_id)
    client = ctx.session.scalar(
        select(Client).where(
            Client.id == project.client_id, Client.workspace_id == ctx.workspace_id
        )
    )
    if client is None:
        raise not_found()
    version = (
        ctx.session.scalar(
            select(func.max(ReportSnapshot.version)).where(
                ReportSnapshot.assessment_id == assessment.id
            )
        )
        or 0
    ) + 1
    findings = list(
        ctx.session.scalars(
            select(Finding)
            .where(
                Finding.workspace_id == ctx.workspace_id,
                Finding.assessment_id == assessment.id,
                Finding.project_id == project.id,
                Finding.verification_status == "confirmed",
                Finding.severity.in_(data.severity_filter),
            )
            .order_by(Finding.created_at, Finding.id)
            .limit(201)
        )
    )
    if len(findings) > 200:
        raise conflict(
            "A report supports at most 200 confirmed findings; narrow the severity filter"
        )
    findings.sort(key=lambda item: (ORDER[item.severity], str(item.id)))
    finding_payload = []
    for item in findings:
        try:
            validate_cvss(item.cvss_vector, item.cvss_score)
        except ValueError as exc:
            raise conflict(
                "A selected finding has invalid CVSS data; review it before reporting"
            ) from exc
        evidence = []
        if data.include_evidence:
            try:
                linked_ids = [
                    UUID(value) for value in item.evidence_provenance.get("evidence_ids", [])
                ]
            except (ValueError, TypeError, AttributeError) as exc:
                raise conflict(
                    "A finding has invalid evidence provenance; review its evidence"
                ) from exc
            rows = ctx.session.scalars(
                select(AssessmentEvidence)
                .where(
                    AssessmentEvidence.workspace_id == ctx.workspace_id,
                    AssessmentEvidence.project_id == project.id,
                    AssessmentEvidence.assessment_id == assessment.id,
                    AssessmentEvidence.id.in_(linked_ids),
                )
                .order_by(AssessmentEvidence.created_at, AssessmentEvidence.id)
                .limit(21)
            ).all()
            if not set(linked_ids).issubset({row.id for row in rows}) or any(
                row.artifact_id != item.artifact_id or row.finding_id not in {None, item.id}
                for row in rows
            ):
                raise conflict("A finding's evidence does not match its assessment and artifact")
            if len(rows) > 20:
                raise conflict("A finding supports at most 20 report evidence excerpts")
            for row in rows:
                evidence.append(
                    {
                        "id": str(row.id),
                        "title": row.title,
                        "sha256": row.sha256,
                        "platform": row.platform,
                        "tool": row.tool,
                        "tool_version": row.tool_version,
                        "environment": row.environment,
                        "created_at": _time(row.created_at),
                        "release_ref": row.release_ref,
                        "text": get_evidence_content(settings, row),
                        "attachment": (
                            {
                                "sha256": row.attachment.sha256,
                                "file_size": row.attachment.file_size,
                                "media_type": row.attachment.media_type,
                                "display_name": row.attachment.display_name,
                            }
                            if row.attachment
                            else None
                        ),
                    }
                )
        finding_payload.append(
            {
                "id": str(item.id),
                "title": item.title,
                "description": item.description,
                "affected_component": item.affected_component,
                "category": item.category,
                "severity": item.severity,
                "verification_status": "confirmed",
                "remediation_status": item.remediation_status,
                "cvss_vector": item.cvss_vector,
                "cvss_score": item.cvss_score,
                "masvs_mapping": item.masvs_mapping,
                "cwe_mapping": item.cwe_mapping,
                "reproduction_steps": item.reproduction_steps,
                "impact": item.impact,
                "remediation": item.remediation if data.include_remediation else None,
                "evidence": evidence,
                "artifact_id": str(item.artifact_id) if item.artifact_id else None,
            }
        )
    all_count = (
        ctx.session.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.workspace_id == ctx.workspace_id,
                Finding.assessment_id == assessment.id,
                Finding.project_id == project.id,
            )
        )
        or 0
    )
    authorization = ctx.session.scalar(
        select(Authorization).where(
            Authorization.id == assessment.authorization_id,
            Authorization.workspace_id == ctx.workspace_id,
            Authorization.project_id == project.id,
        )
    )
    artifact = ctx.session.scalar(
        select(AppArtifact).where(
            AppArtifact.id == assessment.artifact_id,
            AppArtifact.workspace_id == ctx.workspace_id,
            AppArtifact.project_id == project.id,
        )
    )
    pinned = assessment.configuration_snapshot.get("manual")
    scope_source = "manual_execution_snapshot"
    if not isinstance(pinned, dict) or "approved_targets" not in pinned:
        pinned = assessment.configuration_snapshot
        scope_source = "assessment_execution_snapshot"
    if "approved_targets" not in pinned:
        job = ctx.session.scalar(
            select(AnalysisJob).where(
                AnalysisJob.workspace_id == ctx.workspace_id,
                AnalysisJob.assessment_id == assessment.id,
            )
        )
        pinned = job.configuration_snapshot if job is not None else {}
        scope_source = "job_execution_snapshot" if job is not None else "not_recorded"
    scope_payload = {
        "source": scope_source,
        "authorization_id": pinned.get(
            "authorization_id", str(authorization.id) if authorization else None
        ),
        "authorization_revision": pinned.get("authorization_revision"),
        "valid_from": pinned.get("valid_from"),
        "valid_until": pinned.get("valid_until"),
        "approved_targets": deepcopy(pinned.get("approved_targets", [])),
        "exclusions": deepcopy(pinned.get("exclusions", [])),
        "tested_targets": deepcopy(assessment.configuration_snapshot.get("requested_targets", [])),
    }
    coverage_payload = deepcopy(coverage(ctx, assessment.id))
    # Coverage references carry metadata and status, never arbitrary database rows.
    retest_payload = []
    if findings:
        retests = ctx.session.scalars(
            select(Retest)
            .where(
                Retest.workspace_id == ctx.workspace_id,
                Retest.project_id == project.id,
                Retest.original_assessment_id == assessment.id,
                Retest.finding_id.in_([item.id for item in findings]),
                Retest.reviewer_id.is_not(None),
                Retest.review_decision == "approve",
            )
            .order_by(Retest.created_at, Retest.id)
            .limit(201)
        ).all()
        if len(retests) > 200:
            raise conflict("A report supports at most 200 reviewed retest records")
        for item in retests:
            new_artifact = ctx.session.scalar(
                select(AppArtifact).where(
                    AppArtifact.id == item.new_artifact_id,
                    AppArtifact.workspace_id == ctx.workspace_id,
                    AppArtifact.project_id == project.id,
                )
            )
            new_evidence = []
            if data.include_evidence:
                try:
                    proof_ids = [UUID(value) for value in item.new_evidence]
                except (ValueError, TypeError) as exc:
                    raise conflict("Retest evidence provenance must be reviewed") from exc
                proofs = ctx.session.scalars(
                    select(AssessmentEvidence)
                    .where(
                        AssessmentEvidence.id.in_(proof_ids),
                        AssessmentEvidence.workspace_id == ctx.workspace_id,
                        AssessmentEvidence.project_id == project.id,
                        AssessmentEvidence.assessment_id == assessment.id,
                    )
                    .order_by(AssessmentEvidence.created_at, AssessmentEvidence.id)
                    .limit(21)
                ).all()
                if (
                    len(proofs) > 20
                    or set(proof_ids) != {proof.id for proof in proofs}
                    or any(
                        proof.artifact_id != item.new_artifact_id
                        or (
                            item.new_artifact_id is None
                            and proof.release_ref != item.environment.get("new_release_ref")
                        )
                        for proof in proofs
                    )
                ):
                    raise conflict(
                        "Retest evidence does not match its approved artifact or release"
                    )
                new_evidence = [
                    {
                        "id": str(proof.id),
                        "title": proof.title,
                        "sha256": proof.sha256,
                        "release_ref": proof.release_ref,
                        "text": get_evidence_content(settings, proof),
                        "attachment": (
                            {
                                "sha256": proof.attachment.sha256,
                                "file_size": proof.attachment.file_size,
                                "media_type": proof.attachment.media_type,
                                "display_name": proof.attachment.display_name,
                            }
                            if proof.attachment
                            else None
                        ),
                    }
                    for proof in proofs
                ]
            retest_payload.append(
                {
                    "id": str(item.id),
                    "finding_id": str(item.finding_id),
                    "method": item.method,
                    "result": item.result,
                    "new_artifact_sha256": new_artifact.sha256 if new_artifact else None,
                    "version_name": new_artifact.version_name if new_artifact else None,
                    "reviewed_at": _time(item.reviewed_at),
                    "original_release_ref": item.environment.get("original_release_ref"),
                    "new_release_ref": item.environment.get("new_release_ref"),
                    "notes": item.notes,
                    "new_evidence": new_evidence,
                }
            )
    author = ctx.session.get(User, ctx.user.id)
    now = datetime.now(UTC)
    payload = {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "title": data.title,
        "template": data.template,
        "version": version,
        "branding_name": data.branding_name or "DroidShield",
        "client": {"id": str(client.id), "name": client.name},
        "project": {
            "id": str(project.id),
            "name": project.name,
            "application_name": project.application_name,
            "package_id": project.package_id,
            "framework": project.framework,
            "platform": project.platform,
        },
        "assessment": {
            "id": str(assessment.id),
            "name": assessment.name,
            "type": assessment.assessment_type,
            "started_at": _time(assessment.started_at),
            "completed_at": _time(assessment.completed_at),
            "reviewer_id": str(assessment.reviewer_id),
            "artifact_sha256": artifact.sha256 if artifact else None,
            "version_name": artifact.version_name if artifact else None,
            "artifact_format": artifact.metadata_json.get("artifact_format", "apk")
            if artifact
            else None,
        },
        "author": {"id": str(ctx.user.id), "name": author.full_name},
        "scope": scope_payload,
        "executive_summary": data.executive_summary,
        "limitations": data.limitations,
        "alignment_notice": ALIGNMENT_NOTICE,
        "coverage": coverage_payload,
        "risk_summary": {
            severity: sum(item.severity == severity for item in findings) for severity in ORDER
        },
        "excluded_findings_count": all_count - len(findings),
        "severity_filter": data.severity_filter,
        "findings": finding_payload,
        "remediation_roadmap": [
            {
                "priority": index + 1,
                "finding_id": item["id"],
                "title": item["title"],
                "severity": item["severity"],
                "status": item["remediation_status"],
                "recommendation": item["remediation"],
                "due_date": None,
            }
            for index, item in enumerate(finding_payload)
            if item["remediation_status"] != "fixed"
        ]
        if data.include_remediation
        else [],
        "retests": retest_payload,
        "tool_versions": deepcopy(assessment.tool_versions),
        "engine_limitations": [],
    }
    for result in ctx.session.scalars(
        select(AnalysisResult).where(
            AnalysisResult.workspace_id == ctx.workspace_id,
            AnalysisResult.assessment_id == assessment.id,
            AnalysisResult.project_id == project.id,
        )
    ):
        payload["engine_limitations"].extend(result.limitations_json)
    encoded = canonical(payload)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise conflict("Report content exceeds the bounded snapshot size; reduce evidence excerpts")
    record = Report(
        id=uuid4(),
        workspace_id=ctx.workspace_id,
        project_id=project.id,
        assessment_id=assessment.id,
        title=data.title,
        template=data.template,
        version=version,
        status="awaiting_review",
        filters={
            "severities": data.severity_filter,
            "include_evidence": data.include_evidence,
            "include_remediation": data.include_remediation,
        },
        branding={"name": payload["branding_name"]},
        author_id=ctx.user.id,
    )
    ctx.session.add(record)
    ctx.session.flush()
    ctx.session.add(
        ReportSnapshot(
            workspace_id=ctx.workspace_id,
            report_id=record.id,
            project_id=project.id,
            assessment_id=assessment.id,
            version=version,
            snapshot_json=payload,
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
    )
    ctx.session.flush()
    svc.audit(ctx, "report.snapshot_created", "report", record.id)
    return record


def release(ctx: svc.Context, report_id: UUID) -> Report:
    svc.require_admin(ctx)
    record = report(ctx, report_id, lock=True)
    snapshot(ctx, record)
    if record.author_id == ctx.user.id:
        raise DomainError(
            403, "independent_review_required", "A different administrator must approve this report"
        )
    if record.status != "awaiting_review":
        raise conflict("Only a report awaiting review can be approved")
    record.status = "approved"
    record.reviewer_id = ctx.user.id
    record.approved_at = datetime.now(UTC)
    ctx.session.flush()
    svc.audit(ctx, "report.approved", "report", record.id)
    return record


# Parent publication creates apk-prefixed references, so use its hardened object
# protocol unchanged in a separate directory; no client ever sees storage refs.
# Report filenames on download are derived from the immutable report version.
def store(settings: Settings) -> Storage:
    return Storage(settings.storage_root / "reports")


def export_record(ctx: svc.Context, resource_id: UUID) -> ReportExport:
    value = ctx.session.scalar(
        select(ReportExport).where(
            ReportExport.id == resource_id,
            ReportExport.workspace_id == ctx.workspace_id,
            ReportExport.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if value is None:
        raise not_found()
    record = report(ctx, value.report_id)
    if record.status not in {"approved", "exported"}:
        raise conflict("Report release is required before download")
    return value


def export(ctx: svc.Context, report_id: UUID, format: str, settings: Settings) -> ReportExport:
    from droidshield.report_render import RenderError, render

    svc.require_writer(ctx)
    record = report(ctx, report_id, lock=True)
    frozen = snapshot(ctx, record)
    if record.status not in {"approved", "exported"} or record.reviewer_id is None:
        raise conflict("Independent approval is required before client export")
    existing = ctx.session.scalar(
        select(ReportExport).where(
            ReportExport.workspace_id == ctx.workspace_id,
            ReportExport.report_id == record.id,
            ReportExport.project_id == record.project_id,
            ReportExport.format == format,
        )
    )
    if existing is not None:
        return existing
    payload = {
        "report": frozen.snapshot_json,
        "snapshot_sha256": frozen.sha256,
        "release": {
            "reviewer_id": str(record.reviewer_id),
            "approved_at": _time(record.approved_at),
        },
    }
    try:
        content = canonical(payload) if format == "json" else render(canonical(payload))
        ctx.session.refresh(ctx.user)
        if ctx.user.status != "active":
            raise DomainError(401, "unauthenticated", "Valid authentication is required")
        svc.require_writer(ctx)
        svc.project(ctx, record.project_id)
        protected = store(settings)
        staged = protected.stage(io.BytesIO(content), MAX_EXPORT_BYTES)
        try:
            reference = protected.publish(staged)
        finally:
            staged.close()
    except (StorageError, RenderError) as exc:
        raise DomainError(
            503, "report_export_unavailable", "Protected report export is unavailable"
        ) from exc
    output = ReportExport(
        workspace_id=ctx.workspace_id,
        report_id=record.id,
        project_id=record.project_id,
        format=format,
        storage_ref=reference,
        sha256=hashlib.sha256(content).hexdigest(),
        file_size=len(content),
        created_by=ctx.user.id,
    )
    try:
        ctx.session.add(output)
        ctx.session.flush()
        record.status = "exported"
        record.export_ref = reference
        record.export_format = format
        record.checksum = output.sha256
        record.exported_at = output.created_at
        svc.audit(ctx, "report.exported", "report", record.id)
        ctx.session.flush()
    except BaseException:
        # No commit has been attempted: this file cannot be a durable export.
        protected.discard(reference)
        raise
    return output
