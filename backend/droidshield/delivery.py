"""Authorized analyst records, evidence, verification and retesting.

These services record work performed by an authenticated analyst. They do not
execute Frida, Objection, Burp, arbitrary requests or uploaded applications.
"""

import io
import re
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from droidshield import delivery_schemas as ds
from droidshield import services as svc
from droidshield.auth import utc
from droidshield.errors import DomainError, conflict, not_found
from droidshield.methodology import library, test_case
from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    AssessmentEvidence,
    EvidenceAttachment,
    Finding,
    Retest,
    TestExecution,
)
from droidshield.storage import Storage, StorageError

_ANY_ARTIFACT = object()

_SECRET_PATTERNS = [
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        r"(?im)\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]{1,2000}"
    ),
]


def sanitize_evidence(value: str) -> tuple[str, int]:
    count = 0
    for pattern in _SECRET_PATTERNS:
        value, found = pattern.subn("[REDACTED]", value)
        count += found
    # Preserve normal text formatting while excluding NUL and terminal controls.
    value = "".join(char for char in value if char in "\n\t" or ord(char) >= 32)
    return value, count


def _require_sanitized(value: str) -> None:
    if sanitize_evidence(value)[1]:
        raise DomainError(
            422,
            "sensitive_content",
            "Remove credentials from descriptive fields and attach sanitized evidence",
        )


def _active_project(ctx, project_id):
    project = svc.project(ctx, project_id, lock=True)
    if project.status != "active" or svc.client(ctx, project.client_id).status != "active":
        raise conflict("An active project and client are required")
    return project


def _permit(ctx, assessment, authorization_id=None):
    permit_id = authorization_id or assessment.authorization_id
    if permit_id is None:
        raise conflict("A verified authorization is required")
    permit = svc.authorization(ctx, permit_id, lock=True)
    project = _active_project(ctx, assessment.project_id)
    now = datetime.now(UTC)
    if (
        permit.project_id != project.id
        or permit.status != "verified"
        or not (utc(permit.valid_from) <= now < utc(permit.valid_until))
    ):
        raise conflict("Authorization is unverified, revoked or outside its testing window")
    targets = assessment.configuration_snapshot.get("requested_targets", [])
    if not targets or any(target not in permit.approved_targets for target in targets):
        raise conflict("Every requested target must be explicitly approved")
    if any(
        svc.is_excluded(target, exclusion) for target in targets for exclusion in permit.exclusions
    ):
        raise conflict("Requested targets include an excluded target")
    return project, permit


def _artifact(ctx, artifact_id, project_id):
    artifact = ctx.session.scalar(
        select(AppArtifact).where(
            AppArtifact.id == artifact_id,
            AppArtifact.project_id == project_id,
            AppArtifact.workspace_id == ctx.workspace_id,
        )
    )
    if artifact is None:
        raise not_found()
    return artifact


def _artifact_identity(project, artifact, platform):
    metadata = artifact.metadata_json
    prefix = "bundle:" if platform == "ios" else "package:"
    if (
        platform != project.platform
        or metadata.get("platform", "android") != platform
        or metadata.get("package_name") != project.package_id
    ):
        raise conflict("Artifact identity and platform must match the project")
    return prefix + project.package_id


def finding(ctx, resource_id, *, lock=False):
    query = select(Finding).where(
        Finding.id == resource_id,
        Finding.workspace_id == ctx.workspace_id,
        Finding.project_id.in_(svc.visible_projects(ctx)),
    )
    record = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if record is None:
        raise not_found()
    return record


def evidence(ctx, resource_id):
    record = ctx.session.scalar(
        select(AssessmentEvidence).where(
            AssessmentEvidence.id == resource_id,
            AssessmentEvidence.workspace_id == ctx.workspace_id,
            AssessmentEvidence.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if record is None:
        raise not_found()
    return record


def retest(ctx, resource_id, *, lock=False):
    query = select(Retest).where(
        Retest.id == resource_id,
        Retest.workspace_id == ctx.workspace_id,
        Retest.project_id.in_(svc.visible_projects(ctx)),
    )
    record = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if record is None:
        raise not_found()
    return record


def _editable(assessment):
    manual = assessment.configuration_snapshot.get("manual", {})
    if assessment.status != "needs_review" and not (
        assessment.status == "running" and manual.get("mode") == "analyst_record"
    ):
        raise conflict(
            "Analyst edits require a running manual assessment or an assessment awaiting review"
        )


def _locked_assessment(ctx, assessment_id):
    current = svc.assessment(ctx, assessment_id)
    authorization_id = current.authorization_id
    if authorization_id is not None:
        svc.authorization(ctx, authorization_id, lock=True)
    record = svc.assessment(ctx, assessment_id, lock=True)
    if record.authorization_id != authorization_id:
        raise conflict("Assessment authorization changed; reload before saving")
    return record


def manual_start(ctx, assessment_id, data):
    svc.require_writer(ctx)
    record = _locked_assessment(ctx, assessment_id)
    svc.check_revision(record, data.revision)
    if record.status not in {"draft", "awaiting_authorization"}:
        raise conflict("Only a draft or awaiting-authorization assessment can begin manual work")
    if ctx.session.scalar(select(AnalysisJob.id).where(AnalysisJob.assessment_id == record.id)):
        raise conflict("An automated job already exists for this assessment")
    parent, permit = _permit(ctx, record)
    if data.platform != parent.platform:
        raise conflict("Assessment platform must match the project")
    artifact = None
    targets = record.configuration_snapshot.get("requested_targets", [])
    if record.assessment_type != "api":
        artifact = _artifact(ctx, record.artifact_id, parent.id)
        identity = _artifact_identity(parent, artifact, data.platform)
        if identity not in targets:
            raise conflict("The immutable artifact identity must be explicitly in scope")
    elif any(target.startswith(("package:", "bundle:")) for target in targets):
        raise conflict("API assessments require HTTPS targets")
    for text in [
        data.environment,
        data.limitations,
        *[f"{tool.name} {tool.version}" for tool in data.tools],
    ]:
        _require_sanitized(text)
    record.configuration_snapshot = {
        **record.configuration_snapshot,
        "manual": {
            "mode": "analyst_record",
            "started_by": str(ctx.user.id),
            "contributors": [str(ctx.user.id)],
            "platform": data.platform,
            "environment": data.environment,
            "tools": [tool.model_dump() for tool in data.tools],
            "limitations": data.limitations,
            "authorization_id": str(permit.id),
            "authorization_revision": permit.revision,
            "approved_targets": list(permit.approved_targets),
            "exclusions": list(permit.exclusions),
            "valid_from": utc(permit.valid_from).isoformat(),
            "valid_until": utc(permit.valid_until).isoformat(),
            "artifact_sha256": artifact.sha256 if artifact else None,
        },
    }
    record.status = "running"
    record.started_at = datetime.now(UTC)
    record.tool_versions = {tool.name: tool.version for tool in data.tools}
    ctx.session.flush()
    svc.audit(ctx, "assessment.manual_started", "assessment", record.id)
    return record


def manual_finish(ctx, assessment_id, data):
    svc.require_writer(ctx)
    record = _locked_assessment(ctx, assessment_id)
    svc.check_revision(record, data.revision)
    manual = record.configuration_snapshot.get("manual", {})
    if record.status != "running" or manual.get("mode") != "analyst_record":
        raise conflict("Only running manual work can be submitted for review")
    _permit(ctx, record)
    if not ctx.session.scalar(
        select(TestExecution.id).where(
            TestExecution.assessment_id == record.id, TestExecution.status != "not_run"
        )
    ):
        raise conflict("Record test coverage and evidence or explicit limitations before review")
    _require_sanitized(data.summary)
    record.configuration_snapshot = {
        **record.configuration_snapshot,
        "manual": {
            **manual,
            "summary": data.summary,
            "submitted_by": str(ctx.user.id),
            "contributors": sorted(set(manual.get("contributors", [])) | {str(ctx.user.id)}),
            "submitted_at": datetime.now(UTC).isoformat(),
        },
    }
    record.status = "needs_review"
    ctx.session.flush()
    svc.audit(ctx, "assessment.manual_submitted", "assessment", record.id)
    return record


def review_assessment(ctx, assessment_id, data):
    svc.require_admin(ctx)
    record = svc.assessment(ctx, assessment_id, lock=True)
    svc.check_revision(record, data.revision)
    if record.status != "needs_review":
        raise conflict("Only assessments awaiting review can be reviewed")
    manual = record.configuration_snapshot.get("manual", {})
    authors = {record.created_by}
    for field in ("started_by", "submitted_by"):
        if manual.get(field):
            authors.add(UUID(manual[field]))
    authors.update(UUID(value) for value in manual.get("contributors", []))
    for execution in ctx.session.scalars(
        select(TestExecution).where(TestExecution.assessment_id == record.id)
    ):
        authors.add(execution.operator_id)
        authors.update(UUID(value) for value in execution.contributors)
    authors.update(
        ctx.session.scalars(
            select(AssessmentEvidence.created_by).where(
                AssessmentEvidence.assessment_id == record.id
            )
        )
    )
    for issue in ctx.session.scalars(select(Finding).where(Finding.assessment_id == record.id)):
        authors.add(issue.created_by)
        authors.update(UUID(value) for value in issue.evidence_provenance.get("contributors", []))
        if issue.evidence_provenance.get("last_edited_by"):
            authors.add(UUID(issue.evidence_provenance["last_edited_by"]))
    if ctx.user.id in authors:
        raise conflict("A different administrator must review the assessment")
    _require_sanitized(data.notes)
    if data.decision == "complete":
        unresolved = ctx.session.scalar(
            select(Finding.id).where(
                Finding.assessment_id == record.id,
                Finding.verification_status.in_(["unreviewed", "needs_more_evidence"]),
            )
        )
        if unresolved:
            raise conflict("Review unresolved finding candidates before completing the assessment")
        if not ctx.session.scalar(
            select(TestExecution.id).where(
                TestExecution.assessment_id == record.id, TestExecution.status != "not_run"
            )
        ):
            raise conflict("A reviewer must see recorded test coverage and limitations")
        record.status = "completed"
        record.completed_at = datetime.now(UTC)
        record.reviewer_id = ctx.user.id
    elif manual.get("mode") == "analyst_record":
        record.status = "running"
    record.configuration_snapshot = {
        **record.configuration_snapshot,
        "analyst_review": {
            "decision": data.decision,
            "notes": data.notes,
            "reviewer_id": str(ctx.user.id),
            "reviewed_at": datetime.now(UTC).isoformat(),
        },
    }
    ctx.session.flush()
    svc.audit(ctx, "assessment.reviewed", "assessment", record.id)
    return record


def _evidence_links(ctx, identifiers, assessment, *, artifact_id=_ANY_ARTIFACT):
    records = []
    if len(identifiers) != len(set(identifiers)):
        raise DomainError(422, "validation_error", "Duplicate evidence references are not allowed")
    for identifier in identifiers:
        item = evidence(ctx, identifier)
        if (
            item.project_id != assessment.project_id
            or item.assessment_id != assessment.id
            or (artifact_id is not _ANY_ARTIFACT and item.artifact_id != artifact_id)
        ):
            raise not_found()
        records.append(item)
    return records


def create_evidence(ctx, assessment_id, data, settings):
    svc.require_writer(ctx)
    assessment = _locked_assessment(ctx, assessment_id)
    _active_project(ctx, assessment.project_id)
    # Completed assessments accept only distinct-build retest evidence; original
    # evidence is immutable and remains bound to its original digest.
    if assessment.status == "completed":
        api_release = (
            assessment.assessment_type == "api"
            and assessment.artifact_id is None
            and data.artifact_id is None
            and data.release_ref
        )
        if not api_release and (not data.artifact_id or data.artifact_id == assessment.artifact_id):
            raise conflict(
                "Completed assessments accept only new-build or API-release retest evidence"
            )
    else:
        _editable(assessment)
        _permit(ctx, assessment)
    project = svc.project(ctx, assessment.project_id)
    if data.platform != project.platform:
        raise conflict("Evidence platform must match the project")
    if data.artifact_id:
        item = _artifact(ctx, data.artifact_id, project.id)
        _artifact_identity(project, item, data.platform)
    elif assessment.assessment_type != "api":
        raise conflict("Application evidence requires the tested artifact")
    if data.finding_id:
        issue = finding(ctx, data.finding_id)
        if issue.assessment_id != assessment.id:
            raise not_found()
    for text in [
        data.title,
        data.tool,
        data.tool_version,
        data.environment,
        data.release_ref or "",
    ]:
        _require_sanitized(text)
    content, count = sanitize_evidence(data.content)
    if len(content.strip()) < 10:
        raise DomainError(
            422, "validation_error", "Sanitized evidence must contain a meaningful observation"
        )
    store = Storage(settings.storage_root / "evidence")
    staged = store.stage(io.BytesIO(content.encode("utf-8")), 262_144)
    reference = None
    try:
        reference = store.publish(staged)
        record = AssessmentEvidence(
            workspace_id=ctx.workspace_id,
            project_id=assessment.project_id,
            assessment_id=assessment.id,
            finding_id=data.finding_id,
            artifact_id=data.artifact_id,
            title=data.title,
            release_ref=data.release_ref,
            artifact_ref=reference,
            sha256=staged.sha256,
            file_size=staged.file_size,
            platform=data.platform,
            tool=data.tool,
            tool_version=data.tool_version,
            environment=data.environment,
            redaction_count=count,
            created_by=ctx.user.id,
        )
        ctx.session.add(record)
        ctx.session.flush()
        svc.audit(ctx, "evidence.created", "evidence", record.id)
        return record
    except Exception:
        if reference:
            store.discard(reference)
        raise
    finally:
        staged.close()


def create_evidence_attachment(ctx, assessment_id, data, settings, storage_ref, sha256, file_size):
    """Pair a protected screenshot with the normal immutable evidence record."""
    note = f"Protected screenshot attachment is available separately. SHA-256: {sha256}."
    evidence_data = ds.EvidenceCreate(
        title=data.title,
        content=note,
        sanitized=True,
        platform=data.platform,
        tool=data.tool,
        tool_version=data.tool_version,
        environment=data.environment,
        artifact_id=data.artifact_id,
        finding_id=data.finding_id,
        release_ref=data.release_ref,
    )
    record = create_evidence(ctx, assessment_id, evidence_data, settings)
    attachment = EvidenceAttachment(
        workspace_id=ctx.workspace_id,
        evidence_id=record.id,
        storage_ref=storage_ref,
        sha256=sha256,
        file_size=file_size,
        media_type="image/png",
        display_name="screenshot.png",
    )
    record.attachment = attachment
    try:
        ctx.session.add(attachment)
        ctx.session.flush()
        svc.audit(ctx, "evidence.attachment_created", "evidence", record.id)
        return record
    except Exception:
        # The caller owns the separately published media object. Remove the
        # text manifest created by create_evidence when this transaction fails.
        try:
            Storage(settings.storage_root / "evidence").discard(record.artifact_ref)
        except StorageError:
            pass
        raise


def get_evidence_content(settings, record):
    store = Storage(settings.storage_root / "evidence")
    try:
        with store.verified_copy(record.artifact_ref, record.sha256, record.file_size) as path:
            return path.read_text("utf-8")
    except (StorageError, UnicodeError, OSError) as exc:
        raise DomainError(
            503, "evidence_unavailable", "Evidence integrity could not be verified"
        ) from exc


def get_evidence_attachment(settings, record):
    attachment = record.attachment
    if attachment is None:
        raise not_found()
    store = Storage(settings.storage_root / "evidence-attachments")
    try:
        with store.verified_copy(
            attachment.storage_ref, attachment.sha256, attachment.file_size
        ) as path:
            return path.read_bytes()
    except (StorageError, OSError) as exc:
        raise DomainError(
            503, "evidence_unavailable", "Evidence integrity could not be verified"
        ) from exc


def create_finding(ctx, assessment_id, data):
    svc.require_writer(ctx)
    assessment = svc.assessment(ctx, assessment_id, lock=True)
    _editable(assessment)
    _active_project(ctx, assessment.project_id)
    records = _evidence_links(
        ctx, data.evidence_ids, assessment, artifact_id=assessment.artifact_id
    )
    changes = data.model_dump(exclude={"evidence_ids"})
    for value in changes.values():
        if isinstance(value, str):
            _require_sanitized(value)
    record = Finding(
        **changes,
        workspace_id=ctx.workspace_id,
        project_id=assessment.project_id,
        assessment_id=assessment.id,
        artifact_id=assessment.artifact_id,
        created_by=ctx.user.id,
        verification_status="unreviewed",
        remediation_status="open",
        evidence_provenance={
            "source": "manual",
            "contributors": [str(ctx.user.id)],
            "evidence_ids": [str(item.id) for item in records],
            "masvs_version": "2.1.0",
        },
    )
    ctx.session.add(record)
    ctx.session.flush()
    svc.audit(ctx, "finding.created", "finding", record.id)
    return record


def update_finding(ctx, finding_id, data):
    svc.require_writer(ctx)
    record = finding(ctx, finding_id, lock=True)
    assessment = svc.assessment(ctx, record.assessment_id, lock=True)
    _editable(assessment)
    svc.check_revision(record, data.revision)
    changes = data.model_dump(exclude_unset=True, exclude={"revision", "evidence_ids"})
    for value in changes.values():
        if isinstance(value, str):
            _require_sanitized(value)
    if data.evidence_ids is not None:
        records = _evidence_links(
            ctx, data.evidence_ids, assessment, artifact_id=record.artifact_id
        )
        record.evidence_provenance = {
            **record.evidence_provenance,
            "evidence_ids": [str(item.id) for item in records],
        }
    for name, value in changes.items():
        setattr(record, name, value)
    record.verification_status = "unreviewed"
    record.assigned_reviewer = None
    contributors = set(record.evidence_provenance.get("contributors", []))
    contributors.update({str(record.created_by), str(ctx.user.id)})
    if record.evidence_provenance.get("last_edited_by"):
        contributors.add(record.evidence_provenance["last_edited_by"])
    record.evidence_provenance = {
        **record.evidence_provenance,
        "last_edited_by": str(ctx.user.id),
        "contributors": sorted(contributors),
    }
    ctx.session.flush()
    svc.audit(ctx, "finding.updated", "finding", record.id)
    return record


def review_finding(ctx, finding_id, data, settings):
    svc.require_admin(ctx)
    record = finding(ctx, finding_id, lock=True)
    assessment = svc.assessment(ctx, record.assessment_id, lock=True)
    _editable(assessment)
    svc.check_revision(record, data.revision)
    authors = {record.created_by}
    authors.update(UUID(value) for value in record.evidence_provenance.get("contributors", []))
    if record.evidence_provenance.get("last_edited_by"):
        authors.add(UUID(record.evidence_provenance["last_edited_by"]))
    for value in record.evidence_provenance.get("evidence_ids", []):
        authors.add(evidence(ctx, UUID(value)).created_by)
    if ctx.user.id in authors:
        raise conflict("A different administrator must review this finding")
    _require_sanitized(data.notes)
    if data.decision == "confirmed":
        if any(
            len(getattr(record, name).strip()) < 10
            for name in ("description", "reproduction_steps", "impact", "remediation")
        ):
            raise conflict("Confirmation requires meaningful reproduction, impact and remediation")
        identifiers = [UUID(value) for value in record.evidence_provenance.get("evidence_ids", [])]
        if not identifiers:
            raise conflict("Confirmation requires linked sanitized analyst evidence")
        records = _evidence_links(ctx, identifiers, assessment, artifact_id=record.artifact_id)
        for item in records:
            get_evidence_content(settings, item)
        if assessment.assessment_type == "api" and record.artifact_id is None:
            release_refs = {item.release_ref for item in records}
            if None in release_refs or len(release_refs) != 1:
                raise conflict(
                    "API finding confirmation requires one exact original release reference on its evidence"
                )
            record.evidence_provenance = {
                **record.evidence_provenance,
                "original_release_ref": next(iter(release_refs)),
            }
        from droidshield.cvss_scoring import validate_cvss

        try:
            validate_cvss(record.cvss_vector, record.cvss_score)
        except ValueError as exc:
            raise conflict(
                "A valid calculated CVSS vector and score are required before confirmation"
            ) from exc
        if record.severity != "info" and not record.cvss_vector:
            raise conflict(
                "A calculated CVSS vector and score are required for a confirmed vulnerability"
            )
    record.verification_status = data.decision
    record.assigned_reviewer = ctx.user.id
    record.evidence_provenance = {
        **record.evidence_provenance,
        "review": {
            "reviewer_id": str(ctx.user.id),
            "decision": data.decision,
            "reviewed_at": datetime.now(UTC).isoformat(),
            "notes": data.notes,
        },
    }
    ctx.session.flush()
    svc.audit(ctx, "finding.reviewed", "finding", record.id)
    return record


def coverage(ctx, assessment_id):
    assessment = svc.assessment(ctx, assessment_id)
    records = ctx.session.scalars(
        select(TestExecution).where(
            TestExecution.assessment_id == assessment.id,
            TestExecution.workspace_id == ctx.workspace_id,
        )
    ).all()
    executions = {record.case_id: record for record in records}
    cases = []
    summary = {status: 0 for status in ("not_run", "pass", "fail", "na", "blocked")}
    for case in library()["cases"]:
        execution = executions.get(case["id"])
        status = execution.status if execution else "not_run"
        summary[status] += 1
        cases.append(
            {
                **(execution.case_snapshot if execution else case),
                "status": status,
                "execution": ds.ExecutionOut.model_validate(execution).model_dump(mode="json")
                if execution
                else None,
            }
        )
    return {
        "assessment_id": str(assessment.id),
        "frameworks": library()["frameworks"],
        "cases": cases,
        "summary": summary,
    }


def update_coverage(ctx, assessment_id, case_id, data):
    svc.require_writer(ctx)
    assessment = _locked_assessment(ctx, assessment_id)
    _editable(assessment)
    _permit(ctx, assessment)
    case = test_case(case_id)
    if case is None:
        raise not_found()
    if data.platform != svc.project(ctx, assessment.project_id).platform:
        raise conflict("Test platform must match the project")
    records = _evidence_links(
        ctx, data.evidence_ids, assessment, artifact_id=assessment.artifact_id
    )
    for identifier in data.finding_ids:
        issue = finding(ctx, identifier)
        if issue.assessment_id != assessment.id:
            raise not_found()
    for text in [data.notes, data.environment, data.tool, data.tool_version]:
        _require_sanitized(text)
    query = (
        select(TestExecution)
        .where(TestExecution.assessment_id == assessment.id, TestExecution.case_id == case_id)
        .with_for_update()
    )
    record = ctx.session.scalar(query)
    changes = data.model_dump(exclude={"revision", "evidence_ids", "finding_ids"})
    changes.update(
        evidence_ids=[str(item.id) for item in records],
        finding_ids=[str(value) for value in data.finding_ids],
    )
    if record:
        if data.revision is None:
            raise conflict("Existing test results require their current revision")
        svc.check_revision(record, data.revision)
        for name, value in changes.items():
            setattr(record, name, value)
        record.contributors = sorted(
            set(record.contributors) | {str(record.operator_id), str(ctx.user.id)}
        )
        record.operator_id = ctx.user.id
    else:
        if data.revision is not None:
            raise conflict("This test result does not yet exist; reload coverage")
        record = TestExecution(
            **changes,
            workspace_id=ctx.workspace_id,
            project_id=assessment.project_id,
            assessment_id=assessment.id,
            case_id=case_id,
            case_snapshot=case,
            operator_id=ctx.user.id,
            contributors=[str(ctx.user.id)],
        )
        ctx.session.add(record)
    ctx.session.flush()
    svc.audit(ctx, "test_execution.recorded", "test_execution", record.id)
    return record


def create_retest(ctx, finding_id, data):
    svc.require_writer(ctx)
    svc.authorization(ctx, data.authorization_id, lock=True)
    issue = finding(ctx, finding_id, lock=True)
    assessment = svc.assessment(ctx, issue.assessment_id, lock=True)
    if issue.verification_status != "confirmed" or assessment.status != "completed":
        raise conflict("Retesting requires a confirmed finding from a completed assessment")
    if ctx.session.scalar(
        select(Retest.id).where(Retest.finding_id == issue.id, Retest.review_decision.is_(None))
    ):
        raise conflict("Review the pending retest before recording another attempt")
    project, permit = _permit(ctx, assessment, data.authorization_id)
    if project.platform != data.platform:
        raise conflict("Retest platform must match the project")
    artifact = None
    if data.new_artifact_id is None:
        if (
            data.method != "api"
            or assessment.assessment_type != "api"
            or assessment.artifact_id is not None
        ):
            raise conflict("Only an API-only assessment can use release-reference retesting")
        original_release_ref = issue.evidence_provenance.get("original_release_ref")
        original_evidence = _evidence_links(
            ctx,
            [UUID(value) for value in issue.evidence_provenance.get("evidence_ids", [])],
            assessment,
            artifact_id=None,
        )
        if (
            not original_release_ref
            or original_release_ref != data.original_release_ref
            or not original_evidence
            or any(
                item.release_ref != original_release_ref
                or utc(item.created_at) > utc(assessment.completed_at)
                for item in original_evidence
            )
        ):
            raise conflict(
                "The original API release must match evidence pinned before the completed assessment"
            )
        records = _evidence_links(ctx, data.evidence_ids, assessment)
        if any(
            item.artifact_id is not None
            or item.release_ref != data.new_release_ref
            or utc(item.created_at) <= utc(assessment.completed_at)
            for item in records
        ):
            raise conflict(
                "API retest evidence must be captured for the exact new release after the original assessment"
            )
        for reference in [data.original_release_ref, data.new_release_ref]:
            _require_sanitized(reference)
    else:
        artifact = _artifact(ctx, data.new_artifact_id, issue.project_id)
        identity = _artifact_identity(project, artifact, data.platform)
        original = (
            _artifact(ctx, issue.artifact_id, issue.project_id) if issue.artifact_id else None
        )
        if original is None or artifact.sha256 == original.sha256:
            raise conflict("Retesting requires a different immutable application build")
        if identity not in permit.approved_targets or any(
            svc.is_excluded(identity, exclusion) for exclusion in permit.exclusions
        ):
            raise conflict("The retest build identity must be authorized")
        records = _evidence_links(ctx, data.evidence_ids, assessment, artifact_id=artifact.id)
    if any(
        not (utc(permit.valid_from) <= utc(item.created_at) < utc(permit.valid_until))
        for item in records
    ):
        raise conflict(
            "Retest evidence must have been captured inside the selected authorization window"
        )
    for text in [data.notes, data.environment, data.tool, data.tool_version]:
        _require_sanitized(text)
    record = Retest(
        workspace_id=ctx.workspace_id,
        project_id=issue.project_id,
        finding_id=issue.id,
        original_assessment_id=assessment.id,
        new_artifact_id=artifact.id if artifact else None,
        method=data.method,
        operator_id=ctx.user.id,
        environment={
            "platform": data.platform,
            "environment": data.environment,
            "tool": data.tool,
            "tool_version": data.tool_version,
            "authorization_id": str(permit.id),
            "authorization_revision": permit.revision,
            "artifact_sha256": artifact.sha256 if artifact else None,
            "original_release_ref": data.original_release_ref,
            "new_release_ref": data.new_release_ref,
        },
        previous_evidence=list(issue.evidence_provenance.get("evidence_ids", [])),
        new_evidence=[str(item.id) for item in records],
        result=data.result,
        notes=data.notes,
    )
    ctx.session.add(record)
    issue.remediation_status = "retest_required"
    ctx.session.flush()
    svc.audit(ctx, "retest.created", "retest", record.id)
    return record


def review_retest(ctx, retest_id, data, settings):
    svc.require_admin(ctx)
    record = retest(ctx, retest_id, lock=True)
    issue = finding(ctx, record.finding_id, lock=True)
    svc.check_revision(record, data.revision)
    svc.check_revision(issue, data.finding_revision)
    if record.review_decision is not None:
        raise conflict("This retest has already received a reviewer decision")
    authors = {record.operator_id}
    authors.update(evidence(ctx, UUID(value)).created_by for value in record.new_evidence)
    if ctx.user.id in authors:
        raise conflict("A different administrator must review the retest and its evidence")
    _require_sanitized(data.notes)
    if data.decision == "approve":
        assessment = svc.assessment(ctx, issue.assessment_id)
        records = _evidence_links(
            ctx,
            [UUID(value) for value in record.new_evidence],
            assessment,
            artifact_id=record.new_artifact_id,
        )
        for item in records:
            get_evidence_content(settings, item)
        if record.result == "pass":
            issue.remediation_status = "fixed"
        elif record.result == "fail":
            issue.remediation_status = "open"
        else:
            issue.remediation_status = "retest_required"
    record.review_decision = data.decision
    record.reviewer_id = ctx.user.id
    record.reviewed_at = datetime.now(UTC)
    record.environment = {**record.environment, "review_notes": data.notes}
    ctx.session.flush()
    svc.audit(ctx, "retest.reviewed", "retest", record.id)
    return record
