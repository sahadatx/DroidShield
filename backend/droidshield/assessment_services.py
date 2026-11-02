"""Authorization and Assessment lifecycle rules for the request/worker unit of work."""

from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import select

from droidshield.auth import utc
from droidshield.errors import conflict, not_found
from droidshield.models import AnalysisJob, AppArtifact, Assessment, Authorization
from droidshield.service_context import (
    Context,
    assessment,
    audit,
    authorization,
    check_revision,
    client,
    project,
    require_admin,
    require_writer,
)


def create_authorization(ctx: Context, resource_id: UUID, data: BaseModel) -> Authorization:
    require_writer(ctx)
    parent = project(ctx, resource_id, lock=True)
    if parent.status != "active" or client(ctx, parent.client_id).status != "active":
        raise conflict("Authorization requires an active project and client")
    record = Authorization(
        **data.model_dump(),
        workspace_id=ctx.workspace_id,
        project_id=parent.id,
        created_by=ctx.user.id,
        status="pending",
    )
    ctx.session.add(record)
    ctx.session.flush()
    audit(ctx, "authorization.created", "authorization", record.id)
    return record


def verify_authorization(ctx: Context, resource_id: UUID, revision: int) -> Authorization:
    require_admin(ctx)
    record = authorization(ctx, resource_id, lock=True)
    check_revision(record, revision)
    if record.status != "pending":
        raise conflict("Only pending authorizations can be verified")
    if utc(record.valid_until) <= datetime.now(UTC):
        raise conflict("Expired authorization cannot be verified")
    record.status = "verified"
    record.verified_by = ctx.user.id
    record.verified_at = datetime.now(UTC)
    ctx.session.flush()
    audit(ctx, "authorization.verified", "authorization", record.id)
    return record


def revoke_authorization(
    ctx: Context, resource_id: UUID, revision: int, reason: str
) -> Authorization:
    require_admin(ctx)
    record = authorization(ctx, resource_id, lock=True)
    check_revision(record, revision)
    if record.status == "revoked":
        raise conflict("Authorization was already revoked")
    record.status = "revoked"
    record.revoked_at = datetime.now(UTC)
    record.revocation_reason = reason
    # Persist cancellation atomically. The isolated worker monitors this state
    # and kills its subprocess before publishing any results.
    queued = ctx.session.scalars(
        select(Assessment)
        .where(
            Assessment.authorization_id == record.id,
            Assessment.status.in_(["queued", "running"]),
        )
        .with_for_update()
    ).all()
    for item in queued:
        _cancel(ctx, item, "Authorization revoked")
    ctx.session.flush()
    audit(ctx, "authorization.revoked", "authorization", record.id)
    return record


def create_assessment(ctx: Context, data: BaseModel) -> Assessment:
    require_writer(ctx)
    parent = project(ctx, data.project_id, lock=True)
    if parent.status != "active" or client(ctx, parent.client_id).status != "active":
        raise conflict("Assessments require an active project and client")
    if data.artifact_id:
        artifact = ctx.session.scalar(
            select(AppArtifact).where(
                AppArtifact.id == data.artifact_id,
                AppArtifact.project_id == parent.id,
                AppArtifact.workspace_id == ctx.workspace_id,
            )
        )
        if artifact is None:
            raise not_found()
    if data.authorization_id:
        permit = authorization(ctx, data.authorization_id)
        if permit.project_id != parent.id:
            raise not_found()
    record = Assessment(
        workspace_id=ctx.workspace_id,
        project_id=parent.id,
        artifact_id=data.artifact_id,
        authorization_id=data.authorization_id,
        name=data.name,
        assessment_type=data.assessment_type,
        status="draft",
        configuration_snapshot={"requested_targets": data.requested_targets, "engine": data.engine},
        tool_versions={},
        created_by=ctx.user.id,
    )
    ctx.session.add(record)
    ctx.session.flush()
    audit(ctx, "assessment.created", "assessment", record.id)
    return record


def update_assessment(ctx: Context, resource_id: UUID, data: BaseModel) -> Assessment:
    require_writer(ctx)
    record = assessment(ctx, resource_id, lock=True)
    check_revision(record, data.revision)
    if record.status not in {"draft", "awaiting_authorization"}:
        raise conflict("Only draft or awaiting-authorization assessments can be edited")
    changes = data.model_dump(exclude_unset=True, exclude={"revision"})
    if changes.get("authorization_id"):
        permit = authorization(ctx, changes["authorization_id"])
        if permit.project_id != record.project_id:
            raise not_found()
    if changes.get("artifact_id"):
        artifact = ctx.session.scalar(
            select(AppArtifact).where(
                AppArtifact.id == changes["artifact_id"],
                AppArtifact.project_id == record.project_id,
                AppArtifact.workspace_id == ctx.workspace_id,
            )
        )
        if artifact is None:
            raise not_found()
    targets = changes.pop("requested_targets", None)
    engine = changes.pop("engine", None)
    if engine is not None:
        if record.assessment_type != "static" and engine != "manifest":
            raise conflict("Engine selection applies to Static assessments")
        record.configuration_snapshot = {**record.configuration_snapshot, "engine": engine}
    if targets is not None:
        record.configuration_snapshot = {
            **record.configuration_snapshot,
            "requested_targets": targets,
        }
    for field, value in changes.items():
        setattr(record, field, value)
    ctx.session.flush()
    audit(ctx, "assessment.updated", "assessment", record.id)
    return record


def submit_assessment(ctx: Context, resource_id: UUID, revision: int) -> Assessment:
    require_writer(ctx)
    record = assessment(ctx, resource_id, lock=True)
    check_revision(record, revision)
    if record.status != "draft":
        raise conflict("Only draft assessments can be submitted")
    record.status = "awaiting_authorization"
    ctx.session.flush()
    audit(ctx, "assessment.submitted", "assessment", record.id)
    return record


def is_excluded(target: str, exclusion: str) -> bool:
    if target.startswith("package:") or exclusion.startswith("package:"):
        return target == exclusion
    target_url, exclusion_url = urlsplit(target), urlsplit(exclusion)
    if target_url.netloc != exclusion_url.netloc:
        return False
    parent_path = exclusion_url.path.rstrip("/")
    path = target_url.path.rstrip("/")
    return path == parent_path or path.startswith(parent_path + "/")


def queue_assessment(ctx: Context, resource_id: UUID, revision: int) -> Assessment:
    require_writer(ctx)
    # Lock authorization before assessment, matching revocation lock order.
    current = assessment(ctx, resource_id)
    if current.authorization_id is None:
        raise conflict("Verified authorization is required before queuing")
    permit = authorization(ctx, current.authorization_id, lock=True)
    record = assessment(ctx, resource_id, lock=True)
    check_revision(record, revision)
    if record.status not in {"draft", "awaiting_authorization"}:
        raise conflict("Only draft or awaiting-authorization assessments can be queued")
    parent = project(ctx, record.project_id, lock=True)
    if parent.status != "active" or client(ctx, parent.client_id).status != "active":
        raise conflict("Testing requires an active project and client")
    now = datetime.now(UTC)
    if (
        permit.project_id != parent.id
        or permit.status != "verified"
        or not (utc(permit.valid_from) <= now < utc(permit.valid_until))
    ):
        raise conflict("Authorization is unverified, revoked or outside its testing window")
    targets = record.configuration_snapshot.get("requested_targets", [])
    if not targets or any(target not in permit.approved_targets for target in targets):
        raise conflict("Every requested target must be explicitly approved")
    if any(is_excluded(target, excluded) for target in targets for excluded in permit.exclusions):
        raise conflict("Requested targets include an excluded target")
    artifact = None
    if record.assessment_type != "api":
        artifact = ctx.session.scalar(
            select(AppArtifact).where(
                AppArtifact.id == record.artifact_id,
                AppArtifact.project_id == parent.id,
                AppArtifact.workspace_id == ctx.workspace_id,
            )
        )
        if artifact is None:
            raise conflict("A server-processed APK artifact is required")
        if (
            parent.platform != "android"
            or artifact.metadata_json.get("artifact_format", "apk") != "apk"
        ):
            raise conflict(
                "Automated execution requires an Android APK; use the manual engagement workflow for IPA or AAB"
            )
        package = artifact.metadata_json.get("package_name")
        if package != parent.package_id or f"package:{package}" not in targets:
            raise conflict("Artifact package identity must match the project and approved targets")
    elif any(target.startswith(("package:", "bundle:")) for target in targets):
        raise conflict("API assessments require HTTPS API targets")
    if record.assessment_type == "static" and any(
        not target.startswith("package:") for target in targets
    ):
        raise conflict("Static analysis accepts only the artifact package target")
    if record.assessment_type == "static" and targets != [f"package:{parent.package_id}"]:
        raise conflict("Static analysis scope must contain exactly the artifact package target")
    snapshot = {
        "requested_targets": targets,
        "authorization_id": str(permit.id),
        "authorization_revision": permit.revision,
        "approved_targets": list(permit.approved_targets),
        "exclusions": list(permit.exclusions),
        "valid_from": utc(permit.valid_from).isoformat(),
        "valid_until": utc(permit.valid_until).isoformat(),
        "artifact_sha256": artifact.sha256 if artifact else None,
        "engine": record.configuration_snapshot.get("engine", "manifest"),
    }
    if "upload" in record.configuration_snapshot:
        snapshot["upload"] = record.configuration_snapshot["upload"]
    record.configuration_snapshot = snapshot
    record.status = "queued"
    ctx.session.add(
        AnalysisJob(
            workspace_id=ctx.workspace_id,
            assessment_id=record.id,
            artifact_id=record.artifact_id,
            status="queued",
            configuration_snapshot=snapshot,
            tool_versions={},
        )
    )
    ctx.session.flush()
    audit(ctx, "assessment.queued", "assessment", record.id)
    return record


def _cancel(ctx: Context, record: Assessment, reason: str) -> None:
    record.status = "cancelled"
    record.cancelled_at = datetime.now(UTC)
    record.cancellation_reason = reason
    job = ctx.session.scalar(
        select(AnalysisJob).where(AnalysisJob.assessment_id == record.id).with_for_update()
    )
    if job and job.status in {"queued", "running"}:
        job.status = "cancelled"
        job.cancellation_reason = reason
        job.completed_at = datetime.now(UTC)
        job.lease_expires_at = None
    audit(ctx, "assessment.cancelled", "assessment", record.id)


def cancel_assessment(ctx: Context, resource_id: UUID, revision: int, reason: str) -> Assessment:
    require_writer(ctx)
    record = assessment(ctx, resource_id, lock=True)
    check_revision(record, revision)
    if record.status not in {"draft", "awaiting_authorization", "queued", "running"}:
        raise conflict("Only draft, queued or running assessments can be cancelled")
    _cancel(ctx, record, reason)
    ctx.session.flush()
    return record
