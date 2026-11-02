"""Transactional business rules. Routes never accept role or workspace from a form."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TypeVar
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from droidshield.auth import utc
from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    Assessment,
    AuditEvent,
    Authorization,
    Client,
    IdempotencyRecord,
    Project,
    ProjectAccess,
    User,
)

T = TypeVar("T")


@dataclass
class Context:
    session: Session
    user: User
    request_id: str

    @property
    def workspace_id(self) -> UUID:
        return self.user.workspace_id


def require_writer(ctx: Context) -> None:
    if ctx.user.role not in {"ADMIN", "SECURITY_ANALYST"}:
        raise DomainError(403, "forbidden", "Your role cannot modify assessment data")


def require_admin(ctx: Context) -> None:
    if ctx.user.role != "ADMIN":
        raise DomainError(403, "forbidden", "Administrator access is required")


def audit(ctx: Context, action: str, resource_type: str, resource_id: UUID) -> None:
    # Do not persist request bodies, URLs, headers, evidence, notes, or credentials.
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.workspace_id,
            actor_id=ctx.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={"channel": "api"},
        )
    )


def visible_projects(ctx: Context):
    query = select(Project.id).where(Project.workspace_id == ctx.workspace_id)
    if ctx.user.role != "ADMIN":
        query = query.where(
            or_(
                Project.created_by == ctx.user.id,
                exists().where(
                    ProjectAccess.project_id == Project.id,
                    ProjectAccess.workspace_id == ctx.workspace_id,
                    ProjectAccess.user_id == ctx.user.id,
                ),
            )
        )
    return query


def client_query(ctx: Context):
    query = select(Client).where(Client.workspace_id == ctx.workspace_id)
    if ctx.user.role != "ADMIN":
        query = query.where(
            or_(
                Client.created_by == ctx.user.id,
                Client.id.in_(
                    select(Project.client_id).where(Project.id.in_(visible_projects(ctx)))
                ),
            )
        )
    return query


def client(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Client:
    query = client_query(ctx).where(Client.id == resource_id)
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def project(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Project:
    query = select(Project).where(Project.id == resource_id, Project.id.in_(visible_projects(ctx)))
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def assessment(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Assessment:
    query = select(Assessment).where(
        Assessment.id == resource_id,
        Assessment.workspace_id == ctx.workspace_id,
        Assessment.project_id.in_(visible_projects(ctx)),
    )
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def authorization(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Authorization:
    query = select(Authorization).where(
        Authorization.id == resource_id,
        Authorization.workspace_id == ctx.workspace_id,
        Authorization.project_id.in_(visible_projects(ctx)),
    )
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def check_revision(record: Any, expected: int) -> None:
    if record.revision != expected:
        raise conflict("The record changed. Reload it before saving")


def paginate(ctx: Context, query, limit: int, offset: int) -> tuple[list[Any], int]:
    total = ctx.session.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = ctx.session.scalars(query.limit(limit).offset(offset)).all()
    return list(items), total


def once(
    ctx: Context,
    key: str,
    operation: str,
    payload: BaseModel,
    lookup: Callable[[UUID], T],
    create: Callable[[], T],
) -> T:
    request_hash = hashlib.sha256(
        json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    previous = ctx.session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.workspace_id == ctx.workspace_id,
            IdempotencyRecord.user_id == ctx.user.id,
            IdempotencyRecord.key == key,
        )
    )
    if previous:
        if previous.operation != operation or previous.request_hash != request_hash:
            raise conflict("Idempotency key was already used for a different request")
        return lookup(previous.response_resource_id)
    result = create()
    ctx.session.flush()
    ctx.session.add(
        IdempotencyRecord(
            workspace_id=ctx.workspace_id,
            user_id=ctx.user.id,
            key=key,
            operation=operation,
            request_hash=request_hash,
            response_resource_id=result.id,
        )
    )
    ctx.session.flush()
    return result


def create_client(ctx: Context, data: BaseModel) -> Client:
    require_writer(ctx)
    record = Client(
        **data.model_dump(mode="json"), workspace_id=ctx.workspace_id, created_by=ctx.user.id
    )
    ctx.session.add(record)
    ctx.session.flush()
    audit(ctx, "client.created", "client", record.id)
    return record


def update_client(ctx: Context, resource_id: UUID, data: BaseModel) -> Client:
    require_writer(ctx)
    record = client(ctx, resource_id, lock=True)
    # Project access permits reading its contact. Editing the shared client is
    # restricted to its owner/admin so one project grant cannot alter other engagements.
    if ctx.user.role != "ADMIN" and record.created_by != ctx.user.id:
        raise DomainError(403, "forbidden", "Only the client creator or administrator can edit it")
    check_revision(record, data.revision)
    changes = data.model_dump(mode="json", exclude_unset=True, exclude={"revision"})
    status = changes.get("status", record.status)
    reason = changes.get("archive_reason", record.archive_reason)
    if status == "archived" and not reason:
        raise DomainError(
            422,
            "validation_error",
            "Archive reason is required",
            [{"location": ["body", "archive_reason"], "type": "value_error"}],
        )
    if status == "archived" and record.status != "archived":
        active = ctx.session.scalar(
            select(func.count())
            .select_from(Project)
            .where(
                Project.client_id == record.id,
                Project.workspace_id == ctx.workspace_id,
                Project.status != "archived",
            )
        )
        if active:
            raise conflict("Archive this client's active projects first")
    for field, value in changes.items():
        setattr(record, field, value)
    if status == "active":
        record.archive_reason = None
    ctx.session.flush()
    audit(ctx, "client.updated", "client", record.id)
    return record


def create_project(ctx: Context, data: BaseModel) -> Project:
    require_writer(ctx)
    owner = client(ctx, data.client_id, lock=True)
    if owner.status != "active":
        raise conflict("New projects require an active client")
    # A grant to an existing project doesn't grant creation rights under its client.
    if ctx.user.role != "ADMIN" and owner.created_by != ctx.user.id:
        raise DomainError(403, "forbidden", "Client owner or administrator access is required")
    record = Project(**data.model_dump(), workspace_id=ctx.workspace_id, created_by=ctx.user.id)
    ctx.session.add(record)
    ctx.session.flush()
    audit(ctx, "project.created", "project", record.id)
    return record


def update_project(ctx: Context, resource_id: UUID, data: BaseModel) -> Project:
    require_writer(ctx)
    record = project(ctx, resource_id, lock=True)
    check_revision(record, data.revision)
    changes = data.model_dump(mode="json", exclude_unset=True, exclude={"revision"})
    from droidshield.schemas import validate_app_identity

    try:
        validate_app_identity(
            changes.get("package_id", record.package_id), changes.get("platform", record.platform)
        )
    except ValueError as exc:
        raise DomainError(
            422, "validation_error", "App identity does not match the project platform"
        ) from exc
    if changes.get("status", record.status) == "archived" and not changes.get(
        "archive_reason", record.archive_reason
    ):
        raise DomainError(
            422,
            "validation_error",
            "Archive reason is required",
            [{"location": ["body", "archive_reason"], "type": "value_error"}],
        )
    if changes.get("status") in {"archived", "on_hold"}:
        active = ctx.session.scalar(
            select(func.count())
            .select_from(Assessment)
            .where(
                Assessment.project_id == record.id,
                Assessment.status.in_(["queued", "running"]),
            )
        )
        if active:
            raise conflict("Cancel active assessment jobs before pausing or archiving this project")
    if (
        changes.get("package_id", record.package_id) != record.package_id
        or changes.get("platform", record.platform) != record.platform
    ):
        used = ctx.session.scalar(
            select(func.count())
            .select_from(Assessment)
            .where(
                Assessment.project_id == record.id,
            )
        ) or ctx.session.scalar(
            select(func.count())
            .select_from(AppArtifact)
            .where(
                AppArtifact.project_id == record.id,
            )
        )
        if used:
            raise conflict("Package identity cannot change after artifacts or assessments exist")
    if changes.get("status") == "active" and client(ctx, record.client_id).status != "active":
        raise conflict("Reactivate the parent client first")
    for field, value in changes.items():
        setattr(record, field, value)
    if record.status != "archived":
        record.archive_reason = None
    ctx.session.flush()
    audit(ctx, "project.updated", "project", record.id)
    return record


def grant_project(ctx: Context, resource_id: UUID, user_id: UUID) -> ProjectAccess:
    require_admin(ctx)
    record = project(ctx, resource_id, lock=True)
    member = ctx.session.scalar(
        select(User).where(User.id == user_id, User.workspace_id == ctx.workspace_id)
    )
    if member is None:
        raise not_found()
    existing = ctx.session.scalar(
        select(ProjectAccess).where(
            ProjectAccess.project_id == record.id,
            ProjectAccess.user_id == member.id,
        )
    )
    if existing:
        return existing
    access = ProjectAccess(
        workspace_id=ctx.workspace_id,
        project_id=record.id,
        user_id=member.id,
        created_by=ctx.user.id,
    )
    ctx.session.add(access)
    ctx.session.flush()
    audit(ctx, "project.access_granted", "project", record.id)
    return access


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
