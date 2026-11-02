"""Client and Project business rules; mutations flush into the caller-owned unit of work."""

from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import func, select

from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import AppArtifact, Assessment, Client, Project, ProjectAccess, User
from droidshield.service_context import (
    Context,
    audit,
    check_revision,
    client,
    project,
    require_admin,
    require_writer,
)


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
