"""Client and project directory routes."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import or_, select

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import Ctx, Idem, Limit, Offset, client_view, page
from droidshield.models import AppArtifact, Assessment, Client, Project

router = APIRouter()


@router.get("/directory-metrics", response_model=s.DirectoryMetricsOut, tags=["Workspace"])
def directory_metrics(
    ctx: Ctx,
    client_ids: Annotated[list[UUID], Query(default_factory=list, max_length=25)],
    project_ids: Annotated[list[UUID], Query(default_factory=list, max_length=25)],
):
    """Return page-sized directory counts without exposing inaccessible relationships."""
    requested_clients = []
    if client_ids:
        requested_clients = ctx.session.scalars(
            svc.client_query(ctx).where(Client.id.in_(set(client_ids)))
        ).all()
    requested_client_ids = {record.id for record in requested_clients}

    visible = svc.visible_projects(ctx)
    project_filter = []
    if requested_client_ids:
        project_filter.append(Project.client_id.in_(requested_client_ids))
    if project_ids:
        project_filter.append(Project.id.in_(set(project_ids)))
    related_projects = []
    if project_filter:
        related_projects = ctx.session.scalars(
            select(Project).where(Project.id.in_(visible), or_(*project_filter))
        ).all()

    project_records = {record.id: record for record in related_projects}
    related_project_ids = set(project_records)
    assessment_updates: dict[UUID, list] = {}
    if related_project_ids:
        rows = ctx.session.execute(
            select(Assessment.project_id, Assessment.updated_at)
            .where(
                Assessment.workspace_id == ctx.workspace_id,
                Assessment.project_id.in_(related_project_ids),
            )
            .order_by(Assessment.updated_at.desc())
        )
        for project_id, updated_at in rows:
            assessment_updates.setdefault(project_id, []).append(updated_at)

    latest_versions: dict[UUID, str] = {}
    if related_project_ids:
        rows = ctx.session.execute(
            select(
                AppArtifact.project_id,
                AppArtifact.version_name,
                AppArtifact.version_code,
            )
            .where(
                AppArtifact.workspace_id == ctx.workspace_id,
                AppArtifact.project_id.in_(related_project_ids),
            )
            .order_by(AppArtifact.created_at.desc(), AppArtifact.id.desc())
        )
        for project_id, version_name, version_code in rows:
            latest_versions.setdefault(
                project_id,
                version_name or (str(version_code) if version_code is not None else "Build"),
            )

    client_metrics = []
    for record in requested_clients:
        projects = [p for p in related_projects if p.client_id == record.id]
        activities = [record.updated_at]
        activities.extend(p.updated_at for p in projects)
        activities.extend(
            timestamp
            for project in projects
            for timestamp in assessment_updates.get(project.id, [])
        )
        client_metrics.append(
            {
                "client_id": record.id,
                "active_projects": sum(p.status == "active" for p in projects),
                "assessment_count": sum(
                    len(assessment_updates.get(project.id, [])) for project in projects
                ),
                "last_activity": max(activities),
            }
        )

    project_metrics = []
    for project_id in set(project_ids) & related_project_ids:
        timestamps = assessment_updates.get(project_id, [])
        project_metrics.append(
            {
                "project_id": project_id,
                "assessment_count": len(timestamps),
                "latest_version": latest_versions.get(project_id),
                "last_assessment_at": max(timestamps) if timestamps else None,
            }
        )
    return {"clients": client_metrics, "projects": project_metrics}


@router.get("/clients", response_model=s.Page[s.ClientOut], tags=["Clients"])
def clients(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: Literal["active", "archived"] | None = None,
    client_type: Literal["company", "individual"] | None = None,
):
    query = svc.client_query(ctx)
    if status:
        query = query.where(svc.Client.status == status)
    if client_type:
        query = query.where(svc.Client.client_type == client_type)
    if q:
        query = query.where(
            or_(
                svc.Client.name.icontains(q, autoescape=True),
                svc.Client.organization_name.icontains(q, autoescape=True),
                svc.Client.contact_person.icontains(q, autoescape=True),
                svc.Client.contact_email.icontains(q, autoescape=True),
            )
        )
    return page(
        ctx, query.order_by(svc.Client.created_at.desc(), svc.Client.id), s.ClientOut, limit, offset
    )


@router.post("/clients", response_model=s.ClientOut, status_code=201, tags=["Clients"])
def create_client(ctx: Ctx, data: s.ClientCreate, key: Idem):
    svc.require_writer(ctx)
    return client_view(
        ctx,
        svc.once(
            ctx,
            key,
            "client.create",
            data,
            lambda rid: svc.client(ctx, rid),
            lambda: svc.create_client(ctx, data),
        ),
    )


@router.get("/clients/{client_id}", response_model=s.ClientOut, tags=["Clients"])
def client_detail(client_id: UUID, ctx: Ctx):
    return client_view(ctx, svc.client(ctx, client_id))


@router.patch("/clients/{client_id}", response_model=s.ClientOut, tags=["Clients"])
def update_client(client_id: UUID, ctx: Ctx, data: s.ClientUpdate):
    return client_view(ctx, svc.update_client(ctx, client_id, data))


@router.post("/clients/{client_id}/archive", response_model=s.ClientOut, tags=["Clients"])
def archive_client(client_id: UUID, ctx: Ctx, data: s.ArchiveRequest, key: Idem):
    svc.require_writer(ctx)
    return client_view(
        ctx,
        svc.once(
            ctx,
            key,
            f"client.archive:{client_id}",
            data,
            lambda rid: svc.client(ctx, rid),
            lambda: svc.update_client(
                ctx,
                client_id,
                s.ClientUpdate(
                    revision=data.revision, status="archived", archive_reason=data.reason
                ),
            ),
        ),
    )


@router.get("/projects", response_model=s.Page[s.ProjectOut], tags=["Projects"])
def projects(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: Literal["active", "on_hold", "archived"] | None = None,
    client_id: UUID | None = None,
    platform: Literal["android", "ios"] | None = None,
    framework: Literal["native", "flutter", "react_native", "other", "unknown"] | None = None,
):
    query = select(Project).where(Project.id.in_(svc.visible_projects(ctx)))
    if status:
        query = query.where(Project.status == status)
    if client_id:
        query = query.where(Project.client_id == client_id)
    if platform:
        query = query.where(Project.platform == platform)
    if framework:
        query = query.where(Project.framework == framework)
    if q:
        query = query.where(
            or_(
                Project.name.icontains(q, autoescape=True),
                Project.application_name.icontains(q, autoescape=True),
                Project.package_id.icontains(q, autoescape=True),
            )
        )
    return page(
        ctx, query.order_by(Project.created_at.desc(), Project.id), s.ProjectOut, limit, offset
    )


@router.post("/projects", response_model=s.ProjectOut, status_code=201, tags=["Projects"])
def create_project(ctx: Ctx, data: s.ProjectCreate, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        "project.create",
        data,
        lambda rid: svc.project(ctx, rid),
        lambda: svc.create_project(ctx, data),
    )


@router.get("/projects/{project_id}", response_model=s.ProjectOut, tags=["Projects"])
def project_detail(project_id: UUID, ctx: Ctx):
    return svc.project(ctx, project_id)


@router.patch("/projects/{project_id}", response_model=s.ProjectOut, tags=["Projects"])
def update_project(project_id: UUID, ctx: Ctx, data: s.ProjectUpdate):
    return svc.update_project(ctx, project_id, data)


@router.post("/projects/{project_id}/archive", response_model=s.ProjectOut, tags=["Projects"])
def archive_project(project_id: UUID, ctx: Ctx, data: s.ArchiveRequest, key: Idem):
    svc.require_writer(ctx)
    return svc.once(
        ctx,
        key,
        f"project.archive:{project_id}",
        data,
        lambda rid: svc.project(ctx, rid),
        lambda: svc.update_project(
            ctx,
            project_id,
            s.ProjectUpdate(revision=data.revision, status="archived", archive_reason=data.reason),
        ),
    )


@router.post("/projects/{project_id}/members", tags=["Projects"])
def grant_project(project_id: UUID, ctx: Ctx, data: s.ProjectMemberAdd, key: Idem):
    svc.require_admin(ctx)
    # A repeated grant is naturally idempotent; reserve the request key as well.
    record = svc.once(
        ctx,
        key,
        f"project.member:{project_id}",
        data,
        lambda _rid: svc.project(ctx, project_id),
        lambda: _grant_and_return_project(ctx, project_id, data.user_id),
    )
    return {"project_id": record.id, "user_id": data.user_id}


def _grant_and_return_project(ctx: svc.Context, project_id: UUID, user_id: UUID):
    svc.grant_project(ctx, project_id, user_id)
    return svc.project(ctx, project_id)
