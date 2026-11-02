import secrets
from datetime import UTC, date, datetime, time
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from droidshield import schemas as s
from droidshield import services as svc
from droidshield import uploads
from droidshield.auth import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    authenticate,
    authenticate_password,
    issue_token,
    token_hash,
    utc,
)
from droidshield.db import get_session
from droidshield.errors import DomainError, not_found
from droidshield.models import (
    AccessToken,
    AnalysisJob,
    AnalysisResult,
    APIExecution,
    APITarget,
    AppArtifact,
    Assessment,
    AuditEvent,
    Authorization,
    Client,
    DynamicSession,
    Finding,
    Project,
    Report,
    Retest,
    Workspace,
)
from droidshield.storage import Storage, StorageError

router = APIRouter(prefix="/api/v1")
bearer = HTTPBearer(auto_error=False)


def db_session(request: Request):
    yield from get_session(request)


DB = Annotated[Session, Depends(db_session, scope="function")]


def user_view(session: Session, user) -> dict:
    """Return the authenticated identity with its workspace display label."""
    workspace = session.get(Workspace, user.workspace_id)
    return {
        **s.MeOut.model_validate(user).model_dump(),
        "workspace_name": workspace.name if workspace else None,
    }


def context(
    request: Request,
    session: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> svc.Context:
    if credentials is not None and credentials.scheme.lower() == "bearer":
        user = authenticate(session, credentials.credentials)
    else:
        session_cookie = request.cookies.get(SESSION_COOKIE)
        if not session_cookie:
            raise DomainError(401, "unauthenticated", "Valid authentication is required")
        user = authenticate(session, session_cookie)
        request.state.auth_method = "cookie"
        request.state.session_cookie = session_cookie
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    if getattr(request.state, "auth_method", None) == "cookie" and request.method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        origin = request.headers.get("Origin")
        fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if (
            not csrf_cookie
            or not csrf_header
            or not secrets.compare_digest(csrf_cookie, csrf_header)
            or fetch_site == "cross-site"
            or (origin and not _same_host_origin(origin, request.url.netloc))
        ):
            raise DomainError(403, "csrf_failed", "Request origin could not be verified")
    return svc.Context(session, user, request.state.request_id)


def _same_host_origin(origin: str, request_netloc: str) -> bool:
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.netloc.lower() == request_netloc.lower()
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _set_auth_cookies(request: Request, response: Response, session_id: str, csrf: str) -> None:
    settings = request.app.state.settings
    max_age = settings.token_ttl_hours * 60 * 60
    secure = settings.environment == "production"
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


@router.post("/auth/login", response_model=s.AuthSessionOut, tags=["Identity"])
def login(data: s.PasswordLogin, request: Request, response: Response, session: DB):
    origin = request.headers.get("Origin")
    if request.headers.get("Sec-Fetch-Site") == "cross-site" or (
        origin and not _same_host_origin(origin, request.url.netloc)
    ):
        raise DomainError(403, "csrf_failed", "Request origin could not be verified")
    client_host = request.client.host if request.client else "unknown"
    if not request.app.state.login_limiter.allow(client_host):
        raise DomainError(429, "login_rate_limited", "Too many sign-in attempts. Try again shortly")
    user = authenticate_password(session, str(data.email), data.password.get_secret_value())
    session_id = issue_token(session, user.id, request.app.state.settings.token_ttl_hours)
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(request, response, session_id, csrf)
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    session.add(
        AuditEvent(
            workspace_id=user.workspace_id,
            actor_id=user.id,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            result="success",
            request_id=request.state.request_id,
            source_metadata={"method": "password"},
        )
    )
    return {"user": user_view(session, user), "csrf_token": csrf}


@router.get("/auth/session", response_model=s.AuthSessionOut, tags=["Identity"])
def auth_session(request: Request, response: Response, session: DB):
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = authenticate(session, session_id)
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(request, response, session_id, csrf)
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    return {"user": user_view(session, user), "csrf_token": csrf}


@router.post("/auth/logout", tags=["Identity"])
def logout(request: Request, response: Response, ctx: svc.Context = Depends(context)):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        credential = ctx.session.scalar(
            select(AccessToken).where(
                AccessToken.user_id == ctx.user.id,
                AccessToken.token_hash == token_hash(session_id),
                AccessToken.revoked_at.is_(None),
            )
        )
        if credential is not None:
            credential.revoked_at = datetime.now(UTC)
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.user.workspace_id,
            actor_id=ctx.user.id,
            action="auth.logout",
            resource_type="user",
            resource_id=ctx.user.id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={"method": "password_session"},
        )
    )
    secure = request.app.state.settings.environment == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite="strict")
    return {"status": "signed_out"}


Ctx = Annotated[svc.Context, Depends(context)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]
Idem = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
]


def page(ctx: svc.Context, query, output: type[BaseModel], limit: int, offset: int) -> dict:
    items, total = svc.paginate(ctx, query, limit, offset)
    return {
        "items": [
            client_view(ctx, item) if output is s.ClientOut else output.model_validate(item)
            for item in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def client_view(ctx: svc.Context, record: svc.Client) -> s.ClientOut:
    response = s.ClientOut.model_validate(record)
    if ctx.user.role != "ADMIN" and record.created_by != ctx.user.id:
        # A project grant permits necessary contact lookup, not private notes
        # about the parent's other engagements.
        response = response.model_copy(update={"notes": None, "archive_reason": None})
    return response


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


@router.get("/me", response_model=s.MeOut, tags=["Identity"])
def me(ctx: Ctx):
    return user_view(ctx.session, ctx.user)


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
    assessment_id: UUID | None = None,
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    verification_status: Literal["unreviewed", "confirmed", "false_positive", "needs_more_evidence"]
    | None = None,
    remediation_status: Literal["open", "in_progress", "fixed", "accepted_risk", "retest_required"]
    | None = None,
):
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


@router.get(
    "/projects/{project_id}/versions", response_model=s.Page[s.ArtifactOut], tags=["Artifacts"]
)
def versions(
    project_id: UUID,
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    build_type: Literal["debug", "release", "unknown"] | None = None,
    artifact_format: Literal["apk", "aab", "ipa"] | None = None,
):
    svc.project(ctx, project_id)
    query = select(AppArtifact).where(
        AppArtifact.project_id == project_id, AppArtifact.workspace_id == ctx.workspace_id
    )
    if q:
        query = query.where(
            or_(
                AppArtifact.original_filename.icontains(q, autoescape=True),
                AppArtifact.version_name.icontains(q, autoescape=True),
            )
        )
    if build_type:
        query = query.where(AppArtifact.build_type == build_type)
    if artifact_format:
        query = query.where(
            func.coalesce(AppArtifact.metadata_json["artifact_format"].as_string(), "apk")
            == artifact_format
        )
    return page(
        ctx,
        query.order_by(AppArtifact.created_at.desc(), AppArtifact.id),
        s.ArtifactOut,
        limit,
        offset,
    )


@router.post(
    "/assessments/{assessment_id}/apk",
    response_model=s.ArtifactOut,
    status_code=201,
    tags=["Artifacts"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["file", "revision"],
                        "properties": {
                            "file": {"type": "string", "format": "binary"},
                            "revision": {"type": "integer", "minimum": 1},
                            "app_version": {"type": "string", "maxLength": 255},
                            "build_type": {
                                "type": "string",
                                "enum": ["debug", "release", "unknown"],
                                "default": "unknown",
                            },
                            "upload_notes": {"type": "string", "maxLength": 20000},
                        },
                    }
                }
            },
        }
    },
)
async def upload_apk(assessment_id: UUID, request: Request, ctx: Ctx, key: Idem):
    limiter = request.app.state.upload_limiter
    try:
        limiter.acquire_nowait()
    except anyio.WouldBlock as exc:
        raise DomainError(429, "upload_capacity", "Upload capacity is busy; retry later") from exc
    try:
        return await uploads.ingest(request, ctx, assessment_id, key)
    finally:
        limiter.release()


@router.post(
    "/assessments/{assessment_id}/artifact",
    response_model=s.ArtifactOut,
    status_code=201,
    tags=["Artifacts"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["file", "revision"],
                        "properties": {
                            "file": {
                                "type": "string",
                                "format": "binary",
                                "description": "APK, AAB or IPA",
                            },
                            "revision": {"type": "integer", "minimum": 1},
                            "app_version": {"type": "string", "maxLength": 255},
                            "build_type": {
                                "type": "string",
                                "enum": ["debug", "release", "unknown"],
                            },
                            "upload_notes": {"type": "string", "maxLength": 20000},
                        },
                    }
                }
            },
        }
    },
)
async def upload_mobile_artifact(assessment_id: UUID, request: Request, ctx: Ctx, key: Idem):
    limiter = request.app.state.upload_limiter
    try:
        limiter.acquire_nowait()
    except anyio.WouldBlock as exc:
        raise DomainError(429, "upload_capacity", "Upload capacity is busy; retry later") from exc
    try:
        return await uploads.ingest(request, ctx, assessment_id, key, mobile=True)
    finally:
        limiter.release()


@router.get("/artifacts/{artifact_id}", response_model=s.ArtifactDetailOut, tags=["Artifacts"])
def artifact_detail(artifact_id: UUID, ctx: Ctx):
    return uploads.artifact(ctx, artifact_id)


@router.get("/artifacts/{artifact_id}/download", tags=["Artifacts"])
def download_artifact(artifact_id: UUID, request: Request, ctx: Ctx):
    record = uploads.artifact(ctx, artifact_id)
    snapshot = None
    try:
        snapshot = Storage(request.app.state.settings.storage_root).verified_copy(
            record.storage_ref, record.sha256, record.file_size
        )
        path = snapshot.__enter__()
        svc.audit(ctx, "artifact.downloaded", "app_artifact", record.id)
        ctx.session.commit()
        return FileResponse(
            path,
            media_type=(
                "application/vnd.android.package-archive"
                if record.metadata_json.get("artifact_format", "apk") == "apk"
                else "application/octet-stream"
            ),
            filename=record.original_filename,
            headers={"X-Content-SHA256": record.sha256},
            background=BackgroundTask(snapshot.__exit__, None, None, None),
        )
    except StorageError as exc:
        raise uploads._storage_error(exc) from exc
    except BaseException:
        if snapshot:
            snapshot.__exit__(None, None, None)
        raise


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
    status: s.AssessmentStatus | None = None,
    assessment_type: s.AssessmentType | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    if date_from and date_to and date_from > date_to:
        raise DomainError(422, "validation_error", "Start date must be on or before end date")
    query = select(Assessment).where(
        Assessment.project_id.in_(svc.visible_projects(ctx)),
        Assessment.workspace_id == ctx.workspace_id,
    )
    if project_id:
        query = query.where(Assessment.project_id == project_id)
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
    assessment_type: s.AssessmentType | None = None,
    assessment_status: s.AssessmentStatus | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    if date_from and date_to and date_from > date_to:
        raise DomainError(422, "validation_error", "Start date must be on or before end date")

    projects = svc.visible_projects(ctx)
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
    if project_id or assessment_type or assessment_status:
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
        "pending_reviews": assessment_counts.get("needs_review", 0),
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
