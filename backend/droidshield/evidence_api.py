"""Protected artifact intake, lookup, and download routes."""

from typing import Annotated, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from starlette.background import BackgroundTask

from droidshield import schemas as s
from droidshield import services as svc
from droidshield import uploads
from droidshield.api_common import Ctx, Idem, Limit, Offset, page
from droidshield.errors import DomainError
from droidshield.models import AppArtifact
from droidshield.storage import Storage, StorageError

router = APIRouter()


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
