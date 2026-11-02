"""Authenticated, bounded multipart ingestion; all APK parsing runs in a sandbox."""

import asyncio
import re
import time
from typing import Literal
from uuid import UUID

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException
from starlette.requests import Request as StarletteRequest

from droidshield import services as svc
from droidshield.auth import authenticate
from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import AppArtifact, IdempotencyRecord
from droidshield.sandbox import Sandbox, SandboxError
from droidshield.storage import StagedFile, Storage, StorageError


class UploadFields(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    revision: int = Field(ge=1, le=2**31 - 1, strict=True)
    app_version: str | None = Field(default=None, max_length=255)
    build_type: Literal["debug", "release", "unknown"] = "unknown"
    upload_notes: str | None = Field(default=None, max_length=20_000)


class UploadFingerprint(UploadFields):
    sha256: str
    file_size: int
    original_filename: str


def artifact(ctx: svc.Context, artifact_id: UUID) -> AppArtifact:
    record = ctx.session.scalar(
        select(AppArtifact).where(
            AppArtifact.id == artifact_id,
            AppArtifact.workspace_id == ctx.workspace_id,
            AppArtifact.project_id.in_(svc.visible_projects(ctx)),
        )
    )
    if record is None:
        raise not_found()
    return record


def _editable(ctx: svc.Context, record) -> None:
    svc.require_writer(ctx)
    parent = svc.project(ctx, record.project_id)
    if record.status not in {"draft", "awaiting_authorization"}:
        raise conflict("Only draft or awaiting-authorization assessments accept APK uploads")
    if parent.status != "active" or svc.client(ctx, parent.client_id).status != "active":
        raise conflict("APK uploads require an active project and client")


def _storage_error(exc: StorageError) -> DomainError:
    if exc.code == "upload_too_large":
        return DomainError(413, "upload_too_large", "APK exceeds the configured upload size limit")
    if exc.code == "invalid_apk":
        return DomainError(422, "invalid_apk", "Provide a nonempty valid APK")
    if exc.code == "artifact_integrity_failed":
        return DomainError(
            409, "artifact_integrity_failed", "Artifact integrity verification failed"
        )
    return DomainError(503, "storage_unavailable", "Protected artifact storage is unavailable")


async def _parse(
    request: Request, store: Storage, *, mobile: bool = False
) -> tuple[UploadFields, str, StagedFile]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "multipart/form-data"
    ):
        raise DomainError(415, "unsupported_media_type", "Use a multipart APK upload")
    maximum = request.app.state.settings.max_apk_bytes
    body_limit = maximum + 64 * 1024
    length = request.headers.get("content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,12}", length):
            raise DomainError(422, "validation_error", "Invalid content length")
        if int(length) > body_limit:
            raise DomainError(413, "upload_too_large", "Upload exceeds the configured size limit")
    received, exceeded, timed_out = 0, False, False
    deadline = time.monotonic() + request.app.state.settings.upload_timeout_seconds

    async def limited_receive():
        nonlocal received, exceeded, timed_out
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            message = await asyncio.wait_for(request.receive(), timeout=remaining)
        except TimeoutError as exc:
            timed_out = True
            raise MultiPartException("Upload transfer timeout") from exc
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > body_limit:
                exceeded = True
                # Starlette closes its temporary files when this parser exception
                # is raised. Do not bypass that cleanup with an unrelated error.
                raise MultiPartException("Upload exceeds limit")
        return message

    bounded = StarletteRequest(request.scope, receive=limited_receive)
    try:
        async with bounded.form(max_files=1, max_fields=4, max_part_size=24 * 1024) as form:
            values, file = {}, None
            seen = set()
            for name, value in form.multi_items():
                if name in seen or name not in {
                    "file",
                    "revision",
                    "app_version",
                    "build_type",
                    "upload_notes",
                }:
                    raise DomainError(422, "validation_error", "Unknown or duplicate upload field")
                seen.add(name)
                if name == "file":
                    if not isinstance(value, UploadFile):
                        raise DomainError(422, "validation_error", "APK file is required")
                    file = value
                elif isinstance(value, UploadFile):
                    raise DomainError(
                        422, "validation_error", "Only the file field may contain an upload"
                    )
                else:
                    values[name] = value
            if file is None or not file.filename:
                raise DomainError(422, "validation_error", "APK file is required")
            filename = file.filename
            disposition = file.headers.get("content-disposition", "")
            if "/" in disposition or "\\" in disposition:
                # Multipart parsers may normalize old Windows path filenames to
                # a basename. Reject that original path rather than accepting it.
                raise DomainError(
                    422, "validation_error", "Provide an APK filename without path components"
                )
            suffix = r"(?:apk|aab|ipa)" if mobile else "apk"
            if not re.fullmatch(
                rf"[A-Za-z0-9][A-Za-z0-9_. ()+\-]{{0,250}}\.{suffix}", filename, flags=re.IGNORECASE
            ):
                raise DomainError(
                    422, "validation_error", "Provide an APK filename without path components"
                )
            if file.content_type not in {
                "application/vnd.android.package-archive",
                "application/octet-stream",
                "application/zip",
                "application/x-itunes-ipa",
            }:
                raise DomainError(415, "unsupported_media_type", "Unsupported APK file media type")
            revision = values.get("revision", "")
            if not re.fullmatch(r"[1-9][0-9]{0,9}", revision):
                raise DomainError(
                    422,
                    "validation_error",
                    "A positive assessment revision is required",
                    [{"location": ["body", "revision"], "type": "value_error"}],
                )
            values["revision"] = int(revision)
            for field in ["app_version", "upload_notes"]:
                if values.get(field) == "":
                    values[field] = None
            metadata = UploadFields.model_validate(values)
            staged = await run_in_threadpool(store.stage, file.file, maximum)
            return metadata, filename, staged
    except ValidationError as exc:
        raise DomainError(
            422,
            "validation_error",
            "Check the upload fields",
            [{"location": ["body", *item["loc"]], "type": item["type"]} for item in exc.errors()],
        ) from exc
    except HTTPException as exc:
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded:
            raise DomainError(
                413, "upload_too_large", "Upload exceeds the configured size limit"
            ) from exc
        raise DomainError(422, "validation_error", "Malformed multipart APK upload") from exc
    except (ValueError, MultiPartException) as exc:
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded:
            raise DomainError(
                413, "upload_too_large", "Upload exceeds the configured size limit"
            ) from exc
        raise DomainError(422, "validation_error", "Malformed multipart APK upload") from exc


def _credential(request: Request) -> str:
    """Revalidate the credential selected by the authenticated HTTP dependency."""
    if getattr(request.state, "auth_method", None) == "cookie":
        value = getattr(request.state, "session_cookie", None)
        if value:
            return value
    else:
        authorization = request.headers.get("authorization", "").split(None, 1)
        if len(authorization) == 2 and authorization[0].lower() == "bearer":
            return authorization[1]
    raise DomainError(401, "unauthenticated", "Valid authentication is required")


async def ingest(
    request: Request, ctx: svc.Context, assessment_id: UUID, key: str, *, mobile: bool = False
) -> AppArtifact:
    svc.require_writer(ctx)
    current = svc.assessment(ctx, assessment_id)
    operation = f"{'artifact' if mobile else 'apk'}.upload:{assessment_id}"
    previous = ctx.session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.workspace_id == ctx.workspace_id,
            IdempotencyRecord.user_id == ctx.user.id,
            IdempotencyRecord.key == key,
        )
    )
    if previous and previous.operation != operation:
        raise conflict("Idempotency key was already used for a different request")
    if previous is None:
        _editable(ctx, current)
    # No SQLite locks or SQL transaction are held during transfer or APK parsing.
    ctx.session.commit()
    staged, published, commit_attempted = None, None, False
    try:
        store = Storage(request.app.state.settings.storage_root)
        fields, filename, staged = await _parse(request, store, mobile=mobile)
        fingerprint = UploadFingerprint(
            **fields.model_dump(),
            sha256=staged.sha256,
            file_size=staged.file_size,
            original_filename=filename,
        )
        # First inspect in a different, restricted OS namespace. API code does
        # not open the ZIP or interpret manifest bytes.
        format_name = filename.rsplit(".", 1)[1].lower()
        sandbox = Sandbox(request.app.state.settings)
        if format_name == "apk":
            result = await run_in_threadpool(sandbox.run, staged.path, "inspect")
        else:
            result = await run_in_threadpool(
                sandbox.run, staged.path, "inspect", engine=format_name
            )
        if result["sha256"] != staged.sha256 or result["file_size"] != staged.file_size:
            raise DomainError(
                409, "artifact_integrity_failed", "Artifact integrity verification failed"
            )
        ctx.session.expire_all()
        ctx.user = authenticate(ctx.session, _credential(request))
        svc.require_writer(ctx)
        current = svc.assessment(ctx, assessment_id, lock=True)

        def persist():
            nonlocal published
            parent = svc.project(ctx, current.project_id, lock=True)
            _editable(ctx, current)
            svc.check_revision(current, fields.revision)
            if result["metadata"].get("platform", "android") != parent.platform:
                raise DomainError(
                    422, "platform_mismatch", "Artifact platform does not match the project"
                )
            if result["metadata"]["package_name"] != parent.package_id:
                raise DomainError(422, "package_mismatch", "APK package does not match the project")
            record = ctx.session.scalar(
                select(AppArtifact).where(
                    AppArtifact.workspace_id == ctx.workspace_id,
                    AppArtifact.project_id == parent.id,
                    AppArtifact.sha256 == staged.sha256,
                )
            )
            if record is not None and record.metadata_json.get("artifact_format", "apk") != result[
                "metadata"
            ].get("artifact_format", "apk"):
                # One byte digest has one immutable classification per project.
                # A ZIP may satisfy both APK and AAB intake; reusing its first
                # record must not silently replace the incoming format/version.
                raise conflict(
                    "Identical bytes were already stored under a different artifact format"
                )
            if record is None:
                published = store.publish(staged)
                record = AppArtifact(
                    workspace_id=ctx.workspace_id,
                    project_id=parent.id,
                    created_by=ctx.user.id,
                    sha256=staged.sha256,
                    file_size=staged.file_size,
                    storage_ref=published,
                    original_filename=filename,
                    build_type=fields.build_type,
                    version_name=result["metadata"]["version_name"],
                    version_code=result["metadata"]["version_code"],
                    metadata_json=result["metadata"],
                )
                ctx.session.add(record)
                ctx.session.flush()
                svc.audit(ctx, "artifact.uploaded", "app_artifact", record.id)
            current.artifact_id = record.id
            # Uploaded declarations are provenance, not detected immutable metadata.
            current.configuration_snapshot = {
                **current.configuration_snapshot,
                "upload": {
                    "app_version": fields.app_version,
                    "build_type": fields.build_type,
                    "notes": fields.upload_notes,
                    "artifact_id": str(record.id),
                },
            }
            ctx.session.flush()
            svc.audit(ctx, "assessment.artifact_linked", "assessment", current.id)
            return record

        record = svc.once(ctx, key, operation, fingerprint, lambda rid: artifact(ctx, rid), persist)
        # Commit while cleanup still owns the new object, so a failed DB write
        # cannot leave a record pointing at a deleted or incomplete artifact.
        commit_attempted = True
        ctx.session.commit()
        return record
    except SandboxError as exc:
        ctx.session.rollback()
        if exc.code == "isolation_unavailable":
            raise DomainError(503, "isolation_unavailable", "APK isolation is unavailable") from exc
        raise DomainError(
            422, "invalid_apk", "APK inspection failed or exceeded its resource limits"
        ) from exc
    except StorageError as exc:
        ctx.session.rollback()
        if published and not commit_attempted:
            store.discard(published)
        raise _storage_error(exc) from exc
    except BaseException:
        ctx.session.rollback()
        if published and not commit_attempted:
            store.discard(published)
        raise
    finally:
        if staged:
            staged.close()
