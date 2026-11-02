"""Bounded ingestion for analyst screenshot attachments.

Screenshots are stored as opaque protected objects and are never parsed, rendered,
or served inline by the application.
"""

import asyncio
import re
import time
from uuid import UUID

import anyio
from fastapi import Request
from pydantic import ConfigDict, ValidationError
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException
from starlette.requests import Request as StarletteRequest

from droidshield import delivery as delivery_svc
from droidshield import delivery_schemas as ds
from droidshield import services as svc
from droidshield.auth import authenticate
from droidshield.errors import DomainError, conflict
from droidshield.models import IdempotencyRecord
from droidshield.storage import StagedFile, Storage, StorageError

MAX_BYTES = 8 * 1024 * 1024
BODY_OVERHEAD = 64 * 1024


class EvidenceFingerprint(ds.EvidenceAttachmentCreate):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    sha256: str
    file_size: int


async def _parse(request: Request, store: Storage):
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "multipart/form-data"
    ):
        raise DomainError(415, "unsupported_media_type", "Use a multipart screenshot upload")
    body_limit = MAX_BYTES + BODY_OVERHEAD
    length = request.headers.get("content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,12}", length):
            raise DomainError(422, "validation_error", "Invalid content length")
        if int(length) > body_limit:
            raise DomainError(413, "upload_too_large", "Screenshot exceeds the 8 MiB limit")

    received = 0
    exceeded = timed_out = False
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
                raise MultiPartException("Screenshot exceeds upload limit")
        return message

    bounded = StarletteRequest(request.scope, receive=limited_receive)
    staged = None
    try:
        names = {
            "file",
            "title",
            "sanitized",
            "platform",
            "tool",
            "tool_version",
            "environment",
            "artifact_id",
            "finding_id",
            "release_ref",
        }
        async with bounded.form(max_files=1, max_fields=9, max_part_size=24 * 1024) as form:
            values, file, seen = {}, None, set()
            for name, value in form.multi_items():
                if name in seen or name not in names:
                    raise DomainError(422, "validation_error", "Unknown or duplicate upload field")
                seen.add(name)
                if name == "file":
                    if not isinstance(value, UploadFile):
                        raise DomainError(422, "validation_error", "Screenshot file is required")
                    file = value
                elif isinstance(value, UploadFile):
                    raise DomainError(
                        422, "validation_error", "Only the file field may contain a file"
                    )
                else:
                    values[name] = value
            if file is None or not file.filename:
                raise DomainError(422, "validation_error", "Screenshot file is required")
            disposition = file.headers.get("content-disposition", "")
            if (
                "/" in disposition
                or "\\" in disposition
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_. ()+\-]{0,250}\.png", file.filename, re.IGNORECASE
                )
            ):
                raise DomainError(422, "validation_error", "Choose a PNG filename without a path")
            if file.content_type not in {"image/png", "application/octet-stream"}:
                raise DomainError(
                    415, "unsupported_media_type", "Only PNG screenshots are accepted"
                )
            fields = ds.EvidenceAttachmentCreate.model_validate(
                {**values, "sanitized": values.get("sanitized") == "true"}
            )
            staged = await run_in_threadpool(store.stage, file.file, MAX_BYTES)
        _validate_png(staged)
        return fields, staged
    except DomainError:
        if staged:
            staged.close()
        raise
    except ValidationError as exc:
        if staged:
            staged.close()
        raise DomainError(
            422,
            "validation_error",
            "Check the screenshot evidence fields",
            [{"location": ["body", *item["loc"]], "type": item["type"]} for item in exc.errors()],
        ) from exc
    except HTTPException as exc:
        if staged:
            staged.close()
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded:
            raise DomainError(
                413, "upload_too_large", "Screenshot exceeds the 8 MiB limit"
            ) from exc
        raise DomainError(422, "validation_error", "Malformed screenshot upload") from exc
    except (ValueError, MultiPartException, StorageError) as exc:
        if staged:
            staged.close()
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded:
            raise DomainError(
                413, "upload_too_large", "Screenshot exceeds the 8 MiB limit"
            ) from exc
        if isinstance(exc, StorageError) and exc.code == "upload_too_large":
            raise DomainError(
                413, "upload_too_large", "Screenshot exceeds the 8 MiB limit"
            ) from exc
        if isinstance(exc, StorageError):
            raise DomainError(
                503, "storage_unavailable", "Protected evidence storage is unavailable"
            ) from exc
        raise DomainError(
            422, "invalid_evidence_attachment", "Provide a valid PNG screenshot"
        ) from exc


def _validate_png(staged: StagedFile) -> None:
    if staged.file_size < 45:
        raise DomainError(422, "invalid_evidence_attachment", "Provide a valid PNG screenshot")
    with staged.path.open("rb") as stream:
        header = stream.read(33)
        stream.seek(-12, 2)
        trailer = stream.read(12)
    if (
        len(header) != 33
        or header[:8] != b"\x89PNG\r\n\x1a\n"
        or header[8:12] != b"\x00\x00\x00\r"
        or header[12:16] != b"IHDR"
        or trailer != b"\x00\x00\x00\x00IEND\xaeB`\x82"
    ):
        raise DomainError(422, "invalid_evidence_attachment", "Provide a valid PNG screenshot")
    width, height = int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")
    if (
        width < 1
        or height < 1
        or width > 10_000
        or height > 10_000
        or width * height > 25_000_000
        or header[24] != 8
        or header[25] not in {2, 6}
        or header[26:29] != b"\x00\x00\x00"
    ):
        raise DomainError(
            422, "invalid_evidence_attachment", "PNG dimensions or encoding are unsupported"
        )


def _credential(request: Request) -> str:
    if getattr(request.state, "auth_method", None) == "cookie":
        value = getattr(request.state, "session_cookie", None)
        if value:
            return value
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(None, 1)[1]
    raise DomainError(401, "unauthenticated", "Valid authentication is required")


async def ingest(request: Request, ctx: svc.Context, assessment_id: UUID, key: str):
    svc.require_writer(ctx)
    svc.assessment(ctx, assessment_id)
    operation = f"evidence.attachment:{assessment_id}"
    previous = ctx.session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.workspace_id == ctx.workspace_id,
            IdempotencyRecord.user_id == ctx.user.id,
            IdempotencyRecord.key == key,
        )
    )
    if previous and previous.operation != operation:
        raise conflict("Idempotency key was already used for a different request")
    ctx.session.commit()
    limiter = request.app.state.upload_limiter
    try:
        limiter.acquire_nowait()
    except anyio.WouldBlock as exc:
        raise DomainError(429, "upload_capacity", "Upload capacity is busy; retry later") from exc
    store = None
    staged, published, created_record, commit_attempted = None, None, None, False
    try:
        store = Storage(request.app.state.settings.storage_root / "evidence-attachments")
        fields, staged = await _parse(request, store)
        fingerprint = EvidenceFingerprint(
            **fields.model_dump(), sha256=staged.sha256, file_size=staged.file_size
        )
        ctx.session.expire_all()
        ctx.user = authenticate(ctx.session, _credential(request))
        svc.require_writer(ctx)

        def persist():
            nonlocal published, created_record
            published = store.publish(staged)
            created_record = delivery_svc.create_evidence_attachment(
                ctx,
                assessment_id,
                fields,
                request.app.state.settings,
                published,
                staged.sha256,
                staged.file_size,
            )
            return created_record

        record = svc.once(
            ctx,
            key,
            operation,
            fingerprint,
            lambda resource_id: delivery_svc.evidence(ctx, resource_id),
            persist,
        )
        commit_attempted = True
        ctx.session.commit()
        return record
    except StorageError as exc:
        ctx.session.rollback()
        if published and not commit_attempted and store:
            store.discard(published)
        if created_record and not commit_attempted:
            _discard_text_manifest(request, created_record)
        if exc.code == "upload_too_large":
            raise DomainError(
                413, "upload_too_large", "Screenshot exceeds the 8 MiB limit"
            ) from exc
        raise DomainError(
            503, "storage_unavailable", "Protected evidence storage is unavailable"
        ) from exc
    except BaseException:
        ctx.session.rollback()
        if published and not commit_attempted and store:
            store.discard(published)
        if created_record and not commit_attempted:
            _discard_text_manifest(request, created_record)
        raise
    finally:
        if staged:
            staged.close()
        limiter.release()


def _discard_text_manifest(request: Request, record) -> None:
    try:
        Storage(request.app.state.settings.storage_root / "evidence").discard(record.artifact_ref)
    except StorageError:
        pass
