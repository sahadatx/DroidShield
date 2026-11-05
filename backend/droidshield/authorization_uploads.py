"""Bounded private upload handling for client authorization documents."""

import asyncio
import re
import time
from uuid import UUID

import anyio
from fastapi import Request
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException
from starlette.requests import Request as StarletteRequest

from droidshield import services as svc
from droidshield.auth import authenticate
from droidshield.errors import DomainError, conflict
from droidshield.models import IdempotencyRecord
from droidshield.storage import StagedFile, Storage, StorageError

MAX_BYTES = 8 * 1024 * 1024
BODY_OVERHEAD = 64 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. ()+\-]{0,119}\.(?:pdf|png|jpe?g)\Z", re.I)
_MEDIA = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}


class AuthorizationAttachmentFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    display_name: str
    media_type: str
    sha256: str
    file_size: int


async def _parse(request: Request, store: Storage) -> tuple[str, str, StagedFile]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "multipart/form-data"
    ):
        raise DomainError(415, "unsupported_media_type", "Use a multipart document upload")
    body_limit = MAX_BYTES + BODY_OVERHEAD
    length = request.headers.get("content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,12}", length):
            raise DomainError(422, "validation_error", "Invalid content length")
        if int(length) > body_limit:
            raise DomainError(413, "upload_too_large", "Document exceeds the 8 MiB limit")

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
                raise MultiPartException("Document exceeds upload limit")
        return message

    bounded = StarletteRequest(request.scope, receive=limited_receive)
    staged = None
    try:
        async with bounded.form(max_files=1, max_fields=0, max_part_size=24 * 1024) as form:
            items = list(form.multi_items())
            if len(items) != 1 or items[0][0] != "file" or not isinstance(items[0][1], UploadFile):
                raise DomainError(422, "validation_error", "Provide exactly one document file")
            file = items[0][1]
            filename = file.filename or ""
            if len(filename) > 120 or not _NAME.fullmatch(filename):
                raise DomainError(
                    422,
                    "invalid_authorization_attachment",
                    "Use a PDF, PNG or JPEG filename without a path",
                )
            extension = filename.rsplit(".", 1)[1].lower()
            media_type = _MEDIA[extension]
            if file.content_type not in {media_type, "application/octet-stream"}:
                raise DomainError(
                    415, "unsupported_media_type", "File type does not match its extension"
                )
            staged = await run_in_threadpool(store.stage, file.file, MAX_BYTES)
        _validate_signature(staged, extension)
        # Client filenames can contain confidential engagement details.
        return f"authorization-document.{extension}", media_type, staged
    except DomainError:
        if staged:
            staged.close()
        raise
    except ValidationError as exc:
        if staged:
            staged.close()
        raise DomainError(422, "validation_error", "Check the uploaded document") from exc
    except HTTPException as exc:
        if staged:
            staged.close()
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded:
            raise DomainError(413, "upload_too_large", "Document exceeds the 8 MiB limit") from exc
        raise DomainError(422, "validation_error", "Malformed document upload") from exc
    except (ValueError, MultiPartException, StorageError) as exc:
        if staged:
            staged.close()
        if timed_out:
            raise DomainError(408, "upload_timeout", "Upload transfer time limit exceeded") from exc
        if exceeded or isinstance(exc, StorageError) and exc.code == "upload_too_large":
            raise DomainError(413, "upload_too_large", "Document exceeds the 8 MiB limit") from exc
        if isinstance(exc, StorageError) and exc.code == "invalid_apk":
            raise DomainError(
                422, "invalid_authorization_attachment", "Provide a valid PDF, PNG or JPEG document"
            ) from exc
        if isinstance(exc, StorageError):
            raise DomainError(
                503, "storage_unavailable", "Protected document storage is unavailable"
            ) from exc
        raise DomainError(
            422, "invalid_authorization_attachment", "Provide a valid PDF, PNG or JPEG document"
        ) from exc


def _validate_signature(staged: StagedFile, extension: str) -> None:
    if extension == "pdf":
        with staged.path.open("rb") as stream:
            start = stream.read(8)
            stream.seek(max(0, staged.file_size - 1024))
            tail = stream.read(1024)
        valid = staged.file_size >= 8 and start.startswith(b"%PDF-") and b"%%EOF" in tail
    elif extension == "png":
        if staged.file_size < 45:
            valid = False
        else:
            with staged.path.open("rb") as stream:
                header = stream.read(24)
                stream.seek(-12, 2)
                tail = stream.read(12)
            width, height = (
                int.from_bytes(header[16:20], "big"),
                int.from_bytes(header[20:24], "big"),
            )
            valid = (
                header[:8] == b"\x89PNG\r\n\x1a\n"
                and header[8:12] == b"\x00\x00\x00\r"
                and header[12:16] == b"IHDR"
                and tail == b"\x00\x00\x00\x00IEND\xaeB`\x82"
                and 1 <= width <= 10_000
                and 1 <= height <= 10_000
                and width * height <= 25_000_000
            )
    else:
        with staged.path.open("rb") as stream:
            start = stream.read(3)
            stream.seek(-2, 2)
            tail = stream.read(2)
        valid = staged.file_size >= 5 and start == b"\xff\xd8\xff" and tail == b"\xff\xd9"
    if not valid:
        raise DomainError(
            422,
            "invalid_authorization_attachment",
            "Document signature does not match its file type",
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


async def ingest(request: Request, ctx: svc.Context, authorization_id: UUID, key: str):
    svc.require_writer(ctx)
    svc.authorization(ctx, authorization_id)
    operation = f"authorization.attachment:{authorization_id}"
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
    staged = published = created_record = None
    commit_attempted = False
    try:
        store = Storage(
            request.app.state.settings.storage_root / "authorization-attachments",
            reference_prefix="authdoc",
            object_suffix=".bin",
        )
        display_name, media_type, staged = await _parse(request, store)
        fingerprint = AuthorizationAttachmentFingerprint(
            display_name=display_name,
            media_type=media_type,
            sha256=staged.sha256,
            file_size=staged.file_size,
        )
        ctx.session.expire_all()
        ctx.user = authenticate(ctx.session, _credential(request))
        svc.require_writer(ctx)

        def persist():
            nonlocal published, created_record
            published = store.publish(staged)
            created_record = svc.create_authorization_attachment(
                ctx,
                authorization_id,
                storage_ref=published,
                sha256=staged.sha256,
                file_size=staged.file_size,
                media_type=media_type,
                display_name=display_name,
            )
            return created_record

        record = svc.once(
            ctx,
            key,
            operation,
            fingerprint,
            lambda resource_id: svc.authorization_attachment(ctx, resource_id),
            persist,
        )
        commit_attempted = True
        ctx.session.commit()
        return record
    except StorageError as exc:
        ctx.session.rollback()
        if published and not commit_attempted and store:
            store.discard(published)
        if exc.code == "upload_too_large":
            raise DomainError(413, "upload_too_large", "Document exceeds the 8 MiB limit") from exc
        if exc.code == "artifact_integrity_failed":
            raise DomainError(
                503, "storage_unavailable", "Protected document storage is unavailable"
            ) from exc
        raise DomainError(
            503, "storage_unavailable", "Protected document storage is unavailable"
        ) from exc
    except BaseException:
        ctx.session.rollback()
        if published and not commit_attempted and store:
            store.discard(published)
        raise
    finally:
        if staged:
            staged.close()
        limiter.release()
