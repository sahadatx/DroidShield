"""Authenticated API for client authorization supporting documents."""

import hashlib
import os
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import Response

from droidshield import authorization_uploads
from droidshield import delivery_schemas as ds
from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import Ctx, Idem, Limit, Offset, page
from droidshield.errors import DomainError
from droidshield.models import AuthorizationAttachment
from droidshield.storage import Storage, StorageError

router = APIRouter(tags=["Authorizations"])


@router.get(
    "/authorizations/{authorization_id}/attachments",
    response_model=s.Page[ds.AuthorizationAttachmentOut],
)
def list_attachments(authorization_id: UUID, ctx: Ctx, limit: Limit = 25, offset: Offset = 0):
    query = svc.authorization_attachments(ctx, authorization_id).order_by(
        AuthorizationAttachment.created_at.desc(), AuthorizationAttachment.id
    )
    return page(ctx, query, ds.AuthorizationAttachmentOut, limit, offset)


@router.post(
    "/authorizations/{authorization_id}/attachments",
    response_model=ds.AuthorizationAttachmentOut,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["file"],
                        "properties": {"file": {"type": "string", "format": "binary"}},
                    }
                }
            },
        }
    },
)
async def upload_attachment(authorization_id: UUID, request: Request, ctx: Ctx, key: Idem):
    return await authorization_uploads.ingest(request, ctx, authorization_id, key)


@router.get("/authorization-attachments/{attachment_id}/download")
def download_attachment(attachment_id: UUID, request: Request, ctx: Ctx):
    record = svc.authorization_attachment(ctx, attachment_id)
    try:
        store = Storage(
            request.app.state.settings.storage_root / "authorization-attachments",
            reference_prefix="authdoc",
            object_suffix=".bin",
        )
        with store.open_artifact(record.storage_ref) as source:
            if os.fstat(source.fileno()).st_size != record.file_size:
                raise StorageError("artifact_integrity_failed")
            content = source.read(record.file_size + 1)
        if len(content) != record.file_size or hashlib.sha256(content).hexdigest() != record.sha256:
            raise StorageError("artifact_integrity_failed")
    except (StorageError, OSError) as exc:
        raise DomainError(
            503, "storage_unavailable", "Protected document storage is unavailable"
        ) from exc

    extension = {
        "application/pdf": "pdf",
        "image/png": "png",
        "image/jpeg": "jpg",
    }[record.media_type]
    svc.audit(ctx, "authorization.attachment_downloaded", "authorization", record.authorization_id)
    ctx.session.commit()
    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="DroidShield-authorization-{record.id}.{extension}"'
            ),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "X-Content-SHA256": record.sha256,
        },
    )
