"""Protected, immutable supporting documents for client authorizations."""

from uuid import UUID

from sqlalchemy import select

from droidshield.errors import conflict, not_found
from droidshield.models import AuthorizationAttachment
from droidshield.service_context import (
    Context,
    audit,
    authorization,
    require_writer,
    visible_projects,
)


def authorization_attachment(ctx: Context, resource_id: UUID) -> AuthorizationAttachment:
    record = ctx.session.scalar(
        select(AuthorizationAttachment).where(
            AuthorizationAttachment.id == resource_id,
            AuthorizationAttachment.workspace_id == ctx.workspace_id,
            AuthorizationAttachment.project_id.in_(visible_projects(ctx)),
        )
    )
    if record is None:
        raise not_found()
    return record


def authorization_attachments(ctx: Context, authorization_id: UUID):
    authorization(ctx, authorization_id)
    return select(AuthorizationAttachment).where(
        AuthorizationAttachment.authorization_id == authorization_id,
        AuthorizationAttachment.workspace_id == ctx.workspace_id,
        AuthorizationAttachment.project_id.in_(visible_projects(ctx)),
    )


def create_authorization_attachment(
    ctx: Context,
    authorization_id: UUID,
    *,
    storage_ref: str,
    sha256: str,
    file_size: int,
    media_type: str,
    display_name: str,
) -> AuthorizationAttachment:
    require_writer(ctx)
    permit = authorization(ctx, authorization_id, lock=True)
    if permit.status != "pending":
        raise conflict("Supporting documents can only be added to pending authorizations")
    record = AuthorizationAttachment(
        workspace_id=ctx.workspace_id,
        project_id=permit.project_id,
        authorization_id=permit.id,
        storage_ref=storage_ref,
        sha256=sha256,
        file_size=file_size,
        media_type=media_type,
        display_name=display_name,
        created_by=ctx.user.id,
    )
    ctx.session.add(record)
    ctx.session.flush()
    audit(ctx, "authorization.attachment_created", "authorization", permit.id)
    return record
