"""Workspace user lifecycle operations with serialized admin invariants."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select

from droidshield.errors import conflict, not_found
from droidshield.models import AccessToken, AuditEvent, User, Workspace
from droidshield.service_context import Context, require_admin


def user_query(ctx: Context):
    require_admin(ctx)
    return select(User).where(User.workspace_id == ctx.workspace_id)


def workspace_user(ctx: Context, user_id: UUID, *, lock: bool = False) -> User:
    require_admin(ctx)
    query = select(User).where(User.id == user_id, User.workspace_id == ctx.workspace_id)
    if lock:
        query = query.with_for_update()
    record = ctx.session.scalar(query)
    if record is None:
        raise not_found()
    return record


def _lock_workspace(ctx: Context) -> None:
    """Serialize membership mutations so concurrent requests cannot remove all admins."""
    workspace = ctx.session.scalar(
        select(Workspace).where(Workspace.id == ctx.workspace_id).with_for_update()
    )
    if workspace is None:
        raise not_found()


def _active_admin_count(ctx: Context) -> int:
    return int(
        ctx.session.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.workspace_id == ctx.workspace_id,
                User.role == "ADMIN",
                User.status == "active",
            )
        )
        or 0
    )


def _audit_user(ctx: Context, action: str, record: User, **metadata) -> None:
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.workspace_id,
            actor_id=ctx.user.id,
            action=action,
            resource_type="user",
            resource_id=record.id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={"channel": "api", **metadata},
        )
    )


def create_workspace_user(ctx: Context, data) -> User:
    require_admin(ctx)
    _lock_workspace(ctx)
    email = str(data.email).lower()
    if ctx.session.scalar(
        select(User.id).where(User.workspace_id == ctx.workspace_id, User.email == email)
    ):
        raise conflict("A user with this email already exists in the workspace")
    record = User(
        workspace_id=ctx.workspace_id,
        email=email,
        full_name=data.full_name,
        role=data.role,
        # Accounts must receive a password through trusted local setup before activation.
        status="disabled",
    )
    ctx.session.add(record)
    ctx.session.flush()
    _audit_user(ctx, "user.created", record, role=record.role, status=record.status)
    return record


def update_workspace_user(ctx: Context, user_id: UUID, data) -> User:
    require_admin(ctx)
    _lock_workspace(ctx)
    record = workspace_user(ctx, user_id, lock=True)
    changes = data.model_dump(exclude_unset=True)
    new_role = changes.get("role", record.role)
    new_status = changes.get("status", record.status)
    previous_role = record.role
    previous_status = record.status

    loses_admin_access = (
        record.role == "ADMIN"
        and record.status == "active"
        and (new_role != "ADMIN" or new_status != "active")
    )
    if loses_admin_access and _active_admin_count(ctx) <= 1:
        raise conflict("The workspace must keep at least one active administrator")
    if new_status == "active" and record.password_hash is None:
        raise conflict("Set the account password through trusted local administration first")

    changed = any(getattr(record, field) != value for field, value in changes.items())
    for field, value in changes.items():
        setattr(record, field, value)
    revoked_sessions = _revoke_sessions(ctx, record) if record.status == "disabled" else 0
    ctx.session.flush()
    if changed or revoked_sessions:
        metadata = {}
        if previous_role != record.role:
            metadata["role_before"] = previous_role
            metadata["role_after"] = record.role
        if previous_status != record.status:
            metadata["status_before"] = previous_status
            metadata["status_after"] = record.status
        if revoked_sessions:
            metadata["revoked_sessions"] = revoked_sessions
        _audit_user(ctx, "user.updated", record, **metadata)
    return record


def revoke_workspace_user_sessions(ctx: Context, user_id: UUID) -> User:
    require_admin(ctx)
    _lock_workspace(ctx)
    record = workspace_user(ctx, user_id, lock=True)
    revoked = _revoke_sessions(ctx, record)
    if revoked:
        _audit_user(ctx, "user.sessions_revoked", record, revoked_sessions=revoked)
    return record


def _revoke_sessions(ctx: Context, record: User) -> int:
    now = datetime.now(UTC)
    tokens = ctx.session.scalars(
        select(AccessToken).where(
            AccessToken.user_id == record.id,
            AccessToken.revoked_at.is_(None),
        )
    )
    count = 0
    for token in tokens:
        token.revoked_at = now
        count += 1
    return count
