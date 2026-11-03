"""Administrator-only workspace membership and session lifecycle routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import Ctx, Idem, Limit, Offset, page

router = APIRouter()


@router.get("/users", response_model=s.Page[s.WorkspaceUserOut], tags=["Users"])
def list_users(
    ctx: Ctx,
    limit: Limit = 25,
    offset: Offset = 0,
    role: Annotated[s.UserRole | None, Query()] = None,
    status: Annotated[s.UserStatus | None, Query()] = None,
):
    query = svc.user_query(ctx)
    if role is not None:
        query = query.where(svc.User.role == role)
    if status is not None:
        query = query.where(svc.User.status == status)
    return page(
        ctx,
        query.order_by(svc.User.created_at.desc(), svc.User.id),
        s.WorkspaceUserOut,
        limit,
        offset,
    )


@router.post(
    "/users",
    response_model=s.WorkspaceUserOut,
    status_code=201,
    tags=["Users"],
)
def create_user(ctx: Ctx, data: s.WorkspaceUserCreate, key: Idem):
    svc.require_admin(ctx)
    record = svc.once(
        ctx,
        key,
        "user.create",
        data,
        lambda user_id: svc.workspace_user(ctx, user_id),
        lambda: svc.create_workspace_user(ctx, data),
    )
    return s.WorkspaceUserOut.model_validate(record)


@router.patch("/users/{user_id}", response_model=s.WorkspaceUserOut, tags=["Users"])
def update_user(user_id: UUID, ctx: Ctx, data: s.WorkspaceUserUpdate):
    return s.WorkspaceUserOut.model_validate(svc.update_workspace_user(ctx, user_id, data))


@router.post(
    "/users/{user_id}/revoke-sessions",
    response_model=s.WorkspaceUserOut,
    tags=["Users"],
)
def revoke_user_sessions(
    user_id: UUID,
    ctx: Ctx,
    data: s.UserSessionRevoke,
    key: Idem,
):
    svc.require_admin(ctx)
    record = svc.once(
        ctx,
        key,
        f"user.sessions_revoke:{user_id}",
        data,
        lambda rid: svc.workspace_user(ctx, rid),
        lambda: svc.revoke_workspace_user_sessions(ctx, user_id),
    )
    return s.WorkspaceUserOut.model_validate(record)
