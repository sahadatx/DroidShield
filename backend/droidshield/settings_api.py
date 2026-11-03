"""Typed administrator-only workspace settings routes."""

from fastapi import APIRouter, Request

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import Ctx

router = APIRouter()


@router.get("/settings", response_model=s.WorkspaceSettingsOut, tags=["Settings"])
def read_settings(ctx: Ctx, request: Request):
    return svc.get_workspace_settings(ctx, request.app.state.settings)


@router.patch("/settings", response_model=s.WorkspaceSettingsOut, tags=["Settings"])
def edit_settings(ctx: Ctx, request: Request, data: s.WorkspaceSettingsUpdate):
    return svc.update_workspace_settings(ctx, data, request.app.state.settings)
