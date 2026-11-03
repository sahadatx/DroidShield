"""ADMIN-only, allowlisted workspace preference management."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from droidshield.config import Settings
from droidshield.errors import conflict, not_found
from droidshield.models import AuditEvent, Workspace, WorkspaceSettings, utcnow
from droidshield.schemas import WorkspaceSettingsUpdate
from droidshield.service_context import Context, require_admin

DEFAULTS: dict[str, Any] = {
    "display_timezone": "UTC",
    "date_format": "iso",
    "default_report_template": "combined",
    "report_branding_name": None,
}


def _secret_configured(value: Any) -> bool:
    if value is None:
        return False
    getter = getattr(value, "get_secret_value", None)
    if callable(getter):
        value = getter()
    return bool(str(value).strip())


def _view(workspace: Workspace, record: WorkspaceSettings | None, runtime: Settings):
    values = DEFAULTS.copy()
    if record is not None:
        values.update(
            display_timezone=record.display_timezone,
            date_format=record.date_format,
            default_report_template=record.default_report_template,
            report_branding_name=record.report_branding_name,
        )
    mobsf_ready = bool(runtime.mobsf_url) and _secret_configured(runtime.mobsf_api_key)
    proxy_ready = bool(runtime.proxy_ca_cert) and _secret_configured(runtime.proxy_ca_key)
    return {
        "workspace_id": workspace.id,
        "workspace_name": workspace.name,
        **values,
        "revision": record.revision if record is not None else 1,
        "updated_at": record.updated_at if record is not None else None,
        "secret_references": {
            "mobsf_service": {"configured": mobsf_ready},
            "api_secret_store": {"configured": runtime.api_secret_store is not None},
            "frida_runtime": {"configured": _secret_configured(runtime.frida_token)},
            "proxy_certificate_authority": {"configured": proxy_ready},
        },
    }


def _workspace(ctx: Context, *, lock: bool = False) -> Workspace:
    query = select(Workspace).where(Workspace.id == ctx.workspace_id)
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    workspace = ctx.session.scalar(query)
    if workspace is None:
        raise not_found()
    return workspace


def _record(ctx: Context) -> WorkspaceSettings | None:
    return ctx.session.scalar(
        select(WorkspaceSettings).where(WorkspaceSettings.workspace_id == ctx.workspace_id)
    )


def get_workspace_settings(ctx: Context, runtime: Settings):
    require_admin(ctx)
    workspace = _workspace(ctx)
    return _view(workspace, _record(ctx), runtime)


def update_workspace_settings(ctx: Context, data: WorkspaceSettingsUpdate, runtime: Settings):
    require_admin(ctx)
    workspace = _workspace(ctx, lock=True)
    record = _record(ctx)
    current_revision = record.revision if record is not None else 1
    if data.revision != current_revision:
        raise conflict("Workspace settings changed. Reload them before saving")

    requested = data.model_dump(exclude_unset=True, exclude={"revision"})
    workspace_name = requested.pop("workspace_name", None)
    changes = {
        key: value
        for key, value in requested.items()
        if (record is None and value != DEFAULTS[key])
        or (record is not None and getattr(record, key) != value)
    }
    name_changed = workspace_name is not None and workspace.name != workspace_name
    if not name_changed and not changes:
        return _view(workspace, record, runtime)

    if name_changed:
        workspace.name = workspace_name

    if record is None:
        values = DEFAULTS | changes
        record = WorkspaceSettings(
            workspace_id=ctx.workspace_id,
            updated_by=ctx.user.id,
            **values,
        )
        ctx.session.add(record)
        ctx.session.flush()
        # A first save moves the default revision (1) to the first stored edit (2).
        record.revision = current_revision + 1
        record.updated_at = utcnow()
    else:
        for key, value in changes.items():
            setattr(record, key, value)
        record.updated_by = ctx.user.id
        if name_changed and not changes:
            record.updated_at = utcnow()

    ctx.session.flush()
    changed_fields = sorted(set(changes) | ({"workspace_name"} if name_changed else set()))
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.workspace_id,
            actor_id=ctx.user.id,
            action="workspace.settings_updated",
            resource_type="workspace_settings",
            resource_id=workspace.id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={
                "channel": "api",
                "changed_fields": changed_fields,
                "revision": record.revision,
            },
        )
    )
    ctx.session.flush()
    return _view(workspace, record, runtime)
