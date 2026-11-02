"""Shared workspace context, permission checks, lookups, and query helpers."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import (
    Assessment,
    AuditEvent,
    Authorization,
    Client,
    Project,
    ProjectAccess,
    User,
)


@dataclass
class Context:
    session: Session
    user: User
    request_id: str

    @property
    def workspace_id(self) -> UUID:
        return self.user.workspace_id


def require_writer(ctx: Context) -> None:
    if ctx.user.role not in {"ADMIN", "SECURITY_ANALYST"}:
        raise DomainError(403, "forbidden", "Your role cannot modify assessment data")


def require_admin(ctx: Context) -> None:
    if ctx.user.role != "ADMIN":
        raise DomainError(403, "forbidden", "Administrator access is required")


def audit(ctx: Context, action: str, resource_type: str, resource_id: UUID) -> None:
    # Do not persist request bodies, URLs, headers, evidence, notes, or credentials.
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.workspace_id,
            actor_id=ctx.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={"channel": "api"},
        )
    )


def visible_projects(ctx: Context):
    query = select(Project.id).where(Project.workspace_id == ctx.workspace_id)
    if ctx.user.role != "ADMIN":
        query = query.where(
            or_(
                Project.created_by == ctx.user.id,
                exists().where(
                    ProjectAccess.project_id == Project.id,
                    ProjectAccess.workspace_id == ctx.workspace_id,
                    ProjectAccess.user_id == ctx.user.id,
                ),
            )
        )
    return query


def client_query(ctx: Context):
    query = select(Client).where(Client.workspace_id == ctx.workspace_id)
    if ctx.user.role != "ADMIN":
        query = query.where(
            or_(
                Client.created_by == ctx.user.id,
                Client.id.in_(
                    select(Project.client_id).where(Project.id.in_(visible_projects(ctx)))
                ),
            )
        )
    return query


def client(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Client:
    query = client_query(ctx).where(Client.id == resource_id)
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def project(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Project:
    query = select(Project).where(Project.id == resource_id, Project.id.in_(visible_projects(ctx)))
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def assessment(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Assessment:
    query = select(Assessment).where(
        Assessment.id == resource_id,
        Assessment.workspace_id == ctx.workspace_id,
        Assessment.project_id.in_(visible_projects(ctx)),
    )
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def authorization(ctx: Context, resource_id: UUID, *, lock: bool = False) -> Authorization:
    query = select(Authorization).where(
        Authorization.id == resource_id,
        Authorization.workspace_id == ctx.workspace_id,
        Authorization.project_id.in_(visible_projects(ctx)),
    )
    result = ctx.session.scalar(
        query.with_for_update().execution_options(populate_existing=True) if lock else query
    )
    if result is None:
        raise not_found()
    return result


def check_revision(record: Any, expected: int) -> None:
    if record.revision != expected:
        raise conflict("The record changed. Reload it before saving")


def paginate(ctx: Context, query, limit: int, offset: int) -> tuple[list[Any], int]:
    total = ctx.session.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = ctx.session.scalars(query.limit(limit).offset(offset)).all()
    return list(items), total
