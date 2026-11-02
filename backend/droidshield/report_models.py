"""Immutable client deliverable snapshots and protected export metadata."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from droidshield.models import (
    Base,
    CreatedMixin,
    IdentityMixin,
    Report,
    WorkspaceMixin,
    user_reference,
)

Index("uq_reports_project_origin", Report.workspace_id, Report.project_id, Report.id, unique=True)
Index(
    "uq_reports_assessment_origin",
    Report.workspace_id,
    Report.project_id,
    Report.assessment_id,
    Report.id,
    unique=True,
)


class ReportSnapshot(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "report_snapshots"

    report_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), unique=True)
    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    version: Mapped[int] = mapped_column(Integer)
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id", "report_id"],
            ["reports.workspace_id", "reports.project_id", "reports.assessment_id", "reports.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("assessment_id", "version", name="uq_report_snapshots_assessment_version"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint("length(sha256) = 64", name="sha256_length"),
    )


class ReportExport(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "report_exports"

    report_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    format: Mapped[str] = mapped_column(String(8))
    storage_ref: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "report_id"],
            ["reports.workspace_id", "reports.project_id", "reports.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint("format IN ('pdf', 'json')", name="format"),
        CheckConstraint("file_size > 0 AND file_size <= 16777216", name="bounded_file_size"),
        CheckConstraint("length(sha256) = 64", name="sha256_length"),
    )
