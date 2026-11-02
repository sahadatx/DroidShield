"""Strict report authoring and release contracts."""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator

from droidshield.schemas import RequestModel, ResponseModel

Severity = Literal["critical", "high", "medium", "low", "info"]
Text = Annotated[str, StringConstraints(min_length=1, max_length=20_000)]


class ReportCreate(RequestModel):
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    template: Literal["executive", "technical", "combined"] = "combined"
    severity_filter: list[Severity] = Field(
        default_factory=lambda: ["critical", "high", "medium", "low", "info"],
        min_length=1,
        max_length=5,
    )
    include_evidence: bool = Field(default=True, strict=True)
    include_remediation: bool = Field(default=True, strict=True)
    executive_summary: Text
    limitations: Text
    branding_name: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None

    @field_validator("severity_filter")
    @classmethod
    def unique_severities(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Select each severity once")
        return value


class ReportRelease(RequestModel):
    decision: Literal["approve"]


class ReportExportCreate(RequestModel):
    format: Literal["pdf", "json"]


class ReportOut(ResponseModel):
    id: UUID
    project_id: UUID
    assessment_id: UUID
    title: str
    template: str
    version: int
    status: str
    author_id: UUID
    reviewer_id: UUID | None
    approved_at: datetime | None
    created_at: datetime


class ReportDetailOut(ReportOut):
    snapshot: dict[str, Any]
    snapshot_sha256: str


class ReportExportOut(ResponseModel):
    id: UUID
    report_id: UUID
    format: str
    sha256: str
    file_size: int
    created_at: datetime


class CVSSRequest(RequestModel):
    vector: Annotated[str, StringConstraints(min_length=1, max_length=255)]


class CVSSOut(ResponseModel):
    vector: str
    score: float
    severity: Severity
    version: Literal["3.1", "4.0"]
