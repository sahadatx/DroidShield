"""Strict analyst workflow contracts, separate from automated execution."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from droidshield.schemas import RequestModel, ResponseModel, Revision

Platform = Literal["android", "ios"]
Text = Annotated[str, StringConstraints(min_length=10, max_length=20_000)]
Environment = Annotated[str, StringConstraints(min_length=3, max_length=2000)]
ToolName = Annotated[str, StringConstraints(min_length=1, max_length=128)]
IDs = Annotated[list[UUID], Field(max_length=100)]
Severity = Literal["critical", "high", "medium", "low", "info"]


class Tool(RequestModel):
    name: ToolName
    version: ToolName


class ManualStart(RequestModel):
    revision: Revision
    platform: Platform
    environment: Environment
    tools: list[Tool] = Field(min_length=1, max_length=20)
    limitations: Text


class ManualFinish(RequestModel):
    revision: Revision
    summary: Annotated[str, StringConstraints(min_length=20, max_length=20_000)]


class AssessmentReview(RequestModel):
    revision: Revision
    decision: Literal["complete", "return"]
    notes: Text


class EvidenceCreate(RequestModel):
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    content: Annotated[str, StringConstraints(min_length=10, max_length=65_536)]
    sanitized: Literal[True]
    platform: Platform
    tool: ToolName
    tool_version: ToolName
    environment: Environment
    artifact_id: UUID | None = None
    finding_id: UUID | None = None
    release_ref: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None

    @field_validator("sanitized", mode="before")
    @classmethod
    def explicit_sanitization(cls, value):
        if value is not True:
            raise ValueError("Explicit sanitization confirmation is required")
        return value


class EvidenceAttachmentCreate(RequestModel):
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    sanitized: Literal[True]
    platform: Platform
    tool: ToolName
    tool_version: ToolName
    environment: Environment
    artifact_id: UUID | None = None
    finding_id: UUID | None = None
    release_ref: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None

    @field_validator("sanitized", mode="before")
    @classmethod
    def explicit_sanitization(cls, value):
        if value is not True:
            raise ValueError("Explicit sanitization confirmation is required")
        return value


class EvidenceAttachmentOut(ResponseModel):
    sha256: str
    file_size: int
    media_type: Literal["image/png"]
    display_name: Literal["screenshot.png"]


class EvidenceOut(ResponseModel):
    id: UUID
    project_id: UUID
    assessment_id: UUID
    finding_id: UUID | None
    release_ref: str | None
    artifact_id: UUID | None
    title: str
    sha256: str
    file_size: int
    platform: Platform
    tool: str
    tool_version: str
    environment: str
    redaction_count: int
    created_by: UUID
    created_at: datetime
    sanitized: Literal[True] = True
    attachment: EvidenceAttachmentOut | None = None


def _masvs_mappings(value):
    from droidshield.methodology import library

    allowed = {
        reference["id"]
        for case in library()["cases"]
        for reference in case["references"]
        if reference["framework"] == "MASVS"
    }
    if value is not None and (len(value) != len(set(value)) or not set(value) <= allowed):
        raise ValueError("Use unique controls from the pinned MASVS 2.1.0 library")
    return value


class FindingCreate(RequestModel):
    title: Annotated[str, StringConstraints(min_length=3, max_length=200)]
    description: Text
    affected_component: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    category: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    severity: Severity
    reproduction_steps: Text
    impact: Text
    remediation: Text
    cvss_vector: Annotated[str, StringConstraints(max_length=255)] | None = None
    cvss_score: Annotated[float, Field(strict=True, ge=0, le=10, allow_inf_nan=False)] | None = None
    masvs_mapping: list[Annotated[str, StringConstraints(pattern=r"^MASVS-[A-Z]+-[0-9]+$")]] = (
        Field(default_factory=list, max_length=50)
    )
    cwe_mapping: list[Annotated[str, StringConstraints(pattern=r"^CWE-[0-9]{1,6}$")]] = Field(
        default_factory=list, max_length=50
    )
    evidence_ids: IDs = Field(default_factory=list)

    @field_validator("masvs_mapping")
    @classmethod
    def known_masvs(cls, value):
        return _masvs_mappings(value)

    @model_validator(mode="after")
    def cvss_valid(self):
        from droidshield.cvss_scoring import validate_cvss

        validate_cvss(self.cvss_vector, self.cvss_score)
        return self


class FindingUpdate(RequestModel):
    revision: Revision
    title: Annotated[str, StringConstraints(min_length=3, max_length=200)] | None = None
    description: Text | None = None
    affected_component: Annotated[str, StringConstraints(min_length=1, max_length=1024)] | None = (
        None
    )
    category: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    severity: Severity | None = None
    reproduction_steps: Text | None = None
    impact: Text | None = None
    remediation: Text | None = None
    cvss_vector: Annotated[str, StringConstraints(max_length=255)] | None = None
    cvss_score: Annotated[float, Field(strict=True, ge=0, le=10, allow_inf_nan=False)] | None = None
    masvs_mapping: (
        list[Annotated[str, StringConstraints(pattern=r"^MASVS-[A-Z]+-[0-9]+$")]] | None
    ) = Field(default=None, max_length=50)
    cwe_mapping: list[Annotated[str, StringConstraints(pattern=r"^CWE-[0-9]{1,6}$")]] | None = (
        Field(default=None, max_length=50)
    )
    evidence_ids: IDs | None = None
    remediation_status: (
        Literal["open", "in_progress", "accepted_risk", "retest_required"] | None
    ) = None

    @field_validator("masvs_mapping")
    @classmethod
    def known_masvs(cls, value):
        return _masvs_mappings(value)

    @model_validator(mode="after")
    def changes_valid(self):
        if len(self.model_fields_set) < 2:
            raise ValueError("At least one change is required")
        for field in self.model_fields_set - {"cvss_vector", "cvss_score"}:
            if getattr(self, field) is None:
                raise ValueError("This field cannot be null")
        if ("cvss_vector" in self.model_fields_set) != ("cvss_score" in self.model_fields_set):
            raise ValueError("Supply both CVSS vector and score")
        if "cvss_vector" in self.model_fields_set:
            from droidshield.cvss_scoring import validate_cvss

            validate_cvss(self.cvss_vector, self.cvss_score)
        return self


class FindingReview(RequestModel):
    revision: Revision
    decision: Literal["confirmed", "false_positive", "needs_more_evidence"]
    notes: Text


class CoverageUpdate(RequestModel):
    revision: Revision | None = None
    status: Literal["not_run", "pass", "fail", "na", "blocked"]
    platform: Platform
    environment: Environment
    tool: ToolName
    tool_version: ToolName
    notes: Text
    evidence_ids: IDs = Field(default_factory=list)
    finding_ids: IDs = Field(default_factory=list)

    @model_validator(mode="after")
    def supporting_records(self):
        if self.status in {"pass", "fail"} and not self.evidence_ids:
            raise ValueError("Pass or Fail requires sanitized evidence")
        if self.status == "fail" and not self.finding_ids:
            raise ValueError("Fail requires a linked finding")
        return self


class ExecutionOut(ResponseModel):
    id: UUID
    revision: int
    assessment_id: UUID
    case_id: str
    status: str
    platform: Platform
    environment: str
    tool: str
    tool_version: str
    notes: str
    evidence_ids: list[str]
    finding_ids: list[str]
    operator_id: UUID
    contributors: list[str]
    created_at: datetime
    updated_at: datetime


class RetestCreate(RequestModel):
    new_artifact_id: UUID | None = None
    original_release_ref: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = (
        None
    )
    new_release_ref: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    authorization_id: UUID
    method: Literal["static", "dynamic", "api", "manual"]
    platform: Platform
    environment: Environment
    tool: ToolName
    tool_version: ToolName
    evidence_ids: IDs = Field(min_length=1, max_length=100)
    result: Literal["pass", "fail", "inconclusive", "not_reproducible"]
    notes: Text

    @model_validator(mode="after")
    def build_reference(self):
        if self.new_artifact_id is None:
            if self.method != "api" or not self.original_release_ref or not self.new_release_ref:
                raise ValueError("API-only retesting requires original and new release references")
            if self.original_release_ref == self.new_release_ref:
                raise ValueError("Retesting requires a different release")
        elif self.original_release_ref is not None or self.new_release_ref is not None:
            raise ValueError("Application build retesting uses immutable artifacts")
        return self


class RetestReview(RequestModel):
    revision: Revision
    finding_revision: Revision
    decision: Literal["approve", "reject"]
    notes: Text


class RetestEnvironment(ResponseModel):
    platform: Platform
    environment: str
    tool: str
    tool_version: str
    authorization_id: UUID
    authorization_revision: int
    artifact_sha256: str | None
    original_release_ref: str | None = None
    new_release_ref: str | None = None
    review_notes: str | None = None


class RetestOut(ResponseModel):
    id: UUID
    revision: int
    project_id: UUID
    finding_id: UUID
    original_assessment_id: UUID
    new_artifact_id: UUID | None
    method: str
    operator_id: UUID
    environment: RetestEnvironment
    previous_evidence: list[str]
    new_evidence: list[str]
    result: str
    notes: str | None
    reviewer_id: UUID | None
    reviewed_at: datetime | None
    review_decision: Literal["approve", "reject"] | None
    created_at: datetime
