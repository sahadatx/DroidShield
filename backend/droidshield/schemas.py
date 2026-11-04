"""Validated request contracts and explicitly allowlisted response contracts.

ArtifactCreate is a reserved pipeline contract, not a public upload endpoint.
Only trusted ingestion may persist a hash or protected storage reference.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Annotated, Generic, Literal, TypeVar
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    AliasChoices,
    AliasPath,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from droidshield.analysis_contract import (
    DexIndicator,
    DexSummary,
    ManifestIndicator,
    ManifestMetadata,
)
from droidshield.mobile_contract import AABMetadata, IPAMetadata
from droidshield.mobsf import MobSFIndicator, MobSFSummary

PACKAGE_PATTERN = r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
_PACKAGE = re.compile(PACKAGE_PATTERN)
BUNDLE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"
_BUNDLE = re.compile(BUNDLE_PATTERN)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,2047}\Z")

ClientType = Literal["company", "individual"]
ClientStatus = Literal["active", "archived"]
ProjectStatus = Literal["active", "on_hold", "archived"]
Framework = Literal["native", "flutter", "react_native", "other", "unknown"]
BuildType = Literal["debug", "release", "unknown"]
AssessmentType = Literal["static", "dynamic", "api", "full"]
AssessmentStatus = Literal[
    "draft",
    "awaiting_authorization",
    "queued",
    "running",
    "needs_review",
    "completed",
    "failed",
    "cancelled",
]
Name = Annotated[str, StringConstraints(min_length=1, max_length=200)]
ShortText = Annotated[str, StringConstraints(max_length=255)]
Notes = Annotated[str, StringConstraints(max_length=20_000)]
Reason = Annotated[str, StringConstraints(min_length=1, max_length=2_000)]
Revision = Annotated[int, Field(strict=True, ge=1)]
PackageID = Annotated[str, StringConstraints(min_length=3, max_length=255)]


def validate_app_identity(value: str, platform: str) -> str:
    pattern = _BUNDLE if platform == "ios" else _PACKAGE
    if not pattern.fullmatch(value):
        raise ValueError(
            "Provide a valid Android package ID or iOS bundle ID for the selected platform"
        )
    return value


def _normalize_url(value: str, *, https_only: bool) -> str:
    """Normalize addresses without accepting credentials or parser ambiguity."""
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("URL must not contain whitespace or control characters")
    if "\\" in value:
        raise ValueError("URL must not contain backslashes")
    try:
        parts = urlsplit(value)
        allowed_schemes = {"https"} if https_only else {"http", "https"}
        if parts.scheme.lower() not in allowed_schemes or not parts.hostname:
            raise ValueError("URL must have an allowed scheme and hostname")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Use a protected secret reference instead of URL credentials")
        hostname = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parts.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Provide a valid HTTP(S) URL without credentials") from exc
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253 or not all(
            _DNS_LABEL.fullmatch(label) for label in hostname.split(".")
        ):
            raise ValueError("Provide a valid hostname") from None
        host = hostname
    else:
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    scheme = parts.scheme.lower()
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port must be between 1 and 65535")
    if port is not None and port != (443 if scheme == "https" else 80):
        host += f":{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, parts.fragment))


def normalize_http_url(value: str) -> str:
    return _normalize_url(value, https_only=False)


def validate_target(value: str) -> str:
    """An exact target is a package ID or an unambiguous HTTPS endpoint.

    This normalizes identifiers only. A syntactically valid target never grants
    permission to test it; services must check the verified authorization.
    """
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError("Target must contain between 1 and 2048 characters")
    if any(character in value for character in "*?{}"):
        raise ValueError("Targets must be exact and must not contain wildcard expressions")
    if value.startswith(("package:", "bundle:")):
        prefix, package = value.split(":", 1)
        if len(package) > 255:
            raise ValueError("App target identifier is too long")
        validate_app_identity(package, "ios" if prefix == "bundle" else "android")
        return value
    if "#" in value:
        raise ValueError("Target URLs must not contain fragments")
    normalized = _normalize_url(value, https_only=True)
    path = urlsplit(normalized).path
    if "//" in path or ";" in path or not path.isascii():
        raise ValueError("Target paths must use unambiguous ASCII path segments")
    if any(character in path for character in "%[]") or any(
        segment in {".", ".."} for segment in path.split("/")
    ):
        raise ValueError("Target paths must not contain encoded or relative path segments")
    return normalized


def validate_evidence_reference(value: str) -> str:
    if (
        not _REFERENCE.fullmatch(value)
        or "://" in value
        or value.lower().startswith("file:")
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("Provide a bounded evidence reference, not inline content or a file path")
    return value


HttpAddress = Annotated[
    str, StringConstraints(min_length=1, max_length=2048), AfterValidator(normalize_http_url)
]
Target = Annotated[str, AfterValidator(validate_target)]
EvidenceReference = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2048),
    AfterValidator(validate_evidence_reference),
]


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, from_attributes=True)

    @field_validator("*", mode="after")
    @classmethod
    def utc_timestamps(cls, value: object) -> object:
        # SQLite returns naive datetimes; persisted timestamps always represent UTC.
        if isinstance(value, datetime):
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return value


Output = TypeVar("Output", bound=ResponseModel)


class Page(ResponseModel, Generic[Output]):
    items: list[Output]
    total: int
    limit: int
    offset: int


class OverviewActivityOut(ResponseModel):
    """Safe, project-scoped activity for the Overview dashboard."""

    id: UUID
    timestamp: datetime
    actor_id: UUID | None
    action: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    resource_type: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    resource_id: UUID | None
    result: Literal["success", "failure"]


class OverviewPendingActionsOut(ResponseModel):
    """Persisted review queues that currently need an independent decision."""

    assessment_reviews: int
    report_reviews: int
    retest_reviews: int
    total: int


class OverviewOut(ResponseModel):
    """Workspace and accessible-project counts used by dashboard cards."""

    total_clients: int
    active_clients: int
    archived_clients: int
    total_projects: int
    active_projects: int
    on_hold_projects: int
    archived_projects: int
    total_assessments: int
    in_progress: int
    queued_assessments: int
    pending_reviews: int
    completed_assessments: int
    failed_assessments: int
    total_artifacts: int
    artifact_formats: dict[Literal["apk", "aab", "ipa"], int]
    total_findings: int
    open_findings: int
    confirmed_findings: int
    unreviewed_findings: int
    critical_findings: int
    high_findings: int
    severity: dict[Literal["critical", "high", "medium", "low", "info"], int]
    total_reports: int
    reports_awaiting_review: int
    reports_approved: int
    reports_exported: int
    total_retests: int
    retests_awaiting_review: int
    retests_approved: int
    retests_rejected: int
    retests_pass: int
    retests_fail: int
    total_dynamic_sessions: int
    dynamic_sessions_queued: int
    dynamic_sessions_running: int
    dynamic_sessions_completed: int
    dynamic_sessions_failed: int
    total_api_targets: int
    total_api_executions: int
    api_executions_queued: int
    api_executions_running: int
    api_executions_completed: int
    api_executions_failed: int
    recent_activity: list[OverviewActivityOut]
    pending_actions: OverviewPendingActionsOut


class AuditEventOut(ResponseModel):
    id: UUID
    timestamp: datetime
    actor_id: UUID | None
    action: str
    resource_type: str
    resource_id: UUID | None
    result: Literal["success", "failure"]
    request_id: str
    source: dict[str, str]


class AuditEventSummaryOut(ResponseModel):
    success: int
    failure: int


class AuditEventsPageOut(ResponseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int
    summary: AuditEventSummaryOut


class ClientDirectoryMetricsOut(ResponseModel):
    client_id: UUID
    active_projects: int
    assessment_count: int
    last_activity: datetime


class ProjectDirectoryMetricsOut(ResponseModel):
    project_id: UUID
    assessment_count: int
    latest_version: str | None
    last_assessment_at: datetime | None


class DirectoryMetricsOut(ResponseModel):
    clients: list[ClientDirectoryMetricsOut]
    projects: list[ProjectDirectoryMetricsOut]


class ClientCreate(RequestModel):
    client_type: ClientType = "company"
    name: Name
    organization_name: ShortText | None = None
    website: HttpAddress | None = None
    contact_person: ShortText | None = None
    contact_email: EmailStr | None = None
    phone: Annotated[str, StringConstraints(max_length=64)] | None = None
    notes: Notes | None = None
    status: ClientStatus = "active"
    archive_reason: Reason | None = None

    @model_validator(mode="after")
    def archived_reason(self) -> ClientCreate:
        if self.status == "archived" and not self.archive_reason:
            raise ValueError("archive_reason is required when the client is archived")
        return self


class ClientUpdate(RequestModel):
    revision: Revision
    client_type: ClientType | None = None
    name: Name | None = None
    organization_name: ShortText | None = None
    website: HttpAddress | None = None
    contact_person: ShortText | None = None
    contact_email: EmailStr | None = None
    phone: Annotated[str, StringConstraints(max_length=64)] | None = None
    notes: Notes | None = None
    status: ClientStatus | None = None
    archive_reason: Reason | None = None

    @model_validator(mode="after")
    def required_fields_cannot_be_cleared(self) -> ClientUpdate:
        for field in ("client_type", "name", "status"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        # Archive validation needs the existing record and is enforced after merge.
        return self


class ProjectCreate(RequestModel):
    client_id: UUID
    name: Name
    application_name: Name
    package_id: PackageID
    platform: Literal["android", "ios"] = "android"
    framework: Framework = "unknown"
    repository_url: HttpAddress | None = None
    description: Notes | None = None
    scope_notes: Notes | None = None
    status: ProjectStatus = "active"
    archive_reason: Reason | None = None

    @model_validator(mode="after")
    def archived_reason(self) -> ProjectCreate:
        validate_app_identity(self.package_id, self.platform)
        if self.status == "archived" and not self.archive_reason:
            raise ValueError("archive_reason is required when the project is archived")
        return self


class ProjectUpdate(RequestModel):
    revision: Revision
    name: Name | None = None
    application_name: Name | None = None
    package_id: PackageID | None = None
    platform: Literal["android", "ios"] | None = None
    framework: Framework | None = None
    repository_url: HttpAddress | None = None
    description: Notes | None = None
    scope_notes: Notes | None = None
    status: ProjectStatus | None = None
    archive_reason: Reason | None = None

    @model_validator(mode="after")
    def required_fields_cannot_be_cleared(self) -> ProjectUpdate:
        for field in ("name", "application_name", "package_id", "platform", "framework", "status"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class ProjectMemberAdd(RequestModel):
    user_id: UUID


class ArtifactCreate(RequestModel):
    """Reserved metadata contract; a claim is never proof of an uploaded file."""

    version_name: ShortText | None = None
    version_code: Annotated[int, Field(strict=True, ge=0)] | None = None
    sha256: Annotated[str, StringConstraints(min_length=64, max_length=64)]
    file_size: Annotated[int, Field(strict=True, gt=0, le=2 * 1024**3)]
    original_filename: Annotated[str, StringConstraints(min_length=5, max_length=255)]
    build_type: BuildType = "unknown"

    @field_validator("sha256")
    @classmethod
    def normalize_hash(cls, value: str) -> str:
        value = value.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        return value

    @field_validator("original_filename")
    @classmethod
    def apk_basename(cls, value: str) -> str:
        if "/" in value or "\\" in value or not value.lower().endswith(".apk"):
            raise ValueError("Provide an APK basename without directory components")
        if any(ord(character) < 32 for character in value):
            raise ValueError("Filename must not contain control characters")
        return value


class AuthorizationCreate(RequestModel):
    approved_targets: Annotated[list[Target], Field(min_length=1, max_length=100)]
    exclusions: Annotated[list[Target], Field(max_length=100)] = Field(default_factory=list)
    evidence_ref: EvidenceReference
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    notes: Notes | None = None

    @field_validator("valid_from", "valid_until")
    @classmethod
    def as_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("approved_targets", "exclusions")
    @classmethod
    def unique_targets(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("Target lists must not contain duplicate normalized targets")
        return value

    @model_validator(mode="after")
    def valid_window(self) -> AuthorizationCreate:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class AuthorizationVerify(RequestModel):
    revision: Revision


class AuthorizationRevoke(RequestModel):
    revision: Revision
    reason: Reason


class AssessmentCreate(RequestModel):
    project_id: UUID
    artifact_id: UUID | None = None
    authorization_id: UUID | None = None
    name: Name
    assessment_type: AssessmentType
    requested_targets: Annotated[list[Target], Field(min_length=1, max_length=100)]
    engine: Literal["manifest", "dex", "mobsf"] = "manifest"

    @model_validator(mode="after")
    def static_engine_only(self):
        if self.assessment_type != "static" and self.engine != "manifest":
            raise ValueError("Engine selection applies to Static assessments")
        return self

    @field_validator("requested_targets")
    @classmethod
    def unique_targets(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("Target lists must not contain duplicate normalized targets")
        return value


class AssessmentQueue(RequestModel):
    revision: Revision


class AssessmentUpdate(RequestModel):
    revision: Revision
    engine: Literal["manifest", "dex", "mobsf"] | None = None
    name: Name | None = None
    artifact_id: UUID | None = None
    authorization_id: UUID | None = None
    requested_targets: Annotated[list[Target], Field(min_length=1, max_length=100)] | None = None

    @field_validator("requested_targets")
    @classmethod
    def unique_targets(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("Target lists must not contain duplicate normalized targets")
        return value

    @model_validator(mode="after")
    def required_fields_cannot_be_cleared(self) -> AssessmentUpdate:
        for field in ("name", "requested_targets", "engine"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class AssessmentSubmit(RequestModel):
    revision: Revision


class AssessmentCancel(RequestModel):
    revision: Revision
    reason: Reason


class ArchiveRequest(RequestModel):
    revision: Revision
    reason: Reason


class MeOut(ResponseModel):
    id: UUID
    workspace_id: UUID
    workspace_name: str | None = None
    email: str
    full_name: str
    role: Literal["ADMIN", "SECURITY_ANALYST", "VIEWER"]
    status: Literal["active", "disabled"]


UserRole = Literal["ADMIN", "SECURITY_ANALYST", "VIEWER"]
UserStatus = Literal["active", "disabled"]


class WorkspaceUserCreate(RequestModel):
    full_name: Name
    email: EmailStr
    role: UserRole

    @field_validator("email")
    @classmethod
    def normalized_email(cls, value: EmailStr) -> str:
        return str(value).lower()


class WorkspaceUserUpdate(RequestModel):
    role: UserRole | None = None
    status: UserStatus | None = None

    @model_validator(mode="after")
    def require_non_null_change(self):
        if not self.model_fields_set:
            raise ValueError("Provide a role or status change")
        for field in ("role", "status"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class UserSessionRevoke(RequestModel):
    """Empty, strict request body used to make session revocation idempotent."""


class WorkspaceUserOut(ResponseModel):
    id: UUID
    workspace_id: UUID
    email: EmailStr
    full_name: str
    role: UserRole
    status: UserStatus
    created_at: datetime
    updated_at: datetime


class WorkspaceSecretStatusOut(ResponseModel):
    configured: bool


class WorkspaceSecretReferencesOut(ResponseModel):
    mobsf_service: WorkspaceSecretStatusOut
    api_secret_store: WorkspaceSecretStatusOut
    frida_runtime: WorkspaceSecretStatusOut
    proxy_certificate_authority: WorkspaceSecretStatusOut


class WorkspaceSettingsOut(ResponseModel):
    workspace_id: UUID
    workspace_name: str
    display_timezone: str
    date_format: Literal["iso", "dmy", "mdy"]
    default_report_template: Literal["executive", "technical", "combined"]
    report_branding_name: str | None
    revision: int
    updated_at: datetime | None
    secret_references: WorkspaceSecretReferencesOut


class WorkspaceSettingsUpdate(RequestModel):
    revision: Revision
    workspace_name: Annotated[str, StringConstraints(min_length=1, max_length=255)] | None = None
    display_timezone: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    date_format: Literal["iso", "dmy", "mdy"] | None = None
    default_report_template: Literal["executive", "technical", "combined"] | None = None
    report_branding_name: Annotated[str, StringConstraints(min_length=1, max_length=255)] | None = (
        None
    )

    @field_validator("display_timezone")
    @classmethod
    def valid_timezone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            ZoneInfo(value)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise ValueError("Use a recognized IANA time zone") from exc
        return value

    @model_validator(mode="after")
    def require_editable_change(self):
        editable = self.model_fields_set - {"revision"}
        if not editable:
            raise ValueError("Provide at least one settings change")
        for field in (
            "workspace_name",
            "display_timezone",
            "date_format",
            "default_report_template",
        ):
            if field in editable and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class PasswordLogin(RequestModel):
    email: EmailStr
    password: SecretStr

    @field_validator("email")
    @classmethod
    def normalized_email(cls, value: EmailStr) -> str:
        return str(value).lower()

    @field_validator("password")
    @classmethod
    def bounded_password(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) > 1024:
            raise ValueError("Password is too long")
        return value


class AuthSessionOut(ResponseModel):
    user: MeOut
    csrf_token: Annotated[str, StringConstraints(min_length=32, max_length=128)]


class RecordOut(ResponseModel):
    id: UUID
    workspace_id: UUID
    created_at: datetime
    created_by: UUID


class MutableRecordOut(RecordOut):
    updated_at: datetime
    revision: int


class ClientOut(MutableRecordOut):
    client_type: ClientType
    name: str
    organization_name: str | None
    website: str | None
    contact_person: str | None
    contact_email: str | None
    phone: str | None
    notes: str | None
    status: ClientStatus
    archive_reason: str | None


class ProjectOut(MutableRecordOut):
    client_id: UUID
    name: str
    application_name: str
    package_id: str
    platform: Literal["android", "ios"]
    framework: Framework
    repository_url: str | None
    description: str | None
    scope_notes: str | None
    status: ProjectStatus
    archive_reason: str | None


class ArtifactOut(RecordOut):
    project_id: UUID
    version_name: str | None
    version_code: int | None
    sha256: str
    original_filename: str
    file_size: int
    build_type: BuildType
    platform: Literal["android", "ios"] = Field(
        default="android", validation_alias=AliasPath("metadata_json", "platform")
    )
    artifact_format: Literal["apk", "aab", "ipa"] = Field(
        default="apk", validation_alias=AliasPath("metadata_json", "artifact_format")
    )


class ArtifactDetailOut(ArtifactOut):
    metadata: ManifestMetadata | AABMetadata | IPAMetadata = Field(validation_alias="metadata_json")


class AnalysisJobOut(ResponseModel):
    id: UUID
    assessment_id: UUID
    artifact_id: UUID | None
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    attempt_count: int
    started_at: datetime | None
    completed_at: datetime | None
    heartbeat_at: datetime | None
    failure_reason: str | None
    cancellation_reason: str | None
    created_at: datetime
    updated_at: datetime


class AnalysisOut(ResponseModel):
    id: UUID
    project_id: UUID
    assessment_id: UUID
    artifact_id: UUID
    job_id: UUID
    engine_version: str
    schema_version: int
    artifact_sha256: str
    metadata: ManifestMetadata = Field(validation_alias="metadata_json")
    indicators: list[ManifestIndicator | DexIndicator | MobSFIndicator] = Field(
        validation_alias="indicators_json"
    )
    limitations: list[str] = Field(validation_alias="limitations_json")
    dex_summary: DexSummary | None = Field(
        default=None, validation_alias=AliasPath("metadata_json", "_dex_summary")
    )
    mobsf_summary: MobSFSummary | None = Field(
        default=None, validation_alias=AliasPath("metadata_json", "_mobsf_summary")
    )
    requires_review: Literal[True] = True
    created_at: datetime

    @field_validator("metadata", mode="before")
    @classmethod
    def manifest_only(cls, value):
        if isinstance(value, dict):
            return {
                key: item for key, item in value.items() if key in ManifestMetadata.model_fields
            }
        return value


class FindingSummaryOut(ResponseModel):
    id: UUID
    project_id: UUID
    assessment_id: UUID
    artifact_id: UUID | None
    title: str
    affected_component: str
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    verification_status: Literal["unreviewed", "confirmed", "false_positive", "needs_more_evidence"]
    remediation_status: Literal["open", "in_progress", "fixed", "accepted_risk", "retest_required"]
    created_at: datetime


class FindingDetailOut(FindingSummaryOut):
    revision: int
    created_by: UUID
    description: str
    reproduction_steps: str
    impact: str
    remediation: str
    evidence_provenance: dict
    cvss_vector: str | None
    cvss_score: float | None
    masvs_mapping: list[str]
    cwe_mapping: list[str]
    assigned_reviewer: UUID | None


class AuthorizationOut(MutableRecordOut):
    project_id: UUID
    status: Literal["pending", "verified", "revoked"]
    approved_targets: list[str]
    exclusions: list[str]
    evidence_ref: str
    valid_from: datetime
    valid_until: datetime
    notes: str | None
    verified_by: UUID | None
    verified_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None


class AssessmentOut(MutableRecordOut):
    project_id: UUID
    artifact_id: UUID | None
    authorization_id: UUID | None
    name: str
    assessment_type: AssessmentType
    status: AssessmentStatus
    execution_mode: Literal["analyst_record"] | None = Field(
        default=None, validation_alias=AliasPath("configuration_snapshot", "manual", "mode")
    )
    manual_summary: str | None = Field(
        default=None, validation_alias=AliasPath("configuration_snapshot", "manual", "summary")
    )
    engine: Literal["manifest", "dex", "mobsf"] = Field(
        default="manifest",
        validation_alias=AliasChoices("engine", AliasPath("configuration_snapshot", "engine")),
    )
    requested_targets: list[str] = Field(
        validation_alias=AliasChoices(
            "requested_targets", AliasPath("configuration_snapshot", "requested_targets")
        )
    )
    reviewer_id: UUID | None
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    failure_reason: str | None
    cancellation_reason: str | None
