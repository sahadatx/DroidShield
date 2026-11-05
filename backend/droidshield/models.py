"""Workspace-scoped persistence models for DroidShield.

Files, credentials, and raw scanner output live outside the relational database.
These records retain references, normalized results, immutable snapshots, and
provenance. Foreign keys deliberately restrict deletion instead of cascading
through assessment history or audit records.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_name)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class IdentityMixin:
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)


class WorkspaceMixin:
    workspace_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("workspaces.id", ondelete="RESTRICT"), index=True
    )


class CreatedMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UpdatedMixin:
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class RevisionMixin:
    revision: Mapped[int] = mapped_column(Integer, default=1)

    @declared_attr.directive
    def __mapper_args__(cls) -> dict[str, Any]:
        return {"version_id_col": cls.revision}


def user_reference(column: str) -> ForeignKeyConstraint:
    """Require the referenced account to belong to the record's workspace."""
    return ForeignKeyConstraint(
        ["workspace_id", column],
        ["users.workspace_id", "users.id"],
        name=f"fk_user_{column}",
        ondelete="RESTRICT",
    )


class Workspace(IdentityMixin, CreatedMixin, Base):
    __tablename__ = "workspaces"

    name: Mapped[str] = mapped_column(String(255))

    __table_args__ = (CheckConstraint("length(trim(name)) > 0", name="name_required"),)


class User(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320))
    full_name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="VIEWER")
    status: Mapped[str] = mapped_column(String(16), default="active")

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_users_workspace_id"),
        UniqueConstraint("workspace_id", "email", name="uq_users_workspace_email"),
        CheckConstraint("role IN ('ADMIN', 'SECURITY_ANALYST', 'VIEWER')", name="role"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint("length(trim(full_name)) > 0", name="full_name_required"),
        CheckConstraint(
            "length(trim(email)) > 0 AND email = lower(email)", name="normalized_email"
        ),
    )


class WorkspaceSettings(IdentityMixin, WorkspaceMixin, UpdatedMixin, RevisionMixin, Base):
    """Allowlisted workspace display and report defaults, not runtime secrets."""

    __tablename__ = "workspace_settings"

    updated_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    display_timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    date_format: Mapped[str] = mapped_column(String(16), default="iso")
    default_report_template: Mapped[str] = mapped_column(String(16), default="combined")
    report_branding_name: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        UniqueConstraint("workspace_id", name="workspace_unique"),
        user_reference("updated_by"),
        CheckConstraint(
            "length(trim(display_timezone)) > 0 AND length(display_timezone) <= 64",
            name="timezone_required",
        ),
        CheckConstraint("date_format IN ('iso', 'dmy', 'mdy')", name="date_format"),
        CheckConstraint(
            "default_report_template IN ('executive', 'technical', 'combined')",
            name="report_template",
        ),
        CheckConstraint(
            "report_branding_name IS NULL OR length(trim(report_branding_name)) > 0",
            name="branding_name",
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
    )


class AccessToken(IdentityMixin, CreatedMixin, Base):
    __tablename__ = "access_tokens"

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (CheckConstraint("length(token_hash) >= 64", name="token_hash_length"),)


class Client(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    __tablename__ = "clients"

    client_type: Mapped[str] = mapped_column(String(16), default="company")
    name: Mapped[str] = mapped_column(String(255))
    organization_name: Mapped[str | None] = mapped_column(String(255))
    website: Mapped[str | None] = mapped_column(String(2048))
    contact_person: Mapped[str | None] = mapped_column(String(255))
    contact_email: Mapped[str | None] = mapped_column(String(320))
    phone: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")
    archive_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_clients_workspace_id"),
        user_reference("created_by"),
        CheckConstraint("client_type IN ('company', 'individual')", name="client_type"),
        CheckConstraint("status IN ('active', 'archived')", name="status"),
        CheckConstraint("length(trim(name)) > 0", name="name_required"),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint(
            "status != 'archived' OR (archive_reason IS NOT NULL AND length(trim(archive_reason)) > 0)",
            name="archive_reason_required",
        ),
        Index("ix_clients_workspace_status", "workspace_id", "status"),
    )


class Project(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    __tablename__ = "projects"

    client_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255))
    application_name: Mapped[str] = mapped_column(String(255))
    package_id: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(16), default="android", server_default="android")
    framework: Mapped[str] = mapped_column(String(32), default="unknown")
    repository_url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)
    scope_notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")
    archive_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_projects_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint(
            "framework IN ('native', 'flutter', 'react_native', 'other', 'unknown')",
            name="framework",
        ),
        CheckConstraint("status IN ('active', 'on_hold', 'archived')", name="status"),
        CheckConstraint("length(trim(name)) > 0", name="name_required"),
        CheckConstraint("length(trim(application_name)) > 0", name="application_name_required"),
        CheckConstraint("length(trim(package_id)) > 0", name="package_id_required"),
        CheckConstraint("platform IN ('android', 'ios')", name="platform"),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint(
            "status != 'archived' OR (archive_reason IS NOT NULL AND length(trim(archive_reason)) > 0)",
            name="archive_reason_required",
        ),
        Index("ix_projects_workspace_status", "workspace_id", "status"),
    )


_sha256_characters_removed = "sha256"
for _character in "0123456789abcdef":
    _sha256_characters_removed = f"replace({_sha256_characters_removed}, '{_character}', '')"
_sha256_check = f"length(sha256) = 64 AND {_sha256_characters_removed} = ''"


class AppArtifact(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "app_artifacts"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    version_name: Mapped[str | None] = mapped_column(String(255))
    version_code: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    storage_ref: Mapped[str] = mapped_column(String(2048))
    original_filename: Mapped[str] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(Integer)
    build_type: Mapped[str] = mapped_column(String(16), default="unknown")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_artifacts_workspace_id"),
        UniqueConstraint("workspace_id", "project_id", "id", name="uq_artifacts_project_id"),
        UniqueConstraint("project_id", "sha256", name="uq_artifacts_project_sha256"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint(
            "version_code IS NULL OR version_code >= 0", name="version_code_nonnegative"
        ),
        CheckConstraint("file_size > 0", name="file_size_positive"),
        CheckConstraint(_sha256_check, name="sha256_lower_hex"),
        CheckConstraint("length(trim(storage_ref)) > 0", name="storage_ref_required"),
        CheckConstraint("build_type IN ('debug', 'release', 'unknown')", name="build_type"),
    )


class ProjectAccess(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "project_access"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("project_id", "user_id", name="uq_project_access_project_user"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        user_reference("user_id"),
        user_reference("created_by"),
    )


class Authorization(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    __tablename__ = "authorizations"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    approved_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclusions: Mapped[list[str]] = mapped_column(JSON, default=list)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence_ref: Mapped[str] = mapped_column(String(2048))
    notes: Mapped[str | None] = mapped_column(Text)
    verified_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_authorizations_workspace_id"),
        UniqueConstraint("workspace_id", "project_id", "id", name="uq_authorizations_project_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        user_reference("verified_by"),
        CheckConstraint("status IN ('pending', 'verified', 'revoked')", name="status"),
        CheckConstraint("valid_until > valid_from", name="validity_window"),
        CheckConstraint("length(trim(evidence_ref)) > 0", name="evidence_required"),
        CheckConstraint(
            "status != 'verified' OR (verified_by IS NOT NULL AND verified_at IS NOT NULL)",
            name="verified_metadata_required",
        ),
        CheckConstraint(
            "status != 'revoked' OR revoked_at IS NOT NULL", name="revocation_time_required"
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
    )


class AuthorizationAttachment(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    """Private, immutable client approval document linked to one authorization."""

    __tablename__ = "authorization_attachments"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    authorization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    storage_ref: Mapped[str] = mapped_column(String(96))
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(32))
    display_name: Mapped[str] = mapped_column(String(120))
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_authorization_attachments_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "authorization_id"],
            ["authorizations.workspace_id", "authorizations.project_id", "authorizations.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint("file_size BETWEEN 1 AND 8388608", name="file_size"),
        CheckConstraint("length(trim(storage_ref)) > 0", name="storage_ref_required"),
        CheckConstraint(_sha256_check, name="sha256_lower_hex"),
        CheckConstraint(
            "media_type IN ('application/pdf', 'image/png', 'image/jpeg')", name="media_type"
        ),
        CheckConstraint("length(trim(display_name)) BETWEEN 1 AND 120", name="display_name"),
        Index(
            "ix_authorization_attachments_owner",
            "workspace_id",
            "project_id",
            "authorization_id",
        ),
    )


class Assessment(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    __tablename__ = "assessments"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    authorization_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    name: Mapped[str] = mapped_column(String(255))
    assessment_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), default="draft")
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    reviewer_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    cancellation_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_assessments_workspace_id"),
        UniqueConstraint("workspace_id", "project_id", "id", name="uq_assessments_project_id"),
        UniqueConstraint("workspace_id", "id", "artifact_id", name="uq_assessments_artifact_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "authorization_id"],
            ["authorizations.workspace_id", "authorizations.project_id", "authorizations.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        user_reference("reviewer_id"),
        CheckConstraint("length(trim(name)) > 0", name="name_required"),
        CheckConstraint(
            "assessment_type IN ('static', 'dynamic', 'api', 'full')", name="assessment_type"
        ),
        CheckConstraint(
            "status IN ('draft', 'awaiting_authorization', 'queued', 'running', 'needs_review', 'completed', 'failed', 'cancelled')",
            name="status",
        ),
        CheckConstraint(
            "status NOT IN ('queued', 'running') OR authorization_id IS NOT NULL",
            name="execution_authorization_required",
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
        Index("ix_assessments_workspace_status", "workspace_id", "status"),
    )


class AnalysisJob(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, Base):
    __tablename__ = "analysis_jobs"

    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    logs_ref: Mapped[str | None] = mapped_column(String(2048))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    cancellation_reason: Mapped[str | None] = mapped_column(Text)
    worker_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    __table_args__ = (
        Index("uq_jobs_api_origin", "workspace_id", "assessment_id", "id", unique=True),
        UniqueConstraint("workspace_id", "id", name="uq_jobs_workspace_id"),
        UniqueConstraint("assessment_id", name="uq_jobs_assessment_id"),
        UniqueConstraint(
            "workspace_id", "assessment_id", "artifact_id", "id", name="uq_jobs_result_origin"
        ),
        ForeignKeyConstraint(
            ["workspace_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "artifact_id"],
            ["assessments.workspace_id", "assessments.id", "assessments.artifact_id"],
            name="fk_jobs_assessment_artifact",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status"
        ),
        CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        Index("ix_jobs_workspace_status", "workspace_id", "status"),
        Index("ix_jobs_status_lease", "status", "lease_expires_at"),
    )


class AnalysisResult(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    """Immutable normalized engine output, separate from human verification."""

    __tablename__ = "analysis_results"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    engine_version: Mapped[str] = mapped_column(String(128))
    schema_version: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    indicators_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    limitations_json: Mapped[list[str]] = mapped_column(JSON)
    artifact_sha256: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_results_workspace_id"),
        UniqueConstraint("job_id", name="uq_results_job_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "artifact_id", "job_id"],
            [
                "analysis_jobs.workspace_id",
                "analysis_jobs.assessment_id",
                "analysis_jobs.artifact_id",
                "analysis_jobs.id",
            ],
            name="fk_results_job_origin",
            ondelete="RESTRICT",
        ),
        CheckConstraint("schema_version >= 1", name="schema_version_positive"),
        CheckConstraint("length(trim(engine_version)) > 0", name="engine_version_required"),
        CheckConstraint(
            _sha256_check.replace("sha256", "artifact_sha256"), name="artifact_sha256_lower_hex"
        ),
    )


class Finding(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    __tablename__ = "findings"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    affected_component: Mapped[str] = mapped_column(String(1024))
    category: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    verification_status: Mapped[str] = mapped_column(String(32), default="unreviewed")
    remediation_status: Mapped[str] = mapped_column(String(32), default="open")
    retest_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    masvs_mapping: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe_mapping: Mapped[list[str]] = mapped_column(JSON, default=list)
    reproduction_steps: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    evidence_provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    assigned_reviewer: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_findings_workspace_id"),
        UniqueConstraint(
            "workspace_id", "id", "assessment_id", name="uq_findings_original_assessment"
        ),
        UniqueConstraint(
            "workspace_id",
            "project_id",
            "id",
            "assessment_id",
            name="uq_findings_project_assessment",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        user_reference("assigned_reviewer"),
        CheckConstraint("length(trim(title)) > 0", name="title_required"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')", name="severity"
        ),
        CheckConstraint(
            "verification_status IN ('unreviewed', 'confirmed', 'false_positive', 'needs_more_evidence')",
            name="verification_status",
        ),
        CheckConstraint(
            "remediation_status IN ('open', 'in_progress', 'fixed', 'accepted_risk', 'retest_required')",
            name="remediation_status",
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)", name="cvss_range"
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
        Index("ix_findings_workspace_verification", "workspace_id", "verification_status"),
        Index("ix_findings_workspace_retest_due", "workspace_id", "retest_due_at"),
    )


class Evidence(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "evidence"

    finding_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_ref: Mapped[str] = mapped_column(String(2048))
    kind: Mapped[str] = mapped_column(String(64))
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "finding_id"],
            ["findings.workspace_id", "findings.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint("length(trim(artifact_ref)) > 0", name="artifact_ref_required"),
        CheckConstraint("length(trim(kind)) > 0", name="kind_required"),
    )


class Retest(IdentityMixin, WorkspaceMixin, CreatedMixin, RevisionMixin, Base):
    __tablename__ = "retests"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    finding_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    original_assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    review_decision: Mapped[str | None] = mapped_column(String(16))
    new_artifact_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    method: Mapped[str] = mapped_column(String(16))
    operator_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    environment: Mapped[dict[str, Any]] = mapped_column(JSON)
    previous_evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    new_evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    result: Mapped[str] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)
    reviewer_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "finding_id", "original_assessment_id"],
            [
                "findings.workspace_id",
                "findings.project_id",
                "findings.id",
                "findings.assessment_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "new_artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        user_reference("operator_id"),
        user_reference("reviewer_id"),
        CheckConstraint("method IN ('static', 'dynamic', 'api', 'manual')", name="method"),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint(
            "new_artifact_id IS NOT NULL OR method = 'api'", name="mobile_artifact_required"
        ),
        CheckConstraint(
            "review_decision IS NULL OR review_decision IN ('approve', 'reject')",
            name="review_decision",
        ),
        CheckConstraint(
            "result IN ('pass', 'fail', 'inconclusive', 'not_reproducible')", name="result"
        ),
        CheckConstraint(
            "(reviewer_id IS NULL AND reviewed_at IS NULL) OR (reviewer_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="reviewer_metadata_consistent",
        ),
    )


class Report(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "reports"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(255))
    template: Mapped[str] = mapped_column(String(16), default="combined")
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(24), default="draft")
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    branding: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reviewer_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    author_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    export_ref: Mapped[str | None] = mapped_column(String(2048))
    export_format: Mapped[str | None] = mapped_column(String(16))
    checksum: Mapped[str | None] = mapped_column(String(64))
    exported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_reports_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id"],
            ["projects.workspace_id", "projects.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        user_reference("author_id"),
        user_reference("reviewer_id"),
        CheckConstraint("length(trim(title)) > 0", name="title_required"),
        CheckConstraint("template IN ('executive', 'technical', 'combined')", name="template"),
        CheckConstraint(
            "status IN ('draft', 'awaiting_review', 'approved', 'exported')", name="status"
        ),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(
            "export_format IS NULL OR export_format IN ('pdf', 'json')", name="export_format"
        ),
        CheckConstraint(
            "status NOT IN ('approved', 'exported') OR (reviewer_id IS NOT NULL AND approved_at IS NOT NULL)",
            name="approval_required",
        ),
        CheckConstraint(
            "status != 'exported' OR (export_ref IS NOT NULL AND export_format IS NOT NULL AND checksum IS NOT NULL AND exported_at IS NOT NULL)",
            name="export_metadata_required",
        ),
    )


class AuditEvent(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "audit_events"

    actor_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    result: Mapped[str] = mapped_column(String(16))
    request_id: Mapped[str] = mapped_column(String(128), index=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    __table_args__ = (
        user_reference("actor_id"),
        CheckConstraint("result IN ('success', 'failure')", name="result"),
        CheckConstraint("length(trim(action)) > 0", name="action_required"),
        CheckConstraint("length(trim(request_id)) > 0", name="request_id_required"),
        Index("ix_audit_workspace_created", "workspace_id", "created_at"),
    )


class LoginRateLimitEntry(Base):
    """Short-lived, shared sign-in attempt window keyed by a hashed source address."""

    __tablename__ = "login_rate_limit_entries"

    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempt_times_us: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_login_rate_limit_entries_updated", "updated_at"),)


class IdempotencyRecord(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    __tablename__ = "idempotency_records"

    user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    key: Mapped[str] = mapped_column(String(128))
    operation: Mapped[str] = mapped_column(String(200))
    request_hash: Mapped[str] = mapped_column(String(64))
    response_resource_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "user_id", "key", name="uq_idempotency_workspace_user_key"
        ),
        user_reference("user_id"),
        CheckConstraint("length(key) BETWEEN 1 AND 128", name="key_length"),
        CheckConstraint("length(operation) BETWEEN 1 AND 200", name="operation_length"),
        CheckConstraint(
            _sha256_check.replace("sha256", "request_hash"), name="request_hash_lower_hex"
        ),
    )


class DynamicSession(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, Base):
    """One controlled runtime attempt per immutable assessment job."""

    __tablename__ = "dynamic_sessions"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    artifact_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), unique=True)
    device_id: Mapped[str] = mapped_column(String(128))
    scenario: Mapped[str] = mapped_column(String(32))
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    cancellation_reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_dynamic_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "artifact_id", "job_id"],
            [
                "analysis_jobs.workspace_id",
                "analysis_jobs.assessment_id",
                "analysis_jobs.artifact_id",
                "analysis_jobs.id",
            ],
            name="fk_dynamic_job_origin",
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint(
            "scenario IN ('launch_observe', 'package_inspection', 'frida_observe', 'proxy_observe')",
            name="scenario",
        ),
        CheckConstraint("timeout_seconds BETWEEN 10 AND 120", name="timeout"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status"
        ),
        Index("ix_dynamic_status_created", "status", "created_at"),
    )


class DynamicDeviceLease(Base):
    """Global device lock; crashed attempts quarantine devices until reprovisioned."""

    __tablename__ = "dynamic_device_leases"

    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    session_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("dynamic_sessions.id", ondelete="RESTRICT"), unique=True
    )
    worker_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quarantined: Mapped[bool] = mapped_column(default=False)


class APITarget(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    """Immutable approved endpoint and secret-reference configuration."""

    __tablename__ = "api_targets"
    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(200))
    endpoints: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    excluded_endpoints: Mapped[list[str]] = mapped_column(JSON)
    auth_method: Mapped[str] = mapped_column(String(16))
    primary_secret_ref: Mapped[str | None] = mapped_column(String(128))
    secondary_secret_ref: Mapped[str | None] = mapped_column(String(128))
    requests_per_minute: Mapped[int] = mapped_column(Integer)
    test_window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    test_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_api_targets_workspace_id"),
        UniqueConstraint("assessment_id", name="uq_api_targets_assessment_id"),
        UniqueConstraint(
            "workspace_id", "project_id", "assessment_id", "id", name="uq_api_targets_origin"
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint("length(trim(name)) > 0", name="name_required"),
        CheckConstraint(
            "auth_method IN ('none', 'bearer', 'api_key', 'cookie')", name="auth_method"
        ),
        CheckConstraint("requests_per_minute BETWEEN 1 AND 120", name="rate_limit"),
        CheckConstraint("test_window_end > test_window_start", name="test_window"),
    )


class APIExecution(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, Base):
    """A fenced HTTP execution and strictly normalized, write-once result."""

    __tablename__ = "api_executions"
    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON(none_as_null=True))
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON(none_as_null=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    cancellation_reason: Mapped[str | None] = mapped_column(String(64))
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_api_executions_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id", "target_id"],
            [
                "api_targets.workspace_id",
                "api_targets.project_id",
                "api_targets.assessment_id",
                "api_targets.id",
            ],
            name="fk_api_execution_target_origin",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "assessment_id", "job_id"],
            ["analysis_jobs.workspace_id", "analysis_jobs.assessment_id", "analysis_jobs.id"],
            name="fk_api_execution_job_origin",
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status"
        ),
        Index("ix_api_executions_status_created", "status", "created_at"),
    )


class AssessmentEvidence(IdentityMixin, WorkspaceMixin, CreatedMixin, Base):
    """Immutable sanitized analyst evidence; content stays in protected storage."""

    __tablename__ = "assessment_evidence"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    finding_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    artifact_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    release_ref: Mapped[str | None] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(200))
    artifact_ref: Mapped[str] = mapped_column(String(2048))
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    platform: Mapped[str] = mapped_column(String(16))
    tool: Mapped[str] = mapped_column(String(128))
    tool_version: Mapped[str] = mapped_column(String(128))
    environment: Mapped[str] = mapped_column(String(2000))
    redaction_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_assessment_evidence_workspace_id"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "finding_id", "assessment_id"],
            [
                "findings.workspace_id",
                "findings.project_id",
                "findings.id",
                "findings.assessment_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "artifact_id"],
            ["app_artifacts.workspace_id", "app_artifacts.project_id", "app_artifacts.id"],
            ondelete="RESTRICT",
        ),
        user_reference("created_by"),
        CheckConstraint("platform IN ('android', 'ios')", name="platform"),
        CheckConstraint("file_size BETWEEN 1 AND 262144", name="file_size"),
        CheckConstraint("redaction_count >= 0", name="redaction_count"),
        CheckConstraint(_sha256_check, name="sha256_lower_hex"),
    )

    attachment: Mapped[EvidenceAttachment | None] = relationship(
        back_populates="evidence", uselist=False, lazy="selectin"
    )


class EvidenceAttachment(WorkspaceMixin, CreatedMixin, Base):
    """Opaque, protected media paired with an immutable analyst evidence record."""

    __tablename__ = "evidence_attachments"

    evidence_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    storage_ref: Mapped[str] = mapped_column(String(2048))
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(32))
    display_name: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[AssessmentEvidence] = relationship(back_populates="attachment")

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "evidence_id"],
            ["assessment_evidence.workspace_id", "assessment_evidence.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("file_size BETWEEN 1 AND 8388608", name="file_size"),
        CheckConstraint("length(trim(storage_ref)) > 0", name="storage_ref_required"),
        CheckConstraint("media_type = 'image/png'", name="media_type"),
        CheckConstraint("display_name = 'screenshot.png'", name="display_name"),
        CheckConstraint(_sha256_check, name="sha256_lower_hex"),
    )


class TestExecution(IdentityMixin, WorkspaceMixin, CreatedMixin, UpdatedMixin, RevisionMixin, Base):
    """One editable analyst result per assessment and pinned test case."""

    __tablename__ = "test_executions"

    project_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), index=True)
    case_id: Mapped[str] = mapped_column(String(64))
    case_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="not_run")
    platform: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str] = mapped_column(String(2000))
    tool: Mapped[str] = mapped_column(String(128))
    tool_version: Mapped[str] = mapped_column(String(128))
    notes: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    operator_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    contributors: Mapped[list[str]] = mapped_column(JSON, default=list)

    __table_args__ = (
        UniqueConstraint("assessment_id", "case_id", name="uq_test_executions_case"),
        ForeignKeyConstraint(
            ["workspace_id", "project_id", "assessment_id"],
            ["assessments.workspace_id", "assessments.project_id", "assessments.id"],
            ondelete="RESTRICT",
        ),
        user_reference("operator_id"),
        CheckConstraint("platform IN ('android', 'ios')", name="platform"),
        CheckConstraint("status IN ('not_run', 'pass', 'fail', 'na', 'blocked')", name="status"),
        CheckConstraint("revision >= 1", name="revision_positive"),
    )


from droidshield import report_models  # noqa: E402, F401
