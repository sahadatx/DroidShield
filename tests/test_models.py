"""Database invariants are tested directly, independently of HTTP validation."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    Assessment,
    Authorization,
    Base,
    Client,
    Finding,
    IdempotencyRecord,
    Project,
    ProjectAccess,
    Report,
    Retest,
    User,
    Workspace,
)


@pytest.fixture
def model_engine() -> Iterator[Engine]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def records(model_engine: Engine) -> dict[str, UUID]:
    ids = {
        name: uuid4()
        for name in (
            "workspace",
            "other_workspace",
            "user",
            "other_user",
            "client",
            "other_client",
            "project",
            "second_project",
            "other_project",
            "artifact",
            "second_artifact",
            "alternative_artifact",
            "other_artifact",
            "authorization",
            "second_authorization",
            "assessment",
            "second_assessment",
            "finding",
        )
    }
    with Session(model_engine) as session:
        session.add_all(
            [
                Workspace(id=ids["workspace"], name="First workspace"),
                Workspace(id=ids["other_workspace"], name="Other workspace"),
            ]
        )
        session.flush()
        session.add_all(
            [
                User(
                    id=ids["user"],
                    workspace_id=ids["workspace"],
                    email="analyst@example.test",
                    full_name="Analyst",
                    role="ADMIN",
                ),
                User(
                    id=ids["other_user"],
                    workspace_id=ids["other_workspace"],
                    email="other@example.test",
                    full_name="Other analyst",
                    role="ADMIN",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                Client(
                    id=ids["client"],
                    workspace_id=ids["workspace"],
                    name="First client",
                    created_by=ids["user"],
                ),
                Client(
                    id=ids["other_client"],
                    workspace_id=ids["other_workspace"],
                    name="Other client",
                    created_by=ids["other_user"],
                ),
            ]
        )
        session.flush()
        for name, workspace, client, user in (
            ("project", "workspace", "client", "user"),
            ("second_project", "workspace", "client", "user"),
            ("other_project", "other_workspace", "other_client", "other_user"),
        ):
            session.add(
                Project(
                    id=ids[name],
                    workspace_id=ids[workspace],
                    client_id=ids[client],
                    name=name,
                    application_name="Android app",
                    package_id=f"test.{name}",
                    created_by=ids[user],
                )
            )
        session.flush()
        for index, (name, project, workspace, user) in enumerate(
            (
                ("artifact", "project", "workspace", "user"),
                ("second_artifact", "second_project", "workspace", "user"),
                ("alternative_artifact", "project", "workspace", "user"),
                ("other_artifact", "other_project", "other_workspace", "other_user"),
            )
        ):
            session.add(
                AppArtifact(
                    id=ids[name],
                    workspace_id=ids[workspace],
                    project_id=ids[project],
                    sha256=f"{index + 1:064x}",
                    storage_ref=f"protected/{name}.apk",
                    original_filename=f"{name}.apk",
                    file_size=123,
                    created_by=ids[user],
                )
            )
        now = datetime.now(UTC)
        for name, project in (
            ("authorization", "project"),
            ("second_authorization", "second_project"),
        ):
            session.add(
                Authorization(
                    id=ids[name],
                    workspace_id=ids["workspace"],
                    project_id=ids[project],
                    status="verified",
                    approved_targets=["package:test.app"],
                    exclusions=[],
                    valid_from=now,
                    valid_until=now + timedelta(days=1),
                    evidence_ref="evidence/approval.pdf",
                    verified_by=ids["user"],
                    verified_at=now,
                    created_by=ids["user"],
                )
            )
        session.flush()
        for name, project, artifact, authorization in (
            ("assessment", "project", "artifact", "authorization"),
            ("second_assessment", "second_project", "second_artifact", "second_authorization"),
        ):
            session.add(
                Assessment(
                    id=ids[name],
                    workspace_id=ids["workspace"],
                    project_id=ids[project],
                    artifact_id=ids[artifact],
                    authorization_id=ids[authorization],
                    name=name,
                    assessment_type="static",
                    created_by=ids["user"],
                )
            )
        session.flush()
        session.add(
            Finding(
                id=ids["finding"],
                workspace_id=ids["workspace"],
                project_id=ids["project"],
                assessment_id=ids["assessment"],
                artifact_id=ids["artifact"],
                title="Sensitive logging",
                description="Potential secret in logs",
                affected_component="LoginActivity",
                category="storage",
                severity="high",
                reproduction_steps="Inspect test logs",
                impact="Potential disclosure",
                remediation="Remove sensitive logs",
                created_by=ids["user"],
            )
        )
        session.commit()
    return ids


def assert_rejected(engine: Engine, record: Base) -> None:
    with Session(engine) as session:
        session.add(record)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_cross_workspace_creator_and_client_are_rejected(model_engine, records):
    assert_rejected(
        model_engine,
        Client(
            workspace_id=records["workspace"],
            name="Foreign creator",
            created_by=records["other_user"],
        ),
    )
    assert_rejected(
        model_engine,
        Project(
            workspace_id=records["other_workspace"],
            client_id=records["client"],
            name="Foreign client",
            application_name="App",
            package_id="test.app",
            created_by=records["other_user"],
        ),
    )


def test_project_access_cannot_cross_workspace(model_engine, records):
    assert_rejected(
        model_engine,
        ProjectAccess(
            workspace_id=records["workspace"],
            project_id=records["project"],
            user_id=records["other_user"],
            created_by=records["user"],
        ),
    )


@pytest.mark.parametrize(
    "foreign_field,record_name",
    [
        ("artifact_id", "second_artifact"),
        ("authorization_id", "second_authorization"),
    ],
)
def test_assessment_requires_artifact_and_authorization_from_its_project(
    model_engine,
    records,
    foreign_field,
    record_name,
):
    fields = dict(
        workspace_id=records["workspace"],
        project_id=records["project"],
        name="Invalid assessment",
        assessment_type="static",
        created_by=records["user"],
    )
    fields[foreign_field] = records[record_name]
    assert_rejected(model_engine, Assessment(**fields))


def test_report_cannot_include_assessment_from_another_project(model_engine, records):
    assert_rejected(
        model_engine,
        Report(
            workspace_id=records["workspace"],
            project_id=records["second_project"],
            assessment_id=records["assessment"],
            title="Wrong project report",
            author_id=records["user"],
        ),
    )


def test_job_artifact_must_match_its_assessment_even_within_same_project(model_engine, records):
    assert_rejected(
        model_engine,
        AnalysisJob(
            workspace_id=records["workspace"],
            assessment_id=records["assessment"],
            artifact_id=records["alternative_artifact"],
        ),
    )


def test_assessment_has_only_one_job(model_engine, records):
    with Session(model_engine) as session:
        session.add(
            AnalysisJob(
                workspace_id=records["workspace"],
                assessment_id=records["assessment"],
                artifact_id=records["artifact"],
            )
        )
        session.commit()
    assert_rejected(
        model_engine,
        AnalysisJob(
            workspace_id=records["workspace"],
            assessment_id=records["assessment"],
            artifact_id=records["artifact"],
        ),
    )


def test_api_job_can_omit_artifact(model_engine, records):
    with Session(model_engine) as session:
        assessment = Assessment(
            workspace_id=records["workspace"],
            project_id=records["project"],
            name="API assessment",
            assessment_type="api",
            created_by=records["user"],
        )
        session.add(assessment)
        session.flush()
        session.add(AnalysisJob(workspace_id=records["workspace"], assessment_id=assessment.id))
        session.commit()


@pytest.mark.parametrize("artifact", ["second_artifact", "other_artifact"])
def test_retest_requires_new_artifact_from_finding_project(model_engine, records, artifact):
    assert_rejected(
        model_engine,
        Retest(
            workspace_id=records["workspace"],
            project_id=records["project"],
            finding_id=records["finding"],
            original_assessment_id=records["assessment"],
            new_artifact_id=records[artifact],
            method="static",
            operator_id=records["user"],
            environment={"engine": "isolated-worker"},
            result="inconclusive",
        ),
    )


def test_retest_original_assessment_must_match_finding(model_engine, records):
    assert_rejected(
        model_engine,
        Retest(
            workspace_id=records["workspace"],
            project_id=records["project"],
            finding_id=records["finding"],
            original_assessment_id=records["second_assessment"],
            new_artifact_id=records["artifact"],
            method="manual",
            operator_id=records["user"],
            environment={"device": "lab-emulator"},
            result="inconclusive",
        ),
    )


def test_stale_client_update_cannot_overwrite_concurrent_change(model_engine, records):
    with Session(model_engine) as first, Session(model_engine) as second:
        winner = first.get(Client, records["client"])
        stale = second.get(Client, records["client"])
        winner.name = "Reviewed client name"
        first.commit()
        assert winner.revision == 2
        stale.name = "Outdated client name"
        with pytest.raises(StaleDataError):
            second.commit()
        second.rollback()
    with Session(model_engine) as session:
        assert session.get(Client, records["client"]).name == "Reviewed client name"


def test_scanner_severity_does_not_confirm_finding(model_engine, records):
    with Session(model_engine) as session:
        finding = session.get(Finding, records["finding"])
        assert finding.severity == "high"
        assert finding.verification_status == "unreviewed"
        finding.severity = "critical"
        session.commit()
        session.expire(finding)
        assert finding.verification_status == "unreviewed"


@pytest.mark.parametrize("sha256", ["A" * 64, "g" * 64, "a" * 63, "a" * 65])
def test_artifact_hash_requires_exact_lowercase_sha256(model_engine, records, sha256):
    assert_rejected(
        model_engine,
        AppArtifact(
            workspace_id=records["workspace"],
            project_id=records["project"],
            sha256=sha256,
            storage_ref="protected/new.apk",
            original_filename="new.apk",
            file_size=100,
            created_by=records["user"],
        ),
    )


def test_archived_client_requires_a_reason(model_engine, records):
    assert_rejected(
        model_engine,
        Client(
            workspace_id=records["workspace"],
            name="Archived client",
            status="archived",
            archive_reason="   ",
            created_by=records["user"],
        ),
    )


def test_verified_authorization_requires_review_metadata(model_engine, records):
    now = datetime.now(UTC)
    assert_rejected(
        model_engine,
        Authorization(
            workspace_id=records["workspace"],
            project_id=records["project"],
            status="verified",
            valid_from=now,
            valid_until=now + timedelta(hours=1),
            evidence_ref="evidence/approval.pdf",
            created_by=records["user"],
        ),
    )


def test_final_report_requires_reviewer_approval(model_engine, records):
    assert_rejected(
        model_engine,
        Report(
            workspace_id=records["workspace"],
            project_id=records["project"],
            assessment_id=records["assessment"],
            title="Premature release",
            status="exported",
            author_id=records["user"],
            export_ref="reports/final.pdf",
            export_format="pdf",
            checksum="a" * 64,
            exported_at=datetime.now(UTC),
        ),
    )


def test_idempotency_key_cannot_be_reused_for_another_operation(model_engine, records):
    with Session(model_engine) as session:
        session.add(
            IdempotencyRecord(
                workspace_id=records["workspace"],
                user_id=records["user"],
                key="same-key",
                operation="clients.create",
                request_hash="a" * 64,
                response_resource_id=records["client"],
            )
        )
        session.commit()
    assert_rejected(
        model_engine,
        IdempotencyRecord(
            workspace_id=records["workspace"],
            user_id=records["user"],
            key="same-key",
            operation="assessments.queue",
            request_hash="b" * 64,
            response_resource_id=records["assessment"],
        ),
    )
