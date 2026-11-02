"""Queue/revoke must share the same transaction serialization boundary."""

from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from droidshield import services
from droidshield.db import build_engine
from droidshield.errors import DomainError
from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    Assessment,
    Authorization,
    Base,
    Client,
    Project,
    User,
    Workspace,
)


def seed_queueable_assessment(engine):
    with Session(engine) as session:
        workspace = Workspace(name="Concurrency test")
        session.add(workspace)
        session.flush()
        user = User(
            workspace_id=workspace.id, email="admin@example.test", full_name="Admin", role="ADMIN"
        )
        session.add(user)
        session.flush()
        client = Client(workspace_id=workspace.id, name="Client", created_by=user.id)
        session.add(client)
        session.flush()
        project = Project(
            workspace_id=workspace.id,
            client_id=client.id,
            name="Project",
            application_name="App",
            package_id="test.app",
            created_by=user.id,
        )
        session.add(project)
        session.flush()
        artifact = AppArtifact(
            workspace_id=workspace.id,
            project_id=project.id,
            sha256="a" * 64,
            storage_ref="protected/app.apk",
            original_filename="app.apk",
            file_size=100,
            metadata_json={"package_name": "test.app"},
            created_by=user.id,
        )
        now = datetime.now(UTC)
        authorization = Authorization(
            workspace_id=workspace.id,
            project_id=project.id,
            status="verified",
            approved_targets=["package:test.app"],
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
            evidence_ref="evidence/authorization.pdf",
            verified_by=user.id,
            verified_at=now,
            created_by=user.id,
        )
        session.add_all([artifact, authorization])
        session.flush()
        assessment = Assessment(
            workspace_id=workspace.id,
            project_id=project.id,
            artifact_id=artifact.id,
            authorization_id=authorization.id,
            name="Concurrent assessment",
            assessment_type="static",
            configuration_snapshot={"requested_targets": ["package:test.app"]},
            created_by=user.id,
        )
        session.add(assessment)
        session.flush()
        ids = user.id, authorization.id, assessment.id
        session.commit()
        return ids


@pytest.mark.parametrize("first_action", ["queue", "revoke"])
def test_queue_and_revoke_cannot_commit_a_revoked_queued_assessment(tmp_path, first_action):
    engine = build_engine(f"sqlite:///{tmp_path / 'concurrency.sqlite'}")
    Base.metadata.create_all(engine)
    user_id, authorization_id, assessment_id = seed_queueable_assessment(engine)
    first_has_read_permit = Event()
    release_first = Event()
    second_attempted_transaction = Event()
    participant: ContextVar[str] = ContextVar("participant", default="main")

    @event.listens_for(engine, "before_cursor_execute")
    def observe_second_transaction(_connection, _cursor, statement, _parameters, _context, _many):
        if participant.get() == "second" and statement == "BEGIN IMMEDIATE":
            second_attempted_transaction.set()

    def run(action, position):
        participant.set(position)
        with Session(engine) as session:
            user = session.get(User, user_id)
            permit = session.get(Authorization, authorization_id)
            assessment = session.get(Assessment, assessment_id)
            context = services.Context(session, user, f"race-{position}")
            if position == "first":
                first_has_read_permit.set()
                assert release_first.wait(5), "The first transaction was not released"
            try:
                if action == "queue":
                    services.queue_assessment(context, assessment.id, assessment.revision)
                else:
                    services.revoke_authorization(
                        context, permit.id, permit.revision, "Emergency stop"
                    )
                session.commit()
                return "committed"
            except DomainError as error:
                session.rollback()
                return error.status

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(run, first_action, "first")
            try:
                assert first_has_read_permit.wait(5), "The first transaction never read its permit"
                second = executor.submit(
                    run, "revoke" if first_action == "queue" else "queue", "second"
                )
                assert second_attempted_transaction.wait(5), (
                    "The second transaction never attempted its lock"
                )
                assert not second.done(), "A competing transaction passed the held write boundary"
            finally:
                release_first.set()
            assert first.result(timeout=10) == "committed"
            assert second.result(timeout=10) == ("committed" if first_action == "queue" else 409)

        with Session(engine) as session:
            permit = session.get(Authorization, authorization_id)
            assessment = session.get(Assessment, assessment_id)
            job = session.scalar(
                select(AnalysisJob).where(AnalysisJob.assessment_id == assessment.id)
            )
            assert permit.status == "revoked"
            assert assessment.status == ("cancelled" if first_action == "queue" else "draft")
            if first_action == "queue":
                assert job is not None
                assert job.status == "cancelled"
            else:
                assert job is None
    finally:
        engine.dispose()
