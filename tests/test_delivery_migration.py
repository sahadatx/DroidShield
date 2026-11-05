"""Delivery migrations preserve legacy references and enforce private evidence history."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

import droidshield
from droidshield.models import (
    Assessment,
    AssessmentEvidence,
    Authorization,
    AuthorizationAttachment,
    User,
)
from tests.test_analysis_migration import migrated_analysis as _migrated_analysis
from tests.test_concurrency import seed_queueable_assessment

migrated_analysis = _migrated_analysis


def config(engine):
    result = Config()
    result.set_main_option("script_location", str(Path(droidshield.__file__).parent / "migrations"))
    result.attributes["database_url"] = engine.url.render_as_string(hide_password=False)
    return result


def test_delivery_downgrade_preserves_legacy_assessments_and_upgrades_without_drift(
    migrated_analysis,
):
    engine = migrated_analysis
    seed_queueable_assessment(engine)
    with Session(engine) as session:
        original = session.scalar(select(Assessment))
        original_id, project_id, artifact_id = (
            original.id,
            original.project_id,
            original.artifact_id,
        )
    command.downgrade(config(engine), "0004_api_security")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM assessments")) == 1
    command.upgrade(config(engine), "head")
    command.check(config(engine))
    with Session(engine) as session:
        preserved = session.get(Assessment, original_id)
        assert preserved.project_id == project_id
        assert preserved.artifact_id == artifact_id


def test_migrated_evidence_rejects_mutation_and_history_losing_downgrade(migrated_analysis):
    engine = migrated_analysis
    user_id, _, assessment_id = seed_queueable_assessment(engine)
    with Session(engine) as session:
        actor = session.get(User, user_id)
        assessment = session.get(Assessment, assessment_id)
        record = AssessmentEvidence(
            workspace_id=actor.workspace_id,
            project_id=assessment.project_id,
            assessment_id=assessment.id,
            artifact_id=assessment.artifact_id,
            title="Sanitized immutable proof",
            artifact_ref="apk:" + "a" * 32,
            sha256="a" * 64,
            file_size=100,
            platform="android",
            tool="Manual",
            tool_version="1.0",
            environment="Controlled migration test lab",
            created_by=actor.id,
        )
        session.add(record)
        session.commit()
    for statement in (
        "UPDATE assessment_evidence SET title='changed'",
        "DELETE FROM assessment_evidence",
    ):
        with engine.begin() as connection:
            with pytest.raises(DBAPIError):
                connection.execute(text(statement))
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            with pytest.raises(DBAPIError):
                connection.execute(text("TRUNCATE assessment_evidence"))
    with pytest.raises(RuntimeError, match="Refusing"):
        command.downgrade(config(engine), "0004_api_security")
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(AssessmentEvidence)) == 1


def test_authorization_attachments_are_immutable_and_protect_migration_history(migrated_analysis):
    engine = migrated_analysis
    user_id, authorization_id, _assessment_id = seed_queueable_assessment(engine)
    with Session(engine) as session:
        actor = session.get(User, user_id)
        permit = session.get(Authorization, authorization_id)
        record = AuthorizationAttachment(
            workspace_id=actor.workspace_id,
            project_id=permit.project_id,
            authorization_id=permit.id,
            storage_ref="authdoc:" + "a" * 32,
            sha256="b" * 64,
            file_size=32,
            media_type="application/pdf",
            display_name="approval.pdf",
            created_by=actor.id,
        )
        session.add(record)
        session.commit()

    for statement in (
        "UPDATE authorization_attachments SET display_name='changed.pdf'",
        "DELETE FROM authorization_attachments",
    ):
        with engine.begin() as connection:
            with pytest.raises(DBAPIError):
                connection.execute(text(statement))
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            with pytest.raises(DBAPIError):
                connection.execute(text("TRUNCATE authorization_attachments"))
    with pytest.raises(RuntimeError, match="Refusing"):
        command.downgrade(config(engine), "0012_overview_risk_trends")
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(AuthorizationAttachment)) == 1
