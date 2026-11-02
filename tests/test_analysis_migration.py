"""Real versioned migrations retain immutable, relationally scoped scan output."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema, DropSchema

from droidshield import services, worker
from droidshield.cli import migrate
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.models import (
    AnalysisJob,
    AnalysisResult,
    AppArtifact,
    Assessment,
    User,
)
from tests.test_concurrency import seed_queueable_assessment
from tests.test_worker import engine_output


@pytest.fixture(params=["sqlite", "postgresql"])
def migrated_analysis(request, tmp_path):
    original = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL")
    schema, admin = None, None
    if request.param == "postgresql":
        if not original:
            pytest.skip("Set DROIDSHIELD_TEST_DATABASE_URL for isolated migration tests")
        admin = build_engine(original)
        schema = "ds_results_" + uuid4().hex
        with admin.begin() as connection:
            connection.execute(CreateSchema(schema))
        url = (
            make_url(original)
            .update_query_dict({"options": f"-csearch_path={schema}"})
            .render_as_string(hide_password=False)
        )
    else:
        url = f"sqlite:///{tmp_path / 'migrated-results.db'}"
    engine = None
    try:
        settings = Settings(_env_file=None, environment="test", database_url=url)
        migrate(settings)
        engine = build_engine(url)
        yield engine
    finally:
        if engine is not None:
            engine.dispose()
        if admin is not None:
            try:
                with admin.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
            finally:
                admin.dispose()


def seed_result_origins(engine):
    user_id, authorization_id, first_id = seed_queueable_assessment(engine)
    with Session(engine) as session:
        actor = session.get(User, user_id)
        context = services.Context(session, actor, "migration-result-origin")
        first = services.queue_assessment(context, first_id, 1)
        first_artifact_id = first.artifact_id
        second_artifact = AppArtifact(
            workspace_id=first.workspace_id,
            project_id=first.project_id,
            created_by=user_id,
            sha256="b" * 64,
            storage_ref="protected/second.apk",
            original_filename="second.apk",
            file_size=100,
            metadata_json={"package_name": "test.app"},
        )
        session.add(second_artifact)
        session.flush()
        second = Assessment(
            workspace_id=first.workspace_id,
            project_id=first.project_id,
            artifact_id=second_artifact.id,
            authorization_id=authorization_id,
            name="Second artifact",
            assessment_type="static",
            created_by=user_id,
            configuration_snapshot={"requested_targets": ["package:test.app"]},
        )
        session.add(second)
        session.flush()
        services.queue_assessment(context, second.id, 1)
        jobs = {item.assessment_id: item.id for item in session.scalars(select(AnalysisJob))}
        values = {
            "workspace_id": first.workspace_id,
            "project_id": first.project_id,
            "first_assessment": first.id,
            "second_assessment": second.id,
            "first_artifact": first_artifact_id,
            "second_artifact": second_artifact.id,
            "first_job": jobs[first.id],
            "second_job": jobs[second.id],
        }
        session.commit()
        return values


def result_record(origin, *, assessment_id, artifact_id, job_id):
    output = engine_output()
    return AnalysisResult(
        workspace_id=origin["workspace_id"],
        project_id=origin["project_id"],
        assessment_id=assessment_id,
        artifact_id=artifact_id,
        job_id=job_id,
        artifact_sha256=output["sha256"],
        schema_version=1,
        engine_version=worker.ENGINE_VERSION,
        metadata_json=output["metadata"],
        indicators_json=output["indicators"],
        limitations_json=output["limitations"],
    )


def test_result_snapshot_guards_apply_to_real_migrations(migrated_analysis):
    engine = migrated_analysis
    origin = seed_result_origins(engine)
    with Session(engine) as session:
        session.add(
            result_record(
                origin,
                assessment_id=origin["first_assessment"],
                artifact_id=origin["first_artifact"],
                job_id=origin["first_job"],
            )
        )
        session.commit()
    for statement in ("UPDATE analysis_results SET id = id", "DELETE FROM analysis_results"):
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(text(statement))
    if engine.dialect.name == "postgresql":
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(text("TRUNCATE analysis_results"))


@pytest.mark.parametrize("mismatch", ["artifact", "assessment"])
def test_result_origin_foreign_key_rejects_crossed_job_links(migrated_analysis, mismatch):
    engine = migrated_analysis
    origin = seed_result_origins(engine)
    # Both artifacts and assessments belong to the same project. Only the
    # composite job-origin reference distinguishes these crossed linkages.
    with pytest.raises(IntegrityError), Session(engine) as session:
        session.add(
            result_record(
                origin,
                job_id=origin["second_job"],
                assessment_id=origin["first_assessment"]
                if mismatch == "assessment"
                else origin["second_assessment"],
                artifact_id=origin["first_artifact"]
                if mismatch == "artifact"
                else origin["second_artifact"],
            )
        )
        session.commit()
