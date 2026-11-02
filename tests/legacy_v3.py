"""Frozen pre-delivery fixture: never use live ORM models against an old schema."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import MetaData


def seed_running_lab(engine):
    ids = {
        name: uuid4()
        for name in (
            "workspace",
            "user",
            "client",
            "project",
            "artifact",
            "authorization",
            "assessment",
            "job",
            "session",
            "worker",
        )
    }
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=5)
    with engine.begin() as connection:
        metadata = MetaData()
        metadata.reflect(connection)

        def insert(table, **values):
            schema = metadata.tables[table]
            for key in ("created_at", "updated_at"):
                if key in schema.c:
                    values.setdefault(key, now)
            if "revision" in schema.c:
                values.setdefault("revision", 1)
            # SQLite's reflected CHAR(32) UUID columns expect the stored form.
            values = {
                key: value.hex if hasattr(value, "hex") and not callable(value.hex) else value
                for key, value in values.items()
            }
            connection.execute(schema.insert().values(**values))

        workspace = ids["workspace"]
        user = ids["user"]
        project = ids["project"]
        artifact = ids["artifact"]
        assessment = ids["assessment"]
        insert("workspaces", id=workspace, name="Legacy lab fixture")
        insert(
            "users",
            id=user,
            workspace_id=workspace,
            email="legacy@example.test",
            full_name="Legacy operator",
            role="ADMIN",
            status="active",
        )
        insert(
            "clients",
            id=ids["client"],
            workspace_id=workspace,
            name="Legacy client",
            client_type="company",
            status="active",
            created_by=user,
        )
        insert(
            "projects",
            id=project,
            workspace_id=workspace,
            client_id=ids["client"],
            name="Legacy app",
            application_name="App",
            package_id="test.app",
            framework="native",
            status="active",
            created_by=user,
        )
        insert(
            "app_artifacts",
            id=artifact,
            workspace_id=workspace,
            project_id=project,
            sha256="a" * 64,
            storage_ref="protected/app.apk",
            original_filename="app.apk",
            file_size=100,
            build_type="unknown",
            metadata_json={"package_name": "test.app"},
            created_by=user,
        )
        insert(
            "authorizations",
            id=ids["authorization"],
            workspace_id=workspace,
            project_id=project,
            status="verified",
            approved_targets=["package:test.app"],
            exclusions=[],
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
            evidence_ref="evidence/authorization.pdf",
            verified_by=user,
            verified_at=now,
            created_by=user,
        )
        insert(
            "assessments",
            id=assessment,
            workspace_id=workspace,
            project_id=project,
            artifact_id=artifact,
            authorization_id=ids["authorization"],
            name="Legacy assessment",
            assessment_type="static",
            status="queued",
            configuration_snapshot={"requested_targets": ["package:test.app"]},
            tool_versions={},
            created_by=user,
        )
        insert(
            "analysis_jobs",
            id=ids["job"],
            workspace_id=workspace,
            assessment_id=assessment,
            artifact_id=artifact,
            status="queued",
            configuration_snapshot={},
            tool_versions={},
            attempt_count=0,
        )
        insert(
            "dynamic_sessions",
            id=ids["session"],
            workspace_id=workspace,
            project_id=project,
            assessment_id=assessment,
            artifact_id=artifact,
            job_id=ids["job"],
            device_id="owned-existing-lab",
            scenario="package_inspection",
            timeout_seconds=90,
            status="running",
            created_by=user,
            configuration_snapshot={},
        )
        insert(
            "dynamic_device_leases",
            device_id="owned-existing-lab",
            session_id=ids["session"],
            worker_id=ids["worker"],
            expires_at=expires,
            quarantined=True,
        )
    return ids["session"], ids["worker"], expires
