import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import BigInteger, Integer, create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from droidshield.auth import issue_token, token_hash
from droidshield.cli import migrate
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.main import create_app
from droidshield.models import (
    AccessToken,
    AppArtifact,
    Project,
    User,
    Workspace,
)


def config_for(url):
    return Settings(
        _env_file=None, environment="test", database_url=url, allowed_hosts=["testserver"]
    )


@pytest.fixture(params=["sqlite", "postgresql"])
def migrated_url(request, tmp_path):
    if request.param == "sqlite":
        url = f"sqlite:///{tmp_path / 'foundation.db'}"
        migrate(config_for(url))
        yield url
        return
    original = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL")
    if not original:
        pytest.skip("Set DROIDSHIELD_TEST_DATABASE_URL for isolated PostgreSQL migration tests")
    schema = "ds_migration_" + uuid4().hex
    admin = create_engine(original)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = (
        make_url(original)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    try:
        migrate(config_for(url))
        yield url
    finally:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_migration_widens_artifact_version_code(migrated_url):
    engine = create_engine(migrated_url)
    try:
        column = next(
            column
            for column in inspect(engine).get_columns("app_artifacts")
            if column["name"] == "version_code"
        )
        if engine.dialect.name == "sqlite":
            assert isinstance(column["type"], Integer)
        else:
            assert isinstance(column["type"], BigInteger)
    finally:
        engine.dispose()


def test_migration_readiness_workflow_and_immutable_history(migrated_url):
    settings = config_for(migrated_url)
    engine = build_engine(migrated_url)
    with Session(engine) as session:
        workspace = Workspace(name="Isolated migration test")
        session.add(workspace)
        session.flush()
        account = User(
            workspace_id=workspace.id,
            full_name="Test operator",
            email="test@example.com",
            role="ADMIN",
        )
        session.add(account)
        session.flush()
        token = issue_token(session, account.id, 1)
        session.commit()
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "migration-client"}
    with TestClient(create_app(settings, engine)) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        response = client.post("/api/v1/clients", headers=headers, json={"name": "Verified client"})
        assert response.status_code == 201, response.text
        owner = response.json()
        headers["Idempotency-Key"] = "migration-project"
        response = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "client_id": owner["id"],
                "name": "App",
                "application_name": "App",
                "package_id": "com.example.app",
            },
        )
        assert response.status_code == 201, response.text
        project = response.json()
        now = datetime.now(UTC)
        headers["Idempotency-Key"] = "migration-permit"
        response = client.post(
            f"/api/v1/projects/{project['id']}/authorizations",
            headers=headers,
            json={
                "approved_targets": ["https://api.example.test/v1"],
                "evidence_ref": "approval:reviewed-contract",
                "valid_from": (now - timedelta(hours=1)).isoformat(),
                "valid_until": (now + timedelta(hours=1)).isoformat(),
            },
        )
        assert response.status_code == 201, response.text
        permit = response.json()
        headers["Idempotency-Key"] = "migration-verify"
        assert (
            client.post(
                f"/api/v1/authorizations/{permit['id']}/verify",
                headers=headers,
                json={"revision": 1},
            ).status_code
            == 200
        )
        headers["Idempotency-Key"] = "migration-assessment"
        response = client.post(
            "/api/v1/assessments",
            headers=headers,
            json={
                "project_id": project["id"],
                "authorization_id": permit["id"],
                "name": "API review",
                "assessment_type": "api",
                "requested_targets": ["https://api.example.test/v1"],
            },
        )
        assert response.status_code == 201, response.text
        assessment = response.json()
        headers["Idempotency-Key"] = "migration-queue"
        response = client.post(
            f"/api/v1/assessments/{assessment['id']}/queue", headers=headers, json={"revision": 1}
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "queued"
        assert client.get("/api/v1/overview", headers=headers).json()["total_assessments"] == 1
    with Session(engine) as session:
        parent = session.query(Project).one()
        session.add(
            AppArtifact(
                workspace_id=parent.workspace_id,
                project_id=parent.id,
                created_by=parent.created_by,
                sha256="a" * 64,
                storage_ref="protected:test-artifact",
                original_filename="app.apk",
                file_size=10,
                metadata_json={"package_name": parent.package_id},
            )
        )
        session.commit()
    for table in ["audit_events", "app_artifacts"]:
        for statement in [f"DELETE FROM {table}", f"UPDATE {table} SET id = id"]:
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(text(statement))
    if engine.dialect.name == "postgresql":
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(text("TRUNCATE audit_events"))
    # Upgrade is repeatable, downgrade removes all versioned tables cleanly.
    migrate(settings)
    from pathlib import Path

    import droidshield

    config = Config()
    config.set_main_option("script_location", str(Path(droidshield.__file__).parent / "migrations"))
    config.attributes["database_url"] = migrated_url
    command.downgrade(config, "base")
    engine.dispose()


def test_health_before_migration_is_sanitized(tmp_path):
    settings = config_for(f"sqlite:///{tmp_path / 'unmigrated.db'}")
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert "OperationalError" not in response.text
        assert "SELECT" not in response.text


def test_secure_cli_bootstrap_and_revocation(tmp_path):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    env = {**os.environ, "DROIDSHIELD_DATABASE_URL": url, "DROIDSHIELD_ENVIRONMENT": "test"}

    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "droidshield.cli", *args],
            env=env,
            text=True,
            capture_output=True,
            check=True,
        ).stdout

    cli("migrate")
    output = cli(
        "bootstrap", "--workspace", "Test", "--email", "owner@example.com", "--name", "Owner"
    )
    assert "No browser token was issued" in output
    engine = build_engine(url)
    with Session(engine) as session:
        account = session.query(User).one()
        assert account.password_hash is None
        assert session.query(AccessToken).count() == 0
        user_id = str(account.id)
    issued = cli("issue-token", "--user-id", user_id)
    secret = issued.split("hours): ", 1)[1].strip()
    with Session(engine) as session:
        record = session.query(AccessToken).one()
        assert record.token_hash == token_hash(secret)
        assert record.token_hash != secret
    with TestClient(create_app(config_for(url), engine)) as client:
        headers = {"Authorization": f"Bearer {secret}"}
        assert client.get("/api/v1/me", headers=headers).status_code == 200
        cli("revoke-tokens", "--user-id", user_id)
        assert client.get("/api/v1/me", headers=headers).status_code == 401
    engine.dispose()


def test_production_config_rejects_sqlite_and_wildcard_origins():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="production", database_url="sqlite://")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, cors_origins=["*"])


def test_validation_never_echoes_rejected_secrets(migrated_url):
    engine = build_engine(migrated_url)
    with Session(engine) as session:
        workspace = Workspace(name="Validation test")
        session.add(workspace)
        session.flush()
        account = User(
            workspace_id=workspace.id, email="test@example.com", full_name="Test", role="ADMIN"
        )
        session.add(account)
        session.flush()
        credential = issue_token(session, account.id, 1)
        session.commit()
    with TestClient(create_app(config_for(migrated_url), engine)) as client:
        response = client.post(
            "/api/v1/clients",
            json={"name": "Test", "password": "never-echo-this-value"},
            headers={"Authorization": f"Bearer {credential}", "Idempotency-Key": "invalid-client"},
        )
        assert response.status_code == 422
        assert "never-echo-this-value" not in response.text
        assert "input" not in str(response.json()["error"]["details"])
    engine.dispose()
