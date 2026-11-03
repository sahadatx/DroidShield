"""API integration checks with isolated databases and real bearer credentials."""

import csv
import io
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema, DropSchema

from droidshield.auth import hash_password, issue_token, token_hash
from droidshield.config import Settings
from droidshield.db import build_engine
from droidshield.models import (
    AccessToken,
    AnalysisJob,
    AppArtifact,
    Assessment,
    AuditEvent,
    Authorization,
    Base,
    Client,
    Finding,
    LoginRateLimitEntry,
    ProjectAccess,
    User,
    Workspace,
    WorkspaceSettings,
)

PREFIX = "/api/v1"
API_TARGET = "https://api.example.test/v1"


@dataclass
class Harness:
    client: TestClient
    engine: Engine
    users: dict[str, UUID]
    tokens: dict[str, str]
    workspaces: dict[str, UUID]

    def headers(self, role="admin", key=None):
        result = {"Authorization": f"Bearer {self.tokens[role]}"}
        if key is not None:
            result["Idempotency-Key"] = key
        return result

    def post(self, path, body, role="admin", key=None):
        return self.client.post(
            PREFIX + path, json=body, headers=self.headers(role, key or str(uuid4()))
        )

    def get(self, path, role="admin", **kwargs):
        return self.client.get(PREFIX + path, headers=self.headers(role), **kwargs)

    def patch(self, path, body, role="admin"):
        return self.client.patch(PREFIX + path, json=body, headers=self.headers(role))


@pytest.fixture
def api():
    from droidshield.main import create_app

    database_url = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL", "sqlite://")
    with isolated_test_engine(database_url) as engine:
        Base.metadata.create_all(engine)
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=database_url,
            allowed_hosts=["testserver"],
        )
        users, tokens, workspaces = {}, {}, {}
        with Session(engine) as session:
            for key in ("main", "other"):
                workspace = Workspace(name=f"{key} workspace")
                session.add(workspace)
                session.flush()
                workspaces[key] = workspace.id
            for name, role, workspace in (
                ("admin", "ADMIN", "main"),
                ("analyst", "SECURITY_ANALYST", "main"),
                ("viewer", "VIEWER", "main"),
                ("other_admin", "ADMIN", "other"),
            ):
                user = User(
                    workspace_id=workspaces[workspace],
                    email=f"{name}@example.com",
                    full_name=name,
                    role=role,
                    status="active",
                )
                session.add(user)
                session.flush()
                users[name] = user.id
                tokens[name] = issue_token(session, user.id, ttl_hours=12)
            session.commit()
        with TestClient(create_app(settings, engine)) as client:
            yield Harness(client, engine, users, tokens, workspaces)


@contextmanager
def isolated_test_engine(database_url):
    """Translate every ORM table into a new schema on PostgreSQL.

    No public-schema table is created, truncated, or dropped. A separate engine
    removes only the generated schema even if fixture setup or a test fails.
    """
    base_engine = build_engine(database_url)
    schema_name = None
    try:
        engine = base_engine
        if base_engine.dialect.name == "postgresql":
            candidate = f"ds_test_{uuid4().hex}"
            with base_engine.begin() as connection:
                connection.execute(CreateSchema(candidate))
            schema_name = candidate
            engine = base_engine.execution_options(schema_translate_map={None: schema_name})
        elif base_engine.dialect.name != "sqlite":
            raise ValueError("API tests support SQLite or an isolated PostgreSQL schema")
        yield engine
    finally:
        base_engine.dispose()
        if schema_name is not None:
            cleanup_engine = build_engine(database_url)
            try:
                with cleanup_engine.begin() as connection:
                    connection.execute(DropSchema(schema_name, cascade=True))
            finally:
                cleanup_engine.dispose()


def expect(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


def test_workspace_settings_are_admin_only_safe_and_workspace_scoped(api):
    runtime = api.client.app.state.settings
    runtime.mobsf_url = "https://mobsf.internal.example"
    runtime.mobsf_api_key = "mobsf-secret-canary"
    runtime.api_secret_store = "/private/secret-store.json"
    runtime.frida_token = "frida-secret-canary"
    runtime.proxy_ca_cert = "/private/proxy-ca.pem"
    runtime.proxy_ca_key = "proxy-secret-canary"

    defaults = expect(api.get("/settings"))
    assert defaults["workspace_name"] == "main workspace"
    assert defaults["display_timezone"] == "UTC"
    assert defaults["date_format"] == "iso"
    assert defaults["default_report_template"] == "combined"
    assert defaults["revision"] == 1
    assert defaults["secret_references"] == {
        "mobsf_service": {"configured": True},
        "api_secret_store": {"configured": True},
        "frida_runtime": {"configured": True},
        "proxy_certificate_authority": {"configured": True},
    }
    for secret in (
        "mobsf-secret-canary",
        "frida-secret-canary",
        "proxy-secret-canary",
        "mobsf.internal.example",
        "/private/secret-store.json",
        "/private/proxy-ca.pem",
    ):
        assert secret not in api.get("/settings").text

    assert expect(api.get("/settings", role="other_admin"))["workspace_name"] == ("other workspace")
    for role in ("analyst", "viewer"):
        assert api.get("/settings", role=role).status_code == 403
        assert (
            api.patch("/settings", {"revision": 1, "date_format": "dmy"}, role).status_code == 403
        )

    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(WorkspaceSettings)) == 0


def test_workspace_settings_update_revision_validation_and_audit_redaction(api):
    updated = expect(
        api.patch(
            "/settings",
            {
                "revision": 1,
                "workspace_name": "DroidShield Security",
                "display_timezone": "Europe/London",
                "date_format": "dmy",
                "default_report_template": "technical",
                "report_branding_name": "DroidShield Labs",
            },
        )
    )
    assert updated["workspace_name"] == "DroidShield Security"
    assert updated["display_timezone"] == "Europe/London"
    assert updated["date_format"] == "dmy"
    assert updated["default_report_template"] == "technical"
    assert updated["report_branding_name"] == "DroidShield Labs"
    assert updated["revision"] == 2
    assert updated["updated_at"] is not None
    assert expect(api.get("/settings")) == updated

    stale = api.patch("/settings", {"revision": 1, "date_format": "mdy"})
    assert stale.status_code == 409
    assert api.patch("/settings", {"revision": 2}).status_code == 422
    assert api.patch("/settings", {"revision": 2, "unknown": "value"}).status_code == 422
    assert (
        api.patch("/settings", {"revision": 2, "mobsf_api_key": "never-accepted"}).status_code
        == 422
    )
    assert (
        api.patch("/settings", {"revision": 2, "display_timezone": "Mars/Olympus"}).status_code
        == 422
    )
    assert api.patch("/settings", {"revision": 2, "date_format": None}).status_code == 422

    cleared = expect(api.patch("/settings", {"revision": 2, "report_branding_name": None}))
    assert cleared["report_branding_name"] is None
    assert cleared["revision"] == 3
    with Session(api.engine) as session:
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "workspace.settings_updated")
        ).all()
        events.sort(key=lambda event: event.source_metadata["revision"])
        assert len(events) == 2
        assert events[0].resource_type == "workspace_settings"
        assert events[0].resource_id == api.workspaces["main"]
        assert events[0].source_metadata == {
            "channel": "api",
            "changed_fields": [
                "date_format",
                "default_report_template",
                "display_timezone",
                "report_branding_name",
                "workspace_name",
            ],
            "revision": 2,
        }
        assert "DroidShield Security" not in str(events[0].source_metadata)
        assert "DroidShield Labs" not in str(events[0].source_metadata)


def make_client(api, name="Authorized Client", role="admin", **changes):
    return expect(api.post("/clients", {"name": name, **changes}, role=role), 201)


def make_project(api, client=None, name="Store", role="admin", **changes):
    client = client or make_client(api, role=role)
    return expect(
        api.post(
            "/projects",
            {
                "client_id": client["id"],
                "name": name,
                "application_name": name,
                "package_id": "com.example.store",
                **changes,
            },
            role=role,
        ),
        201,
    )


def make_authorization(api, project, verify=True, **changes):
    now = datetime.now(UTC)
    permit = expect(
        api.post(
            f"/projects/{project['id']}/authorizations",
            {
                "approved_targets": [API_TARGET],
                "exclusions": [],
                "evidence_ref": "approval:engagement-001",
                "valid_from": (now - timedelta(hours=1)).isoformat(),
                "valid_until": (now + timedelta(days=1)).isoformat(),
                **changes,
            },
        ),
        201,
    )
    assert permit["status"] == "pending"
    if verify:
        permit = expect(
            api.post(f"/authorizations/{permit['id']}/verify", {"revision": permit["revision"]})
        )
    return permit


def make_assessment(api, project, permit=None, targets=None, role="admin", **changes):
    return expect(
        api.post(
            "/assessments",
            {
                "project_id": project["id"],
                "name": "API assessment",
                "assessment_type": "api",
                "authorization_id": permit["id"] if permit else None,
                "requested_targets": [API_TARGET] if targets is None else targets,
                **changes,
            },
            role=role,
        ),
        201,
    )


def queue(api, assessment, key=None):
    return api.post(
        f"/assessments/{assessment['id']}/queue", {"revision": assessment["revision"]}, key=key
    )


def grant(api, project, role):
    return expect(api.post(f"/projects/{project['id']}/members", {"user_id": str(api.users[role])}))


@pytest.mark.parametrize(
    "header", [None, "Basic credentials", "Bearer ds_unknown", "Bearer invalid"]
)
def test_missing_or_unknown_authentication_is_rejected(api, header):
    headers = {"Authorization": header} if header else {}
    response = api.client.get(PREFIX + "/me", headers=headers)
    expect(response, 401)
    assert "ds_unknown" not in response.text


@pytest.mark.parametrize("invalidation", ["revoked", "expired", "disabled"])
def test_existing_credentials_stop_working_immediately(api, invalidation):
    expect(api.get("/me"))
    with Session(api.engine) as session:
        credential = session.scalar(
            select(AccessToken).where(AccessToken.token_hash == token_hash(api.tokens["admin"]))
        )
        if invalidation == "revoked":
            credential.revoked_at = datetime.now(UTC)
        elif invalidation == "expired":
            credential.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            session.get(User, api.users["admin"]).status = "disabled"
        session.commit()
    expect(api.get("/me"), 401)
    expect(api.post("/clients", {"name": "Should not exist"}), 401)
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(Client)) == 0


def test_email_password_session_survives_reload_and_logout_revokes_cookie(api):
    password = "A-very-long-local-test-passphrase!"
    with Session(api.engine) as session, session.begin():
        account = session.get(User, api.users["admin"])
        account.password_hash = hash_password(password)

    login = api.client.post(
        PREFIX + "/auth/login",
        json={"email": "ADMIN@example.com", "password": password},
    )
    assert login.status_code == 200
    assert login.json()["user"]["email"] == "admin@example.com"
    assert "access_token" not in login.json()
    assert "token" not in login.json()
    assert "httponly" in login.headers["set-cookie"].lower()

    reloaded = api.client.get(PREFIX + "/auth/session")
    assert reloaded.status_code == 200
    assert reloaded.json()["user"]["id"] == str(api.users["admin"])
    csrf = reloaded.json()["csrf_token"]

    denied = api.client.post(PREFIX + "/auth/logout")
    assert denied.status_code == 403
    signed_out = api.client.post(PREFIX + "/auth/logout", headers={"X-CSRF-Token": csrf})
    assert signed_out.status_code == 200
    assert signed_out.json() == {"status": "signed_out"}
    assert api.client.get(PREFIX + "/auth/session").status_code == 401

    wrong_password = api.client.post(
        PREFIX + "/auth/login",
        json={"email": "admin@example.com", "password": "incorrect password"},
    )
    assert wrong_password.status_code == 401
    assert wrong_password.json()["error"]["message"] == "Email or password is incorrect"


def test_login_attempt_limit_is_shared_across_api_instances(api):
    from droidshield.main import create_app

    settings = Settings(
        _env_file=None,
        environment="test",
        database_url="sqlite://",
        allowed_hosts=["testserver"],
    )
    with TestClient(create_app(settings, api.engine)) as second_worker:
        clients = (api.client, second_worker)
        for index in range(10):
            response = clients[index % 2].post(
                PREFIX + "/auth/login",
                json={"email": "admin@example.com", "password": "incorrect password"},
            )
            assert response.status_code == 401

        limited = api.client.post(
            PREFIX + "/auth/login",
            json={"email": "admin@example.com", "password": "incorrect password"},
        )
        assert limited.status_code == 429
        assert limited.json()["error"]["code"] == "login_rate_limited"

    with Session(api.engine) as session:
        entries = session.scalars(select(LoginRateLimitEntry)).all()
        assert len(entries) == 1
        assert len(entries[0].attempt_times_us) == 10
        assert "testclient" not in entries[0].key_hash


def test_viewer_and_analyst_roles_are_enforced_by_the_server(api):
    project = make_project(api)
    permit = make_authorization(api, project, verify=False)
    grant(api, project, "viewer")
    grant(api, project, "analyst")
    expect(api.get(f"/projects/{project['id']}", role="viewer"))
    expect(api.post("/clients", {"name": "Forbidden"}, role="viewer"), 403)
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {
                "revision": project["revision"],
                "name": "Forbidden",
            },
            role="viewer",
        ),
        403,
    )
    expect(
        api.post(
            f"/authorizations/{permit['id']}/verify",
            {
                "revision": permit["revision"],
            },
            role="analyst",
        ),
        403,
    )
    expect(api.get("/audit-events", role="analyst"), 403)
    expect(
        api.post(
            f"/projects/{project['id']}/members",
            {
                "user_id": str(api.users["viewer"]),
            },
            role="analyst",
        ),
        403,
    )


def test_projects_and_clients_are_hidden_until_an_explicit_project_grant(api):
    client = make_client(api)
    visible = make_project(api, client, name="Granted project")
    hidden = make_project(api, client, name="Private sibling")
    assessment = make_assessment(api, hidden)
    assert expect(api.get("/projects", role="analyst"))["total"] == 0
    expect(api.get(f"/clients/{client['id']}", role="analyst"), 404)
    expect(api.get(f"/projects/{visible['id']}", role="analyst"), 404)
    grant(api, visible, "analyst")
    projects = expect(api.get("/projects", role="analyst"))
    assert {item["id"] for item in projects["items"]} == {visible["id"]}
    expect(api.get(f"/clients/{client['id']}", role="analyst"))
    expect(api.get(f"/projects/{hidden['id']}", role="analyst"), 404)
    expect(api.get(f"/assessments/{assessment['id']}", role="analyst"), 404)
    assert expect(api.get("/assessments", role="analyst"))["total"] == 0
    # A grant permits assessment work, but cannot expand ownership of its shared client.
    expect(
        api.patch(
            f"/projects/{visible['id']}",
            {
                "revision": visible["revision"],
                "description": "Permitted analyst update",
            },
            role="analyst",
        )
    )
    expect(
        api.patch(
            f"/clients/{client['id']}",
            {
                "revision": client["revision"],
                "name": "Unauthorized shared-client edit",
            },
            role="analyst",
        ),
        403,
    )
    expect(
        api.post(
            "/projects",
            {
                "client_id": client["id"],
                "name": "Unauthorized sibling",
                "application_name": "Store",
                "package_id": "com.example.sibling",
            },
            role="analyst",
        ),
        403,
    )


def test_assessment_list_filters_by_type(api):
    project = make_project(api)
    static = make_assessment(api, project, name="Static review", assessment_type="static")
    api_assessment = make_assessment(api, project, name="API review", assessment_type="api")

    static_page = expect(api.get("/assessments", params={"assessment_type": "static"}))
    assert [item["id"] for item in static_page["items"]] == [static["id"]]

    api_page = expect(api.get("/assessments", params={"assessment_type": "api"}))
    assert [item["id"] for item in api_page["items"]] == [api_assessment["id"]]

    expect(api.get("/assessments", params={"assessment_type": "not-a-type"}), 422)


def test_directory_and_finding_filters_cover_visible_record_fields(api):
    company = make_client(
        api,
        name="Northstar",
        client_type="company",
        organization_name="Northstar Labs",
        contact_person="Morgan Tester",
        contact_email="morgan@northstar.example",
    )
    individual = make_client(
        api,
        name="Taylor Reviewer",
        client_type="individual",
        contact_email="taylor@example.com",
    )
    ios = make_project(
        api,
        company,
        name="Commerce iOS",
        application_name="Northstar Shop",
        package_id="com.northstar.shop",
        platform="ios",
        framework="flutter",
    )
    android = make_project(
        api,
        individual,
        name="Wallet Android",
        application_name="Taylor Wallet",
        package_id="com.taylor.wallet",
        platform="android",
        framework="native",
    )

    with Session(api.engine) as session:
        for filename, digest, app_format, build_type in (
            ("northstar-release.aab", "a" * 64, "aab", "release"),
            ("northstar-debug.apk", "b" * 64, "apk", "debug"),
        ):
            session.add(
                AppArtifact(
                    workspace_id=api.workspaces["main"],
                    project_id=UUID(ios["id"]),
                    version_name="2.4.1",
                    version_code=241,
                    sha256=digest,
                    storage_ref=f"artifacts/{digest}",
                    original_filename=filename,
                    file_size=128,
                    build_type=build_type,
                    metadata_json={"platform": "ios", "artifact_format": app_format},
                    created_by=api.users["admin"],
                )
            )
        session.commit()

    assert [
        item["id"]
        for item in expect(api.get("/clients", params={"client_type": "individual"}))["items"]
    ] == [individual["id"]]
    assert (
        expect(api.get("/clients", params={"q": "morgan@northstar.example"}))["items"][0]["id"]
        == company["id"]
    )
    assert (
        expect(
            api.get(
                "/projects",
                params={"q": "com.northstar", "platform": "ios", "framework": "flutter"},
            )
        )["items"][0]["id"]
        == ios["id"]
    )
    assert (
        expect(api.get("/projects", params={"client_id": individual["id"], "platform": "android"}))[
            "items"
        ][0]["id"]
        == android["id"]
    )
    artifacts = expect(
        api.get(
            f"/projects/{ios['id']}/versions",
            params={"q": "release", "build_type": "release", "artifact_format": "aab"},
        )
    )
    assert artifacts["total"] == 1
    assert artifacts["items"][0]["artifact_format"] == "aab"
    overview = expect(api.get("/overview"))
    assert overview["artifact_formats"] == {"apk": 1, "aab": 1, "ipa": 0}

    assessed = make_assessment(
        api, ios, name="Credential and session review", assessment_type="static"
    )
    other = make_assessment(api, android, name="Wallet API review", assessment_type="api")
    with Session(api.engine) as session:
        for assessment, project, title, component, severity, verification, remediation in (
            (
                assessed,
                ios,
                "Token stored in preferences",
                "SharedPreferences/auth-token",
                "high",
                "confirmed",
                "retest_required",
            ),
            (
                assessed,
                ios,
                "Candidate weak cipher",
                "CryptoConfig",
                "medium",
                "unreviewed",
                "open",
            ),
            (
                other,
                android,
                "Wallet authorization",
                "GET /v1/wallet",
                "critical",
                "confirmed",
                "open",
            ),
        ):
            session.add(
                Finding(
                    workspace_id=api.workspaces["main"],
                    project_id=UUID(project["id"]),
                    assessment_id=UUID(assessment["id"]),
                    created_by=api.users["admin"],
                    title=title,
                    description="A scoped test observation.",
                    affected_component=component,
                    category="storage",
                    severity=severity,
                    verification_status=verification,
                    remediation_status=remediation,
                    reproduction_steps="Use the approved test build and account.",
                    impact="Sensitive application behavior may be exposed.",
                    remediation="Apply the documented control and verify it independently.",
                )
            )
        session.commit()

    matched = expect(
        api.get(
            "/findings",
            params={
                "q": "SharedPreferences",
                "project_id": ios["id"],
                "assessment_id": assessed["id"],
                "severity": "high",
                "verification_status": "confirmed",
                "remediation_status": "retest_required",
            },
        )
    )
    assert matched["total"] == 1
    assert matched["items"][0]["title"] == "Token stored in preferences"
    expect(api.get("/findings", params={"remediation_status": "unknown"}), 422)


def test_audit_filters_include_actor_resource_and_inclusive_utc_dates(api):
    expected_resource = uuid4()
    with Session(api.engine) as session:
        session.add_all(
            [
                AuditEvent(
                    workspace_id=api.workspaces["main"],
                    actor_id=api.users["admin"],
                    action="report.exported",
                    resource_type="report",
                    resource_id=expected_resource,
                    result="success",
                    request_id="audit-filter-success",
                    source_metadata={"source": "test"},
                ),
                AuditEvent(
                    workspace_id=api.workspaces["main"],
                    actor_id=api.users["analyst"],
                    action="report.exported",
                    resource_type="report",
                    resource_id=uuid4(),
                    result="failure",
                    request_id="audit-filter-failure",
                    source_metadata={"source": "test"},
                ),
            ]
        )
        session.commit()
    today = datetime.now(UTC).date().isoformat()
    page = expect(
        api.get(
            "/audit-events",
            params={
                "action": "report.exported",
                "resource_type": "report",
                "result": "success",
                "actor_id": str(api.users["admin"]),
                "resource_id": str(expected_resource),
                "date_from": today,
                "date_to": today,
            },
        )
    )
    assert page["total"] == 1
    assert page["summary"] == {"success": 1, "failure": 0}
    expect(
        api.get("/audit-events", params={"date_from": "2026-10-31", "date_to": "2026-10-30"}),
        422,
    )


def test_audit_export_is_workspace_scoped_filtered_admin_only_and_sanitized(api):
    main_resource = uuid4()
    with Session(api.engine) as session:
        session.add_all(
            [
                AuditEvent(
                    workspace_id=api.workspaces["main"],
                    actor_id=api.users["admin"],
                    action="client.created",
                    resource_type="client",
                    resource_id=main_resource,
                    result="success",
                    request_id="export-main-event",
                    source_metadata={
                        "channel": "api",
                        "changed_fields": ["workspace_name", "evil\n=SUM(1)"],
                        "method": {"secret": "must-not-export"},
                        "private_token": "must-not-export",
                    },
                ),
                AuditEvent(
                    workspace_id=api.workspaces["other"],
                    actor_id=api.users["other_admin"],
                    action="other.secret",
                    resource_type="credential",
                    resource_id=uuid4(),
                    result="success",
                    request_id="foreign-workspace-event",
                    source_metadata={"channel": "api", "private_token": "foreign-secret"},
                ),
            ]
        )
        session.commit()

    expect(api.get("/audit-events/export", role="analyst", params={"format": "json"}), 403)
    response = api.get(
        "/audit-events/export",
        params={"format": "json", "action": "client.created", "resource_id": str(main_resource)},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert 'filename="droidshield-audit-export.json"' in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "no-store"
    exported = response.json()
    assert exported["total"] == 1
    assert exported["items"][0]["resource_id"] == str(main_resource)
    assert exported["items"][0]["source"] == {
        "channel": "api",
        "changed_fields": "workspace_name",
    }
    assert "must-not-export" not in response.text
    assert "foreign-workspace-event" not in response.text

    foreign = api.get("/audit-events/export", role="other_admin", params={"format": "json"})
    assert foreign.status_code == 200
    assert foreign.json()["total"] == 1
    assert foreign.json()["items"][0]["request_id"] == "foreign-workspace-event"
    assert "client.created" not in foreign.text

    export_audit = expect(api.get("/audit-events", params={"action": "audit.exported"}))
    assert export_audit["total"] == 1
    assert export_audit["items"][0]["source"] == {
        "channel": "api",
        "format": "json",
        "record_count": "1",
        "filters": "action, resource_id",
    }
    assert str(main_resource) not in str(export_audit["items"][0]["source"])


def test_audit_csv_export_neutralizes_spreadsheet_formulas_and_rejects_bad_filters(api):
    with Session(api.engine) as session:
        session.add(
            AuditEvent(
                workspace_id=api.workspaces["main"],
                actor_id=api.users["admin"],
                action="=1+1",
                resource_type="api",
                resource_id=None,
                result="success",
                request_id="csv-formula-event",
                source_metadata={"channel": "api"},
            )
        )
        session.commit()

    response = api.get("/audit-events/export", params={"format": "csv", "action": "=1+1"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'filename="droidshield-audit-export.csv"' in response.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0] == [
        "id",
        "timestamp",
        "actor_id",
        "action",
        "resource_type",
        "resource_id",
        "result",
        "request_id",
        "source",
    ]
    assert rows[1][3] == "'=1+1"
    expect(api.get("/audit-events/export", params={"format": "xml"}), 422)
    expect(
        api.get(
            "/audit-events/export",
            params={"format": "csv", "date_from": "2026-10-31", "date_to": "2026-10-30"},
        ),
        422,
    )


def test_audit_export_enforces_record_limit_without_logging_failed_export(api, monkeypatch):
    import droidshield.assessment_api as assessment_api

    monkeypatch.setattr(assessment_api, "MAX_AUDIT_EXPORT_RECORDS", 1)
    with Session(api.engine) as session:
        session.add_all(
            [
                AuditEvent(
                    workspace_id=api.workspaces["main"],
                    actor_id=api.users["admin"],
                    action="test.one",
                    resource_type="test",
                    resource_id=None,
                    result="success",
                    request_id="export-limit-one",
                    source_metadata={},
                ),
                AuditEvent(
                    workspace_id=api.workspaces["main"],
                    actor_id=api.users["admin"],
                    action="test.two",
                    resource_type="test",
                    resource_id=None,
                    result="success",
                    request_id="export-limit-two",
                    source_metadata={},
                ),
            ]
        )
        session.commit()
    expect(api.get("/audit-events/export", params={"format": "json"}), 413)
    assert expect(api.get("/audit-events", params={"action": "audit.exported"}))["total"] == 0


def test_audit_export_enforces_encoded_size_limit_without_logging_failed_export(api, monkeypatch):
    import droidshield.assessment_api as assessment_api

    monkeypatch.setattr(assessment_api, "MAX_AUDIT_EXPORT_BYTES", 1)
    response = api.get("/audit-events/export", params={"format": "json"})
    assert response.status_code == 413
    assert expect(api.get("/audit-events", params={"action": "audit.exported"}))["total"] == 0


def test_workspace_isolation_includes_direct_ids_and_membership_grants(api):
    local = make_project(api)
    foreign = make_project(api, role="other_admin")
    foreign_assessment = make_assessment(api, foreign, role="other_admin")
    expect(api.get(f"/projects/{foreign['id']}"), 404)
    expect(api.get(f"/clients/{foreign['client_id']}"), 404)
    expect(api.get(f"/assessments/{foreign_assessment['id']}"), 404)
    expect(
        api.post(
            f"/projects/{local['id']}/members",
            {
                "user_id": str(api.users["other_admin"]),
            },
        ),
        404,
    )
    assert {item["id"] for item in expect(api.get("/projects"))["items"]} == {local["id"]}
    assert {item["id"] for item in expect(api.get("/projects", role="other_admin"))["items"]} == {
        foreign["id"]
    }
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(ProjectAccess)) == 0


def test_idempotency_replays_creation_and_conflicts_on_changed_content(api):
    key = "client-create-request-001"
    payload = {"name": "Client", "notes": "Internal engagement notes"}
    first = expect(api.post("/clients", payload, key=key), 201)
    replay = expect(api.post("/clients", payload, key=key), 201)
    assert replay["id"] == first["id"]
    expect(api.post("/clients", {**payload, "name": "Different client"}, key=key), 409)
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(Client)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "client.created")
            )
            == 1
        )


def test_edits_reject_stale_revisions_and_leave_the_saved_value_intact(api):
    client = make_client(api)
    changed = expect(
        api.patch(
            f"/clients/{client['id']}",
            {
                "revision": client["revision"],
                "name": "Updated name",
            },
        )
    )
    assert changed["revision"] > client["revision"]
    expect(
        api.patch(
            f"/clients/{client['id']}",
            {
                "revision": client["revision"],
                "name": "Stale overwrite",
            },
        ),
        409,
    )
    assert expect(api.get(f"/clients/{client['id']}"))["name"] == "Updated name"


def test_archive_rules_require_a_reason_and_active_children_are_preserved(api):
    client = make_client(api)
    project = make_project(api, client)
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {
                "revision": project["revision"],
                "status": "archived",
            },
        ),
        422,
    )
    expect(
        api.post(
            f"/clients/{client['id']}/archive",
            {
                "revision": client["revision"],
                "reason": "Engagement ended",
            },
        ),
        409,
    )
    archived_project = expect(
        api.post(
            f"/projects/{project['id']}/archive",
            {
                "revision": project["revision"],
                "reason": "Engagement ended",
            },
        )
    )
    assert archived_project["status"] == "archived"
    archived_client = expect(
        api.post(
            f"/clients/{client['id']}/archive",
            {
                "revision": client["revision"],
                "reason": "Engagement ended",
            },
        )
    )
    assert archived_client["archive_reason"] == "Engagement ended"
    expect(
        api.post(
            "/projects",
            {
                "client_id": client["id"],
                "name": "New project",
                "application_name": "Store",
                "package_id": "com.example.store",
            },
        ),
        409,
    )
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {
                "revision": archived_project["revision"],
                "status": "active",
            },
        ),
        409,
    )


@pytest.mark.parametrize(
    "blocker", ["missing", "pending", "expired", "future", "excluded", "outside_scope"]
)
def test_queue_requires_current_verified_authorization_and_explicit_scope(api, blocker):
    project = make_project(api)
    permit = None
    targets = [API_TARGET]
    if blocker != "missing":
        changes = {}
        if blocker == "future":
            changes = {
                "valid_from": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            }
        elif blocker == "excluded":
            changes = {"exclusions": ["https://api.example.test/"]}
        permit = make_authorization(api, project, verify=blocker != "pending", **changes)
        if blocker == "expired":
            with Session(api.engine) as session:
                record = session.get(Authorization, UUID(permit["id"]))
                record.valid_from = datetime.now(UTC) - timedelta(days=2)
                record.valid_until = datetime.now(UTC) - timedelta(days=1)
                session.commit()
        if blocker == "outside_scope":
            targets = ["https://other.example.test/v1"]
    assessment = make_assessment(api, project, permit, targets=targets)
    expect(queue(api, assessment), 409)
    assert expect(api.get(f"/assessments/{assessment['id']}"))["status"] == "draft"
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AnalysisJob)) == 0


def test_expired_authorization_cannot_be_verified(api):
    project = make_project(api)
    permit = make_authorization(
        api,
        project,
        verify=False,
        valid_from=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
        valid_until=(datetime.now(UTC) - timedelta(days=1)).isoformat(),
    )
    expect(
        api.post(
            f"/authorizations/{permit['id']}/verify",
            {
                "revision": permit["revision"],
            },
        ),
        409,
    )


def test_verified_api_queue_replays_once_and_revocation_cancels_its_job(api):
    project = make_project(api)
    permit = make_authorization(api, project)
    assessment = make_assessment(api, project, permit)
    queued = expect(queue(api, assessment, key="queue-api-once"))
    assert queued["status"] == "queued"
    assert expect(queue(api, assessment, key="queue-api-once"))["id"] == assessment["id"]
    expect(
        api.patch(
            f"/projects/{project['id']}",
            {
                "revision": project["revision"],
                "status": "on_hold",
            },
        ),
        409,
    )
    expect(
        api.patch(
            f"/assessments/{assessment['id']}",
            {
                "revision": queued["revision"],
                "name": "Queued edits are disallowed",
            },
        ),
        409,
    )
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AnalysisJob)) == 1
        job = session.scalar(select(AnalysisJob))
        assert job.status == "queued"
        assert job.configuration_snapshot["authorization_revision"] == permit["revision"]
        assert job.configuration_snapshot["approved_targets"] == [API_TARGET]
    revoked = expect(
        api.post(
            f"/authorizations/{permit['id']}/revoke",
            {
                "revision": permit["revision"],
                "reason": "Client withdrew permission",
            },
        )
    )
    assert revoked["status"] == "revoked"
    assert revoked["revocation_reason"] == "Client withdrew permission"
    assert expect(api.get(f"/assessments/{assessment['id']}"))["status"] == "cancelled"
    with Session(api.engine) as session:
        job = session.scalar(select(AnalysisJob))
        assert job.status == "cancelled"
        assert job.cancellation_reason == "Authorization revoked"


def test_draft_can_be_submitted_linked_to_authorization_and_queued(api):
    project = make_project(api)
    draft = make_assessment(api, project)
    submitted = expect(
        api.post(
            f"/assessments/{draft['id']}/submit",
            {
                "revision": draft["revision"],
            },
        )
    )
    assert submitted["status"] == "awaiting_authorization"
    permit = make_authorization(api, project)
    linked = expect(
        api.patch(
            f"/assessments/{draft['id']}",
            {
                "revision": submitted["revision"],
                "authorization_id": permit["id"],
            },
        )
    )
    assert linked["authorization_id"] == permit["id"]
    assert expect(queue(api, linked))["status"] == "queued"


def test_artifacts_and_authorizations_cannot_be_linked_across_projects(api):
    project = make_project(api)
    sibling = make_project(api)
    sibling_permit = make_authorization(api, sibling)
    draft = make_assessment(api, project)
    expect(
        api.patch(
            f"/assessments/{draft['id']}",
            {
                "revision": draft["revision"],
                "authorization_id": sibling_permit["id"],
            },
        ),
        404,
    )
    expect(
        api.post(
            "/assessments",
            {
                "project_id": project["id"],
                "name": "Invalid link",
                "assessment_type": "api",
                "authorization_id": sibling_permit["id"],
                "requested_targets": [API_TARGET],
            },
        ),
        404,
    )
    with Session(api.engine) as session:
        artifact = AppArtifact(
            workspace_id=api.workspaces["main"],
            project_id=UUID(sibling["id"]),
            sha256="b" * 64,
            storage_ref="protected/sibling.apk",
            original_filename="sibling.apk",
            file_size=1024,
            build_type="release",
            created_by=api.users["admin"],
            metadata_json={"package_name": "com.example.store"},
        )
        session.add(artifact)
        session.flush()
        artifact_id = str(artifact.id)
        session.commit()
    expect(
        api.patch(
            f"/assessments/{draft['id']}",
            {
                "revision": draft["revision"],
                "artifact_id": artifact_id,
            },
        ),
        404,
    )


@pytest.mark.parametrize("assessment_type", ["static", "dynamic", "full"])
def test_non_api_queue_requires_a_server_processed_artifact(api, assessment_type):
    project = make_project(api)
    targets = ["package:com.example.store"]
    permit = make_authorization(api, project, approved_targets=targets)
    assessment = make_assessment(
        api, project, permit, targets=targets, assessment_type=assessment_type
    )
    expect(queue(api, assessment), 409)
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AnalysisJob)) == 0
    # This release cannot register a caller-claimed hash as a trusted artifact.
    expect(
        api.post(
            f"/projects/{project['id']}/versions",
            {
                "sha256": "a" * 64,
                "file_size": 1024,
                "original_filename": "claimed.apk",
            },
        ),
        405,
    )


def test_artifact_and_assessment_outputs_hide_storage_raw_metadata_and_secrets(api):
    project = make_project(api)
    assessment = make_assessment(api, project)
    with Session(api.engine) as session:
        session.add(
            AppArtifact(
                workspace_id=api.workspaces["main"],
                project_id=UUID(project["id"]),
                version_name="1.0",
                version_code=1,
                sha256="a" * 64,
                storage_ref="protected-storage/must-stay-hidden.apk",
                original_filename="store.apk",
                file_size=1024,
                build_type="release",
                created_by=api.users["admin"],
                metadata_json={
                    "package_name": "com.example.store",
                    "api_token": "must-stay-hidden",
                },
            )
        )
        record = session.get(Assessment, UUID(assessment["id"]))
        record.configuration_snapshot = {
            "requested_targets": [API_TARGET],
            "secret": "must-stay-hidden",
        }
        record.tool_versions = {"secret": "must-stay-hidden"}
        session.commit()
    versions = expect(api.get(f"/projects/{project['id']}/versions"))
    assert versions["total"] == 1
    assert "storage_ref" not in versions["items"][0]
    assert "metadata_json" not in versions["items"][0]
    for response in (api.get(f"/assessments/{assessment['id']}"), api.get("/assessments")):
        expect(response)
        assert "must-stay-hidden" not in response.text
        assert "tool_versions" not in response.text
        assert "configuration_snapshot" not in response.text
    assert "must-stay-hidden" not in api.get(f"/projects/{project['id']}/versions").text


def test_audit_events_capture_actions_without_bodies_or_credentials(api):
    client = make_client(
        api, notes="sensitive-note-not-for-audit", contact_email="client@example.com"
    )
    events = expect(api.get("/audit-events", params={"action": "client.created"}))
    assert events["total"] == 1
    event = events["items"][0]
    assert event["resource_id"] == client["id"]
    assert event["actor_id"] == str(api.users["admin"])
    assert event["result"] == "success"
    assert event["request_id"]
    assert "sensitive-note-not-for-audit" not in str(events)
    assert "client@example.com" not in str(events)
    assert api.tokens["admin"] not in str(events)


def test_project_grant_does_not_expose_parent_client_private_notes(api):
    owner = make_client(api, notes="Private sibling engagement details")
    project = make_project(api, owner)
    grant(api, project, "viewer")
    grant(api, project, "analyst")
    for role in ("viewer", "analyst"):
        detail = expect(api.get(f"/clients/{owner['id']}", role=role))
        assert detail["name"] == owner["name"]
        assert detail["notes"] is None
        assert detail["archive_reason"] is None
        listing = expect(api.get("/clients", role=role))
        assert listing["items"][0]["notes"] is None
        assert "Private sibling engagement details" not in str(listing)
    assert expect(api.get(f"/clients/{owner['id']}"))["notes"] == owner["notes"]


def test_overview_counts_database_records_and_respects_project_visibility(api):
    empty = expect(api.get("/overview"))
    assert empty["total_projects"] == empty["total_assessments"] == empty["open_findings"] == 0
    assert empty["total_clients"] == empty["total_artifacts"] == empty["total_reports"] == 0
    assert empty["artifact_formats"] == {"apk": 0, "aab": 0, "ipa": 0}
    first, second = make_project(api), make_project(api)
    permit = make_authorization(api, first)
    active = make_assessment(api, first, permit)
    expect(queue(api, active))
    hidden = make_assessment(api, second)
    with Session(api.engine) as session:
        for assessment, project, severity, verification, remediation in (
            (active, first, "high", "confirmed", "open"),
            (active, first, "critical", "confirmed", "fixed"),
            (active, first, "critical", "unreviewed", "open"),
            (hidden, second, "medium", "confirmed", "retest_required"),
        ):
            session.add(
                Finding(
                    workspace_id=api.workspaces["main"],
                    project_id=UUID(project["id"]),
                    assessment_id=UUID(assessment["id"]),
                    created_by=api.users["admin"],
                    title="Review finding",
                    description="Evidence-backed issue",
                    affected_component="API",
                    category="authorization",
                    severity=severity,
                    verification_status=verification,
                    remediation_status=remediation,
                    reproduction_steps="Review sanitized evidence",
                    impact="Test impact",
                    remediation="Apply the documented fix",
                )
            )
        session.commit()
    overview = expect(api.get("/overview"))
    assert overview["total_projects"] == overview["total_assessments"] == 2
    assert overview["in_progress"] == 1
    assert overview["open_findings"] == 2
    assert overview["total_findings"] == 4
    assert overview["confirmed_findings"] == 3
    assert overview["unreviewed_findings"] == 1
    assert overview["critical_findings"] == 0
    assert overview["high_findings"] == 1
    assert overview["severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    grant(api, first, "viewer")
    restricted = expect(api.get("/overview", role="viewer"))
    assert (
        restricted["total_projects"]
        == restricted["total_assessments"]
        == restricted["open_findings"]
        == 1
    )
    assert restricted["total_findings"] == 3
    assert restricted["total_clients"] == 1
    assert restricted["severity"]["medium"] == 0


def test_overview_filters_scope_counts_and_recent_assessments(api):
    project = make_project(api, name="Filtered mobile app")
    other_project = make_project(api, name="Other mobile app")
    current_static = make_assessment(api, project, name="Current static", assessment_type="static")
    current_api = make_assessment(api, project, name="Current API", assessment_type="api")
    old_static = make_assessment(api, project, name="Previous static", assessment_type="static")
    other = make_assessment(api, other_project, name="Other project", assessment_type="static")
    now = datetime.now(UTC)
    with Session(api.engine) as session:
        session.get(Assessment, UUID(current_static["id"])).status = "completed"
        session.get(Assessment, UUID(current_api["id"])).status = "failed"
        session.get(Assessment, UUID(old_static["id"])).status = "completed"
        session.get(Assessment, UUID(old_static["id"])).created_at = now - timedelta(days=3)
        session.get(Assessment, UUID(other["id"])).status = "completed"
        session.commit()

    today = now.date().isoformat()
    filtered = expect(
        api.get(
            "/overview",
            params={
                "project_id": project["id"],
                "assessment_type": "static",
                "assessment_status": "completed",
                "date_from": today,
                "date_to": today,
            },
        )
    )
    assert filtered["total_projects"] == 1
    assert filtered["total_assessments"] == 1
    assert filtered["completed_assessments"] == 1
    assert filtered["failed_assessments"] == 0

    recent = expect(
        api.get(
            "/assessments",
            params={"project_id": project["id"], "date_from": today, "date_to": today},
        )
    )
    assert {item["id"] for item in recent["items"]} == {
        current_static["id"],
        current_api["id"],
    }

    expect(
        api.get(
            "/overview",
            params={"date_from": today, "date_to": (now.date() - timedelta(days=1)).isoformat()},
        ),
        422,
    )
    expect(api.get("/overview", params={"assessment_status": "not-a-status"}), 422)
    grant(api, project, "viewer")
    expect(api.get("/overview", role="viewer", params={"project_id": other_project["id"]}), 404)


def test_list_pagination_and_literal_search_have_stable_totals(api):
    clients = [make_client(api, name=name) for name in ("alpha_one", "alphaXone", "beta")]
    first = expect(api.get("/clients", params={"limit": 2, "offset": 0}))
    second = expect(api.get("/clients", params={"limit": 2, "offset": 2}))
    assert first["total"] == second["total"] == 3
    assert first["limit"] == 2 and second["offset"] == 2
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    ids = [item["id"] for item in first["items"] + second["items"]]
    assert len(set(ids)) == 3
    assert set(ids) == {item["id"] for item in clients}
    filtered = expect(api.get("/clients", params={"q": "_"}))
    assert filtered["total"] == 1
    assert filtered["items"][0]["name"] == "alpha_one"


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 10001}, {"q": "q" * 201}]
)
def test_list_filters_are_bounded(api, params):
    expect(api.get("/clients", params=params), 422)


def test_form_validation_does_not_echo_sensitive_extra_fields(api):
    response = api.post("/clients", {"name": "Client", "password": "secret-never-echo"})
    expect(response, 422)
    assert "secret-never-echo" not in response.text
    expect(
        api.client.post(PREFIX + "/clients", json={"name": "Client"}, headers=api.headers()), 422
    )


def test_workspace_user_lifecycle_is_admin_scoped_and_requires_password_setup(api):
    payload = {
        "full_name": "New Analyst",
        "email": "New.Analyst@Example.com",
        "role": "SECURITY_ANALYST",
    }
    created = expect(api.post("/users", payload, key="create-new-analyst"), 201)
    assert created["email"] == "new.analyst@example.com"
    assert created["status"] == "disabled"
    assert "password_hash" not in created
    assert "password" not in created

    replay = expect(api.post("/users", payload, key="create-new-analyst"), 201)
    assert replay["id"] == created["id"]
    expect(
        api.post(
            "/users",
            {**payload, "full_name": "Changed payload"},
            key="create-new-analyst",
        ),
        409,
    )

    users = expect(api.get("/users", params={"role": "SECURITY_ANALYST", "status": "disabled"}))
    assert users["total"] == 1
    assert users["items"][0]["id"] == created["id"]
    expect(api.get("/users", role="analyst"), 403)
    expect(
        api.patch(f"/users/{created['id']}", {"status": "active"}),
        409,
    )

    with Session(api.engine) as session:
        record = session.get(User, UUID(created["id"]))
        record.password_hash = hash_password("correct-horse-battery-staple")
        session.commit()
    activated = expect(api.patch(f"/users/{created['id']}", {"status": "active"}))
    assert activated["status"] == "active"

    expect(api.patch(f"/users/{api.users['other_admin']}", {"role": "VIEWER"}), 404)
    expect(api.get("/users", role="viewer"), 403)


def test_workspace_user_admin_invariants_and_session_revocation(api):
    user_id = uuid4()
    with Session(api.engine) as session:
        record = User(
            id=user_id,
            workspace_id=api.workspaces["main"],
            email="temporary@example.com",
            full_name="Temporary Analyst",
            password_hash=hash_password("correct-horse-battery-staple"),
            role="SECURITY_ANALYST",
            status="active",
        )
        session.add(record)
        session.flush()
        credential = issue_token(session, record.id, ttl_hours=12)
        session.commit()
    expect(api.patch(f"/users/{api.users['admin']}", {"status": "disabled"}), 409)
    expect(api.patch(f"/users/{api.users['admin']}", {"role": "VIEWER"}), 409)

    disabled = expect(api.patch(f"/users/{user_id}", {"status": "disabled"}))
    assert disabled["status"] == "disabled"
    expect(
        api.client.get(PREFIX + "/me", headers={"Authorization": f"Bearer {credential}"}),
        401,
    )
    with Session(api.engine) as session:
        token = session.scalar(select(AccessToken).where(AccessToken.user_id == user_id))
        assert token.revoked_at is not None

    with Session(api.engine) as session:
        # Re-enable the member to exercise the explicit session-revocation action.
        record = session.get(User, user_id)
        record.status = "active"
        session.add(
            AccessToken(
                user_id=user_id,
                token_hash=token_hash("ds_session_to_revoke"),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        session.commit()
    revoked = expect(
        api.post(
            f"/users/{user_id}/revoke-sessions",
            {},
            key="revoke-temporary-sessions",
        )
    )
    assert revoked["id"] == str(user_id)
    expect(
        api.client.get(
            PREFIX + "/me",
            headers={"Authorization": "Bearer ds_session_to_revoke"},
        ),
        401,
    )


def test_workspace_user_contract_rejects_null_and_extra_fields(api):
    created = expect(
        api.post(
            "/users",
            {"full_name": "Contract User", "email": "contract@example.com", "role": "VIEWER"},
        ),
        201,
    )
    expect(api.patch(f"/users/{created['id']}", {"role": None}), 422)
    expect(api.patch(f"/users/{created['id']}", {"status": "active", "email": "x@y.z"}), 422)
    expect(api.patch(f"/users/{created['id']}", {}), 422)


@pytest.mark.parametrize(
    ("role", "client_create_status", "project_update_status"),
    [("admin", 201, 200), ("analyst", 201, 200), ("viewer", 403, 403)],
)
def test_workspace_role_matrix_for_client_and_project_writes(
    api, role, client_create_status, project_update_status
):
    response = api.post("/clients", {"name": f"Created by {role}"}, role=role)
    expect(response, client_create_status)

    project = make_project(api)
    if role in {"analyst", "viewer"}:
        grant(api, project, role)
    update = api.patch(
        f"/projects/{project['id']}",
        {"revision": project["revision"], "description": f"Updated by {role}"},
        role=role,
    )
    body = expect(update, project_update_status)
    if project_update_status == 200:
        assert body["description"] == f"Updated by {role}"
    else:
        assert expect(api.get(f"/projects/{project['id']}"))["description"] is None


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_project_grant_is_limited_to_one_project_and_its_client(api, role):
    allowed_client = make_client(api, name="Allowed Client")
    allowed_project = make_project(api, allowed_client, name="Allowed App")
    allowed_assessment = make_assessment(api, allowed_project, name="Allowed Assessment")

    sibling_project = make_project(api, allowed_client, name="Sibling App")
    sibling_assessment = make_assessment(api, sibling_project, name="Sibling Assessment")
    other_client = make_client(api, name="Other Client")
    other_project = make_project(api, other_client, name="Other Client App")
    other_assessment = make_assessment(api, other_project, name="Other Client Assessment")
    grant(api, allowed_project, role)

    projects = expect(api.get("/projects", role=role))
    assert {record["id"] for record in projects["items"]} == {allowed_project["id"]}
    clients = expect(api.get("/clients", role=role))
    assert {record["id"] for record in clients["items"]} == {allowed_client["id"]}
    assessments = expect(api.get("/assessments", role=role))
    assert {record["id"] for record in assessments["items"]} == {allowed_assessment["id"]}

    expect(api.get(f"/projects/{allowed_project['id']}", role=role))
    expect(api.get(f"/assessments/{allowed_assessment['id']}", role=role))
    for path in (
        f"/projects/{sibling_project['id']}",
        f"/assessments/{sibling_assessment['id']}",
        f"/clients/{other_client['id']}",
        f"/projects/{other_project['id']}",
        f"/assessments/{other_assessment['id']}",
    ):
        expect(api.get(path, role=role), 404)
