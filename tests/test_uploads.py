"""Protected intake, artifact reads and real isolated execution through the HTTP API."""

import hashlib
import os
import zipfile
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from droidshield.auth import issue_token
from droidshield.config import Settings
from droidshield.models import AppArtifact, Assessment, Base, Client, User, Workspace
from tests.apk_factory import build_apk
from tests.test_api import (
    PREFIX,
    Harness,
    expect,
    grant,
    isolated_test_engine,
    make_assessment,
    make_authorization,
    make_client,
    make_project,
    queue,
)

PACKAGE_TARGET = "package:com.example.store"
DEFAULT_APK = build_apk(package_name="com.example.store")


@pytest.fixture
def upload_api(tmp_path):
    from droidshield.main import create_app

    database_url = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL", "sqlite://")
    with isolated_test_engine(database_url) as engine:
        Base.metadata.create_all(engine)
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=database_url,
            allowed_hosts=["testserver"],
            storage_root=tmp_path / "artifacts",
            sandbox_executable="/usr/bin/bwrap",
            sandbox_python="/usr/bin/python3",
        )
        users, tokens, workspaces = {}, {}, {}
        with Session(engine) as session:
            for name in ("main", "other"):
                workspace = Workspace(name=f"{name} workspace")
                session.add(workspace)
                session.flush()
                workspaces[name] = workspace.id
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


def static_draft(api, project=None, permit=None):
    project = project or make_project(api)
    assessment = make_assessment(
        api,
        project,
        permit,
        targets=[PACKAGE_TARGET],
        assessment_type="static",
        name="Manifest assessment",
    )
    return project, assessment


def upload(
    api,
    assessment,
    *,
    content=None,
    filename="store.apk",
    mime=None,
    key=None,
    role="admin",
    **fields,
):
    body = {
        "revision": str(assessment["revision"]),
        "build_type": "release",
        **fields,
    }
    return api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/apk",
        data=body,
        files={
            "file": (
                filename,
                DEFAULT_APK if content is None else content,
                mime or "application/vnd.android.package-archive",
            )
        },
        headers=api.headers(role, key or str(uuid4())),
    )


def artifact_count(api):
    with Session(api.engine) as session:
        return session.scalar(select(func.count()).select_from(AppArtifact))


def test_upload_calculates_digest_links_revision_and_protects_original_bytes(upload_api):
    api = upload_api
    project, draft = static_draft(api)
    content = build_apk(package_name="com.example.store", version_name="1.2.3", version_code=7)
    artifact = expect(
        upload(
            api,
            draft,
            content=content,
            app_version="Client build label",
            upload_notes="private upload note",
        ),
        201,
    )
    assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
    assert artifact["file_size"] == len(content)
    assert artifact["version_name"] == "1.2.3"
    assert artifact["version_code"] == 7
    assert artifact["build_type"] == "release"
    assert "storage_ref" not in artifact
    assert "metadata_json" not in artifact
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] == artifact["id"]
    assert current["revision"] == draft["revision"] + 1
    assert current["status"] == "draft"
    versions = expect(api.get(f"/projects/{project['id']}/versions"))
    assert versions["total"] == 1
    assert versions["items"][0]["id"] == artifact["id"]
    assert "private upload note" not in str(versions)
    assert "private upload note" not in str(expect(api.get("/audit-events")))
    stored = list(api.client.app.state.settings.storage_root.rglob("*.apk"))
    assert len(stored) == 1
    assert stored[0].read_bytes() == content
    assert stored[0].stat().st_mode & 0o077 == 0
    response = api.get(f"/artifacts/{artifact['id']}/download")
    assert response.status_code == 200
    assert response.content == content
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]


def test_exact_upload_replay_survives_advanced_revision_without_duplicate_artifacts(upload_api):
    api = upload_api
    project, draft = static_draft(api)
    key = str(uuid4())
    first = expect(upload(api, draft, key=key), 201)
    replay = expect(upload(api, draft, key=key), 201)
    assert replay == first
    assert artifact_count(api) == 1
    assert expect(api.get(f"/assessments/{draft['id']}"))["revision"] == draft["revision"] + 1
    _, sibling = static_draft(api, project)
    same = expect(upload(api, sibling), 201)
    assert same["id"] == first["id"]
    assert artifact_count(api) == 1
    assert expect(api.get(f"/assessments/{sibling['id']}"))["artifact_id"] == first["id"]


@pytest.mark.parametrize("changed", ["bytes", "revision", "metadata"])
def test_reusing_upload_key_for_changed_payload_conflicts(upload_api, changed):
    api = upload_api
    _, draft = static_draft(api)
    key = str(uuid4())
    expect(upload(api, draft, key=key), 201)
    fields = {}
    if changed == "bytes":
        fields["content"] = build_apk(package_name="com.example.store", version_code=999)
    elif changed == "revision":
        fields["revision"] = str(draft["revision"] + 1)
    else:
        fields["upload_notes"] = "Different notes"
    expect(upload(api, draft, key=key, **fields), 409)
    assert artifact_count(api) == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"filename": "../store.apk"},
        {"filename": r"C:\\apps\\store.apk"},
        {"filename": "store.zip"},
        {"mime": "text/plain"},
        {"revision": "true"},
        {"revision": "1.0"},
        {"revision": "-1"},
        {"build_type": "production"},
        {"upload_notes": "x" * 20_001},
        {"sha256": "a" * 64},
    ],
)
def test_upload_contract_rejects_paths_types_invalid_fields_and_claimed_hashes(upload_api, fields):
    api = upload_api
    _, draft = static_draft(api)
    expect(upload(api, draft, **fields), 415 if "mime" in fields else 422)
    assert artifact_count(api) == 0
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] is None
    assert current["revision"] == draft["revision"]


def test_upload_and_download_enforce_current_identity_role_and_project_grants(upload_api):
    api = upload_api
    project, draft = static_draft(api)
    raw = build_apk(package_name="com.example.store")
    response = api.client.post(
        PREFIX + f"/assessments/{draft['id']}/apk",
        data={"revision": "1"},
        files={"file": ("store.apk", raw, "application/octet-stream")},
    )
    expect(response, 401)
    grant(api, project, "viewer")
    expect(upload(api, draft, role="viewer"), 403)
    expect(upload(api, draft, role="analyst"), 404)
    expect(upload(api, draft, role="other_admin"), 404)
    grant(api, project, "analyst")
    artifact = expect(upload(api, draft, role="analyst", mime="application/octet-stream"), 201)
    for role, status in (("viewer", 200), ("analyst", 200), ("other_admin", 404)):
        assert api.get(f"/artifacts/{artifact['id']}/download", role=role).status_code == status
    no_key = api.client.post(
        PREFIX + f"/assessments/{draft['id']}/apk",
        data={"revision": "1"},
        files={"file": ("store.apk", raw, "application/octet-stream")},
        headers=api.headers(),
    )
    expect(no_key, 422)


def test_upload_rechecks_project_and_parent_client_activity(upload_api):
    api = upload_api
    client = make_client(api)
    project = make_project(api, client)
    _, draft = static_draft(api, project)
    expect(
        api.patch(
            f"/projects/{project['id']}", {"revision": project["revision"], "status": "on_hold"}
        )
    )
    expect(upload(api, draft), 409)
    project = expect(api.get(f"/projects/{project['id']}"))
    expect(
        api.patch(
            f"/projects/{project['id']}", {"revision": project["revision"], "status": "active"}
        )
    )
    # A parent can also change through trusted administrative maintenance.
    # Intake still validates that parent instead of assuming prior API guards.
    with Session(api.engine) as session:
        parent = session.get(Client, UUID(client["id"]))
        parent.status = "archived"
        parent.archive_reason = "Engagement ended"
        session.commit()
    expect(upload(api, draft), 409)
    assert artifact_count(api) == 0


@pytest.mark.parametrize(
    "content",
    [
        b"not an APK",
        build_apk(manifest=b"<manifest package='com.example.store'/>"),
        build_apk(package_name="com.example.store", extra_entries=(("../escape", b"bad"),)),
        build_apk(
            package_name="com.example.store",
            compression=zipfile.ZIP_DEFLATED,
            extra_entries=(("assets/bomb.txt", b"x" * 1_000_000),),
        ),
    ],
)
def test_invalid_or_unsafe_archives_never_become_registered_artifacts(upload_api, content):
    api = upload_api
    _, draft = static_draft(api)
    expect(upload(api, draft, content=content), 422)
    assert artifact_count(api) == 0
    assert not list(api.client.app.state.settings.storage_root.rglob("*.apk"))


def test_detected_package_must_match_the_scoped_project(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    expect(upload(api, draft, content=build_apk(package_name="com.other.app")), 422)
    assert artifact_count(api) == 0


@pytest.mark.parametrize("payload_size", [2048, 70_000])
def test_declared_and_streamed_size_limits_reject_without_linking_an_artifact(
    upload_api, payload_size
):
    api = upload_api
    _, draft = static_draft(api)
    api.client.app.state.settings.max_apk_bytes = 1024
    expect(upload(api, draft, content=b"x" * payload_size), 413)
    assert artifact_count(api) == 0
    assert expect(api.get(f"/assessments/{draft['id']}"))["artifact_id"] is None


def test_chunked_request_cannot_bypass_upload_body_budget(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    api.client.app.state.settings.max_apk_bytes = 1024
    boundary = "droidshield-test-boundary"
    chunks = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="revision"\r\n\r\n1\r\n'.encode(),
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="store.apk"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
        b"x" * 70_000,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    response = api.client.post(
        PREFIX + f"/assessments/{draft['id']}/apk",
        content=iter(chunks),
        headers={
            **api.headers(key=str(uuid4())),
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    expect(response, 413)
    assert artifact_count(api) == 0


def test_missing_sandbox_fails_closed_before_artifact_registration(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    api.client.app.state.settings.sandbox_executable = "/unavailable/bwrap"
    response = upload(api, draft)
    expect(response, 503)
    assert "/unavailable" not in response.text
    assert artifact_count(api) == 0


def test_queue_freezes_uploaded_artifact_and_sanitized_read_endpoints_are_scoped(upload_api):
    api = upload_api
    project = make_project(api)
    permit = make_authorization(api, project, approved_targets=[PACKAGE_TARGET])
    _, draft = static_draft(api, project, permit)
    expect(upload(api, draft), 201)
    current = expect(api.get(f"/assessments/{draft['id']}"))
    expect(queue(api, current))
    expect(upload(api, current), 409)
    job = expect(api.get(f"/assessments/{draft['id']}/job"))
    assert job["status"] == "queued"
    for field in ("configuration_snapshot", "logs_ref", "worker_id"):
        assert field not in job
    for resource in ("job", "analysis", "findings"):
        expect(api.get(f"/assessments/{draft['id']}/{resource}", role="other_admin"), 404)
    with Session(api.engine) as session:
        assessment = session.get(Assessment, UUID(draft["id"]))
        assert assessment.artifact_id is not None


def test_real_isolated_manifest_analysis_delivers_reviewable_unconfirmed_results(upload_api):
    from droidshield.worker import run_once

    api = upload_api
    project = make_project(api)
    permit = make_authorization(api, project, approved_targets=[PACKAGE_TARGET])
    _, draft = static_draft(api, project, permit)
    content = build_apk(
        package_name="com.example.store",
        debuggable=True,
        cleartext=True,
        allow_backup=True,
        components=({"kind": "activity", "name": ".MainActivity", "exported": True},),
    )
    artifact = expect(upload(api, draft, content=content), 201)
    current = expect(api.get(f"/assessments/{draft['id']}"))
    expect(queue(api, current))
    assert run_once(api.client.app.state.settings, api.engine)
    assert not run_once(api.client.app.state.settings, api.engine)
    completed = expect(api.get(f"/assessments/{draft['id']}"))
    assert completed["status"] == "needs_review"
    assert completed["completed_at"] is None
    job = expect(api.get(f"/assessments/{draft['id']}/job"))
    assert job["status"] == "completed"
    assert job["started_at"] and job["completed_at"]
    analysis = expect(api.get(f"/assessments/{draft['id']}/analysis"))
    assert analysis["artifact_id"] == artifact["id"]
    assert analysis["artifact_sha256"] == hashlib.sha256(content).hexdigest()
    assert analysis["engine_version"] == "droidshield-manifest-1"
    assert analysis["metadata"]["package_name"] == "com.example.store"
    assert analysis["metadata"]["application"]["debuggable"] is True
    assert len(analysis["limitations"]) == 4
    findings = expect(api.get(f"/assessments/{draft['id']}/findings"))
    assert findings["total"] == 4
    assert {item["verification_status"] for item in findings["items"]} == {"unreviewed"}
    assert {item["remediation_status"] for item in findings["items"]} == {"open"}
    assert {item["artifact_id"] for item in findings["items"]} == {artifact["id"]}
    grant(api, project, "viewer")
    for resource in ("job", "analysis", "findings"):
        expect(api.get(f"/assessments/{draft['id']}/{resource}", role="viewer"))
        expect(api.get(f"/assessments/{draft['id']}/{resource}", role="other_admin"), 404)
    assert "storage_ref" not in str(analysis)
    assert "logs_ref" not in str(job)


@pytest.mark.parametrize("duplicate", ["revision", "file"])
def test_duplicate_multipart_fields_cannot_create_ambiguous_records(upload_api, duplicate):
    api = upload_api
    _, draft = static_draft(api)
    fields = [
        ("file", ("store.apk", DEFAULT_APK, "application/octet-stream")),
        ("revision", (None, str(draft["revision"]))),
    ]
    fields.append(fields[1] if duplicate == "revision" else fields[0])
    response = api.client.post(
        PREFIX + f"/assessments/{draft['id']}/apk",
        files=fields,
        headers=api.headers(key=str(uuid4())),
    )
    expect(response, 422)
    assert artifact_count(api) == 0


def test_stale_upload_revision_does_not_create_an_unlinked_artifact(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    expect(
        api.patch(
            f"/assessments/{draft['id']}",
            {"revision": draft["revision"], "name": "Updated draft"},
        )
    )
    expect(upload(api, draft), 409)
    assert artifact_count(api) == 0
    assert not list(api.client.app.state.settings.storage_root.rglob("*.apk"))


def test_upload_key_replay_does_not_bypass_revoked_project_access(upload_api):
    from droidshield.models import ProjectAccess

    api = upload_api
    project, draft = static_draft(api)
    grant(api, project, "analyst")
    key = str(uuid4())
    artifact = expect(upload(api, draft, role="analyst", key=key), 201)
    with Session(api.engine) as session:
        access = session.scalar(
            select(ProjectAccess).where(
                ProjectAccess.project_id == UUID(project["id"]),
                ProjectAccess.user_id == api.users["analyst"],
            )
        )
        session.delete(access)
        session.commit()
    expect(upload(api, draft, role="analyst", key=key), 404)
    expect(api.get(f"/artifacts/{artifact['id']}/download", role="analyst"), 404)
    assert artifact_count(api) == 1


def test_protected_download_rejects_changed_bytes_and_cleans_private_snapshot(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    artifact = expect(upload(api, draft), 201)
    settings = api.client.app.state.settings
    stored = next((settings.storage_root / "objects").glob("*.apk"))
    altered = bytearray(stored.read_bytes())
    altered[-1] ^= 1
    stored.chmod(0o600)
    stored.write_bytes(altered)
    response = api.get(f"/artifacts/{artifact['id']}/download")
    error = expect(response, 409)
    assert error["error"]["code"] == "artifact_integrity_failed"
    assert str(settings.storage_root) not in response.text
    assert not list((settings.storage_root / "staging").iterdir())


def test_awaiting_authorization_allows_intake_without_granting_execution(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    submitted = expect(
        api.post(f"/assessments/{draft['id']}/submit", {"revision": draft["revision"]})
    )
    assert submitted["status"] == "awaiting_authorization"
    expect(upload(api, submitted), 201)
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["status"] == "awaiting_authorization"
    assert current["artifact_id"] is not None
    expect(queue(api, current), 409)
    expect(api.get(f"/assessments/{draft['id']}/job"), 404)


@pytest.mark.parametrize(
    "change,status", [("disabled", 401), ("viewer", 403), ("grant_removed", 404)]
)
def test_access_changes_during_sandbox_inspection_prevent_artifact_publication(
    upload_api, monkeypatch, change, status
):
    from droidshield.models import ProjectAccess
    from droidshield.sandbox import Sandbox

    api = upload_api
    project, draft = static_draft(api)
    grant(api, project, "analyst")
    inspect = Sandbox.run

    def inspect_then_revoke(sandbox, *args, **kwargs):
        result = inspect(sandbox, *args, **kwargs)
        with Session(api.engine) as session:
            if change == "grant_removed":
                access = session.scalar(
                    select(ProjectAccess).where(
                        ProjectAccess.project_id == UUID(project["id"]),
                        ProjectAccess.user_id == api.users["analyst"],
                    )
                )
                session.delete(access)
            else:
                user = session.get(User, api.users["analyst"])
                if change == "disabled":
                    user.status = "disabled"
                else:
                    user.role = "VIEWER"
            session.commit()
        return result

    monkeypatch.setattr(Sandbox, "run", inspect_then_revoke)
    expect(upload(api, draft, role="analyst"), status)
    assert artifact_count(api) == 0
    assert not list(api.client.app.state.settings.storage_root.rglob("*.apk"))
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] is None
    assert current["revision"] == draft["revision"]


def test_ambiguous_database_commit_keeps_bytes_for_the_persisted_artifact(upload_api):
    from droidshield.api import db_session

    api = upload_api
    _, draft = static_draft(api)
    factory = api.client.app.state.session_factory
    committed = False

    def uncertain_session():
        nonlocal committed
        with factory() as session:
            commit = session.commit
            attempts = 0

            def commit_then_disconnect():
                nonlocal attempts, committed
                attempts += 1
                commit()
                if attempts == 2:
                    committed = True
                    raise RuntimeError("Simulated ambiguous commit outcome")

            session.commit = commit_then_disconnect
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise

    api.client.app.dependency_overrides[db_session] = uncertain_session
    try:
        with pytest.raises(RuntimeError, match="Simulated ambiguous commit outcome"):
            upload(api, draft)
    finally:
        api.client.app.dependency_overrides.clear()
    assert committed
    assert artifact_count(api) == 1
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] is not None
    downloaded = api.get(f"/artifacts/{current['artifact_id']}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == DEFAULT_APK


def cookie_login(api, role="admin"):
    from droidshield.auth import hash_password

    password = "Local-upload-test-passphrase!"
    with Session(api.engine) as session, session.begin():
        account = session.get(User, api.users[role])
        account.password_hash = hash_password(password)
    response = api.client.post(
        PREFIX + "/auth/login",
        json={"email": f"{role}@example.com", "password": password},
    )
    return expect(response)["csrf_token"]


def cookie_upload(api, draft, endpoint, csrf, *, key=None):
    return api.client.post(
        PREFIX + f"/assessments/{draft['id']}/{endpoint}",
        data={"revision": str(draft["revision"])},
        files={"file": ("store.apk", DEFAULT_APK, "application/vnd.android.package-archive")},
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": key or str(uuid4())},
    )


@pytest.mark.parametrize("endpoint", ["apk", "artifact"])
def test_email_password_cookie_upload_preserves_csrf_and_idempotent_replay(upload_api, endpoint):
    api = upload_api
    _, draft = static_draft(api)
    csrf = cookie_login(api)
    denied = cookie_upload(api, draft, endpoint, "")
    expect(denied, 403)
    assert artifact_count(api) == 0

    key = str(uuid4())
    created = expect(cookie_upload(api, draft, endpoint, csrf, key=key), 201)
    replay = expect(cookie_upload(api, draft, endpoint, csrf, key=key), 201)
    assert created == replay
    assert created["sha256"] == hashlib.sha256(DEFAULT_APK).hexdigest()
    assert artifact_count(api) == 1
    assert api.client.get(PREFIX + "/auth/session").status_code == 200
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] == created["id"]
    assert current["revision"] == draft["revision"] + 1


@pytest.mark.parametrize("endpoint", ["apk", "artifact"])
@pytest.mark.parametrize(
    "change,status",
    [
        ("revoked", 401),
        ("expired", 401),
        ("disabled", 401),
        ("viewer", 403),
        ("grant_removed", 404),
    ],
)
def test_cookie_access_changes_during_inspection_prevent_artifact_publication(
    upload_api, monkeypatch, endpoint, change, status
):
    from datetime import UTC, datetime, timedelta

    from droidshield.auth import SESSION_COOKIE, token_hash
    from droidshield.models import AccessToken, ProjectAccess
    from droidshield.sandbox import Sandbox

    api = upload_api
    project, draft = static_draft(api)
    grant(api, project, "analyst")
    csrf = cookie_login(api, "analyst")
    session_id = api.client.cookies.get(SESSION_COOKIE)
    inspect = Sandbox.run

    def inspect_then_revoke(sandbox, *args, **kwargs):
        result = inspect(sandbox, *args, **kwargs)
        with Session(api.engine) as session, session.begin():
            if change in {"revoked", "expired"}:
                credential = session.scalar(
                    select(AccessToken).where(AccessToken.token_hash == token_hash(session_id))
                )
                if change == "revoked":
                    credential.revoked_at = datetime.now(UTC)
                else:
                    credential.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            elif change == "grant_removed":
                access = session.scalar(
                    select(ProjectAccess).where(
                        ProjectAccess.project_id == UUID(project["id"]),
                        ProjectAccess.user_id == api.users["analyst"],
                    )
                )
                session.delete(access)
            else:
                account = session.get(User, api.users["analyst"])
                if change == "disabled":
                    account.status = "disabled"
                else:
                    account.role = "VIEWER"
        return result

    monkeypatch.setattr(Sandbox, "run", inspect_then_revoke)
    expect(cookie_upload(api, draft, endpoint, csrf), status)
    assert artifact_count(api) == 0
    assert not list(api.client.app.state.settings.storage_root.rglob("*.apk"))
    assert not list((api.client.app.state.settings.storage_root / "staging").glob("*"))
    current = expect(api.get(f"/assessments/{draft['id']}"))
    assert current["artifact_id"] is None
    assert current["revision"] == draft["revision"]
