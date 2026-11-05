"""Exact-scope HTTPS execution, tenant isolation, secret safety and real TLS probes."""

import hashlib
import json
import os
import ssl
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from droidshield import api_secrets, api_transport, services
from droidshield import api_security as api
from droidshield.api_transport import Observation, RequestCancelled, TransportError
from droidshield.config import Settings
from droidshield.models import (
    AnalysisJob,
    APIExecution,
    APITarget,
    Assessment,
    Authorization,
    Base,
    Finding,
    User,
)
from tests.test_api import isolated_test_engine
from tests.test_concurrency import seed_queueable_assessment

URL = "https://api.example.test/profile"
SECRET = "secret-never-persisted-123"


def target_data(url=URL, **updates):
    now = datetime.now(UTC)
    return api.TargetCreate.model_validate(
        {
            "name": "Approved profile",
            "endpoints": [{"url": url, "expect_authentication": True}],
            "auth_method": "bearer",
            "primary_secret_ref": "account-a",
            "secondary_secret_ref": "account-b",
            "requests_per_minute": 120,
            "test_window_start": now - timedelta(minutes=1),
            "test_window_end": now + timedelta(hours=1),
            **updates,
        }
    )


def write_secrets(path, workspace_id, project_id):
    path.write_text(
        json.dumps(
            {
                ref: {
                    "workspace_id": str(workspace_id),
                    "project_id": str(project_id),
                    "kind": "bearer",
                    "header": None,
                    "value": SECRET + ref,
                }
                for ref in ["account-a", "account-b"]
            }
        )
    )
    path.chmod(0o600)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    url = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    with isolated_test_engine(url) as engine:
        Base.metadata.create_all(engine)
        user_id, permit_id, assessment_id = seed_queueable_assessment(engine)
        config = Settings(_env_file=None, environment="test", database_url=url).model_dump()
        config.update(
            api_secret_store=tmp_path / "secrets.json",
            api_allowed_networks=[],
            api_ca_bundle=None,
            api_timeout_seconds=120,
            api_request_timeout_seconds=5,
            api_max_response_bytes=65536,
            api_max_requests=60,
        )
        settings = SimpleNamespace(**config)
        with Session(engine) as session:
            assessment = session.get(Assessment, assessment_id)
            assessment.assessment_type, assessment.artifact_id = "api", None
            assessment.configuration_snapshot = {"requested_targets": [URL]}
            session.get(Authorization, permit_id).approved_targets = [URL]
            write_secrets(settings.api_secret_store, assessment.workspace_id, assessment.project_id)
            session.commit()
            ctx = services.Context(session, session.get(User, user_id), "api-create")
            item = api.create_target(ctx, assessment_id, target_data(), settings)
            session.commit()
            output = api.execute(ctx, item.id, assessment.revision, settings)
            target_id, execution_id, job_id = item.id, output.id, output.job_id
            session.commit()
        calls = []

        class Probe:
            def __init__(self, settings):
                pass

            def request(self, url, method, headers, *, should_cancel, deadline):
                assert not should_cancel()
                calls.append((url, method, headers))
                return Observation(
                    200 if headers else 401,
                    10,
                    False,
                    hashlib.sha256(b"safe response").hexdigest(),
                    True,
                    True,
                )

        monkeypatch.setattr(api, "HTTPSProbe", Probe)
        yield (
            engine,
            settings,
            user_id,
            permit_id,
            assessment_id,
            target_id,
            execution_id,
            job_id,
            calls,
        )


def test_worker_probes_only_exact_scope_with_project_credentials_and_sanitizes(runtime):
    engine, settings, _, _, assessment_id, _, execution_id, job_id, calls = runtime
    assert api.run_once(settings, engine)
    assert not api.run_once(settings, engine)
    assert [item[:2] for item in calls] == [(URL, "GET")] * 3
    assert calls[0][2] == {} and calls[1][2] == {"Authorization": "Bearer " + SECRET + "account-a"}
    with Session(engine) as session:
        item = session.get(APIExecution, execution_id)
        assert item.status == session.get(AnalysisJob, job_id).status == "completed"
        assert session.get(Assessment, assessment_id).status == "needs_review"
        result = api.ExecutionOut.model_validate(item).model_dump(mode="json")
        assert result["result_json"]["requests_sent"] == 3
        assert result["result_json"]["endpoints"][0]["comparison"] == "same_bounded_response"
        assert not list(session.scalars(select(Finding)))
        serialized = json.dumps(result)
        assert (
            SECRET not in serialized
            and "Authorization" not in serialized
            and "body_digest" not in serialized
            and URL not in serialized
        )


def test_anonymous_success_is_unreviewed_candidate_never_confirmed(runtime, monkeypatch):
    engine, settings, *_, execution_id, job_id, calls = runtime

    def probe(*args, **kwargs):
        return Observation(200, 10, False, "a" * 64, False, True)

    monkeypatch.setattr(api.HTTPSProbe, "request", probe)
    api.run_once(settings, engine)
    with Session(engine) as session:
        finding = session.scalar(select(Finding))
        assert finding.verification_status == "unreviewed" and finding.remediation_status == "open"
        assert finding.artifact_id is None
        assert finding.evidence_provenance["api_execution_id"] == str(execution_id)
        assert "potential" in finding.impact.lower()
        assert SECRET not in str(finding.evidence_provenance)


@pytest.mark.parametrize(
    "change,expected",
    [
        ("revoke", "authorization_invalid"),
        ("disable", "operator_access_revoked"),
        ("policy", "execution_snapshot_invalid"),
        ("secret", "target_configuration_invalid"),
        ("window", "test_window_inactive"),
    ],
)
def test_claim_rechecks_authorization_access_policy_reference_and_window(runtime, change, expected):
    engine, settings, user_id, permit_id, _, target_id, execution_id, job_id, calls = runtime
    with Session(engine) as session:
        if change == "revoke":
            permit = session.get(Authorization, permit_id)
            permit.status, permit.revoked_at = "revoked", datetime.now(UTC)
        elif change == "disable":
            session.get(User, user_id).status = "disabled"
        elif change == "policy":
            settings.api_allowed_networks = ["127.0.0.1/32"]
        elif change == "secret":
            settings.api_secret_store.write_text("{}")
        else:
            item = session.get(APITarget, target_id)
            item.test_window_end = datetime.now(UTC) - timedelta(seconds=1)
            # Keep target snapshot equivalent so the failure is specifically the window.
            output = session.get(APIExecution, execution_id)
            output.configuration_snapshot = {
                "target": api._target_snapshot(item),
                "policy": api._policy(settings),
            }
        session.commit()
    assert api.run_once(settings, engine)
    assert calls == []
    with Session(engine) as session:
        assert session.get(APIExecution, execution_id).failure_reason == expected
        assert session.get(AnalysisJob, job_id).status == "failed"


@pytest.mark.parametrize("change", ["revoke", "cancel", "disable"])
def test_control_change_during_request_discards_result_and_sends_no_next_probe(
    runtime, monkeypatch, change
):
    engine, settings, user_id, permit_id, _, _, execution_id, _, calls = runtime

    def interrupted(self, *args, should_cancel, **kwargs):
        calls.append("first")
        with Session(engine) as session:
            ctx = services.Context(session, session.get(User, user_id), "withdraw")
            if change == "cancel":
                api.cancel(ctx, execution_id, "Stop")
            elif change == "revoke":
                permit = session.get(Authorization, permit_id)
                services.revoke_authorization(ctx, permit.id, permit.revision, "Withdraw scope")
            else:
                session.get(User, user_id).status = "disabled"
            session.commit()
        assert should_cancel()
        raise RequestCancelled()

    monkeypatch.setattr(api.HTTPSProbe, "request", interrupted)
    assert api.run_once(settings, engine)
    assert calls == ["first"]
    with Session(engine) as session:
        item = session.get(APIExecution, execution_id)
        assert item.status == "cancelled" and item.result_json is None
        assert not list(session.scalars(select(Finding)))


def test_expired_or_lost_lease_cannot_publish(runtime):
    engine, settings, _, _, _, _, execution_id, job_id, calls = runtime
    _, claim = api._claim(settings, engine)
    assert claim
    with Session(engine) as session:
        session.get(AnalysisJob, job_id).lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    assert api.run_once(settings, engine)
    api._finish(settings, engine, claim, result={"raw_body": SECRET})
    with Session(engine) as session:
        item = session.get(APIExecution, execution_id)
        assert item.failure_reason == "worker_lease_expired" and item.result_json is None
    assert calls == []


@pytest.mark.parametrize(
    "update",
    [
        {"endpoints": [{"url": "http://example.test/"}]},
        {"endpoints": [{"url": "https://example.test/a?token=secret"}]},
        {"endpoints": [{"url": "https://example.test/a", "method": "POST"}]},
        {"endpoints": [{"url": URL}, {"url": URL}]},
        {"excluded_endpoints": ["https://api.example.test/"]},
        {"auth_method": "none"},
        {"primary_secret_ref": "bad reference"},
        {"secondary_secret_ref": "account-a"},
        {"requests_per_minute": True},
        {"raw_token": SECRET},
        {"test_window_end": datetime(2020, 1, 1)},
    ],
)
def test_strict_target_contract(update):
    with pytest.raises(ValidationError):
        target_data(**update)


@pytest.mark.parametrize(
    "address,networks,allowed",
    [
        ("127.0.0.1", [], False),
        ("127.0.0.1", ["127.0.0.1/32"], True),
        ("10.1.2.3", [], False),
        ("10.1.2.3", ["10.1.2.0/24"], True),
        ("169.254.169.254", ["0.0.0.0/0"], False),
        ("100.100.100.200", ["0.0.0.0/0"], False),
        ("::ffff:127.0.0.1", [], False),
        ("::1", [], False),
        ("224.1.1.1", ["0.0.0.0/0"], False),
        ("8.8.8.8", [], True),
    ],
)
def test_outbound_policy(address, networks, allowed):
    assert api_transport.allowed_address(address, networks) is allowed


def test_mixed_dns_answer_rejects_rebinding_before_connect(monkeypatch):
    monkeypatch.setattr(
        api_transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.215.14", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(TransportError, match="target_network_denied"):
        api_transport.resolve_addresses(
            "api.example.test", 443, [], lambda: False, time.monotonic() + 5
        )


def test_secret_store_is_bound_private_and_never_returns_values(tmp_path):
    workspace, project = uuid4(), uuid4()
    path = tmp_path / "credentials.json"
    write_secrets(path, workspace, project)
    settings = SimpleNamespace(api_secret_store=path)
    assert api_secrets.list_references(settings, workspace, project) == [
        {"ref": "account-a", "kind": "bearer"},
        {"ref": "account-b", "kind": "bearer"},
    ]
    assert api_secrets.list_references(settings, workspace, uuid4()) == []
    with pytest.raises(api_secrets.SecretError):
        api_secrets.resolve(settings, "account-a", uuid4(), project, "bearer")
    path.chmod(0o644)
    with pytest.raises(api_secrets.SecretError):
        api_secrets.list_references(settings, workspace, project)
    path.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(api_secrets.SecretError):
        api_secrets.list_references(SimpleNamespace(api_secret_store=link), workspace, project)


@pytest.fixture
def tls_target(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            if self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "4096")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass
                finally:
                    requests.append(("slow_closed", None))
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://169.254.169.254/latest/meta-data")
                body = b""
            elif self.path == "/large":
                self.send_response(200)
                body = b"a" * 4096
            else:
                self.send_response(200 if self.headers.get("Authorization") else 401)
                body = b'{"private":"NEVER_RETAIN_THIS_BODY"}'
            self.send_header("Content-Type", "application/json")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            requests.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = SimpleNamespace(
        api_ca_bundle=cert,
        api_allowed_networks=["127.0.0.1/32"],
        api_request_timeout_seconds=3,
        api_max_response_bytes=1024,
    )
    try:
        yield f"https://127.0.0.1:{server.server_port}", settings, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_real_https_baseline_pins_ip_verifies_tls_and_does_not_follow_redirect(tls_target):
    base, settings, requests = tls_target
    probe = api_transport.HTTPSProbe(settings)
    result = probe.request(
        base + "/profile",
        "GET",
        {"Authorization": "Bearer fixture"},
        should_cancel=lambda: False,
        deadline=time.monotonic() + 5,
    )
    assert result.status == 200 and result.tls_verified
    assert "NEVER_RETAIN_THIS_BODY" not in str(result)
    redirect = probe.request(
        base + "/redirect", "GET", {}, should_cancel=lambda: False, deadline=time.monotonic() + 5
    )
    assert redirect.status == 302
    assert [item[0] for item in requests] == ["/profile", "/redirect"]
    raw = api_transport.exchange(
        settings,
        base + "/profile",
        "GET",
        {},
        should_cancel=lambda: False,
        deadline=time.monotonic() + 5,
    )
    assert raw.status == 401 and b"NEVER_RETAIN_THIS_BODY" in raw.body
    assert raw.tls_version in {"TLSv1.2", "TLSv1.3"}


def test_real_https_body_budget_truncates_summary_and_rejects_raw_forward(tls_target):
    base, settings, _ = tls_target
    result = api_transport.HTTPSProbe(settings).request(
        base + "/large", "GET", {}, should_cancel=lambda: False, deadline=time.monotonic() + 5
    )
    assert result.response_bytes == 1024 and result.truncated
    with pytest.raises(TransportError, match="response_body_exceeded"):
        api_transport.exchange(
            settings,
            base + "/large",
            "GET",
            {},
            should_cancel=lambda: False,
            deadline=time.monotonic() + 5,
        )


def test_real_https_untrusted_certificate_fails_closed(tls_target):
    base, settings, _ = tls_target
    settings.api_ca_bundle = None
    with pytest.raises(TransportError, match="tls_verification_failed"):
        api_transport.HTTPSProbe(settings).request(
            base + "/profile", "GET", {}, should_cancel=lambda: False, deadline=time.monotonic() + 5
        )


def test_real_versioned_migration_protects_target_and_published_result(tmp_path):
    from droidshield.cli import migrate
    from droidshield.db import build_engine

    settings = Settings(
        _env_file=None, environment="test", database_url=f"sqlite:///{tmp_path / 'migrate.db'}"
    )
    migrate(settings)
    engine = build_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0014_android_long_version_code"
            )
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            names = (
                connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='trigger'")
                .scalars()
                .all()
            )
            assert "api_targets_immutable_update" in names and "api_result_write_once" in names
            assert "ds_evidence_attachment_update" in names
            assert "ds_evidence_attachment_delete" in names
    finally:
        engine.dispose()


def test_real_https_full_api_worker_to_immutable_safe_result(runtime, tls_target, monkeypatch):
    engine, settings, _, permit_id, assessment_id, target_id, execution_id, job_id, calls = runtime
    base, tls_settings, requests = tls_target
    settings.api_ca_bundle = tls_settings.api_ca_bundle
    settings.api_allowed_networks = tls_settings.api_allowed_networks
    settings.api_max_response_bytes = tls_settings.api_max_response_bytes
    with Session(engine) as session:
        permit = session.get(Authorization, permit_id)
        permit.approved_targets = [base + "/profile"]
        session.flush()
        assessment = session.get(Assessment, assessment_id)
        snapshot = {
            **assessment.configuration_snapshot,
            "requested_targets": [base + "/profile"],
            "approved_targets": permit.approved_targets,
            "authorization_revision": permit.revision,
        }
        assessment.configuration_snapshot = snapshot
        session.get(AnalysisJob, job_id).configuration_snapshot = snapshot
        item = session.get(APITarget, target_id)
        item.endpoints = [
            {"url": base + "/profile", "method": "GET", "expect_authentication": True}
        ]
        session.get(APIExecution, execution_id).configuration_snapshot = {
            "target": api._target_snapshot(item),
            "policy": api._policy(settings),
        }
        session.commit()
    monkeypatch.setattr(api, "HTTPSProbe", api_transport.HTTPSProbe)
    assert api.run_once(settings, engine)
    assert [entry[0] for entry in requests] == ["/profile"] * 3
    with Session(engine) as session:
        item = session.get(APIExecution, execution_id)
        assert item.status == "completed", item.failure_reason
        assert item.result_json["requests_sent"] == 3
        assert item.result_json["endpoints"][0]["anonymous"]["status"] == 401
        assert "NEVER_RETAIN_THIS_BODY" not in json.dumps(item.result_json)
        assert SECRET not in json.dumps(item.result_json)
        assert session.get(Assessment, assessment_id).status == "needs_review"


def test_api_http_scope_strictness_idempotency_and_cancel(runtime):
    from fastapi.testclient import TestClient

    from droidshield.auth import issue_token
    from droidshield.main import create_app
    from droidshield.models import ProjectAccess, Workspace

    engine, settings, user_id, _, assessment_id, target_id, execution_id, _, _ = runtime
    settings.allowed_hosts = ["testserver"]
    with Session(engine) as session:
        origin = session.get(Assessment, assessment_id)
        second = Assessment(
            workspace_id=origin.workspace_id,
            project_id=origin.project_id,
            authorization_id=origin.authorization_id,
            name="Second API",
            assessment_type="api",
            created_by=user_id,
            configuration_snapshot={"requested_targets": [URL]},
        )
        viewer = User(
            workspace_id=origin.workspace_id,
            email="api-viewer@example.test",
            full_name="Viewer",
            role="VIEWER",
        )
        hidden = User(
            workspace_id=origin.workspace_id,
            email="api-hidden@example.test",
            full_name="Unassigned analyst",
            role="SECURITY_ANALYST",
        )
        foreign_workspace = Workspace(name="Foreign API")
        session.add_all([second, viewer, hidden, foreign_workspace])
        session.flush()
        foreign = User(
            workspace_id=foreign_workspace.id,
            email="foreign-api@example.test",
            full_name="Foreign",
            role="ADMIN",
        )
        session.add(foreign)
        session.flush()
        session.add(
            ProjectAccess(
                workspace_id=origin.workspace_id,
                project_id=origin.project_id,
                user_id=viewer.id,
                created_by=user_id,
            )
        )
        tokens = {
            name: issue_token(session, uid, 1)
            for name, uid in [
                ("admin", user_id),
                ("viewer", viewer.id),
                ("hidden", hidden.id),
                ("foreign", foreign.id),
            ]
        }
        second_id, project_id = second.id, origin.project_id
        session.commit()
    app = create_app(settings, engine)
    if "/api/v1/api-targets/{target_id}" not in app.openapi()["paths"]:
        app.include_router(api.router)
    with TestClient(app) as client:
        headers = {
            "Authorization": "Bearer " + tokens["admin"],
            "Idempotency-Key": "api-target-http",
        }
        body = target_data().model_dump(mode="json")
        base = f"/api/v1/assessments/{second_id}/api-targets"
        created = client.post(base, json=body, headers=headers)
        assert created.status_code == 201, created.text
        filtered_targets = client.get(base, params={"auth_method": "bearer"}, headers=headers)
        assert filtered_targets.status_code == 200
        assert filtered_targets.json()["total"] == 1
        assert (
            client.get(base, params={"auth_method": "none"}, headers=headers).json()["total"] == 0
        )
        assert created.json()["test_window_start"].endswith(("Z", "+00:00"))
        assert created.json()["test_window_end"].endswith(("Z", "+00:00"))
        assert created.json()["created_at"].endswith(("Z", "+00:00"))
        repeated = client.post(base, json=body, headers=headers)
        assert repeated.status_code == 201 and repeated.json()["id"] == created.json()["id"]
        changed = client.post(base, json={**body, "name": "Another name"}, headers=headers)
        assert changed.status_code == 409
        extra = client.post(
            base,
            json={**body, "token": SECRET},
            headers={**headers, "Idempotency-Key": "bad-extra"},
        )
        assert extra.status_code == 422 and SECRET not in extra.text
        assert client.get(f"/api/v1/api-targets/{target_id}").status_code == 401
        refs = client.get(f"/api/v1/projects/{project_id}/api-secret-refs", headers=headers)
        assert refs.status_code == 200 and refs.json()["items"][0]["ref"] == "account-a"
        assert SECRET not in refs.text
        for name in ["hidden", "foreign"]:
            other = {"Authorization": "Bearer " + tokens[name]}
            assert client.get(f"/api/v1/api-targets/{target_id}", headers=other).status_code == 404
            assert (
                client.get(f"/api/v1/api-executions/{execution_id}", headers=other).status_code
                == 404
            )
            assert (
                client.get(
                    f"/api/v1/projects/{project_id}/api-secret-refs", headers=other
                ).status_code
                == 404
            )
        viewer = {
            "Authorization": "Bearer " + tokens["viewer"],
            "Idempotency-Key": "viewer-no-write",
        }
        assert client.get(base, headers=viewer).status_code == 200
        assert client.post(base, json=body, headers=viewer).status_code == 403
        started = client.post(
            f"/api/v1/api-targets/{created.json()['id']}/execute",
            json={"revision": 1},
            headers={**headers, "Idempotency-Key": "api-execute-http"},
        )
        assert started.status_code == 201, started.text
        assert started.json()["created_at"].endswith(("Z", "+00:00"))
        execution_path = f"/api/v1/assessments/{second_id}/api-executions"
        queued = client.get(execution_path, params={"status": "queued"}, headers=headers)
        assert queued.status_code == 200 and queued.json()["total"] == 1
        assert (
            client.get(execution_path, params={"status": "completed"}, headers=headers).json()[
                "total"
            ]
            == 0
        )
        assert (
            client.get(execution_path, params={"status": "unknown"}, headers=headers).status_code
            == 422
        )
        again = client.post(
            f"/api/v1/api-targets/{created.json()['id']}/execute",
            json={"revision": 1},
            headers={**headers, "Idempotency-Key": "api-execute-http"},
        )
        assert again.status_code == 201 and again.json()["id"] == started.json()["id"]
        cancelled = client.post(
            f"/api/v1/api-executions/{started.json()['id']}/cancel",
            json={"reason": "Client requested pause"},
            headers={**headers, "Idempotency-Key": "api-cancel-http"},
        )
        assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"


def test_migration_roundtrip_preserves_legacy_lease_and_blocks_new_scenario_history(tmp_path):
    from alembic import command
    from alembic.config import Config

    from droidshield.db import build_engine
    from droidshield.models import DynamicDeviceLease, DynamicSession

    url = f"sqlite:///{tmp_path / 'upgrade-existing.db'}"
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parents[1] / "backend/droidshield/migrations"),
    )
    config.attributes["database_url"] = url
    command.upgrade(config, "0003_dynamic_lab")
    engine = build_engine(url)
    from tests.legacy_v3 import seed_running_lab

    session_id, worker_id, expires = seed_running_lab(engine)
    engine.dispose()
    command.upgrade(config, "head")
    engine = build_engine(url)
    try:
        with Session(engine) as session:
            item = session.get(DynamicSession, session_id)
            lease = session.get(DynamicDeviceLease, "owned-existing-lab")
            assert item.status == "running" and item.scenario == "package_inspection"
            assert (
                lease.session_id == session_id
                and lease.worker_id == worker_id
                and lease.quarantined
            )
            assert lease.expires_at.replace(tzinfo=UTC) == expires
            assert session.execute(text("PRAGMA foreign_key_check")).all() == []
        # An empty new-feature surface may downgrade without losing legacy
        # running sessions, active owners, quarantine flags or expiries.
        command.downgrade(config, "0003_dynamic_lab")
        command.upgrade(config, "head")
        with Session(engine) as session:
            item = session.get(DynamicSession, session_id)
            lease = session.get(DynamicDeviceLease, "owned-existing-lab")
            assert item.scenario == "package_inspection" and item.status == "running"
            assert (
                lease.session_id == session_id
                and lease.worker_id == worker_id
                and lease.quarantined
            )
            assert lease.expires_at.replace(tzinfo=UTC) == expires
            item.scenario = "frida_observe"
            session.commit()
        with pytest.raises(RuntimeError, match="reviewed backup"):
            command.downgrade(config, "0003_dynamic_lab")
        with Session(engine) as session:
            assert session.get(DynamicSession, session_id).scenario == "frida_observe"
            assert (
                session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0004_api_security"
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("database", ["sqlite", "postgresql"])
def test_migrated_api_target_and_published_result_are_write_once(tmp_path, monkeypatch, database):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.schema import CreateSchema, DropSchema

    from droidshield.db import build_engine

    original = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL")
    admin, schema = None, None
    if database == "postgresql":
        if not original:
            pytest.skip("Set DROIDSHIELD_TEST_DATABASE_URL for PostgreSQL migration guards")
        admin = build_engine(original)
        schema = "ds_api_migration_" + uuid4().hex
        with admin.begin() as connection:
            connection.execute(CreateSchema(schema))
        url = (
            make_url(original)
            .update_query_dict({"options": f"-csearch_path={schema}"})
            .render_as_string(hide_password=False)
        )
    else:
        url = f"sqlite:///{tmp_path / 'guarded-api.db'}"
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parents[1] / "backend/droidshield/migrations"),
    )
    config.attributes["database_url"] = url
    engine = None
    try:
        command.upgrade(config, "head")
        engine = build_engine(url)
        user_id, permit_id, assessment_id = seed_queueable_assessment(engine)
        settings_data = Settings(_env_file=None, environment="test", database_url=url).model_dump()
        settings_data.update(
            api_secret_store=tmp_path / "guard-secrets.json",
            api_allowed_networks=[],
            api_ca_bundle=None,
            api_timeout_seconds=120,
            api_request_timeout_seconds=5,
            api_max_response_bytes=65536,
            api_max_requests=60,
        )
        settings = SimpleNamespace(**settings_data)
        with Session(engine) as session:
            assessment = session.get(Assessment, assessment_id)
            assessment.assessment_type, assessment.artifact_id = "api", None
            assessment.configuration_snapshot = {"requested_targets": [URL]}
            session.get(Authorization, permit_id).approved_targets = [URL]
            write_secrets(settings.api_secret_store, assessment.workspace_id, assessment.project_id)
            session.commit()
            ctx = services.Context(session, session.get(User, user_id), "migrated-api")
            target = api.create_target(
                ctx, assessment_id, target_data(secondary_secret_ref=None), settings
            )
            session.commit()
            execution = api.execute(ctx, target.id, assessment.revision, settings)
            target_id, execution_id = target.id, execution.id
            session.commit()

        class Probe:
            def __init__(self, settings):
                pass

            def request(self, *args, **kwargs):
                return Observation(200, 10, False, "a" * 64, True, True)

        monkeypatch.setattr(api, "HTTPSProbe", Probe)
        assert api.run_once(settings, engine)
        with Session(engine) as session:
            assert session.get(APIExecution, execution_id).status == "completed"
            assert session.get(APIExecution, execution_id).result_json is not None
        with pytest.raises(DBAPIError), Session(engine) as session:
            session.get(APITarget, target_id).name = "Edited history"
            session.commit()
        with pytest.raises(DBAPIError), Session(engine) as session:
            session.get(APIExecution, execution_id).result_json = {"tampered": True}
            session.commit()
        with pytest.raises(DBAPIError), Session(engine) as session:
            session.delete(session.get(APIExecution, execution_id))
            session.commit()
        with pytest.raises(RuntimeError, match="reviewed backup"):
            command.downgrade(config, "0003_dynamic_lab")
        with Session(engine) as session:
            assert session.get(APIExecution, execution_id).status == "completed"
            assert session.get(APITarget, target_id).name == "Approved profile"
            assert session.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == (
                "0009_evidence_attachment_scope"
                if database == "postgresql"
                else "0004_api_security"
            )
    finally:
        if engine is not None:
            engine.dispose()
        if admin is not None:
            with admin.begin() as connection:
                connection.execute(DropSchema(schema, cascade=True))
            admin.dispose()


def test_real_https_total_deadline_closes_http10_response_socket(tls_target):
    base, settings, requests = tls_target
    settings.api_request_timeout_seconds = 2
    started = time.monotonic()
    with pytest.raises(TransportError, match="request_timeout"):
        api_transport.HTTPSProbe(settings).request(
            base + "/slow",
            "GET",
            {},
            should_cancel=lambda: False,
            deadline=started + 0.3,
        )
    assert time.monotonic() - started < 1
    # HTTP/1.0 getresponse() clears connection.sock while the response's file
    # retains the TLS descriptor. The independent active socket must be shut
    # down too, preventing a slow trickle from leaving a background read alive.
    until = time.monotonic() + 1
    while ("slow_closed", None) not in requests and time.monotonic() < until:
        time.sleep(0.025)
    assert ("slow_closed", None) in requests
