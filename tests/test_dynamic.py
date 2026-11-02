"""Session lifecycle, tenancy and lease fencing checks with simulated ADB faults."""

import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield import dynamic, services
from droidshield.config import Settings
from droidshield.errors import DomainError
from droidshield.lab import ENGINE_VERSION, LIMITATIONS, LabCancelled, LabError
from droidshield.models import (
    AnalysisJob,
    Assessment,
    Authorization,
    Base,
    DynamicDeviceLease,
    DynamicSession,
    User,
)
from tests.test_api import isolated_test_engine
from tests.test_concurrency import seed_queueable_assessment
from tests.test_lab import DEVICE


def output():
    return {
        "engine_version": ENGINE_VERSION,
        "checks": [
            {"name": "device_identity", "status": "pass"},
            {"name": "offline_firewall", "status": "pass"},
            {"name": "apk_installed", "status": "pass"},
            {"name": "package_inspected", "status": "pass"},
            {"name": "app_launched", "status": "not_run"},
            {"name": "cleanup", "status": "pass"},
        ],
        "pid_observed": False,
        "exception_categories": [],
        "exception_count": 0,
        "requires_review": True,
        "limitations": list(LIMITATIONS),
    }


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    url = os.environ.get("DROIDSHIELD_TEST_DATABASE_URL", f"sqlite:///{tmp_path / 'dynamic.db'}")
    with isolated_test_engine(url) as engine:
        Base.metadata.create_all(engine)
        user_id, permit_id, assessment_id = seed_queueable_assessment(engine)
        configuration = Settings(
            _env_file=None, environment="test", database_url=url, storage_root=tmp_path / "storage"
        ).model_dump()
        configuration.update(
            lab_devices=[DEVICE],
            adb_executable="/usr/bin/adb",
            dynamic_timeout_seconds=90,
            dynamic_max_output_bytes=65536,
        )
        settings = SimpleNamespace(**configuration)
        with Session(engine) as session:
            assessment = session.get(Assessment, assessment_id)
            assessment.assessment_type = "dynamic"
            session.commit()
            revision = assessment.revision
            item = dynamic.create(
                services.Context(session, session.get(User, user_id), "create-dynamic"),
                assessment_id,
                dynamic.DynamicCreate(
                    revision=revision, device_id="ds-lab", scenario="package_inspection"
                ),
                settings,
            )
            session_id, job_id = item.id, item.job_id
            session.commit()
        calls = []

        class SafeStorage:
            def __init__(self, root):
                pass

            @contextmanager
            def verified_copy(self, reference, sha256, size):
                assert (reference, sha256, size) == ("protected/app.apk", "a" * 64, 100)
                yield tmp_path / "test.apk"

        class SafeLab:
            def __init__(self, settings, device):
                assert device == DEVICE

            def run(self, path, package, scenario, timeout, *, should_cancel, owns_device):
                assert not should_cancel() and owns_device()
                calls.append((package, scenario))
                return output()

        monkeypatch.setattr(dynamic, "Storage", SafeStorage)
        monkeypatch.setattr(dynamic, "AdbLab", SafeLab)
        yield engine, settings, user_id, permit_id, assessment_id, session_id, job_id, calls


def test_runtime_publishes_sanitized_result_and_releases_exclusive_device(runtime):
    engine, settings, _, _, assessment_id, session_id, job_id, calls = runtime
    assert dynamic.run_once(settings, engine)
    assert not dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item, job = session.get(DynamicSession, session_id), session.get(AnalysisJob, job_id)
        assert item.status == job.status == "completed"
        assert session.get(Assessment, assessment_id).status == "needs_review"
        lease = session.get(DynamicDeviceLease, "ds-lab")
        assert not lease.quarantined and lease.session_id is None
        safe = dynamic.DynamicOut.model_validate(item).model_dump(mode="json")
        assert safe["result_json"]["requires_review"] is True
        assert "serial" not in str(safe) and "storage" not in str(safe)
        assert "configuration_snapshot" not in safe and "notes" not in safe
    assert calls == [("test.app", "package_inspection")]


def test_proxy_thread_and_adb_owner_serialize_control_database_callbacks(runtime, monkeypatch):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    engine, settings, _, _, _, session_id, _, _ = runtime
    monitor, owner = dynamic._monitor, dynamic._owns_device
    active, maximum = 0, 0
    count_lock = threading.Lock()

    def measured(callback, *args):
        nonlocal active, maximum
        with count_lock:
            active += 1
            maximum = max(maximum, active)
        try:
            # Keep a real control transaction's callback active long enough for
            # the competing observer thread to enter if serialization is absent.
            time.sleep(0.03)
            return callback(*args)
        finally:
            with count_lock:
                active -= 1

    monkeypatch.setattr(dynamic, "_monitor", lambda *args: measured(monitor, *args))
    monkeypatch.setattr(dynamic, "_owns_device", lambda *args: measured(owner, *args))

    def concurrent(self, *args, should_cancel, owns_device):
        ready = threading.Barrier(2)

        def call(callback):
            ready.wait(timeout=2)
            return callback()

        with ThreadPoolExecutor(max_workers=2) as pool:
            cancellation = pool.submit(call, should_cancel)
            ownership = pool.submit(call, owns_device)
            assert not cancellation.result(timeout=3)
            assert ownership.result(timeout=3)
        return output()

    monkeypatch.setattr(dynamic.AdbLab, "run", concurrent)
    assert dynamic.run_once(settings, engine)
    assert maximum == 1
    with Session(engine) as session:
        assert session.get(DynamicSession, session_id).status == "completed"


@pytest.mark.parametrize(
    "change,reason",
    [
        ("revoked", "authorization_invalid"),
        ("disabled", "operator_access_revoked"),
        ("device_changed", "lab_configuration_changed"),
    ],
)
def test_claim_rechecks_authorization_operator_and_device_snapshot(runtime, change, reason):
    engine, settings, user_id, permit_id, _, session_id, job_id, calls = runtime
    with Session(engine) as session:
        if change == "revoked":
            permit = session.get(Authorization, permit_id)
            permit.status, permit.revoked_at = "revoked", datetime.now(UTC)
        elif change == "disabled":
            session.get(User, user_id).status = "disabled"
        else:
            settings.lab_devices = [{**DEVICE, "serial": "emulator-5562"}]
        session.commit()
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(DynamicSession, session_id).failure_reason == reason
        assert session.get(AnalysisJob, job_id).status == "failed"
    assert not calls


@pytest.mark.parametrize("change", ["cancel", "revoke", "access"])
def test_during_runtime_control_changes_stop_processing_and_discard_results(
    runtime, monkeypatch, change
):
    engine, settings, user_id, permit_id, assessment_id, session_id, job_id, _ = runtime

    def interrupted(self, *args, should_cancel, owns_device):
        with Session(engine) as session:
            actor = session.get(User, user_id)
            ctx = services.Context(session, actor, "stop-runtime")
            if change == "cancel":
                dynamic._cancel(ctx, session_id, "Stop runtime")
            elif change == "revoke":
                permit = session.get(Authorization, permit_id)
                services.revoke_authorization(ctx, permit.id, permit.revision, "Scope withdrawn")
            else:
                actor.status = "disabled"
            session.commit()
        assert should_cancel() and owns_device()
        raise LabCancelled()

    monkeypatch.setattr(dynamic.AdbLab, "run", interrupted)
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "cancelled" and item.result_json is None
        assert session.get(Assessment, assessment_id).status == "cancelled"
        assert session.get(AnalysisJob, job_id).status == "cancelled"
        assert session.get(DynamicDeviceLease, "ds-lab").session_id is None


def test_failed_cleanup_quarantines_device_and_never_publishes(runtime, monkeypatch):
    engine, settings, _, _, _, session_id, job_id, _ = runtime

    def broken(*args, **kwargs):
        raise LabError("device_cleanup_failed")

    monkeypatch.setattr(dynamic.AdbLab, "run", broken)
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "failed" and item.failure_reason == "device_cleanup_failed"
        assert item.result_json is None and session.get(AnalysisJob, job_id).status == "failed"
        assert session.get(DynamicDeviceLease, "ds-lab").quarantined


def test_crash_expiry_fails_attempt_and_quarantines_without_using_adb(runtime):
    engine, settings, _, _, _, session_id, job_id, calls = runtime
    handled, claim = dynamic._claim(settings, engine)
    assert handled and claim
    with Session(engine) as session:
        past = datetime.now(UTC) - timedelta(seconds=1)
        session.get(AnalysisJob, job_id).lease_expires_at = past
        session.get(DynamicDeviceLease, "ds-lab").expires_at = past
        session.commit()
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        assert session.get(DynamicSession, session_id).failure_reason == "worker_lease_expired"
        assert session.get(DynamicDeviceLease, "ds-lab").quarantined
    assert calls == []


def test_lost_lease_cannot_publish_or_release_new_owner(runtime):
    engine, settings, _, _, _, session_id, job_id, _ = runtime
    _, claim = dynamic._claim(settings, engine)
    other = uuid4()
    with Session(engine) as session:
        session.get(DynamicDeviceLease, "ds-lab").worker_id = other
        session.get(AnalysisJob, job_id).worker_id = other
        session.commit()
    dynamic._finish(settings, engine, claim, output=output())
    with Session(engine) as session:
        assert session.get(DynamicSession, session_id).result_json is None
        assert session.get(DynamicDeviceLease, "ds-lab").worker_id == other


def test_simultaneous_worker_cannot_claim_reserved_device(runtime):
    engine, settings, *_ = runtime
    assert dynamic._claim(settings, engine)[1]
    assert dynamic._claim(settings, engine) == (False, None)


def test_unexpected_engine_payload_is_rejected(runtime, monkeypatch):
    engine, settings, _, _, _, session_id, _, _ = runtime
    monkeypatch.setattr(
        dynamic.AdbLab, "run", lambda *args, **kwargs: {**output(), "raw_log": "password=SECRET"}
    )
    dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "failed" and item.result_json is None
        assert "SECRET" not in str(dynamic.DynamicOut.model_validate(item).model_dump())


@pytest.mark.parametrize(
    "update",
    [
        {"revision": True},
        {"timeout_seconds": 121},
        {"timeout_seconds": 0},
        {"scenario": "arbitrary_shell"},
        {"device_id": "emulator-5554;id"},
        {"serial": "emulator-5554"},
        {"token": "secret"},
    ],
)
def test_strict_session_contract(update):
    with pytest.raises(ValidationError):
        dynamic.DynamicCreate(
            **{"revision": 1, "device_id": "ds-lab", "scenario": "launch_observe", **update}
        )


def test_unavailable_lab_refuses_creation_before_queue(runtime):
    engine, settings, user_id, _, assessment_id, _, _, _ = runtime
    with Session(engine) as session:
        ctx = services.Context(session, session.get(User, user_id), "bad-lab")
        assessment = session.get(Assessment, assessment_id)
        with pytest.raises(DomainError) as error:
            dynamic.create(
                ctx,
                assessment_id,
                dynamic.DynamicCreate(
                    revision=assessment.revision,
                    device_id="not-configured",
                    scenario="launch_observe",
                ),
                settings,
            )
        assert error.value.status == 409
        assert session.scalar(select(DynamicSession)).status == "queued"


def test_http_session_creation_is_scoped_strict_and_idempotent(runtime):
    from fastapi.testclient import TestClient
    from sqlalchemy import func

    from droidshield.auth import issue_token
    from droidshield.main import create_app
    from droidshield.models import ProjectAccess, Workspace

    engine, settings, admin_id, _, first_assessment_id, first_session_id, _, _ = runtime
    settings.allowed_hosts = ["testserver"]
    with Session(engine) as session:
        original = session.get(Assessment, first_assessment_id)
        assessment = Assessment(
            workspace_id=original.workspace_id,
            project_id=original.project_id,
            artifact_id=original.artifact_id,
            authorization_id=original.authorization_id,
            name="Runtime HTTP",
            assessment_type="dynamic",
            created_by=admin_id,
            configuration_snapshot={"requested_targets": ["package:test.app"]},
        )
        session.add(assessment)
        session.flush()
        assessment_id = assessment.id
        admin_token = issue_token(session, admin_id, 1)
        viewer = User(
            workspace_id=original.workspace_id,
            full_name="Viewer",
            email="viewer@example.test",
            role="VIEWER",
        )
        hidden_analyst = User(
            workspace_id=original.workspace_id,
            full_name="Other analyst",
            email="hidden@example.test",
            role="SECURITY_ANALYST",
        )
        foreign_workspace = Workspace(name="Foreign")
        session.add_all([viewer, hidden_analyst, foreign_workspace])
        session.flush()
        foreign_admin = User(
            workspace_id=foreign_workspace.id,
            full_name="Foreign admin",
            email="admin@example.test",
            role="ADMIN",
        )
        session.add(foreign_admin)
        session.flush()
        session.add(
            ProjectAccess(
                workspace_id=original.workspace_id,
                project_id=original.project_id,
                user_id=viewer.id,
                created_by=admin_id,
            )
        )
        viewer_token = issue_token(session, viewer.id, 1)
        hidden_token = issue_token(session, hidden_analyst.id, 1)
        foreign_token = issue_token(session, foreign_admin.id, 1)
        session.commit()
    app = create_app(settings, engine)
    if "/api/v1/dynamic-sessions/{session_id}" not in app.openapi()["paths"]:
        app.include_router(dynamic.router)
    with TestClient(app) as client:
        base = f"/api/v1/assessments/{assessment_id}/dynamic-sessions"
        body = {"revision": 1, "device_id": "ds-lab", "scenario": "package_inspection"}
        headers = {
            "Authorization": "Bearer " + admin_token,
            "Idempotency-Key": "runtime-create-http",
        }
        first = client.post(base, json=body, headers=headers)
        assert first.status_code == 201, first.text
        assert first.json()["created_at"].endswith("Z")
        filtered_sessions = client.get(
            base,
            params={"status": "queued", "scenario": "package_inspection"},
            headers=headers,
        )
        assert filtered_sessions.status_code == 200
        assert filtered_sessions.json()["total"] == 1
        assert filtered_sessions.json()["items"][0]["id"] == first.json()["id"]
        invalid_filter = client.get(
            base,
            params={"status": "unknown"},
            headers=headers,
        )
        assert invalid_filter.status_code == 422
        repeated = client.post(base, json=body, headers=headers)
        assert repeated.status_code == 201 and repeated.json()["id"] == first.json()["id"]
        changed = client.post(base, json={**body, "scenario": "launch_observe"}, headers=headers)
        assert changed.status_code == 409
        extra = client.post(
            base,
            json={**body, "secret": "NEVER_ECHO_ME"},
            headers={**headers, "Idempotency-Key": "runtime-extra"},
        )
        assert extra.status_code == 422 and "NEVER_ECHO_ME" not in extra.text
        missing = client.post(base, json=body, headers={"Authorization": "Bearer " + admin_token})
        assert missing.status_code == 422
        for token in (hidden_token, foreign_token):
            denied = client.get(
                f"/api/v1/dynamic-sessions/{first_session_id}",
                headers={"Authorization": "Bearer " + token},
            )
            assert denied.status_code == 404
            denied_create = client.post(
                base,
                json=body,
                headers={"Authorization": "Bearer " + token, "Idempotency-Key": str(uuid4())},
            )
            assert denied_create.status_code == 404
        read = client.get(base, headers={"Authorization": "Bearer " + viewer_token})
        assert read.status_code == 200 and read.json()["total"] == 1
        denied_write = client.post(
            base,
            json=body,
            headers={"Authorization": "Bearer " + viewer_token, "Idempotency-Key": "viewer-denied"},
        )
        assert denied_write.status_code == 403
        assert client.get(f"/api/v1/dynamic-sessions/{first_session_id}").status_code == 401
        assert "emulator-5560" not in first.text and "DroidShield_Lab" not in first.text
        assert dynamic.run_once(settings, engine)
        finished = client.get(
            f"/api/v1/dynamic-sessions/{first_session_id}",
            headers={"Authorization": "Bearer " + admin_token},
        )
        assert finished.status_code == 200 and finished.json()["status"] == "completed"
        for field in ("created_at", "started_at", "completed_at"):
            assert finished.json()[field].endswith("Z")
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(DynamicSession)) == 2


@pytest.mark.parametrize("crossed", ["artifact", "assessment", "workspace"])
def test_dynamic_origin_constraints_reject_crossed_records(tmp_path, crossed):
    from sqlalchemy.exc import IntegrityError

    from droidshield.cli import migrate
    from droidshield.db import build_engine
    from droidshield.models import Workspace
    from tests.test_analysis_migration import seed_result_origins

    url = f"sqlite:///{tmp_path / 'migrated-dynamic.db'}"
    migrate(Settings(_env_file=None, environment="test", database_url=url))
    engine = build_engine(url)
    try:
        origin = seed_result_origins(engine)
        workspace_id = origin["workspace_id"]
        with Session(engine) as session:
            first = session.get(Assessment, origin["first_assessment"])
            user_id, project_id = first.created_by, first.project_id
            if crossed == "workspace":
                other = Workspace(name="Other")
                session.add(other)
                session.flush()
                workspace_id = other.id
                session.commit()
        with pytest.raises(IntegrityError), Session(engine) as session:
            session.add(
                DynamicSession(
                    workspace_id=workspace_id,
                    project_id=project_id,
                    assessment_id=origin["second_assessment"]
                    if crossed == "assessment"
                    else origin["first_assessment"],
                    artifact_id=origin["second_artifact"]
                    if crossed == "artifact"
                    else origin["first_artifact"],
                    job_id=origin["first_job"],
                    created_by=user_id,
                    device_id="ds-lab",
                    scenario="package_inspection",
                    timeout_seconds=90,
                    configuration_snapshot={},
                )
            )
            session.commit()
    finally:
        engine.dispose()


@pytest.mark.parametrize("scenario", ["package_inspection", "launch_observe", "frida_observe"])
def test_real_disposable_emulator_upload_to_runtime(tmp_path, scenario):
    """Opt-in only: never discovers, starts or uses a developer's existing device."""
    import json
    from pathlib import Path

    from fastapi.testclient import TestClient

    from droidshield.auth import issue_token
    from droidshield.cli import migrate
    from droidshield.db import build_engine
    from droidshield.main import create_app
    from droidshield.models import Workspace
    from tests.test_api import Harness, expect, make_assessment, make_authorization, make_project

    apk_path, device_json = (
        os.environ.get("DROIDSHIELD_TEST_RUNTIME_APK"),
        os.environ.get("DROIDSHIELD_TEST_RUNTIME_DEVICE"),
    )
    if not apk_path or not device_json:
        pytest.skip("Explicit runtime smoke APK and disposable device configuration required")
    device = json.loads(device_json)
    frida_options = {}
    if scenario == "frida_observe":
        import sys

        from pydantic import SecretStr

        digest, token = (
            os.environ.get("DROIDSHIELD_TEST_FRIDA_HASH"),
            os.environ.get("DROIDSHIELD_TEST_FRIDA_TOKEN"),
        )
        if not digest or not token:
            pytest.skip("Explicit pinned Frida server hash and protected token required")
        frida_options = {
            "frida_server_sha256": digest,
            "frida_token": SecretStr(token),
            "frida_python": sys.executable,
        }
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'runtime-real.db'}",
        storage_root=tmp_path / "protected",
        allowed_hosts=["testserver"],
        lab_devices=[device],
        **frida_options,
    )
    migrate(settings)
    engine = build_engine(settings.database_url)
    try:
        with Session(engine) as session:
            workspace = Workspace(name="Disposable runtime test")
            session.add(workspace)
            session.flush()
            user = User(
                workspace_id=workspace.id,
                email="runtime@example.test",
                full_name="Runtime test",
                role="ADMIN",
            )
            session.add(user)
            session.flush()
            token, user_id, workspace_id = issue_token(session, user.id, 1), user.id, workspace.id
            session.commit()
        app = create_app(settings, engine)
        if "/api/v1/dynamic-sessions/{session_id}" not in app.openapi()["paths"]:
            app.include_router(dynamic.router)
        with TestClient(app) as client:
            api = Harness(
                client, engine, {"admin": user_id}, {"admin": token}, {"main": workspace_id}
            )
            project = make_project(api, package_id="dev.droidshield.smoke")
            permit = make_authorization(
                api, project, approved_targets=["package:dev.droidshield.smoke"]
            )
            assessment = make_assessment(
                api,
                project,
                permit,
                targets=["package:dev.droidshield.smoke"],
                assessment_type="dynamic",
            )
            uploaded = client.post(
                f"/api/v1/assessments/{assessment['id']}/apk",
                data={"revision": str(assessment["revision"]), "build_type": "debug"},
                files={
                    "file": (
                        "smoke.apk",
                        Path(apk_path).read_bytes(),
                        "application/vnd.android.package-archive",
                    )
                },
                headers=api.headers(key="real-runtime-upload"),
            )
            artifact = expect(uploaded, 201)
            assessment = expect(api.get(f"/assessments/{assessment['id']}"))
            created = expect(
                api.post(
                    f"/assessments/{assessment['id']}/dynamic-sessions",
                    {
                        "revision": assessment["revision"],
                        "device_id": device["id"],
                        "scenario": scenario,
                    },
                ),
                201,
            )
            assert created["status"] == "queued" and created["artifact_id"] == artifact["id"]
            assert dynamic.run_once(settings, engine)
            finished = expect(api.get(f"/dynamic-sessions/{created['id']}"))
            assert finished["status"] == "completed", finished
            assert finished["result_json"]["requires_review"]
            assert finished["result_json"]["checks"][-1] == {"name": "cleanup", "status": "pass"}
            assert finished["result_json"]["pid_observed"] == (
                scenario in {"launch_observe", "frida_observe"}
            )
            if scenario == "frida_observe":
                assert finished["result_json"]["frida"]["version"] == "17.9.10"
                assert finished["result_json"]["frida"]["hooked_apis"]
                assert finished["result_json"]["frida"]["counters"]["filesystem_open"] > 0
                assert frida_options["frida_token"].get_secret_value() not in str(finished)
            assert expect(api.get(f"/assessments/{assessment['id']}"))["status"] == "needs_review"
            assert not dynamic.run_once(settings, engine)
    finally:
        engine.dispose()


def test_other_worker_does_not_quarantine_live_cancel_cleanup(runtime):
    engine, settings, user_id, permit_id, _, session_id, _, _ = runtime
    _, claim = dynamic._claim(settings, engine)
    with Session(engine) as session:
        permit = session.get(Authorization, permit_id)
        services.revoke_authorization(
            services.Context(session, session.get(User, user_id), "revoke-live"),
            permit.id,
            permit.revision,
            "Withdraw authorization",
        )
        session.commit()
    assert dynamic._claim(settings, engine) == (False, None)
    assert dynamic._owns_device(engine, claim)
    dynamic._finish(settings, engine, claim, reason="execution_cancelled", cancelled=True)
    with Session(engine) as session:
        assert session.get(DynamicSession, session_id).status == "cancelled"
        lease = session.get(DynamicDeviceLease, "ds-lab")
        assert lease.session_id is None and not lease.quarantined


def configure_frida_runtime(runtime, monkeypatch, *, result=None):
    import sys

    from pydantic import SecretStr

    from droidshield.frida_runtime import FRIDA_LIMITATIONS, configuration
    from tests.test_frida import DIGEST, TOKEN, observation

    engine, settings, _, _, _, session_id, _, calls = runtime
    settings.frida_version = "17.9.10"
    settings.frida_server_sha256 = DIGEST
    settings.frida_python = sys.executable
    settings.frida_observation_seconds = 1
    settings.frida_token = SecretStr(TOKEN)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        item.scenario = "frida_observe"
        item.configuration_snapshot = {
            **item.configuration_snapshot,
            "frida_configuration": configuration(settings),
        }
        session.commit()

    class SafeFrida:
        def __init__(self, settings, device):
            assert device == DEVICE

        def run(self, path, package, scenario, timeout, *, should_cancel, owns_device):
            assert not should_cancel() and owns_device()
            calls.append((package, scenario))
            payload = result or {
                **output(),
                "pid_observed": True,
                "frida": observation(),
                "limitations": list(FRIDA_LIMITATIONS),
            }
            payload["checks"][4]["status"] = "pass"
            return payload

    monkeypatch.setattr(dynamic, "FridaLab", SafeFrida)
    return SafeFrida


def test_frida_dynamic_worker_pins_configuration_and_publishes_only_counters(runtime, monkeypatch):
    from tests.test_frida import TOKEN

    configure_frida_runtime(runtime, monkeypatch)
    engine, settings, _, _, assessment_id, session_id, job_id, calls = runtime
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert (
            item.status == "completed"
            and item.result_json["frida"]["counters"]["filesystem_open"] == 4
        )
        assert session.get(Assessment, assessment_id).status == "needs_review"
        assert session.get(AnalysisJob, job_id).tool_versions == {
            "dynamic": ENGINE_VERSION,
            "frida": "17.9.10",
        }
        assert session.get(Assessment, assessment_id).tool_versions == {
            "dynamic": ENGINE_VERSION,
            "frida": "17.9.10",
        }
        safe = dynamic.DynamicOut.model_validate(item).model_dump(mode="json")
        assert TOKEN not in str(safe) and "frida_configuration" not in str(safe)
        assert not session.get(DynamicDeviceLease, "ds-lab").quarantined
    assert calls == [("test.app", "frida_observe")]


@pytest.mark.parametrize("change", ["token", "digest", "duration", "python"])
def test_frida_dynamic_claim_rejects_changed_admin_configuration(runtime, monkeypatch, change):
    from pydantic import SecretStr

    configure_frida_runtime(runtime, monkeypatch)
    engine, settings, _, _, _, session_id, _, calls = runtime
    if change == "token":
        settings.frida_token = SecretStr("y" * 48)
    elif change == "digest":
        settings.frida_server_sha256 = "c" * 64
    elif change == "duration":
        settings.frida_observation_seconds = 2
    else:
        settings.frida_python = "/missing/python"
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "failed" and item.failure_reason == "lab_configuration_changed"
    assert calls == []


@pytest.mark.parametrize("bad_result", ["missing", "wrong_version", "wrong_duration", "raw_value"])
def test_frida_dynamic_rejects_mismatched_or_sensitive_worker_results(
    runtime, monkeypatch, bad_result
):
    from droidshield.frida_runtime import FRIDA_LIMITATIONS
    from tests.test_frida import observation

    result = {
        **output(),
        "pid_observed": True,
        "frida": observation(),
        "limitations": list(FRIDA_LIMITATIONS),
    }
    if bad_result == "missing":
        result.pop("frida")
    elif bad_result == "wrong_version":
        result["frida"]["version"] = "17.0.0"
    elif bad_result == "wrong_duration":
        result["frida"]["observation_seconds"] = 2
    else:
        result["frida"]["raw_value"] = "password=NEVER_PERSIST"
    configure_frida_runtime(runtime, monkeypatch, result=result)
    engine, settings, _, _, _, session_id, _, _ = runtime
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "failed" and item.result_json is None
        assert session.get(DynamicDeviceLease, "ds-lab").quarantined


def test_frida_dynamic_revocation_discards_observations_and_keeps_cleanup_lease(
    runtime, monkeypatch
):
    lab = configure_frida_runtime(runtime, monkeypatch)
    engine, settings, user_id, permit_id, _, session_id, _, _ = runtime

    def interrupted(self, *args, should_cancel, owns_device):
        with Session(engine) as session:
            permit = session.get(Authorization, permit_id)
            services.revoke_authorization(
                services.Context(session, session.get(User, user_id), "revoke-frida"),
                permit.id,
                permit.revision,
                "Withdraw instrumentation scope",
            )
            session.commit()
        assert should_cancel() and owns_device()
        raise LabCancelled()

    monkeypatch.setattr(lab, "run", interrupted)
    assert dynamic.run_once(settings, engine)
    with Session(engine) as session:
        item = session.get(DynamicSession, session_id)
        assert item.status == "cancelled" and item.result_json is None
        lease = session.get(DynamicDeviceLease, "ds-lab")
        assert lease.session_id is None and not lease.quarantined


def test_dynamic_observation_contract_rejects_unsupported_proxy_configuration():
    for body in (
        {"scenario": "frida_observe", "proxy_targets": ["https://api.example.test/health"]},
        {"scenario": "proxy_observe", "proxy_targets": []},
        {"scenario": "proxy_observe", "proxy_targets": ["x"] * 11},
    ):
        with pytest.raises(ValidationError):
            dynamic.DynamicCreate(revision=1, device_id="ds-lab", **body)
