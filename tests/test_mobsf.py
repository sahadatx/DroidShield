import asyncio
import copy
import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from droidshield.mobsf import MobSF, MobSFAnalysisResult, validate_mobsf_result
from droidshield.sandbox import SandboxCancelled, SandboxError
from tests.dex_factory import dex_apk
from tests.test_api import expect, make_assessment, make_authorization, make_project, queue
from tests.test_uploads import PACKAGE_TARGET, upload
from tests.test_uploads import upload_api as upload_api


def settings(**updates):
    values = dict(
        mobsf_url="http://127.0.0.1:8788",
        mobsf_api_key=SecretStr("ephemeral-test-service-key"),
        mobsf_timeout_seconds=3,
        mobsf_max_report_bytes=1024 * 1024,
        max_apk_bytes=1024 * 1024,
    )
    values.update(updates)
    return SimpleNamespace(**values)


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "protected.apk"
    path.write_bytes(dex_apk())
    return path


@pytest.fixture
def metadata():
    return {
        "package_name": "com.example.app",
        "version_name": "1.2.3",
        "version_code": 7,
        "min_sdk": 23,
        "target_sdk": 35,
        "permissions": [],
        "application": {
            "debuggable": False,
            "uses_cleartext_traffic": False,
            "allow_backup": False,
            "test_only": False,
        },
        "components": [],
        "signing_certificate": None,
    }


def report_for(path):
    data = path.read_bytes()
    return {
        "version": "v4.5.3",
        "package_name": "com.example.app",
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "manifest_analysis": {
            "manifest_findings": [{"severity": "warning", "description": "UNSAFE SECRET VALUE"}]
        },
        "code_analysis": {
            "findings": {
                "arbitrary_private_rule_name": {
                    "metadata": {"severity": "high", "description": "UNSAFE SECRET VALUE"},
                    "files": {"/private/server/source.java": "raw token"},
                }
            }
        },
        "certificate_analysis": {
            "certificate_findings": [["info", "UNSAFE SECRET VALUE", "raw private certificate"]]
        },
        "binary_analysis": [{"severity": "warning", "description": "private binary data"}],
        "secrets": ["AKIA0123456789ABCDEF", "UNSAFE SECRET VALUE"],
        "urls": ["https://secret.example/token"],
        "logs": [{"timestamp": "2026-10-28", "status": "Analysis completed", "exception": None}],
    }


class ByteStream(httpx.AsyncByteStream):
    def __init__(self, payload):
        self.payload = payload

    async def __aiter__(self):
        for offset in range(0, len(self.payload), 37):
            yield self.payload[offset : offset + 37]


def response(payload=None, *, status=200, headers=None, raw=None):
    raw = json.dumps(payload).encode() if raw is None else raw
    return httpx.Response(
        status,
        headers={"Content-Type": "application/json", **(headers or {})},
        stream=ByteStream(raw),
    )


def install_service(monkeypatch, artifact, *, report=None, modify=None, handler=None):
    calls = []
    scanned = report_for(artifact) if report is None else report
    real_client = httpx.AsyncClient

    async def respond(request):
        calls.append(request)
        assert request.url.host == "127.0.0.1"
        assert request.headers["Authorization"] == "ephemeral-test-service-key"
        if handler is not None:
            custom = await handler(request)
            if custom is not None:
                return custom
        route = request.url.path
        if route == "/api/v1/upload":
            body = await request.aread()
            assert b'filename="application.apk"' in body
            assert artifact.name.encode() not in body
            data = {"hash": scanned.get("md5"), "analyzer": "static_analyzer", "scan_type": "apk"}
        elif route == "/api/v1/scan":
            assert b"re_scan" not in await request.aread()
            data = {key: scanned.get(key) for key in ("md5", "sha256", "package_name")}
        elif route == "/api/v1/report_json":
            data = scanned
        else:
            raise AssertionError("Unexpected service route")
        if modify is not None:
            data = modify(route, copy.deepcopy(data))
        return response(data)

    def factory(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["headers"]["Accept-Encoding"] == "identity"
        return real_client(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return calls


def test_service_workflow_binds_hashes_and_uses_safe_normalized_categories(
    monkeypatch, artifact, metadata
):
    calls = install_service(monkeypatch, artifact)
    result = MobSF(settings()).run(artifact, metadata=metadata)
    assert [request.url.path for request in calls] == [
        "/api/v1/upload",
        "/api/v1/scan",
        "/api/v1/report_json",
    ]
    assert validate_mobsf_result(result) == result
    assert result["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert result["mobsf_summary"] == {
        "service_version": "4.5.3",
        "manifest_findings": 1,
        "code_findings": 1,
        "certificate_findings": 1,
        "binary_findings": 1,
        "secret_candidates": 2,
        "tool_error_count": 0,
        "analysis_complete": True,
    }
    assert len(result["indicators"]) == 5
    serialized = json.dumps(result)
    for private in (
        "UNSAFE",
        "SECRET VALUE",
        "AKIA0123456789ABCDEF",
        "server/source",
        "arbitrary_private_rule",
        "secret.example",
        "ephemeral-test-service-key",
    ):
        assert private not in serialized


def test_tool_failure_is_explicit_and_never_looks_like_clean_analysis(
    monkeypatch, artifact, metadata
):
    report = report_for(artifact)
    report["code_analysis"]["findings"] = {}
    report["logs"].append(
        {
            "status": "Decompiling with JADX failed",
            "exception": "secret source paths and exception content",
        }
    )
    install_service(monkeypatch, artifact, report=report)
    result = MobSF(settings()).run(artifact, metadata=metadata)
    assert result["mobsf_summary"]["analysis_complete"] is False
    assert result["mobsf_summary"]["tool_error_count"] == 1
    assert result["indicators"][-1]["rule_id"] == "MOBSF_INCOMPLETE_ANALYSIS"
    assert "secret source" not in json.dumps(result)


def test_secure_and_good_observations_do_not_become_vulnerabilities(
    monkeypatch, artifact, metadata
):
    report = report_for(artifact)
    report["manifest_analysis"]["manifest_findings"] = [{"severity": "good"}]
    report["code_analysis"]["findings"] = {"safe": {"metadata": {"severity": "secure"}}}
    install_service(monkeypatch, artifact, report=report)
    result = MobSF(settings()).run(artifact, metadata=metadata)
    assert result["mobsf_summary"]["manifest_findings"] == 0
    assert result["mobsf_summary"]["code_findings"] == 0


def test_native_elf_hardening_report_is_normalized_without_library_paths(
    monkeypatch, artifact, metadata
):
    report = report_for(artifact)
    report["binary_analysis"] = [
        {
            "name": "lib/private-client/secret-native.so",
            "nx": {"severity": "info", "is_nx": True, "description": "withheld raw evidence"},
            "stack_canary": {"severity": "high", "has_canary": False},
            "relocation_readonly": {"severity": "warning", "relro": "Partial RELRO"},
        }
    ]
    install_service(monkeypatch, artifact, report=report)
    result = MobSF(settings()).run(artifact, metadata=metadata)
    assert result["mobsf_summary"]["binary_findings"] == 3
    indicator = next(i for i in result["indicators"] if i["rule_id"] == "MOBSF_BINARY_REVIEW")
    assert indicator["severity"] == "high"
    assert "secret-native" not in json.dumps(result)


@pytest.mark.parametrize(
    "route,key,value",
    [
        ("upload", "hash", "0" * 32),
        ("upload", "scan_type", "zip"),
        ("upload", "analyzer", "static_analyzer_ios"),
        ("scan", "md5", "0" * 32),
        ("scan", "sha256", "0" * 64),
        ("scan", "package_name", "com.other.client"),
        ("report_json", "md5", "0" * 32),
        ("report_json", "sha256", "0" * 64),
        ("report_json", "package_name", "com.other.client"),
        ("report_json", "version", "v9.99.0"),
    ],
)
def test_upload_scan_and_report_identity_mismatch_fail_closed(
    monkeypatch, artifact, metadata, route, key, value
):
    def modify(path, data):
        if path.endswith("/" + route):
            data[key] = value
        return data

    install_service(monkeypatch, artifact, modify=modify)
    with pytest.raises(SandboxError) as error:
        MobSF(settings()).run(artifact, metadata=metadata)
    assert error.value.code == "invalid_analysis_result"


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_analysis", []),
        ("code_analysis", []),
        ("certificate_analysis", []),
        ("binary_analysis", {}),
        ("secrets", {}),
        ("logs", []),
        ("manifest_analysis", {"manifest_findings": [{"severity": "secret-value"}]}),
        ("certificate_analysis", {"certificate_findings": [["warning"]]}),
    ],
)
def test_malformed_or_unknown_report_shapes_are_not_partially_accepted(
    monkeypatch, artifact, metadata, field, value
):
    report = report_for(artifact)
    report[field] = value
    install_service(monkeypatch, artifact, report=report)
    with pytest.raises(SandboxError):
        MobSF(settings()).run(artifact, metadata=metadata)


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 500])
def test_redirects_auth_failures_and_service_errors_do_not_leak_bodies(
    monkeypatch, artifact, metadata, status
):
    async def handler(request):
        return response(
            {"secret": "credential must not leak"},
            status=status,
            headers={"Location": "https://evil.example/steal"},
        )

    calls = install_service(monkeypatch, artifact, handler=handler)
    with pytest.raises(SandboxError) as error:
        MobSF(settings()).run(artifact, metadata=metadata)
    assert len(calls) == 1 and "credential" not in str(error.value)


@pytest.mark.parametrize(
    "headers,raw",
    [
        ({"Content-Type": "text/html"}, b"secret error page"),
        ({"Content-Encoding": "gzip"}, b"compressed body"),
        ({"Content-Length": "10000000"}, b"{}"),
        ({}, b"{invalid private body}"),
        ({}, b'{"hash":"one","hash":"two"}'),
        ({}, b'{"value":NaN}'),
        ({}, b" " * 2000),
    ],
)
def test_response_media_json_and_byte_limits_fail_closed(
    monkeypatch, artifact, metadata, headers, raw
):
    async def handler(request):
        return response(headers=headers, raw=raw)

    install_service(monkeypatch, artifact, handler=handler)
    with pytest.raises(SandboxError):
        MobSF(settings(mobsf_max_report_bytes=1024)).run(artifact, metadata=metadata)


def test_cancellation_closes_inflight_io_promptly(monkeypatch, artifact, metadata):
    entered, cancelled = threading.Event(), threading.Event()

    async def handler(request):
        entered.set()
        try:
            await asyncio.sleep(30)
        finally:
            cancelled.set()

    install_service(monkeypatch, artifact, handler=handler)
    started = time.monotonic()
    with pytest.raises(SandboxCancelled):
        MobSF(settings()).run(artifact, metadata=metadata, should_cancel=entered.is_set)
    assert time.monotonic() - started < 1 and cancelled.wait(0.5)


def test_deadline_independently_cancels_io_when_authorization_check_blocks(
    monkeypatch, artifact, metadata
):
    entered, cancelled = threading.Event(), threading.Event()

    async def handler(request):
        entered.set()
        try:
            await asyncio.sleep(30)
        finally:
            cancelled.set()

    def blocking_check():
        if entered.is_set():
            time.sleep(0.35)
        return False

    install_service(monkeypatch, artifact, handler=handler)
    with pytest.raises(SandboxError) as error:
        MobSF(settings(mobsf_timeout_seconds=0.15)).run(
            artifact, metadata=metadata, should_cancel=blocking_check
        )
    assert error.value.code == "analysis_timeout" and cancelled.is_set()


@pytest.mark.parametrize(
    "problem",
    [
        "missing_url",
        "missing_key",
        "unsafe_http",
        "credentials",
        "root",
        "symlink",
        "too_large",
        "directory",
    ],
)
def test_disabled_unsafe_configuration_and_untrusted_paths_fail_closed(
    monkeypatch, artifact, metadata, problem
):
    config, path = settings(), artifact
    if problem == "missing_url":
        config.mobsf_url = None
    elif problem == "missing_key":
        config.mobsf_api_key = None
    elif problem == "unsafe_http":
        config.mobsf_url = "http://169.254.169.254"
    elif problem == "credentials":
        config.mobsf_url = "https://user:secret@example.org"
    elif problem == "root":
        monkeypatch.setattr(os, "getuid", lambda: 0)
    elif problem == "symlink":
        path = artifact.with_name("link.apk")
        path.symlink_to(artifact)
    elif problem == "too_large":
        config.max_apk_bytes = 1
    elif problem == "directory":
        path = artifact.parent
    with pytest.raises(SandboxError):
        MobSF(config).run(path, metadata=metadata)


@pytest.mark.parametrize(
    "mutation", ["text", "evidence", "summary", "complete", "duplicate", "version"]
)
def test_normalized_result_contract_rejects_injection_and_inconsistent_counts(
    monkeypatch, artifact, metadata, mutation
):
    install_service(monkeypatch, artifact)
    result = MobSF(settings()).run(artifact, metadata=metadata)
    if mutation == "text":
        result["indicators"][0]["description"] = "raw service secret"
    elif mutation == "evidence":
        result["indicators"][0]["evidence"]["excerpt"] = "raw secret"
    elif mutation == "summary":
        result["mobsf_summary"]["manifest_findings"] += 1
    elif mutation == "complete":
        result["mobsf_summary"]["analysis_complete"] = False
    elif mutation == "duplicate":
        result["indicators"].append(result["indicators"][0])
    else:
        result["schema_version"] = True
    with pytest.raises(ValidationError):
        MobSFAnalysisResult.model_validate(result)


def test_actual_isolated_mobsf_service_opt_in(artifact, metadata):
    url, key = os.getenv("DROIDSHIELD_MOBSF_TEST_URL"), os.getenv("DROIDSHIELD_MOBSF_TEST_KEY")
    if not url or not key:
        pytest.skip("Opt-in isolated MobSF 4.5.3 service not configured")
    result = MobSF(
        settings(mobsf_url=url, mobsf_api_key=SecretStr(key), mobsf_timeout_seconds=180)
    ).run(artifact, metadata=metadata)
    assert result["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert result["engine_version"] == "droidshield-mobsf-1"
    assert result["mobsf_summary"]["service_version"] == "4.5.3"
    assert validate_mobsf_result(result) == result


def test_actual_service_through_protected_upload_worker_and_scoped_api_opt_in(request):
    from droidshield.worker import run_once

    url, key = os.getenv("DROIDSHIELD_MOBSF_TEST_URL"), os.getenv("DROIDSHIELD_MOBSF_TEST_KEY")
    if not url or not key:
        pytest.skip("Opt-in isolated MobSF 4.5.3 service not configured")
    api = request.getfixturevalue("upload_api")
    config = api.client.app.state.settings
    config.mobsf_url = url
    config.mobsf_api_key = SecretStr(key)
    config.mobsf_timeout_seconds = 180
    project = make_project(api)
    permit = make_authorization(api, project, approved_targets=[PACKAGE_TARGET])
    draft = make_assessment(
        api, project, permit, targets=[PACKAGE_TARGET], assessment_type="static", engine="mobsf"
    )
    content = dex_apk(package_name="com.example.store", version_name="1.2.8")
    artifact = expect(upload(api, draft, content=content), 201)
    current = expect(api.get(f"/assessments/{draft['id']}"))
    expect(queue(api, current))
    assert run_once(config, api.engine)
    job = expect(api.get(f"/assessments/{draft['id']}/job"))
    assert job["status"] == "completed"
    completed = expect(api.get(f"/assessments/{draft['id']}"))
    assert completed["status"] == "needs_review"
    analysis = expect(api.get(f"/assessments/{draft['id']}/analysis"))
    assert analysis["schema_version"] == 3
    assert analysis["engine_version"] == "droidshield-mobsf-1"
    assert analysis["artifact_sha256"] == hashlib.sha256(content).hexdigest()
    assert analysis["metadata"]["package_name"] == "com.example.store"
    assert analysis["mobsf_summary"]["service_version"] == "4.5.3"
    assert analysis["mobsf_summary"]["analysis_complete"] is True
    assert analysis["mobsf_summary"]["code_findings"] > 0
    findings = expect(api.get(f"/assessments/{draft['id']}/findings"))
    assert findings["total"] > 0
    assert {item["verification_status"] for item in findings["items"]} == {"unreviewed"}
    assert {item["remediation_status"] for item in findings["items"]} == {"open"}
    assert {item["artifact_id"] for item in findings["items"]} == {artifact["id"]}
    expect(api.get(f"/assessments/{draft['id']}/analysis", role="other_admin"), 404)
    serialized = json.dumps(analysis)
    assert key not in serialized and "AKIA0123456789ABCDEF" not in serialized
