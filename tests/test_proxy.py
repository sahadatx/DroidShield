"""Actual TLS interception and adversarial proxy boundary checks, with local targets."""

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from threading import Event
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError

from droidshield.config import Settings
from droidshield.lab import LabError
from droidshield.proxy import (
    GuardedProxy,
    ProxyLab,
    initialize_ca,
    proxy_configuration,
    validate_proxy_targets,
)
from droidshield.proxy_contract import PROXY_LIMITATIONS, ProxySummary
from tests.test_api import expect, make_assessment, make_authorization, make_project
from tests.test_api_security import tls_target as _tls_target
from tests.test_uploads import upload
from tests.test_uploads import upload_api as _upload_api

tls_target, upload_api = _tls_target, _upload_api


@pytest.fixture
def proxy_settings(tmp_path, tls_target):
    base, upstream, calls = tls_target
    directory = tmp_path / "lab-ca"
    initialize_ca(directory)
    settings = Settings(
        _env_file=None,
        proxy_ca_cert=directory / "cert.pem",
        proxy_ca_key=directory / "key.pem",
        api_ca_bundle=upstream.api_ca_bundle,
        api_allowed_networks=["127.0.0.1/32"],
        api_request_timeout_seconds=2,
        api_max_response_bytes=1024,
        proxy_observation_seconds=6,
    )
    return settings, base, calls


def client(proxy, settings, url):
    parts = urlsplit(url)
    context = ssl.create_default_context(cafile=settings.proxy_ca_cert)
    connection = http.client.HTTPSConnection("127.0.0.1", proxy.port, context=context, timeout=3)
    connection.set_tunnel(parts.hostname, parts.port or 443)
    return connection


def test_real_connect_proxy_pins_upstream_tls_and_retains_no_raw_traffic(proxy_settings):
    settings, base, calls = proxy_settings
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 8, should_cancel=lambda: False
    ) as proxy:
        connection = client(proxy, settings, base)
        connection.request(
            "GET", "/profile", headers={"Authorization": "Bearer PRIVATE_FIXTURE_TOKEN"}
        )
        response = connection.getresponse()
        assert response.status == 200 and b"NEVER_RETAIN_THIS_BODY" in response.read()
        connection.close()
        summary = proxy.summary()
        assert summary["requests_forwarded"] == 1
        assert summary["observations"][0]["tls_version"] in {"TLSv1.2", "TLSv1.3"}
        assert summary["observations"][0]["target_index"] == 0
        assert calls == [("/profile", "Bearer PRIVATE_FIXTURE_TOKEN")]
        assert "PRIVATE_FIXTURE_TOKEN" not in json.dumps(summary)
        assert "NEVER_RETAIN_THIS_BODY" not in json.dumps(summary)
        assert base not in json.dumps(summary)


@pytest.mark.parametrize(
    "method,path,headers",
    [
        ("POST", "/profile", {}),
        ("GET", "/elsewhere", {}),
        ("GET", "/profile?token=PRIVATE", {}),
        ("GET", "/%70rofile", {}),
        ("GET", "/../profile", {}),
        ("GET", "/profile", {"Host": "evil.invalid"}),
        ("GET", "/profile", {"Content-Length": "1"}),
        ("GET", "/profile", {"Transfer-Encoding": "chunked"}),
        ("GET", "/profile", {"Upgrade": "websocket"}),
    ],
)
def test_disallowed_methods_paths_hosts_and_framing_never_reach_target(
    proxy_settings, method, path, headers
):
    settings, base, calls = proxy_settings
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 5, should_cancel=lambda: False
    ) as proxy:
        connection = client(proxy, settings, base)
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        assert response.status == 403
        response.read()
        connection.close()
        assert not calls
        assert proxy.summary()["blocked_requests"] == 1


def test_unknown_connect_authority_is_blocked_before_tunnel(proxy_settings):
    settings, base, calls = proxy_settings
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 5, should_cancel=lambda: False
    ) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as channel:
            channel.sendall(
                b"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"
            )
            assert b"403" in channel.recv(1024)
        assert not calls and not proxy.summary()["requests_forwarded"]


def test_canonical_default_tls_port_and_ipv6_authorities():
    assert GuardedProxy._authority("EXAMPLE.com:443") == "example.com"
    assert GuardedProxy._authority("[::1]:443") == "[::1]"
    for bad in ("host/a", "user@host", "host?token=x", "host#fragment", "host\\evil"):
        with pytest.raises(ValueError):
            GuardedProxy._authority(bad)


def test_redirect_observation_never_follows_or_returns_redirect(proxy_settings):
    settings, base, calls = proxy_settings
    with GuardedProxy(
        settings, [base + "/redirect"], deadline=time.monotonic() + 5, should_cancel=lambda: False
    ) as proxy:
        connection = client(proxy, settings, base)
        connection.request("GET", "/redirect")
        response = connection.getresponse()
        assert response.status == 403 and response.getheader("Location") is None
        response.read()
        connection.close()
        assert calls == [("/redirect", None)]
        assert proxy.summary()["observations"][0]["status_code"] == 302


def test_cancellation_and_independent_deadline_close_pending_tls(proxy_settings):
    settings, base, calls = proxy_settings
    cancel = Event()
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 0.5, should_cancel=cancel.is_set
    ) as proxy:
        channel = socket.create_connection(("127.0.0.1", proxy.port), timeout=2)
        authority = urlsplit(base).netloc
        channel.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        assert b"200" in channel.recv(1024)
        assert channel.recv(1024) == b""
        channel.close()
        assert not calls


def test_request_budget_stops_additional_upstream_calls(proxy_settings):
    settings, base, calls = proxy_settings
    settings.proxy_max_requests = 1
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 5, should_cancel=lambda: False
    ) as proxy:
        for expected in (401, 403):
            connection = client(proxy, settings, base)
            connection.request("GET", "/profile")
            response = connection.getresponse()
            assert response.status == expected
            response.read()
            connection.close()
        assert calls == [("/profile", None)]
        assert proxy.summary()["requests_forwarded"] == 1


def test_upstream_tls_failure_is_counted_and_never_forwarded(proxy_settings):
    settings, base, calls = proxy_settings
    settings.api_ca_bundle = None
    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 5, should_cancel=lambda: False
    ) as proxy:
        connection = client(proxy, settings, base)
        connection.request("GET", "/profile")
        with pytest.raises(http.client.RemoteDisconnected):
            connection.getresponse()
        connection.close()
        result = proxy.summary()
        assert result["tls_failures"] == 1 and result["blocked_requests"] == 1
        assert result["requests_forwarded"] == 0 and not calls


def test_independent_deadline_closes_socket_while_permission_callback_waits(proxy_settings):
    settings, base, calls = proxy_settings
    release = Event()
    checks = []

    def permission():
        checks.append(True)
        if len(checks) > 1:
            release.wait(2)
        return False

    with GuardedProxy(
        settings, [base + "/profile"], deadline=time.monotonic() + 0.3, should_cancel=permission
    ) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=1) as channel:
            channel.sendall(f"CONNECT {urlsplit(base).netloc} HTTP/1.1\r\n\r\n".encode())
            started = time.monotonic()
            assert channel.recv(1024) == b""
            assert time.monotonic() - started < 1
        release.set()
    assert not calls


@pytest.mark.parametrize("problem", ["missing", "world_readable", "symlink", "wrong_key", "not_ca"])
def test_private_ca_configuration_fails_closed(proxy_settings, tmp_path, problem):
    settings, _, _ = proxy_settings
    if problem == "missing":
        settings.proxy_ca_key = None
    elif problem == "world_readable":
        settings.proxy_ca_key.chmod(0o644)
    elif problem == "symlink":
        link = tmp_path / "link"
        link.symlink_to(settings.proxy_ca_key)
        settings.proxy_ca_key = link
    elif problem == "wrong_key":
        initialize_ca(tmp_path / "other-ca")
        settings.proxy_ca_key = tmp_path / "other-ca/key.pem"
    else:
        settings.proxy_ca_cert = settings.api_ca_bundle
    with pytest.raises(LabError):
        proxy_configuration(settings)


def test_ca_provisioning_never_overwrites_and_private_config_is_not_serialized(proxy_settings):
    settings, _, _ = proxy_settings
    before = settings.proxy_ca_key.read_bytes()
    with pytest.raises(FileExistsError):
        initialize_ca(settings.proxy_ca_key.parent)
    assert settings.proxy_ca_key.read_bytes() == before
    assert "proxy_ca_key" not in settings.model_dump()
    assert "frida_token" not in settings.model_dump()
    assert "api_secret_store" not in settings.model_dump()
    safe = proxy_configuration(settings)
    assert "key.pem" not in str(safe) and "cert.pem" not in str(safe)


@pytest.mark.parametrize(
    "targets,requested,approved,excluded",
    [
        ([], ["package:com.example.app"], [], []),
        (
            ["https://example.test/profile"],
            ["package:com.example.app"],
            ["https://example.test/profile"],
            [],
        ),
        (
            ["https://example.test/profile"],
            ["package:com.example.app", "https://example.test/profile"],
            [],
            [],
        ),
        (
            ["https://example.test/profile"],
            ["package:com.example.app", "https://example.test/profile"],
            ["https://example.test/profile"],
            ["https://example.test/"],
        ),
    ],
)
def test_proxy_targets_require_identical_assessment_scope_and_explicit_approval(
    targets, requested, approved, excluded
):
    with pytest.raises(LabError):
        validate_proxy_targets(targets, requested, approved, excluded, "com.example.app")


def test_proxy_summary_rejects_raw_evidence_and_inconsistent_counts():
    safe = {
        "requests_forwarded": 0,
        "blocked_requests": 0,
        "tls_failures": 0,
        "response_bytes": 0,
        "observations": [],
        "requires_review": True,
        "limitations": PROXY_LIMITATIONS,
    }
    ProxySummary.model_validate(safe)
    for change in (
        {"request_headers": {"Authorization": "secret"}},
        {"requests_forwarded": 1},
        {"limitations": ["allsecure"]},
    ):
        with pytest.raises(ValidationError):
            ProxySummary.model_validate({**safe, **change})


def test_cleanup_fault_still_attempts_setting_reverse_and_local_listener():
    from types import SimpleNamespace

    calls = []
    instance = object.__new__(ProxyLab)
    instance.rules = instance.global_proxy = instance.reverse = True
    instance.proxy = SimpleNamespace(port=4567, close=lambda: calls.append(("closed",)))

    def command(*args, **kwargs):
        calls.append(args)
        assert kwargs.get("cleanup") is True
        if "iptables" in args:
            raise OSError("private simulated device error")
        if args[:2] == ("reverse", "--list"):
            return "host-14 tcp:8081 tcp:4567"
        if "get" in args:
            return "null"
        return ""

    instance._run = command
    with pytest.raises(LabError, match="device_cleanup_failed"):
        instance._cleanup_observer()
    assert ("shell", "settings", "delete", "global", "http_proxy") in calls
    assert ("reverse", "--remove", "tcp:8081") in calls
    assert ("closed",) in calls


def test_cleanup_never_deletes_a_replaced_reverse_mapping():
    from types import SimpleNamespace

    calls = []
    instance = object.__new__(ProxyLab)
    instance.rules = instance.global_proxy = False
    instance.reverse = True
    instance.proxy = SimpleNamespace(port=4567, close=lambda: calls.append(("closed",)))

    def command(*args, **kwargs):
        calls.append(args)
        return "host-14 tcp:8081 tcp:9999"

    instance._run = command
    with pytest.raises(LabError):
        instance._cleanup_observer()
    assert ("reverse", "--remove", "tcp:8081") not in calls
    assert ("closed",) in calls


def test_real_android_proxy_through_protected_worker_opt_in(upload_api, proxy_settings, tmp_path):
    raw = os.environ.get("DROIDSHIELD_TEST_RUNTIME_DEVICE")
    if not raw:
        pytest.skip("Explicit disposable emulator configuration required")
    from droidshield.dynamic import run_once

    api = upload_api
    settings, base, calls = proxy_settings
    config = api.client.app.state.settings
    for field in (
        "proxy_ca_cert",
        "proxy_ca_key",
        "api_ca_bundle",
        "api_allowed_networks",
        "proxy_observation_seconds",
    ):
        setattr(config, field, getattr(settings, field))
    config.lab_devices = [json.loads(raw)]
    target = base + "/profile"
    directory = tmp_path / "network-apk"
    subprocess.run(
        [
            sys.executable,
            "scripts/build-proxy-smoke.py",
            "--directory",
            str(directory),
            "--ca-cert",
            str(config.proxy_ca_cert),
            "--url",
            target,
        ],
        check=True,
        capture_output=True,
        timeout=90,
    )
    package = "dev.droidshield.proxysmoke"
    project = make_project(api, package_id=package)
    targets = ["package:" + package, target]
    permit = make_authorization(api, project, approved_targets=targets)
    assessment = make_assessment(api, project, permit, targets=targets, assessment_type="dynamic")
    expect(upload(api, assessment, content=(directory / "proxy-smoke.apk").read_bytes()), 201)
    assessment = expect(api.get(f"/assessments/{assessment['id']}"))
    created = expect(
        api.post(
            f"/assessments/{assessment['id']}/dynamic-sessions",
            {
                "revision": assessment["revision"],
                "device_id": config.lab_devices[0]["id"],
                "scenario": "proxy_observe",
                "proxy_targets": [target],
            },
        ),
        201,
    )
    assert run_once(config, api.engine)
    finished = expect(api.get(f"/dynamic-sessions/{created['id']}"))
    assert finished["status"] == "completed", (
        finished["status"],
        finished["failure_reason"],
        finished["cancellation_reason"],
    )
    assert finished["result_json"]["traffic"]["requests_forwarded"] >= 1, finished["result_json"][
        "traffic"
    ]
    assert calls == [("/profile", None)]
    assert "NEVER_RETAIN_THIS_BODY" not in json.dumps(finished)
