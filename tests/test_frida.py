"""Fixed Frida instrumentation, credential boundaries, cancellation and cleanup."""

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr, ValidationError

from droidshield.frida_runtime import (
    FORWARD_TARGET,
    FRIDA_LIMITATIONS,
    SERVER_PATH,
    SOCKET_ADDRESS,
    FridaLab,
    configuration,
)
from droidshield.lab import FridaObservation, LabCancelled, LabError
from tests.test_lab import DEVICE, SimulatedAdb

TOKEN = "test-fixture-frida-token-" + "x" * 32
DIGEST = "b" * 64


def frida_settings(**updates):
    values = dict(
        lab_devices=[DEVICE],
        adb_executable="/usr/bin/adb",
        dynamic_max_output_bytes=65536,
        frida_version="17.9.10",
        frida_server_sha256=DIGEST,
        frida_python=sys.executable,
        frida_observation_seconds=1,
        frida_token=SecretStr(TOKEN),
    )
    return SimpleNamespace(**{**values, **updates})


def observation(**updates):
    return {
        "version": "17.9.10",
        "observation_seconds": 1,
        "hooked_apis": ["filesystem_open", "socket_connect", "dns_lookup"],
        "counters": {"filesystem_open": 4, "socket_connect": 0, "dns_lookup": 0},
        **updates,
    }


class SimulatedFrida(FridaLab):
    def __init__(self, *, failure=None, existing=False, cancellation=False):
        super().__init__(frida_settings(), DEVICE)
        self.calls = []
        self.existing, self.bad_identity, self.bad_firewall = existing, False, False
        self.cleanup_failure = self.cancel_after_install = self.installed = False
        self.failure, self.cancellation = failure, cancellation
        self.forward_live = False

    def _run(self, *args, cleanup=False, allow_failure=False):
        if args == ("shell", "cat", "/proc/mounts"):
            return (
                "proc /proc proc rw,hidepid=" + ("0" if self.failure == "hidepid" else "2") + " 0 0"
            )
        if args in (
            ("shell", "readlink", "-f", SERVER_PATH),
            ("shell", "readlink", "/proc/555/exe"),
        ):
            self.calls.append((args, cleanup))
            return "/untrusted" if self.failure == "path" else SERVER_PATH
        if args == ("shell", "stat", "-c", "%u:%a", SERVER_PATH):
            return "0:777" if self.failure == "permissions" else "0:700"
        if args == ("shell", "sha256sum", SERVER_PATH):
            return ("a" * 64 if self.failure == "digest" else DIGEST) + "  " + SERVER_PATH
        if args == ("shell", SERVER_PATH, "--version"):
            return "17.0.0" if self.failure == "version" else "17.9.10"
        if args == ("shell", "pidof", SERVER_PATH):
            return "555"
        if args == ("shell", "cat", "/proc/555/cmdline"):
            token = "wrong" if self.failure == "token" else TOKEN
            return "\x00".join([SERVER_PATH, "--listen=" + SOCKET_ADDRESS, "--token=" + token, ""])
        if args == ("forward", "--no-rebind", "tcp:0", FORWARD_TARGET):
            self.calls.append((args, cleanup))
            self.forward_live = True
            return "43333"
        if args == ("forward", "--list"):
            self.calls.append((args, cleanup))
            return f"other-device tcp:44444 tcp:9999\n{DEVICE['serial']} tcp:43333 {FORWARD_TARGET}"
        if args == ("forward", "--remove", "tcp:43333"):
            self.calls.append((args, cleanup))
            self.forward_live = False
            return ""
        return SimulatedAdb._run(self, *args, cleanup=cleanup, allow_failure=allow_failure)

    def _helper(self, package):
        assert self.installed and self.forward_live and package == "test.app"
        if self.cancellation:
            raise LabCancelled()
        return observation()


def run(lab, *, owns_device=lambda: True):
    return lab.run(
        Path("/tmp/session.apk"),
        "test.app",
        "frida_observe",
        30,
        should_cancel=lambda: False,
        owns_device=owns_device,
    )


def test_fixed_frida_counters_preserve_offline_cleanup_and_redact_credentials():
    lab = SimulatedFrida()
    result = run(lab)
    assert result["frida"] == observation() and result["pid_observed"]
    assert result["limitations"] == FRIDA_LIMITATIONS
    assert not lab.installed and not lab.forward_live
    assert TOKEN not in str(result) and DIGEST not in str(result)
    assert not any("--remove-all" in args for args, _ in lab.calls)
    commands = [args for args, _ in lab.calls]
    assert commands.index(("shell", "ip6tables", "-S", "OUTPUT")) < commands.index(
        ("forward", "--no-rebind", "tcp:0", FORWARD_TARGET)
    )
    assert not any("-A" in args or "ACCEPT" in args for args in commands)


@pytest.mark.parametrize(
    "failure", ["path", "digest", "version", "token", "permissions", "hidepid"]
)
def test_frida_rejects_unpinned_or_unauthenticated_server_before_install(failure):
    lab = SimulatedFrida(failure=failure)
    with pytest.raises(LabError):
        run(lab)
    assert not lab.installed and not lab.forward_live
    assert not any(args[0] == "install" for args, _ in lab.calls)


def test_frida_cancel_cleans_only_own_package_and_owned_forward():
    lab = SimulatedFrida(cancellation=True)
    with pytest.raises(LabCancelled):
        run(lab)
    assert not lab.installed and not lab.forward_live
    assert any(
        args == ("forward", "--remove", "tcp:43333") and cleanup for args, cleanup in lab.calls
    )


def test_frida_preexisting_app_remains_untouched_and_forward_is_released():
    lab = SimulatedFrida(existing=True)
    with pytest.raises(LabError, match="package_already_installed"):
        run(lab)
    assert not lab.forward_live
    assert not any(args[0] in {"install", "uninstall"} for args, _ in lab.calls)


def test_frida_lost_device_lease_cannot_remove_reused_device_resources():
    lab = SimulatedFrida()
    with pytest.raises(LabError, match="device_lease_lost"):
        run(lab, owns_device=lambda: False)
    assert lab.installed and lab.forward_live
    assert not any(args[:2] == ("forward", "--remove") for args, _ in lab.calls)


@pytest.mark.parametrize(
    "update",
    [
        {"frida_server_sha256": None},
        {"frida_python": "python"},
        {"frida_token": None},
        {"frida_token": SecretStr("short")},
        {"frida_observation_seconds": True},
    ],
)
def test_missing_or_malformed_frida_configuration_fails_closed(update):
    with pytest.raises(LabError, match="frida_unavailable"):
        configuration(frida_settings(**update))


def test_frida_fingerprint_changes_when_admin_rotates_credentials():
    first = configuration(frida_settings())
    second = configuration(frida_settings(frida_token=SecretStr("y" * 48)))
    assert first != second and TOKEN not in str(first)


@pytest.mark.parametrize(
    "update",
    [
        {"raw_value": "password=NEVER_PERSIST"},
        {"hooked_apis": ["filesystem_open", "filesystem_open"]},
        {"hooked_apis": ["socket_connect"]},
        {"counters": {"filesystem_open": True, "socket_connect": 0, "dns_lookup": 0}},
    ],
)
def test_frida_result_contract_rejects_raw_strings_and_inconsistent_counters(update):
    with pytest.raises(ValidationError):
        FridaObservation.model_validate(observation(**update))


def test_real_helper_subprocess_is_bounded_and_its_command_never_contains_token(tmp_path):
    script = tmp_path / "trusted-python-fixture"
    # Administrative interpreter test double: receive the credential over stdin,
    # verify it is absent from argv, then emit the exact safe result contract.
    script.write_text(
        "#!/usr/bin/python3\nimport sys,json\n"
        f"assert sys.stdin.read()=={TOKEN!r}\nassert {TOKEN!r} not in str(sys.argv)\n"
        f"print({json.dumps(json.dumps(observation()))})\n"
    )
    script.chmod(0o700)
    lab = FridaLab(frida_settings(frida_python=str(script)), DEVICE)
    lab.frida_configuration = configuration(lab.settings)
    lab.forward_port, lab.deadline = 43333, time.monotonic() + 3
    assert lab._helper("test.app") == observation()
    script.write_text("#!/usr/bin/python3\nimport sys\nsys.stdin.read()\nprint('x'*5000)\n")
    lab.deadline = time.monotonic() + 3
    with pytest.raises(LabError, match="frida_output_invalid"):
        lab._helper("test.app")
    script.write_text("#!/bin/sh\nsleep 5\n")
    lab.deadline = time.monotonic() + 0.15
    started = time.monotonic()
    with pytest.raises(LabError, match="dynamic_timeout"):
        lab._helper("test.app")
    assert time.monotonic() - started < 1


def test_builtin_frida_program_never_reads_values_or_loads_caller_script():
    source = Path(__file__).parents[1].joinpath("backend/droidshield/frida_agent.js").read_text()
    assert all(name in source for name in ("filesystem_open", "socket_connect", "dns_lookup"))
    assert all(
        name not in source for name in ("readUtf8", "readByteArray", "args[", "retval", "eval(")
    )
