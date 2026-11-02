"""ADB fault tests. Real emulator validation is described separately in the runbook."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from droidshield.lab import AdbLab, LabCancelled, LabError, LabResult, configured_devices

DEVICE = {
    "id": "ds-lab",
    "label": "Disposable lab",
    "serial": "emulator-5560",
    "avd_name": "DroidShield_Lab",
    "android_version": "11",
}


def settings(**updates):
    return SimpleNamespace(
        lab_devices=[DEVICE],
        adb_executable="/usr/bin/adb",
        dynamic_max_output_bytes=65536,
        **updates,
    )


class SimulatedAdb(AdbLab):
    def __init__(
        self,
        *,
        existing=False,
        bad_identity=False,
        bad_firewall=False,
        cleanup_failure=False,
        cancel_after_install=False,
    ):
        super().__init__(settings(), DEVICE)
        self.calls = []
        self.existing, self.bad_identity, self.bad_firewall = existing, bad_identity, bad_firewall
        self.cleanup_failure, self.cancel_after_install = cleanup_failure, cancel_after_install
        self.installed = False

    def _run(self, *args, cleanup=False, allow_failure=False):
        self.calls.append((args, cleanup))
        if args[:2] == ("shell", "getprop"):
            return {
                "ro.kernel.qemu": "0" if self.bad_identity else "1",
                "ro.boot.qemu.avd_name": "DroidShield_Lab",
                "sys.boot_completed": "1",
            }[args[-1]]
        if args == ("emu", "avd", "name"):
            return "DroidShield_Lab\nOK"
        if args == ("shell", "id", "-u"):
            return "0"
        if args == ("shell", "cmd", "package", "list", "packages", "-U", "test.app"):
            return "package:test.app uid:10050"
        if args[:2] == ("shell", "pm"):
            return "package:/some.apk" if self.existing or self.installed else ""
        if "-S" in args:
            return "-P OUTPUT ACCEPT" if self.bad_firewall else "-P OUTPUT DROP"
        if args[0] == "install":
            self.installed = True
            return "Success"
        if args[:3] == ("shell", "dumpsys", "package"):
            if self.cancel_after_install:
                raise LabCancelled()
            return "Package [test.app] (123)"
        if args[:4] == ("shell", "cmd", "package", "resolve-activity"):
            return "test.app/.MainActivity"
        if args[:3] == ("shell", "am", "start"):
            return "Status: ok"
        if args[:2] == ("shell", "pidof"):
            return "123"
        if args[0] == "logcat":
            return "api_key=SHOULD_NEVER_PERSIST java.lang.SecurityException password=PRIVATE"
        if args[0] == "uninstall":
            if not self.cleanup_failure:
                self.installed = False
            return "Failure" if self.cleanup_failure else "Success"
        return ""


def run(lab, **kwargs):
    return lab.run(
        Path("/tmp/session.apk"),
        "test.app",
        "package_inspection",
        10,
        should_cancel=lambda: False,
        owns_device=kwargs.get("owns_device", lambda: True),
    )


def test_package_runtime_requires_identity_firewall_and_cleanup():
    lab = SimulatedAdb()
    result = LabResult.model_validate(run(lab))
    assert not lab.installed and result.requires_review
    assert [check.name for check in result.checks] == [
        "device_identity",
        "offline_firewall",
        "apk_installed",
        "package_inspected",
        "app_launched",
        "cleanup",
    ]
    commands = [call[0] for call in lab.calls]
    assert commands.index(("shell", "ip6tables", "-S", "OUTPUT")) < next(
        i for i, item in enumerate(commands) if item[0] == "install"
    )
    assert not any("logcat" in item for item in commands)


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"bad_identity": True}, "device_identity_invalid"),
        ({"bad_firewall": True}, "lab_isolation_unavailable"),
        ({"existing": True}, "package_already_installed"),
    ],
)
def test_refuses_physical_nonisolated_or_preexisting_package(kwargs, reason):
    lab = SimulatedAdb(**kwargs)
    with pytest.raises(LabError, match=reason):
        run(lab)
    assert not any(args[0] in {"install", "uninstall"} for args, _ in lab.calls)


def test_cancellation_after_install_always_cleans_own_app():
    lab = SimulatedAdb(cancel_after_install=True)
    with pytest.raises(LabCancelled):
        run(lab)
    assert not lab.installed
    assert any(args[0] == "uninstall" and cleanup for args, cleanup in lab.calls)


def test_lost_device_lease_prevents_cleanup_on_potentially_reused_device():
    lab = SimulatedAdb()
    with pytest.raises(LabError, match="device_lease_lost"):
        run(lab, owns_device=lambda: False)
    assert lab.installed
    assert not any(args[0] == "uninstall" for args, _ in lab.calls)


def test_cleanup_failure_never_reports_success():
    with pytest.raises(LabError, match="device_cleanup_failed"):
        run(SimulatedAdb(cleanup_failure=True))


def test_unexpected_observer_cleanup_error_still_removes_owned_package():
    class BrokenObserver(SimulatedAdb):
        def _cleanup_observer(self):
            raise OSError("observer resource cleanup failed")

    lab = BrokenObserver()
    with pytest.raises(LabError, match="device_cleanup_failed"):
        run(lab)
    assert not lab.installed
    assert any(args[0] == "uninstall" and cleanup for args, cleanup in lab.calls)


def test_unexpected_observer_error_never_cleans_without_verified_lease():
    class BrokenObserver(SimulatedAdb):
        def _cleanup_observer(self):
            raise OSError("observer resource cleanup failed")

    lab = BrokenObserver()

    def unavailable():
        raise RuntimeError("control database is unavailable")

    with pytest.raises(LabError, match="device_lease_lost"):
        run(lab, owns_device=unavailable)
    assert lab.installed
    assert not any(args[0] == "uninstall" for args, _ in lab.calls)


def test_cleanup_deadline_is_checked_before_and_after_ownership_lookup(tmp_path, monkeypatch):
    import time

    script = tmp_path / "unused-adb"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o700)
    configuration = settings()
    configuration.adb_executable = str(script)
    lab = AdbLab(configuration, DEVICE)
    calls = []
    lab.owns_device = lambda: calls.append("ownership") or True
    lab.cleanup_deadline = time.monotonic() - 1
    with pytest.raises(LabError, match="dynamic_timeout"):
        lab._run("uninstall", "test.app", cleanup=True)
    assert calls == []

    def expires_during_lookup():
        calls.append("ownership")
        lab.cleanup_deadline = time.monotonic() - 1
        return True

    lab.owns_device = expires_during_lookup
    lab.cleanup_deadline = time.monotonic() + 5
    monkeypatch.setattr(
        "droidshield.lab.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("An expired cleanup must not start ADB"),
    )
    with pytest.raises(LabError, match="dynamic_timeout"):
        lab._run("uninstall", "test.app", cleanup=True)
    assert calls == ["ownership"]


@pytest.mark.parametrize(
    "package", ["com.x;id", "com.x$(id)", "com.x/other", "../data", "test.app\nfoo"]
)
def test_untrusted_package_never_enters_adb_shell(package):
    lab = SimulatedAdb()
    with pytest.raises(LabError, match="target_scope_invalid"):
        lab.run(
            Path("/tmp/test.apk"),
            package,
            "launch_observe",
            10,
            should_cancel=lambda: False,
            owns_device=lambda: True,
        )
    assert lab.calls == []


def test_device_inventory_requires_explicit_disposable_emulator_allowlist():
    assert configured_devices(settings()) == [DEVICE]
    for change in ({"serial": "physical123"}, {"avd_name": "Pixel_4"}, {"id": "$(id)"}):
        bad = settings()
        bad.lab_devices = [{**DEVICE, **change}]
        with pytest.raises(LabError, match="lab_configuration_invalid"):
            configured_devices(bad)
    repeated = settings()
    repeated.lab_devices = [DEVICE, DEVICE]
    with pytest.raises(LabError):
        configured_devices(repeated)


def test_launch_persists_only_fixed_exception_categories():
    lab = SimulatedAdb()
    result = lab.run(
        Path("/tmp/session.apk"),
        "test.app",
        "launch_observe",
        10,
        should_cancel=lambda: False,
        owns_device=lambda: True,
    )
    assert result["pid_observed"] and result["exception_categories"] == ["SecurityException"]
    assert result["exception_count"] == 1
    assert "PRIVATE" not in str(result) and "api_key" not in str(result)
    assert any(args[0] == "logcat" and "--pid=123" in args for args, _ in lab.calls)
    assert not any("-c" in args for args, _ in lab.calls)


def test_actual_subprocess_enforces_output_budget_and_cancellation(tmp_path):
    import time

    script = tmp_path / "bounded-adb"
    script.write_text("#!/bin/sh\nprintf '%010000d' 1\n")
    script.chmod(0o700)
    configuration = settings()
    configuration.adb_executable = str(script)
    configuration.dynamic_max_output_bytes = 4096
    lab = AdbLab(configuration, DEVICE)
    lab.deadline = time.monotonic() + 5
    with pytest.raises(LabError, match="dynamic_output_limit"):
        lab._run("shell", "getprop", "ro.kernel.qemu")
    lab.should_cancel = lambda: True
    with pytest.raises(LabCancelled):
        lab._run("shell", "getprop", "ro.kernel.qemu")


def test_optional_boot_name_still_requires_exact_emulator_console_identity():
    lab = SimulatedAdb()
    original = lab._run

    def old_android(*args, **kwargs):
        if args == ("shell", "getprop", "ro.boot.qemu.avd_name"):
            return ""
        return original(*args, **kwargs)

    lab._run = old_android
    assert run(lab)["requires_review"]
    wrong = SimulatedAdb()
    other_original = wrong._run

    def foreign_console(*args, **kwargs):
        if args == ("emu", "avd", "name"):
            return "Personal_AVD\nOK"
        return other_original(*args, **kwargs)

    wrong._run = foreign_console
    with pytest.raises(LabError, match="device_identity_invalid"):
        run(wrong)
    assert not any(args[0] in {"root", "install", "uninstall"} for args, _ in wrong.calls)


def test_actual_subprocess_wall_deadline_has_independent_watchdog(tmp_path):
    import time

    script = tmp_path / "sleeping-adb"
    script.write_text("#!/bin/sh\nsleep 5\n")
    script.chmod(0o700)
    configuration = settings()
    configuration.adb_executable = str(script)
    lab = AdbLab(configuration, DEVICE)
    lab.deadline = time.monotonic() + 0.1
    start = time.monotonic()
    with pytest.raises(LabError, match="dynamic_timeout"):
        lab._run("shell", "getprop", "ro.kernel.qemu")
    assert time.monotonic() - start < 1


@pytest.mark.parametrize("uid", ["0", "1000", "2000", "9999", "20000", "1010050"])
def test_privileged_or_other_user_application_uid_is_never_launched(uid):
    lab = SimulatedAdb()
    original = lab._run

    def wrong_uid(*args, **kwargs):
        if args == ("shell", "cmd", "package", "list", "packages", "-U", "test.app"):
            return "package:test.app uid:" + uid
        return original(*args, **kwargs)

    lab._run = wrong_uid
    with pytest.raises(LabError, match="package_uid_invalid"):
        run(lab)
    assert not lab.installed
    assert not any(args[:3] == ("shell", "am", "start") for args, _ in lab.calls)
