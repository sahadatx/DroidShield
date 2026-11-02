"""Narrow trusted ADB adapter for explicitly configured disposable emulators.

No caller-supplied command, shell text, serial or host path is accepted. APK code
runs only after offline guest firewall policy has been installed and verified.
Raw Android output is transient and never becomes evidence, errors or logs.
"""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from droidshield.proxy_contract import PROXY_LIMITATIONS, ProxySummary

ENGINE_VERSION = "droidshield-adb-offline-1"
PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
COMPONENT = re.compile(r"[A-Za-z][A-Za-z0-9_.]*/[A-Za-z.][A-Za-z0-9_.]*")
LIMITATIONS = [
    "Offline disposable emulator only; no API, TLS or traffic testing.",
    "Package inspection and optional launcher observation only; no Frida or exploit execution.",
    "Logs are discarded; only fixed exception categories and counts are retained.",
    "Runtime observations require analyst review and do not confirm vulnerabilities.",
]


class LabError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class LabCancelled(LabError):
    def __init__(self):
        super().__init__("execution_cancelled")


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: Literal[
        "device_identity",
        "offline_firewall",
        "apk_installed",
        "package_inspected",
        "app_launched",
        "cleanup",
    ]
    status: Literal["pass", "not_run"]


class FridaCounters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    filesystem_open: int = Field(ge=0, le=1_000_000)
    socket_connect: int = Field(ge=0, le=1_000_000)
    dns_lookup: int = Field(ge=0, le=1_000_000)


class FridaObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=32)
    observation_seconds: int = Field(ge=1, le=10)
    hooked_apis: list[Literal["filesystem_open", "socket_connect", "dns_lookup"]] = Field(
        min_length=1, max_length=3
    )
    counters: FridaCounters

    @model_validator(mode="after")
    def consistent(self):
        if len(set(self.hooked_apis)) != len(self.hooked_apis):
            raise ValueError("Duplicate runtime hook category")
        if any(
            value and key not in self.hooked_apis
            for key, value in self.counters.model_dump().items()
        ):
            raise ValueError("Counter without a declared runtime hook")
        return self


class LabResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    engine_version: Literal[ENGINE_VERSION] = ENGINE_VERSION
    checks: list[Check] = Field(max_length=6)
    frida: FridaObservation | None = None
    traffic: ProxySummary | None = None
    pid_observed: bool
    exception_categories: list[
        Literal[
            "SecurityException",
            "SQLiteException",
            "SSLException",
            "NullPointerException",
            "IllegalStateException",
        ]
    ] = Field(max_length=5)
    exception_count: int = Field(ge=0, le=10000)
    requires_review: Literal[True] = True
    limitations: list[str] = Field(max_length=8)

    @model_validator(mode="after")
    def consistent(self):
        if self.frida is not None and self.traffic is not None:
            raise ValueError("Runtime engines have distinct output contracts")
        expected = LIMITATIONS
        if self.frida is not None:
            from droidshield.frida_runtime import FRIDA_LIMITATIONS

            expected = FRIDA_LIMITATIONS
        elif self.traffic is not None:
            expected = PROXY_LIMITATIONS
        if self.limitations != expected:
            raise ValueError("Unexpected runtime limitations")
        if [item.name for item in self.checks] != [
            "device_identity",
            "offline_firewall",
            "apk_installed",
            "package_inspected",
            "app_launched",
            "cleanup",
        ] or any(item.status != "pass" for item in self.checks if item.name != "app_launched"):
            raise ValueError("Incomplete successful runtime checks")
        if self.pid_observed and self.checks[4].status != "pass":
            raise ValueError("Inconsistent launch observation")
        return self


def configured_devices(settings) -> list[dict]:
    """Fail closed on ambiguous/untrusted configuration; never autodiscover targets."""
    devices = []
    seen_ids, seen_serials = set(), set()
    for item in settings.lab_devices:
        if not isinstance(item, dict):
            raise LabError("lab_configuration_invalid")
        device = {
            key: item.get(key) for key in ("id", "label", "serial", "avd_name", "android_version")
        }
        if (
            not all(isinstance(value, str) and 0 < len(value) <= 128 for value in device.values())
            or not re.fullmatch(r"[A-Za-z0-9_-]+", device["id"])
            or not re.fullmatch(r"emulator-[0-9]{4,5}", device["serial"])
            or not re.fullmatch(r"DroidShield_[A-Za-z0-9_]+", device["avd_name"])
            or device["id"] in seen_ids
            or device["serial"] in seen_serials
        ):
            raise LabError("lab_configuration_invalid")
        seen_ids.add(device["id"])
        seen_serials.add(device["serial"])
        devices.append(device)
    return devices


class AdbLab:
    def __init__(self, settings, device: dict):
        self.settings = settings
        self.device = device
        self.deadline = 0.0
        self.should_cancel: Callable[[], bool] = lambda: False
        self.output_used = 0
        self.cleanup_deadline = 0.0
        self.owns_device: Callable[[], bool] = lambda: False

    def _run(self, *args: str, cleanup: bool = False, allow_failure: bool = False) -> str:
        executable = Path(self.settings.adb_executable)
        if (
            os.getuid() == 0
            or os.geteuid() == 0
            or not executable.is_absolute()
            or not executable.is_file()
        ):
            raise LabError("lab_unavailable")
        if not cleanup and self.should_cancel():
            raise LabCancelled()
        if cleanup:
            if time.monotonic() >= self.cleanup_deadline:
                raise LabError("dynamic_timeout")
            if not self.owns_device():
                raise LabError("device_lease_lost")
            if time.monotonic() >= self.cleanup_deadline:
                raise LabError("dynamic_timeout")
        remaining = (
            min(10, self.cleanup_deadline - time.monotonic())
            if cleanup
            else min(15, self.deadline - time.monotonic())
        )
        if remaining <= 0:
            raise LabError("dynamic_timeout")
        # ADB constructs a guest shell command: every dynamic argument is strictly
        # checked before reaching this boundary. No general-purpose shell API exists.
        command = [str(executable), "-s", self.device["serial"], *args]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key in {"HOME", "PATH", "ANDROID_ADB_SERVER_PORT"}
                },
            )
        except OSError as exc:
            raise LabError("lab_unavailable") from exc
        output = bytearray()
        stop = time.monotonic() + remaining
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        timed_out = threading.Event()

        def watchdog():
            # A slow control-database callback must not extend an ADB command's
            # independent deadline. Only this command's process group is killed.
            timed_out.set()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        timer = threading.Timer(remaining, watchdog)
        timer.daemon = True
        timer.start()
        try:
            while selector.get_map():
                if timed_out.is_set():
                    raise LabError("dynamic_timeout")
                if cleanup:
                    if time.monotonic() >= self.cleanup_deadline:
                        raise LabError("dynamic_timeout")
                    if not self.owns_device():
                        raise LabError("device_lease_lost")
                    if timed_out.is_set() or time.monotonic() >= stop:
                        raise LabError("dynamic_timeout")
                if not cleanup and self.should_cancel():
                    raise LabCancelled()
                if time.monotonic() >= stop:
                    raise LabError("dynamic_timeout")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > self.settings.dynamic_max_output_bytes or (
                        not cleanup
                        and self.output_used + len(output) > self.settings.dynamic_max_output_bytes
                    ):
                        raise LabError("dynamic_output_limit")
            process.wait(timeout=max(0.1, stop - time.monotonic()))
            if timed_out.is_set():
                raise LabError("dynamic_timeout")
            if process.returncode != 0 and not allow_failure:
                raise LabError("lab_command_failed")
            if not cleanup:
                self.output_used += len(output)
            return output.decode("utf-8", errors="replace").strip()
        finally:
            timer.cancel()
            selector.close()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            process.stdout.close()

    def _identity(self, *, cleanup=False):
        for prop, expected in (("ro.kernel.qemu", "1"), ("sys.boot_completed", "1")):
            if self._run("shell", "getprop", prop, cleanup=cleanup) != expected:
                raise LabError("device_identity_invalid")
        # Android 11 images do not consistently expose ro.boot.qemu.avd_name.
        # The emulator console itself must report the configured disposable AVD;
        # an exposed boot property must agree rather than override that identity.
        boot_name = self._run("shell", "getprop", "ro.boot.qemu.avd_name", cleanup=cleanup)
        console_name = self._run("emu", "avd", "name", cleanup=cleanup).splitlines()
        if (boot_name and boot_name != self.device["avd_name"]) or console_name != [
            self.device["avd_name"],
            "OK",
        ]:
            raise LabError("device_identity_invalid")

    def _app_uid(self, package):
        value = self._run("shell", "cmd", "package", "list", "packages", "-U", package)
        match = re.fullmatch(r"package:" + re.escape(package) + r" uid:([0-9]{1,6})", value)
        if not match or not 10000 <= int(match.group(1)) <= 19999:
            raise LabError("package_uid_invalid")
        return match.group(1)

    scenarios = frozenset({"launch_observe", "package_inspection"})

    def _limitations(self, scenario):
        return list(LIMITATIONS)

    def _prepare_observer(self, package, scenario):
        """Trusted extensions configure observation only after verified offline policy."""

    def _cleanup_observer(self):
        """Extensions release only resources created by this exact device lease."""

    def _observe(self, package, scenario):
        pid_observed, categories, count = False, [], 0
        if scenario == "launch_observe":
            component = self._run(
                "shell", "cmd", "package", "resolve-activity", "--brief", package
            ).splitlines()[-1]
            if not COMPONENT.fullmatch(component) or component.split("/")[0] != package:
                raise LabError("launcher_unavailable")
            launch = self._run("shell", "am", "start", "-W", "-n", component)
            if "Status: ok" not in launch:
                raise LabError("app_launch_failed")
            until = min(self.deadline, time.monotonic() + 2)
            while time.monotonic() < until:
                if self.should_cancel():
                    raise LabCancelled()
                time.sleep(0.1)
            pid = self._run("shell", "pidof", package, allow_failure=True)
            if re.fullmatch(r"[1-9][0-9]{0,8}", pid):
                pid_observed = True
                logs = self._run("logcat", "-d", "--pid=" + pid, "-t", "100", "*:E")
                for category in (
                    "SecurityException",
                    "SQLiteException",
                    "SSLException",
                    "NullPointerException",
                    "IllegalStateException",
                ):
                    found = len(re.findall(r"\b" + category + r"\b", logs))
                    if found:
                        categories.append(category)
                        count += found

        return pid_observed, categories, min(count, 10000), {}

    def run(
        self,
        path: Path,
        package: str,
        scenario: str,
        timeout: int,
        *,
        should_cancel: Callable[[], bool],
        owns_device: Callable[[], bool],
    ) -> dict:
        if not PACKAGE.fullmatch(package) or scenario not in self.scenarios:
            raise LabError("target_scope_invalid")
        if self.device not in configured_devices(self.settings):
            raise LabError("lab_configuration_invalid")
        self.deadline = time.monotonic() + timeout
        self.should_cancel = should_cancel
        self.owns_device = owns_device
        self.output_used = 0
        checks = []
        installed = False
        result = None
        try:
            self._identity()
            checks.append({"name": "device_identity", "status": "pass"})
            self._run("root")
            self._run("wait-for-device")
            if self._run("shell", "id", "-u") != "0":
                raise LabError("lab_isolation_unavailable")
            self._identity()
            # Do not flush existing rules or loosen policy during cleanup. ADB
            # emulator transport is outside the guest's application IP egress.
            self._run("shell", "svc", "wifi", "disable")
            self._run("shell", "svc", "data", "disable")
            for binary in ("iptables", "ip6tables"):
                self._run("shell", binary, "-P", "OUTPUT", "DROP")
                self._run("shell", binary, "-F", "OUTPUT")
                rules = self._run("shell", binary, "-S", "OUTPUT")
                if rules.strip() != "-P OUTPUT DROP":
                    raise LabError("lab_isolation_unavailable")
            checks.append({"name": "offline_firewall", "status": "pass"})
            self._prepare_observer(package, scenario)
            existing = self._run("shell", "pm", "path", package, allow_failure=True)
            if existing:
                raise LabError("package_already_installed")
            # From this point the exclusive device lease owns any installation of
            # this previously absent package, including a timed-out install.
            installed = True
            if "Success" not in self._run("install", "-t", str(Path(path).resolve())):
                raise LabError("apk_install_failed")
            checks.append({"name": "apk_installed", "status": "pass"})
            details = self._run("shell", "dumpsys", "package", package)
            if f"Package [{package}]" not in details:
                raise LabError("package_inspection_failed")
            # Root/system/shared privileged identities are never eligible to run
            # untrusted assessment code on this dedicated single-user emulator.
            self._app_uid(package)
            checks.append({"name": "package_inspected", "status": "pass"})
            pid_observed, categories, count, extra = self._observe(package, scenario)
            checks.append({"name": "app_launched", "status": "pass" if pid_observed else "not_run"})
            result = {
                "engine_version": ENGINE_VERSION,
                "checks": checks,
                "pid_observed": pid_observed,
                "exception_categories": categories,
                "exception_count": min(count, 10000),
                "requires_review": True,
                "limitations": self._limitations(scenario),
                **extra,
            }
        finally:
            observer_error = None
            try:
                self.cleanup_deadline = time.monotonic() + 20
                self._cleanup_observer()
            except Exception as exc:
                observer_error = exc
            if installed:
                # A worker whose device lease was lost may not touch a reused
                # device. It also cannot publish. Recovery quarantines the AVD.
                try:
                    owned = owns_device()
                except Exception as exc:
                    raise LabError("device_lease_lost") from exc
                if not owned:
                    raise LabError("device_lease_lost")
                try:
                    self.cleanup_deadline = time.monotonic() + 20
                    self._identity(cleanup=True)
                    self._run("shell", "am", "force-stop", package, cleanup=True)
                    removed = self._run("uninstall", package, cleanup=True, allow_failure=True)
                    remaining = self._run(
                        "shell", "pm", "path", package, cleanup=True, allow_failure=True
                    )
                    if remaining or ("Success" not in removed and "Unknown package" not in removed):
                        raise LabError("device_cleanup_failed")
                    checks.append({"name": "cleanup", "status": "pass"})
                except Exception as exc:
                    raise LabError("device_cleanup_failed") from exc
            if observer_error:
                raise LabError("device_cleanup_failed") from observer_error
        return LabResult.model_validate(result).model_dump(mode="json")
