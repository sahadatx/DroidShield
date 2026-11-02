"""Pinned Frida observation for one APK on a leased offline disposable emulator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path

from pydantic import ValidationError

from droidshield.lab import AdbLab, FridaObservation, LabCancelled, LabError

SERVER_PATH = "/data/local/tmp/droidshield-frida-server"
SOCKET_ADDRESS = "unix:/data/local/tmp/droidshield-frida.sock"
FORWARD_TARGET = "localabstract:/data/local/tmp/droidshield-frida.sock"
FRIDA_LIMITATIONS = [
    "Offline disposable emulator only; application network egress remains denied.",
    "Fixed native API invocation counters only; no arguments, return values or memory contents retained.",
    "Only the launched application process is instrumented; Java, child processes and bypass testing are outside coverage.",
    "Runtime observations require analyst review and do not confirm vulnerabilities.",
]


def configuration(settings):
    version = getattr(settings, "frida_version", "17.9.10")
    digest = getattr(settings, "frida_server_sha256", None)
    executable = Path(getattr(settings, "frida_python", ""))
    duration = getattr(settings, "frida_observation_seconds", 3)
    secret = getattr(settings, "frida_token", None)
    token = (
        secret.get_secret_value()
        if secret is not None and hasattr(secret, "get_secret_value")
        else ""
    )
    if (
        not isinstance(version, str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not executable.is_absolute()
        or not executable.is_file()
        or isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 1 <= duration <= 10
        or not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token)
    ):
        raise LabError("frida_unavailable")
    return {
        "version": version,
        "server_sha256": digest,
        "python": str(executable),
        "duration": duration,
        "token_fingerprint": hashlib.sha256(token.encode()).hexdigest(),
    }


class FridaLab(AdbLab):
    scenarios = frozenset({"frida_observe"})

    def __init__(self, settings, device):
        super().__init__(settings, device)
        self.forward_port = None
        self.frida_configuration = None

    def _limitations(self, scenario):
        return list(FRIDA_LIMITATIONS)

    def _prepare_observer(self, package, scenario):
        configuration_value = configuration(self.settings)
        self.frida_configuration = configuration_value
        mounts = self._run("shell", "cat", "/proc/mounts").splitlines()
        proc_options = [
            line.split()[3].split(",")
            for line in mounts
            if len(line.split()) >= 4 and line.split()[1:3] == ["/proc", "proc"]
        ]
        if len(proc_options) != 1 or "hidepid=2" not in proc_options[0]:
            raise LabError("frida_process_isolation_invalid")
        if self._run("shell", "readlink", "-f", SERVER_PATH) != SERVER_PATH:
            raise LabError("frida_server_invalid")
        if self._run("shell", "stat", "-c", "%u:%a", SERVER_PATH) not in {"0:500", "0:700"}:
            raise LabError("frida_server_invalid")
        digest = self._run("shell", "sha256sum", SERVER_PATH).split()
        if digest != [configuration_value["server_sha256"], SERVER_PATH]:
            raise LabError("frida_server_invalid")
        if self._run("shell", SERVER_PATH, "--version") != configuration_value["version"]:
            raise LabError("frida_version_mismatch")
        pid = self._run("shell", "pidof", SERVER_PATH)
        if not re.fullmatch(r"[1-9][0-9]{0,8}", pid):
            raise LabError("frida_server_invalid")
        if self._run("shell", "readlink", "/proc/" + pid + "/exe") != SERVER_PATH:
            raise LabError("frida_server_invalid")
        command = self._run("shell", "cat", "/proc/" + pid + "/cmdline").split("\x00")
        while command and command[-1] == "":
            command.pop()
        if command not in (
            [
                SERVER_PATH,
                "-l",
                SOCKET_ADDRESS,
                "--token=" + self.settings.frida_token.get_secret_value(),
            ],
            [
                SERVER_PATH,
                "--listen=" + SOCKET_ADDRESS,
                "--token=" + self.settings.frida_token.get_secret_value(),
            ],
        ):
            raise LabError("frida_server_invalid")
        # ADB's tcp:0 allocates a fresh owned forward; never replace a preexisting one.
        port = self._run("forward", "--no-rebind", "tcp:0", FORWARD_TARGET)
        if not re.fullmatch(r"[0-9]{4,5}", port) or not 1024 <= int(port) <= 65535:
            raise LabError("frida_forward_failed")
        self.forward_port = int(port)

    def _helper(self, package):
        configuration_value = self.frida_configuration
        executable = configuration_value["python"]
        if os.getuid() == 0 or os.geteuid() == 0 or self.forward_port is None:
            raise LabError("frida_unavailable")
        remaining = min(25, self.deadline - time.monotonic())
        if remaining <= 0:
            raise LabError("dynamic_timeout")
        command = [
            executable,
            "-I",
            str(Path(__file__).with_name("frida_helper.py")),
            str(self.forward_port),
            package,
            configuration_value["version"],
            str(configuration_value["duration"]),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={key: value for key, value in os.environ.items() if key in {"HOME", "PATH"}},
            )
        except OSError as exc:
            raise LabError("frida_unavailable") from exc
        try:
            process.stdin.write(self.settings.frida_token.get_secret_value().encode())
            process.stdin.close()
        except OSError:
            try:
                process.stdin.close()
            except OSError:
                pass
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            process.stdout.close()
            raise LabError("frida_execution_failed") from None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        expired = threading.Event()

        def stop():
            expired.set()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        timer = threading.Timer(remaining, stop)
        timer.daemon = True
        timer.start()
        output = bytearray()
        try:
            while selector.get_map():
                if expired.is_set():
                    raise LabError("dynamic_timeout")
                if self.should_cancel():
                    raise LabCancelled()
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > 4096:
                        raise LabError("frida_output_invalid")
            process.wait(timeout=2)
            if expired.is_set():
                raise LabError("dynamic_timeout")
            if process.returncode != 0:
                raise LabError("frida_execution_failed")
            try:
                result = FridaObservation.model_validate(json.loads(output)).model_dump(mode="json")
            except (ValueError, ValidationError) as exc:
                raise LabError("frida_output_invalid") from exc
            if result["version"] != configuration_value["version"]:
                raise LabError("frida_version_mismatch")
            return result
        finally:
            timer.cancel()
            selector.close()
            stop()
            process.wait(timeout=2)
            process.stdout.close()

    def _observe(self, package, scenario):
        result = self._helper(package)
        pid = self._run("shell", "pidof", package, allow_failure=True)
        if not re.fullmatch(r"[1-9][0-9]{0,8}", pid):
            raise LabError("app_launch_failed")
        return True, [], 0, {"frida": result}

    def _cleanup_observer(self):
        if self.forward_port is None:
            return
        if not self.owns_device():
            raise LabError("device_lease_lost")
        # Check ownership of the exact mapping before removing it. Never --remove-all.
        entries = self._run("forward", "--list", cleanup=True).splitlines()
        expected = f"{self.device['serial']} tcp:{self.forward_port} {FORWARD_TARGET}"
        if expected not in entries:
            raise LabError("frida_forward_lost")
        self._run("forward", "--remove", f"tcp:{self.forward_port}", cleanup=True)
        self.forward_port = None
