"""Fail-closed Linux namespace launcher for untrusted APK processing."""

import json
import os
import selectors
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from droidshield.analysis_contract import AnalysisResult, DexAnalysisResult
from droidshield.apk_engine import analyze
from droidshield.mobile_contract import MobileIntakeResult

ERROR_MESSAGES = {
    "isolation_unavailable": "APK isolation is unavailable on this host",
    "invalid_apk": "The APK is malformed or unsupported",
    "analysis_timeout": "APK processing exceeded its time limit",
    "analysis_output_limit": "APK processing exceeded its output limit",
    "analysis_failed": "APK processing could not complete",
    "invalid_analysis_result": "APK processing returned an invalid result",
    "cancelled": "APK processing was cancelled",
}
LIMIT_WRAPPER = """import os, resource, sys
cpu, memory, output = map(int, sys.argv[1:4])
for limit, value in ((resource.RLIMIT_CPU,cpu),(resource.RLIMIT_AS,memory),
                     (resource.RLIMIT_FSIZE,output),(resource.RLIMIT_NOFILE,32),
                     (resource.RLIMIT_NPROC,1),(resource.RLIMIT_CORE,0)):
    resource.setrlimit(limit,(value,value))
os.execv(sys.executable,[sys.executable,'-I','-S',*sys.argv[4:]])
"""


class SandboxError(Exception):
    def __init__(self, code: str):
        self.code = code if code in ERROR_MESSAGES else "analysis_failed"
        super().__init__(ERROR_MESSAGES[self.code])


class SandboxCancelled(SandboxError):
    def __init__(self):
        super().__init__("cancelled")


class Sandbox:
    def __init__(self, settings):
        self.settings = settings
        self._engine_path = Path(__file__).with_name("apk_engine.py")
        self._dex_engine_path = Path(__file__).with_name("dex_engine.py")
        self._mobile_engine_path = Path(__file__).with_name("mobile_engine.py")

    def _command(self, input_fd: int, mode: str, engine: str = "manifest") -> list[str]:
        settings = self.settings
        executable = Path(settings.sandbox_executable)
        python = Path(settings.sandbox_python)
        # The runtime must reside under the explicitly exposed read-only runtime.
        if (
            os.getuid() == 0
            or os.geteuid() == 0
            or not executable.is_absolute()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or not python.is_absolute()
            or not python.is_file()
            or not os.access(python, os.X_OK)
            or not python.resolve().is_relative_to("/usr")
            or not self._engine_path.is_file()
            or (engine == "dex" and not self._dex_engine_path.is_file())
            or (engine in {"ipa", "aab"} and not self._mobile_engine_path.is_file())
        ):
            raise SandboxError("isolation_unavailable")
        command = [
            str(executable),
            "--unshare-all",
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
        ]
        # /usr/src and /usr/local/share commonly hold source, secrets or data.
        # Expose library runtimes and the single trusted interpreter file only.
        runtimes = ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
        if python.is_relative_to("/usr/local") or python.resolve().is_relative_to("/usr/local"):
            runtimes.append("/usr/local/lib")
        for runtime in runtimes:
            if Path(runtime).exists():
                command.extend(["--ro-bind", runtime, runtime])
        command.extend(["--ro-bind", str(python.resolve()), str(python)])
        command.extend(
            [
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                str(min(self.settings.analysis_memory_mb * 1024 * 1024, 32 * 1024 * 1024)),
                "--tmpfs",
                "/tmp",
                "--dir",
                "/input",
                "--dir",
                "/engine",
                "--ro-bind-fd",
                str(input_fd),
                "/input/app.apk",
                "--ro-bind",
                str(self._engine_path.resolve()),
                "/engine/apk_engine.py",
            ]
        )
        if engine == "dex":
            command.extend(
                ["--ro-bind", str(self._dex_engine_path.resolve()), "/engine/dex_engine.py"]
            )
        if engine in {"ipa", "aab"}:
            command.extend(
                ["--ro-bind", str(self._mobile_engine_path.resolve()), "/engine/mobile_engine.py"]
            )
        script = {
            "manifest": "/engine/apk_engine.py",
            "dex": "/engine/dex_engine.py",
            "ipa": "/engine/mobile_engine.py",
            "aab": "/engine/mobile_engine.py",
        }[engine]
        command.extend(
            [
                "--remount-ro",
                "/",
                "--clearenv",
                "--chdir",
                "/tmp",
                "--",
                str(python),
                "-I",
                "-S",
                "-c",
                LIMIT_WRAPPER,
                str(settings.analysis_cpu_seconds),
                str(settings.analysis_memory_mb * 1024 * 1024),
                str(settings.analysis_output_bytes),
                script,
                "--mode",
                mode,
                "--input",
                "/input/app.apk",
            ]
        )
        if engine in {"ipa", "aab"}:
            command.extend(["--format", engine])
        limits = {
            "max-bytes": settings.max_apk_bytes,
            "max-entries": settings.apk_max_entries,
            "max-uncompressed": settings.apk_max_uncompressed_bytes,
            "max-manifest": settings.apk_max_manifest_bytes,
            "max-ratio": settings.apk_max_compression_ratio,
            "cpu-seconds": settings.analysis_cpu_seconds,
            "memory-bytes": settings.analysis_memory_mb * 1024 * 1024,
            "output-bytes": settings.analysis_output_bytes,
        }
        if engine == "dex":
            limits.update(
                {
                    "dex-max-files": getattr(settings, "dex_max_files", 16),
                    "dex-max-bytes": getattr(settings, "dex_max_bytes", 64 * 1024 * 1024),
                    "dex-max-ids": getattr(settings, "dex_max_ids", 100_000),
                    "dex-max-code-units": getattr(settings, "dex_max_code_units", 4_000_000),
                }
            )
        for key, value in limits.items():
            command.extend(["--" + key, str(value)])
        return command

    @staticmethod
    def _kill(process: subprocess.Popen) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def run(
        self,
        path: Path | str,
        mode: str = "inspect",
        should_cancel: Callable[[], bool] | None = None,
        engine: str = "manifest",
    ) -> dict:
        if mode not in ("inspect", "analyze"):
            raise ValueError("Unknown analysis mode")
        if (
            engine not in ("manifest", "dex", "ipa", "aab")
            or (engine == "dex" and mode != "analyze")
            or (engine in {"ipa", "aab"} and mode != "inspect")
        ):
            raise ValueError("Unknown analysis engine or unsupported mode")
        if should_cancel is not None and should_cancel():
            raise SandboxCancelled()
        try:
            input_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as exc:
            raise SandboxError("invalid_apk") from exc
        try:
            file_stat = os.fstat(input_fd)
            if not stat.S_ISREG(file_stat.st_mode) or not (
                0 < file_stat.st_size <= self.settings.max_apk_bytes
            ):
                raise SandboxError("invalid_apk")
            command = self._command(input_fd, mode, engine)
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd="/",
                    env={},
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(input_fd,),
                )
            except OSError as exc:
                raise SandboxError("isolation_unavailable") from exc
        finally:
            os.close(input_fd)
        output = bytearray()
        stderr_prefix = bytearray()
        output_size = 0
        deadline = time.monotonic() + self.settings.analysis_timeout_seconds
        finished = threading.Event()
        expired = threading.Event()

        def expire() -> None:
            # Revalidation can block on a database lock. Enforce the subprocess
            # budget independently of the thread executing that callback.
            if not finished.is_set():
                expired.set()
                self._kill(process)

        watchdog = threading.Timer(max(0, deadline - time.monotonic()), expire)
        watchdog.daemon = True
        try:
            try:
                watchdog.start()
            except RuntimeError as exc:
                raise SandboxError("analysis_failed") from exc
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    if should_cancel is not None and should_cancel():
                        raise SandboxCancelled()
                    if expired.is_set() or time.monotonic() >= deadline:
                        raise SandboxError("analysis_timeout")
                    for key, _ in selector.select(timeout=0.1):
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        output_size += len(block)
                        if output_size > self.settings.analysis_output_bytes:
                            raise SandboxError("analysis_output_limit")
                        if key.fileobj is process.stdout:
                            output.extend(block)
                        elif len(stderr_prefix) < 256:
                            stderr_prefix.extend(block[: 256 - len(stderr_prefix)])
            return_code = process.wait(timeout=2)
            if should_cancel is not None and should_cancel():
                raise SandboxCancelled()
            if expired.is_set() or time.monotonic() >= deadline:
                raise SandboxError("analysis_timeout")
            if return_code != 0:
                # bwrap's setup failure returns 1; trusted parser rejection returns 2.
                code = "invalid_apk" if return_code == 2 else "analysis_failed"
                if (
                    return_code == 1
                    and not output
                    and (not stderr_prefix or stderr_prefix.startswith(b"bwrap:"))
                ):
                    code = "isolation_unavailable"
                raise SandboxError(code)
            try:
                contract = (
                    MobileIntakeResult
                    if engine in {"ipa", "aab"}
                    else DexAnalysisResult
                    if engine == "dex"
                    else AnalysisResult
                )
                result = contract.model_validate_json(bytes(output)).model_dump()
                if (
                    result["file_size"] != file_stat.st_size
                    or (mode == "inspect" and result["indicators"])
                    or (
                        engine == "manifest"
                        and mode == "analyze"
                        and result["indicators"] != analyze(result["metadata"])
                    )
                ):
                    raise ValueError("Unexpected result")
                if engine in {"ipa", "aab"} and result["metadata"]["artifact_format"] != engine:
                    raise ValueError("Unexpected artifact format")
            except (ValidationError, ValueError, json.JSONDecodeError) as exc:
                raise SandboxError("invalid_analysis_result") from exc
            return result
        finally:
            finished.set()
            watchdog.cancel()
            self._kill(process)
            if watchdog.ident is not None:
                watchdog.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
