"""Independent PDF process budgets; no thread timeout leaves rendering alive."""

import os
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time

MAX_INPUT = 8 * 1024**2
MAX_OUTPUT = 16 * 1024**2
_CAPACITY = threading.BoundedSemaphore(2)


class RenderError(Exception):
    pass


def _command():
    return [sys.executable, "-I", "-m", "droidshield.report_helper"]


def _kill(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def render(encoded: bytes, *, wall_seconds: float = 30) -> bytes:
    if len(encoded) > MAX_INPUT:
        raise RenderError("report_input_limit")
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RenderError("unprivileged_renderer_required")
    if not _CAPACITY.acquire(blocking=False):
        raise RenderError("report_render_busy")
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="droidshield-report-") as directory:
            process = subprocess.Popen(
                _command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=directory,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
                start_new_session=True,
                close_fds=True,
            )
            deadline = time.monotonic() + wall_seconds
            for pipe in (process.stdin, process.stdout):
                os.set_blocking(pipe.fileno(), False)
            remaining = memoryview(encoded)
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE, "input")
                selector.register(process.stdout, selectors.EVENT_READ, "output")
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise RenderError("report_render_timeout")
                    for key, _ in selector.select(
                        timeout=min(0.1, max(0, deadline - time.monotonic()))
                    ):
                        if key.data == "input":
                            try:
                                count = os.write(key.fd, remaining[:65536])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                raise RenderError("report_render_failed") from None
                            remaining = remaining[count:]
                            if not remaining:
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            try:
                                chunk = os.read(key.fd, 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(process.stdout)
                                continue
                            output.extend(chunk)
                            if len(output) > MAX_OUTPUT:
                                raise RenderError("report_output_limit")
            try:
                status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise RenderError("report_render_timeout") from None
            if status != 0 or not output.startswith(b"%PDF-"):
                raise RenderError("report_render_failed")
            return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RenderError("report_render_unavailable") from exc
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    _kill(process)
                for pipe in (process.stdin, process.stdout):
                    if pipe is not None and not pipe.closed:
                        pipe.close()
        finally:
            _CAPACITY.release()
