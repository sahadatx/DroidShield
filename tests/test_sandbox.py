import json
import os
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from droidshield.sandbox import Sandbox, SandboxCancelled, SandboxError
from tests.apk_factory import write_apk


def sandbox_settings(**updates):
    values = dict(
        sandbox_executable="/usr/bin/bwrap",
        sandbox_python="/usr/bin/python3",
        analysis_timeout_seconds=5,
        analysis_cpu_seconds=3,
        analysis_memory_mb=256,
        analysis_output_bytes=1048576,
        apk_max_entries=10000,
        apk_max_uncompressed_bytes=512 * 1024 * 1024,
        apk_max_manifest_bytes=4 * 1024 * 1024,
        apk_max_compression_ratio=100,
        max_apk_bytes=100 * 1024 * 1024,
    )
    values.update(updates)
    return SimpleNamespace(**values)


@pytest.fixture
def real_sandbox(tmp_path):
    sandbox = Sandbox(sandbox_settings())
    path = write_apk(tmp_path / "app.apk")
    try:
        sandbox.run(path)
    except SandboxError as exc:
        if exc.code == "isolation_unavailable":
            pytest.skip("Linux bubblewrap user/network/PID isolation is unavailable")
        raise
    return sandbox, path


def probe_engine(tmp_path, sandbox, code):
    probe = tmp_path / "trusted_probe.py"
    probe.write_text(code)
    sandbox._engine_path = probe


def test_real_sandbox_inspects_and_analyzes_binary_apk(real_sandbox):
    sandbox, path = real_sandbox
    write_apk(path, debuggable=True)
    result = sandbox.run(path, mode="analyze")
    assert result["metadata"]["package_name"] == "com.example.app"
    assert result["indicators"][0]["rule_id"] == "MANIFEST_DEBUGGABLE"


def test_runtime_mounts_expose_libraries_and_single_python_file_only(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    settings = sandbox_settings()
    command = Sandbox(settings)._command(3, "inspect")
    mounts = [
        tuple(command[index + 1 : index + 3])
        for index, argument in enumerate(command)
        if argument == "--ro-bind"
    ]
    assert (str(Path(settings.sandbox_python).resolve()), settings.sandbox_python) in mounts
    libraries = {"/usr/lib", "/usr/lib64", "/lib", "/lib64"}
    for source, destination in mounts:
        assert source not in {
            "/usr",
            "/usr/src",
            "/usr/share",
            "/usr/local",
            "/usr/local/share",
            "/usr/etc",
        }
        if Path(source).is_dir():
            assert source in libraries and source == destination
    assert ("/usr/local/lib", "/usr/local/lib") not in mounts
    assert command[command.index("--remount-ro") + 1] == "/"


def test_sandbox_hides_host_files_environment_and_network(real_sandbox, tmp_path, monkeypatch):
    sandbox, path = real_sandbox
    result = sandbox.run(path)
    sentinel = tmp_path / "host-secret.txt"
    sentinel.write_text("database password must not be visible")
    monkeypatch.setenv("DROIDSHIELD_TEST_SECRET", "must not be inherited")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        probe_engine(
            tmp_path,
            sandbox,
            f"""import os, resource, socket, json
assert not os.path.exists({str(sentinel)!r})
assert not os.path.exists('/home/kali/Projects/DroidShield')
assert not os.path.exists('/etc/passwd')
assert not os.path.exists('/usr/src')
assert not os.path.exists('/usr/share')
assert not os.path.exists('/usr/local/share')
assert not os.path.exists('/usr/local/lib')
assert not os.path.exists('/usr/etc')
assert 'DROIDSHIELD_TEST_SECRET' not in os.environ
assert resource.getrlimit(resource.RLIMIT_CPU) == (3,3)
assert resource.getrlimit(resource.RLIMIT_AS) == (268435456,268435456)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (32,32)
assert resource.getrlimit(resource.RLIMIT_NPROC) == (1,1)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0,0)
assert os.getuid() != 0
try:
    child = os.fork()
except OSError:
    pass
else:
    if child == 0:
        os._exit(0)
    os.waitpid(child,0)
    raise AssertionError('fork must be limited')
try:
    open('/input/app.apk','wb')
except OSError:
    pass
else:
    raise AssertionError('input must be read only')
try:
    open('/usr/sandbox-must-not-write','wb')
except OSError:
    pass
else:
    raise AssertionError('runtime must be read only')
connection=socket.socket()
connection.settimeout(0.2)
try:
    connection.connect(('127.0.0.1',{port}))
except OSError:
    pass
else:
    raise AssertionError('host network reachable')
assert os.getpid() < 10
print({json.dumps(result)!r})
""",
        )
        assert sandbox.run(path) == result


def test_timeout_and_cancellation_kill_sandbox(real_sandbox, tmp_path):
    sandbox, path = real_sandbox
    sandbox.settings.analysis_timeout_seconds = 0.2
    probe_engine(tmp_path, sandbox, "import time\ntime.sleep(30)\n")
    started = time.monotonic()
    with pytest.raises(SandboxError, match="time limit") as error:
        sandbox.run(path)
    assert error.value.code == "analysis_timeout"
    assert time.monotonic() - started < 3
    sandbox.settings.analysis_timeout_seconds = 5
    checks = 0

    def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 3

    with pytest.raises(SandboxCancelled):
        sandbox.run(path, should_cancel=cancelled)
    assert checks == 3


def test_watchdog_kills_child_while_revalidation_is_blocked(real_sandbox, tmp_path, monkeypatch):
    sandbox, path = real_sandbox
    sandbox.settings.analysis_timeout_seconds = 0.2
    probe_engine(tmp_path, sandbox, "import time\ntime.sleep(1)\nprint('late output')\n")
    entered, release, killed = threading.Event(), threading.Event(), threading.Event()
    checks, errors, processes, kill_times = 0, [], [], []
    original_kill = sandbox._kill

    def observed_kill(process):
        kill_times.append(time.monotonic())
        original_kill(process)
        processes.append(process)
        killed.set()

    def blocking_check():
        nonlocal checks
        checks += 1
        if checks == 2:
            entered.set()
            release.wait(timeout=1.5)
        return False

    def run():
        try:
            sandbox.run(path, should_cancel=blocking_check)
        except SandboxError as exc:
            errors.append(exc.code)

    monkeypatch.setattr(sandbox, "_kill", observed_kill)
    caller = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    caller.start()
    try:
        assert entered.wait(timeout=0.5)
        assert killed.wait(timeout=0.7)
        assert caller.is_alive()  # Database callback has not returned yet.
        assert all(process.poll() is not None for process in processes)
        assert kill_times[0] - started < 0.8
    finally:
        release.set()
        caller.join(timeout=1)
    assert not caller.is_alive()
    assert errors == ["analysis_timeout"]


def test_output_cap_counts_stderr_and_stdout(real_sandbox, tmp_path):
    sandbox, path = real_sandbox
    sandbox.settings.analysis_output_bytes = 1024
    probe_engine(tmp_path, sandbox, "import os\nos.write(2,b'SECRET'*10000)\n")
    with pytest.raises(SandboxError) as error:
        sandbox.run(path)
    assert error.value.code == "analysis_output_limit"
    assert "SECRET" not in str(error.value)


def test_cpu_and_memory_exhaustion_are_contained(real_sandbox, tmp_path):
    sandbox, path = real_sandbox
    sandbox.settings.analysis_cpu_seconds = 1
    started = time.monotonic()
    probe_engine(tmp_path, sandbox, "while True:\n    pass\n")
    with pytest.raises(SandboxError) as error:
        sandbox.run(path)
    assert error.value.code == "analysis_failed"
    assert time.monotonic() - started < 4
    sandbox.settings.analysis_memory_mb = 64
    probe_engine(tmp_path, sandbox, "memory = bytearray(512 * 1024 * 1024)\n")
    with pytest.raises(SandboxError) as error:
        sandbox.run(path)
    assert error.value.code == "analysis_failed"
    assert "MemoryError" not in str(error.value)


def test_malformed_engine_output_rejected(real_sandbox, tmp_path):
    sandbox, path = real_sandbox
    probe_engine(tmp_path, sandbox, 'print(\'{"secret":"do not expose"}\')\n')
    with pytest.raises(SandboxError) as error:
        sandbox.run(path)
    assert error.value.code == "invalid_analysis_result"
    assert "do not expose" not in str(error.value)


def test_missing_or_nonfunctional_isolation_fails_closed(tmp_path):
    path = write_apk(tmp_path / "app.apk")
    for executable in ("/nonexistent/bwrap", "/usr/bin/false"):
        sandbox = Sandbox(sandbox_settings(sandbox_executable=executable))
        with pytest.raises(SandboxError) as error:
            sandbox.run(path)
        assert error.value.code == "isolation_unavailable"


@pytest.mark.parametrize("identity", ["getuid", "geteuid"])
def test_root_identity_fails_closed(tmp_path, monkeypatch, identity):
    path = write_apk(tmp_path / "app.apk")
    monkeypatch.setattr(os, identity, lambda: 0)
    with pytest.raises(SandboxError) as error:
        Sandbox(sandbox_settings()).run(path)
    assert error.value.code == "isolation_unavailable"


def test_input_symlink_and_nonregular_file_rejected(tmp_path):
    path = write_apk(tmp_path / "app.apk")
    link = tmp_path / "link.apk"
    link.symlink_to(path)
    sandbox = Sandbox(sandbox_settings())
    with pytest.raises(SandboxError) as error:
        sandbox.run(link)
    assert error.value.code == "invalid_apk"
    with pytest.raises(SandboxError):
        sandbox.run(Path(tmp_path))
    fifo = tmp_path / "pipe.apk"
    os.mkfifo(fifo)
    with pytest.raises(SandboxError):
        sandbox.run(fifo)


def test_pre_cancelled_work_does_not_launch(tmp_path):
    sandbox = Sandbox(sandbox_settings(sandbox_executable="/nonexistent/bwrap"))
    with pytest.raises(SandboxCancelled):
        sandbox.run(tmp_path / "absent.apk", should_cancel=lambda: True)
