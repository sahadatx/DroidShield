"""Trusted subprocess entry point. No script/endpoint/path is supplied by the API."""

from __future__ import annotations

import json
import re
import resource
import sys
import time
from pathlib import Path


def main():
    # These arguments come only from the trusted parent, and are checked again.
    if len(sys.argv) != 5:
        return 2
    _, port_text, package, version, observation = sys.argv
    if (
        not re.fullmatch(r"[0-9]{1,5}", port_text)
        or not 1024 <= int(port_text) <= 65535
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or not observation.isdecimal()
        or not 1 <= int(observation) <= 10
    ):
        return 2
    token_bytes = sys.stdin.buffer.read(129)
    if not re.fullmatch(rb"[A-Za-z0-9_-]{32,128}", token_bytes):
        return 2
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
    import frida

    if frida.__version__ != version:
        return 3
    device = frida.get_device_manager().add_remote_device(
        f"127.0.0.1:{port_text}", token=token_bytes.decode("ascii")
    )
    session, pid = None, None
    try:
        pid = device.spawn([package])
        session = device.attach(pid)
        script = session.create_script(Path(__file__).with_name("frida_agent.js").read_text())
        # Raw script/target errors and send() payloads are never serialized.
        script.load()
        device.resume(pid)
        time.sleep(int(observation))
        output = script.exports_sync.summary()
        output["observation_seconds"] = int(observation)
        sys.stdout.write(json.dumps(output, separators=(",", ":")))
        return 0
    except Exception:
        return 4
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        # The parent owns APK cleanup. Do not risk killing a reused PID here.


if __name__ == "__main__":
    raise SystemExit(main())
