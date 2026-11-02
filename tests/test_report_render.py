"""The PDF deadline kills actual work and budgets both process and output."""

import os
import sys
import time

import pytest

from droidshield import report_render


def test_pdf_deadline_kills_and_reaps_actual_child(monkeypatch):
    processes = []
    popen = report_render.subprocess.Popen

    def capture(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(report_render.subprocess, "Popen", capture)
    monkeypatch.setattr(
        report_render,
        "_command",
        lambda: [
            sys.executable,
            "-I",
            "-c",
            "import sys,time; sys.stdin.buffer.read(); time.sleep(60)",
        ],
    )
    started = time.monotonic()
    with pytest.raises(report_render.RenderError, match="report_render_timeout"):
        report_render.render(b"{}", wall_seconds=0.2)
    assert time.monotonic() - started < 3
    assert len(processes) == 1 and processes[0].poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(processes[0].pid, 0)


def test_pdf_output_budget_stops_flooding_process(monkeypatch):
    monkeypatch.setattr(report_render, "MAX_OUTPUT", 65536)
    monkeypatch.setattr(
        report_render,
        "_command",
        lambda: [
            sys.executable,
            "-I",
            "-c",
            "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'%PDF-'+b'x'*2000000); sys.stdout.buffer.flush()",
        ],
    )
    with pytest.raises(report_render.RenderError, match="report_output_limit"):
        report_render.render(b"{}", wall_seconds=2)


def test_pdf_capacity_refuses_to_start_additional_work(monkeypatch):
    monkeypatch.setattr(report_render, "_command", lambda: pytest.fail("must not start a child"))
    assert report_render._CAPACITY.acquire(blocking=False)
    assert report_render._CAPACITY.acquire(blocking=False)
    try:
        with pytest.raises(report_render.RenderError, match="report_render_busy"):
            report_render.render(b"{}")
    finally:
        report_render._CAPACITY.release()
        report_render._CAPACITY.release()


def test_pdf_renderer_clears_secret_environment_and_does_not_use_shell(monkeypatch):
    monkeypatch.setenv("DROIDSHIELD_QA_SECRET", "never-forward-this-secret")
    monkeypatch.setattr(
        report_render,
        "_command",
        lambda: [
            sys.executable,
            "-I",
            "-c",
            "import os,sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'%PDF-'+str(os.environ.get('DROIDSHIELD_QA_SECRET')).encode())",
        ],
    )
    assert report_render.render(b"{}") == b"%PDF-None"


def test_pdf_fixed_helper_sets_resource_budgets(monkeypatch):
    script = "import json,resource; import droidshield.report_pdf as p; p.render_pdf=lambda data:b'%PDF-'+json.dumps({key:resource.getrlimit(getattr(resource,'RLIMIT_'+key)) for key in ('AS','CPU','FSIZE','NOFILE','CORE')}).encode(); from droidshield.report_helper import main; raise SystemExit(main())"
    monkeypatch.setattr(report_render, "_command", lambda: [sys.executable, "-I", "-c", script])
    content = report_render.render(b"{}")
    assert b'"AS": [536870912, 536870912]' in content
    assert b'"CPU": [20, 21]' in content
    assert b'"FSIZE": [16777216, 16777216]' in content
    assert b'"NOFILE": [64, 64]' in content
    assert b'"CORE": [0, 0]' in content
