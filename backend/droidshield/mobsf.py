"""Protected, bounded adapter for an administrator-provisioned MobSF 4.5.3 service.

The remote service is a separate trust boundary and must be isolated by deployment.
Only fixed sanitized categories and counts cross into DroidShield's result store.
"""

import asyncio
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from droidshield.analysis_contract import ContractModel, ManifestMetadata
from droidshield.sandbox import SandboxCancelled, SandboxError

MOBSF_ENGINE_VERSION = "droidshield-mobsf-1"
MOBSF_LIMITATIONS = [
    "Static results originate from an administrator-provisioned isolated MobSF 4.5.3 service; DroidShield does not launch application code.",
    "Candidates are aggregated by source category with fixed redacted narratives; original descriptions, source excerpts, paths and secret values are withheld.",
    "Tool failures are reported as incomplete analysis; empty candidate counts never establish that an application is secure.",
    "Scanner results require analyst verification; runtime behavior, exploitability and backend API authorization are not established.",
]
RULE_SOURCES = {
    "MOBSF_MANIFEST_REVIEW": "manifest_analysis",
    "MOBSF_CODE_REVIEW": "code_analysis",
    "MOBSF_CERTIFICATE_REVIEW": "certificate_analysis",
    "MOBSF_BINARY_REVIEW": "binary_analysis",
    "MOBSF_SECRET_REVIEW": "secrets",
    "MOBSF_INCOMPLETE_ANALYSIS": "logs",
}
TITLES = {
    "MOBSF_MANIFEST_REVIEW": "MobSF manifest candidates require review",
    "MOBSF_CODE_REVIEW": "MobSF code candidates require review",
    "MOBSF_CERTIFICATE_REVIEW": "MobSF certificate candidates require review",
    "MOBSF_BINARY_REVIEW": "MobSF binary candidates require review",
    "MOBSF_SECRET_REVIEW": "MobSF secret-like candidates require review (redacted)",
    "MOBSF_INCOMPLETE_ANALYSIS": "MobSF analysis is incomplete because a tool reported an error",
}
SEVERITIES = {
    "critical": "critical",
    "high": "high",
    "danger": "high",
    "warning": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "secure": None,
    "good": None,
}
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _indicator(rule, package, severity, count):
    return {
        "rule_id": rule,
        "severity": severity,
        "title": TITLES[rule],
        "affected_component": package,
        "description": "The isolated MobSF service reported candidates in the stated category. This is an aggregated scanner observation; raw service evidence is withheld and analyst verification is required.",
        "impact": "Impact depends on the actual application behavior, affected code and authorized assessment context; scanner severity does not establish exploitability.",
        "remediation": "Review the protected APK and the configured isolated service within the authorized scope, verify each candidate and apply context-appropriate remediation.",
        "reproduction_steps": "Re-run the pinned service against the same protected APK hash and review the stated result category in the authorized analysis environment.",
        "evidence": {
            "source": RULE_SOURCES[rule],
            "observed": "scanner_candidates",
            "reported_count": count,
        },
    }


class MobSFEvidence(ContractModel):
    source: Literal[
        "manifest_analysis",
        "code_analysis",
        "certificate_analysis",
        "binary_analysis",
        "secrets",
        "logs",
    ]
    observed: Literal["scanner_candidates"]
    reported_count: StrictInt = Field(ge=1, le=100_000)


class MobSFIndicator(ContractModel):
    rule_id: Literal[
        "MOBSF_MANIFEST_REVIEW",
        "MOBSF_CODE_REVIEW",
        "MOBSF_CERTIFICATE_REVIEW",
        "MOBSF_BINARY_REVIEW",
        "MOBSF_SECRET_REVIEW",
        "MOBSF_INCOMPLETE_ANALYSIS",
    ]
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str = Field(max_length=200)
    affected_component: str = Field(min_length=3, max_length=255)
    description: str = Field(max_length=2000)
    impact: str = Field(max_length=2000)
    remediation: str = Field(max_length=2000)
    reproduction_steps: str = Field(max_length=2000)
    evidence: MobSFEvidence

    @model_validator(mode="after")
    def fixed_content(self):
        if self.model_dump() != _indicator(
            self.rule_id, self.affected_component, self.severity, self.evidence.reported_count
        ):
            raise ValueError("Unexpected scanner indicator")
        if self.rule_id == "MOBSF_SECRET_REVIEW" and self.severity != "high":
            raise ValueError("Unexpected secret candidate severity")
        if self.rule_id == "MOBSF_INCOMPLETE_ANALYSIS" and self.severity != "info":
            raise ValueError("Unexpected incomplete analysis severity")
        return self


class MobSFSummary(ContractModel):
    service_version: Literal["4.5.3"]
    manifest_findings: StrictInt = Field(ge=0, le=100_000)
    code_findings: StrictInt = Field(ge=0, le=100_000)
    certificate_findings: StrictInt = Field(ge=0, le=100_000)
    binary_findings: StrictInt = Field(ge=0, le=100_000)
    secret_candidates: StrictInt = Field(ge=0, le=100_000)
    tool_error_count: StrictInt = Field(ge=0, le=100_000)
    analysis_complete: StrictBool


class MobSFAnalysisResult(ContractModel):
    schema_version: Literal[3]
    engine_version: Literal["droidshield-mobsf-1"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_size: StrictInt = Field(gt=0)
    metadata: ManifestMetadata
    indicators: list[MobSFIndicator] = Field(max_length=6)
    mobsf_summary: MobSFSummary
    limitations: list[str] = Field(min_length=4, max_length=4)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int or value != 3:
            raise ValueError("Unknown analysis protocol")
        return value

    @field_validator("limitations")
    @classmethod
    def fixed_limitations(cls, value):
        if value != MOBSF_LIMITATIONS:
            raise ValueError("Unknown limitations")
        return value

    @model_validator(mode="after")
    def consistent_summary(self):
        summary = self.mobsf_summary
        expected = dict(
            zip(
                RULE_SOURCES,
                [
                    summary.manifest_findings,
                    summary.code_findings,
                    summary.certificate_findings,
                    summary.binary_findings,
                    summary.secret_candidates,
                    summary.tool_error_count,
                ],
                strict=True,
            )
        )
        seen = set()
        for item in self.indicators:
            if (
                item.affected_component != self.metadata.package_name
                or item.rule_id in seen
                or item.evidence.reported_count != expected[item.rule_id]
            ):
                raise ValueError("Inconsistent scanner evidence")
            seen.add(item.rule_id)
        if seen != {
            rule for rule, count in expected.items() if count
        } or summary.analysis_complete != (summary.tool_error_count == 0):
            raise ValueError("Inconsistent scanner summary")
        return self


def validate_mobsf_result(value):
    return MobSFAnalysisResult.model_validate(value).model_dump()


def _checked(condition):
    if not condition:
        raise SandboxError("invalid_analysis_result")


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        _checked(key not in result)
        result[key] = value
    return result


def _normalize(report, metadata, digest, md5, size):
    _checked(
        isinstance(report, dict)
        and report.get("md5") == md5
        and report.get("sha256") == digest
        and report.get("package_name") == metadata["package_name"]
    )
    _checked(report.get("version") in ("4.5.3", "v4.5.3"))
    for source in ("manifest_analysis", "code_analysis", "certificate_analysis"):
        _checked(isinstance(report.get(source), dict))
    manifest = report["manifest_analysis"].get("manifest_findings")
    code = report["code_analysis"].get("findings")
    certificates = report["certificate_analysis"].get("certificate_findings")
    binaries, secrets, logs = (report.get(key) for key in ("binary_analysis", "secrets", "logs"))
    _checked(
        isinstance(manifest, list)
        and isinstance(code, dict)
        and isinstance(certificates, list)
        and isinstance(binaries, list)
        and isinstance(secrets, list)
        and isinstance(logs, list)
        and bool(logs)
    )
    _checked(
        all(
            len(group) <= 100_000
            for group in (manifest, code, certificates, binaries, secrets, logs)
        )
    )

    def severity(value):
        _checked(isinstance(value, str) and value.lower() in SEVERITIES)
        return SEVERITIES[value.lower()]

    groups = []
    for entries, kind in (
        (manifest, "manifest"),
        (list(code.values()), "code"),
        (certificates, "certificate"),
        (binaries, "binary"),
    ):
        levels = []
        for entry in entries:
            if kind == "binary" and isinstance(entry, dict) and "severity" not in entry:
                # ELF records group compiler-hardening checks under a library
                # name. Neither names nor descriptions cross this boundary.
                checks = {
                    "nx",
                    "pie",
                    "stack_canary",
                    "relocation_readonly",
                    "rpath",
                    "runpath",
                    "fortify",
                    "symbol",
                }
                _checked(
                    isinstance(entry.get("name"), str)
                    and bool(checks.intersection(entry))
                    and set(entry).issubset(checks | {"name"})
                )
                for check in checks.intersection(entry):
                    _checked(isinstance(entry[check], dict))
                    level = severity(entry[check].get("severity"))
                    if level:
                        levels.append(level)
                continue
            if kind == "certificate":
                _checked(isinstance(entry, list) and len(entry) == 3)
                raw = entry[0]
            else:
                _checked(isinstance(entry, dict))
                if kind == "code":
                    _checked(isinstance(entry.get("metadata"), dict))
                    raw = entry["metadata"].get("severity")
                else:
                    raw = entry.get("severity")
            level = severity(raw)
            if level:
                levels.append(level)
        groups.append(levels)
    tool_errors = 0
    for entry in logs:
        _checked(
            isinstance(entry, dict)
            and isinstance(entry.get("status"), str)
            and isinstance(entry.get("exception", ""), (str, type(None)))
        )
        status = entry["status"].lower()
        if entry.get("exception") or any(
            word in status for word in ("failed", "error", "timed out", "timeout")
        ):
            tool_errors += 1
    counts = [len(group) for group in groups] + [len(secrets), tool_errors]
    levels = [max(group, key=RANK.get) if group else "info" for group in groups] + ["high", "info"]
    indicators = [
        _indicator(rule, metadata["package_name"], level, count)
        for rule, count, level in zip(RULE_SOURCES, counts, levels, strict=True)
        if count
    ]
    return validate_mobsf_result(
        {
            "schema_version": 3,
            "engine_version": MOBSF_ENGINE_VERSION,
            "sha256": digest,
            "file_size": size,
            "metadata": metadata,
            "indicators": indicators,
            "limitations": MOBSF_LIMITATIONS,
            "mobsf_summary": dict(
                zip(
                    [
                        "manifest_findings",
                        "code_findings",
                        "certificate_findings",
                        "binary_findings",
                        "secret_candidates",
                        "tool_error_count",
                    ],
                    counts,
                    strict=True,
                ),
                service_version="4.5.3",
                analysis_complete=tool_errors == 0,
            ),
        }
    )


class _BoundedFile:
    """Pin multipart length even if a protected input is concurrently modified."""

    def __init__(self, source, size):
        self.source, self.size, self.position = source, size, 0

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset + (self.position if whence == 1 else self.size if whence == 2 else 0)
        _checked(whence in (0, 1, 2) and 0 <= position <= self.size)
        self.source.seek(position)
        self.position = position
        return position

    def read(self, size=-1):
        remaining = self.size - self.position
        if remaining == 0:
            if self.source.read(1):
                raise SandboxError("invalid_apk")
            return b""
        requested = remaining if size < 0 else min(remaining, size)
        result = self.source.read(requested)
        if not result and requested:
            raise SandboxError("invalid_apk")
        self.position += len(result)
        return result


class MobSF:
    def __init__(self, settings):
        self.settings = settings

    async def _request(self, client, route, **kwargs):
        limit = self.settings.mobsf_max_report_bytes
        async with client.stream(
            "POST", self.settings.mobsf_url.rstrip("/") + route, **kwargs
        ) as response:
            if response.status_code != 200:
                raise SandboxError("analysis_failed")
            _checked(
                response.headers.get("content-type", "").split(";", 1)[0].lower()
                == "application/json"
            )
            _checked(response.headers.get("content-encoding", "identity").lower() == "identity")
            declared = response.headers.get("content-length")
            _checked(declared is None or declared.isdecimal() and int(declared) <= limit)
            payload = bytearray()
            async for chunk in response.aiter_raw():
                _checked(len(payload) + len(chunk) <= limit)
                payload.extend(chunk)
            result = json.loads(
                payload,
                object_pairs_hook=_unique_json,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON")),
            )
            _checked(isinstance(result, dict) and "error" not in result)
            return result

    async def _workflow(self, source, metadata, digest, md5, size):
        key = self.settings.mobsf_api_key
        key = key.get_secret_value() if hasattr(key, "get_secret_value") else key
        async with httpx.AsyncClient(
            headers={
                "Authorization": key,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
            timeout=httpx.Timeout(
                min(self.settings.mobsf_timeout_seconds, 30),
                read=self.settings.mobsf_timeout_seconds,
            ),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            uploaded = await self._request(
                client,
                "/api/v1/upload",
                files={
                    "file": ("application.apk", source, "application/vnd.android.package-archive")
                },
            )
            _checked(
                uploaded.get("hash") == md5
                and uploaded.get("scan_type") == "apk"
                and uploaded.get("analyzer") == "static_analyzer"
            )
            scanned = await self._request(client, "/api/v1/scan", data={"hash": md5})
            _checked(
                scanned.get("md5") == md5
                and scanned.get("sha256") == digest
                and scanned.get("package_name") == metadata["package_name"]
            )
            report = await self._request(client, "/api/v1/report_json", data={"hash": md5})
            return _normalize(report, metadata, digest, md5, size)

    def run(self, path: Path | str, *, metadata: dict, should_cancel=None):
        """Run a bounded HTTP workflow; cancellation closes client I/O, not remote jobs."""
        settings = self.settings
        deadline = time.monotonic() + settings.mobsf_timeout_seconds
        url = getattr(settings, "mobsf_url", None)
        key = getattr(settings, "mobsf_api_key", None)
        raw_key = key.get_secret_value() if hasattr(key, "get_secret_value") else key
        parsed = urlsplit(url or "")
        if (
            os.getuid() == 0
            or os.geteuid() == 0
            or not url
            or not isinstance(raw_key, str)
            or not raw_key
            or any(ord(char) < 32 or ord(char) > 126 for char in raw_key)
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or any(char.isspace() for char in url)
            or (
                parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            )
        ):
            raise SandboxError("isolation_unavailable")
        if should_cancel is not None and should_cancel():
            raise SandboxCancelled()
        try:
            safe_metadata = ManifestMetadata.model_validate(metadata).model_dump()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            source = os.fdopen(fd, "rb")
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= settings.max_apk_bytes:
                source.close()
                raise SandboxError("invalid_apk")
        except (OSError, ValueError) as exc:
            raise SandboxError("invalid_apk") from exc
        with source:
            sha256, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
            total = 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                total += len(block)
                if total > settings.max_apk_bytes:
                    raise SandboxError("invalid_apk")
                sha256.update(block)
                md5.update(block)
                if should_cancel is not None and should_cancel():
                    raise SandboxCancelled()
                if time.monotonic() >= deadline:
                    raise SandboxError("analysis_timeout")
            _checked(total == info.st_size)
            source.seek(0)
            loop = asyncio.new_event_loop()
            done = threading.Event()
            state = {}

            async def execute():
                return await self._workflow(
                    _BoundedFile(source, total),
                    safe_metadata,
                    sha256.hexdigest(),
                    md5.hexdigest(),
                    total,
                )

            task = loop.create_task(execute())

            def runner():
                try:
                    asyncio.set_event_loop(loop)
                    state["result"] = loop.run_until_complete(task)
                except BaseException as exc:
                    state["error"] = exc
                finally:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                    loop.close()
                    done.set()

            def stop():
                if not done.is_set():
                    try:
                        loop.call_soon_threadsafe(task.cancel)
                    except RuntimeError:
                        pass

            thread = threading.Thread(target=runner, daemon=True)
            watchdog = threading.Timer(max(0, deadline - time.monotonic()), stop)
            watchdog.daemon = True
            try:
                thread.start()
                watchdog.start()
                while not done.wait(0.1):
                    if should_cancel is not None and should_cancel():
                        raise SandboxCancelled()
                    if time.monotonic() >= deadline:
                        raise SandboxError("analysis_timeout")
                if should_cancel is not None and should_cancel():
                    raise SandboxCancelled()
                if time.monotonic() >= deadline:
                    raise SandboxError("analysis_timeout")
                error = state.get("error")
                if error is not None:
                    if isinstance(error, SandboxError):
                        raise error
                    if isinstance(error, httpx.TimeoutException):
                        raise SandboxError("analysis_timeout") from None
                    raise SandboxError("analysis_failed") from None
                _checked("result" in state)
                return state["result"]
            finally:
                watchdog.cancel()
                stop()
                if thread.ident is not None:
                    thread.join(timeout=2)
