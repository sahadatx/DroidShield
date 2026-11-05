"""Bounded normalizer for externally generated CycloneDX dependency reports.

This module does not scan artifacts, resolve dependencies, or query advisory
services. Every imported identifier remains an unreviewed analyst candidate.
"""

from __future__ import annotations

import json
import math
import re
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from droidshield.analysis_contract import ContractModel

DEPENDENCY_REVIEW_VERSION = "droidshield-dependency-review-1"
CYCLONEDX_VERSION = "1.6"
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 5_000
MAX_VULNERABILITIES = 5_000
MAX_AFFECTS_PER_VULNERABILITY = 512
MAX_CANDIDATES = 1_024
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 32

LIMITATIONS = [
    "This adapter only normalizes an externally generated CycloneDX 1.6 JSON report; it does not scan code or resolve dependencies.",
    "The caller-reported tool name, tool version, and artifact SHA-256 are not independently verified or cryptographically bound to the report.",
    "CVE identifiers and component associations are unreviewed external candidates; affected-version ranges, reachability, exploitability, and advisory freshness are not assessed.",
    "Library/framework components without a bom-ref cannot be associated with vulnerabilities and are counted separately.",
    "No candidates means no candidates were imported; it does not establish that an artifact or dependency inventory is secure.",
]

_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,23}\Z", re.IGNORECASE)
_BOM_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/#-]{0,511}\Z")
_PACKAGE_COORDINATE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._+@/-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\Z")
_SOURCE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+() -]{0,79}\Z")


class DependencyReportError(ValueError):
    """A safe, non-echoing validation error for an imported report."""

    def __init__(self) -> None:
        super().__init__("Invalid or unsupported CycloneDX dependency report")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyReportError
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise DependencyReportError


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise DependencyReportError
    return parsed


def _check_json_budget(value: object) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise DependencyReportError
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise DependencyReportError
    return value


def _list(value: object, *, limit: int) -> list[object]:
    if not isinstance(value, list) or len(value) > limit:
        raise DependencyReportError
    return value


def _safe_label(value: object, pattern: re.Pattern[str], *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DependencyReportError
    return value


def _component_key(item: DependencyComponent) -> tuple[str, str, str, str]:
    return (item.component_type, item.group or "", item.name, item.version or "")


class DependencyComponent(ContractModel):
    component_type: Literal["library", "framework"]
    group: str | None = Field(max_length=128)
    name: str = Field(min_length=1, max_length=128)
    version: str | None = Field(max_length=128)

    @field_validator("group", "name")
    @classmethod
    def safe_coordinate(cls, value: str | None) -> str | None:
        if value is not None and not _PACKAGE_COORDINATE.fullmatch(value):
            raise ValueError("Invalid component coordinate")
        return value

    @field_validator("version")
    @classmethod
    def safe_version(cls, value: str | None) -> str | None:
        if value is not None and not _PACKAGE_VERSION.fullmatch(value):
            raise ValueError("Invalid component version")
        return value


class DependencyCandidate(ContractModel):
    component: DependencyComponent
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=32)
    review_status: Literal["unreviewed"]
    source_format: Literal["CycloneDX 1.6"]


class DependencyReviewResult(ContractModel):
    schema_version: Literal[1]
    engine_version: Literal["droidshield-dependency-review-1"]
    cyclonedx_version: Literal["1.6"]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_tool: str = Field(min_length=1, max_length=80)
    source_version: str = Field(min_length=1, max_length=80)
    component_count: StrictInt = Field(ge=0, le=MAX_COMPONENTS)
    unlinked_component_count: StrictInt = Field(ge=0, le=MAX_COMPONENTS)
    components: list[DependencyComponent] = Field(max_length=MAX_COMPONENTS)
    candidates: list[DependencyCandidate] = Field(max_length=MAX_CANDIDATES)
    limitations: list[str] = Field(min_length=5, max_length=5)

    @field_validator("source_tool", "source_version")
    @classmethod
    def safe_source_label(cls, value: str) -> str:
        if not _SOURCE_LABEL.fullmatch(value):
            raise ValueError("Invalid source label")
        return value

    @field_validator("limitations")
    @classmethod
    def fixed_limitations(cls, value: list[str]) -> list[str]:
        if value != LIMITATIONS:
            raise ValueError("Unknown limitations")
        return value

    @model_validator(mode="after")
    def consistent_result(self) -> DependencyReviewResult:
        if self.component_count != len(self.components):
            raise ValueError("Inconsistent component inventory")
        component_keys = [_component_key(item) for item in self.components]
        if component_keys != sorted(set(component_keys)):
            raise ValueError("Component inventory must be unique and sorted")
        candidate_keys = [
            (*_component_key(item.component), item.cve_id) for item in self.candidates
        ]
        if candidate_keys != sorted(set(candidate_keys)):
            raise ValueError("Dependency candidates must be unique and sorted")
        if any(item.component not in self.components for item in self.candidates):
            raise ValueError("Candidate component is outside the inventory")
        return self


def normalize_cyclonedx_report(
    payload: bytes,
    *,
    artifact_sha256: str,
    source_tool: str,
    source_version: str,
) -> dict[str, object]:
    """Return a strict allowlist from a caller-supplied CycloneDX 1.6 VDR.

    The hash and tool provenance are caller declarations only. No external
    report fields other than constrained coordinates and CVE IDs are returned.
    """
    if (
        not isinstance(payload, bytes)
        or not 0 < len(payload) <= MAX_REPORT_BYTES
        or not isinstance(artifact_sha256, str)
        or not _SHA256.fullmatch(artifact_sha256)
        or not isinstance(source_tool, str)
        or not _SOURCE_LABEL.fullmatch(source_tool)
        or not isinstance(source_version, str)
        or not _SOURCE_LABEL.fullmatch(source_version)
    ):
        raise DependencyReportError
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        _check_json_budget(document)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, TypeError):
        raise DependencyReportError from None

    root = _object(document)
    if (
        root.get("bomFormat") != "CycloneDX"
        or root.get("specVersion") != CYCLONEDX_VERSION
        or type(root.get("version")) is not int
        or root.get("version") < 1
    ):
        raise DependencyReportError

    raw_components = _list(root.get("components", []), limit=MAX_COMPONENTS)
    raw_vulnerabilities = _list(root.get("vulnerabilities", []), limit=MAX_VULNERABILITIES)
    by_ref: dict[str, DependencyComponent] = {}
    seen_refs: set[str] = set()
    unlinked_count = 0
    for raw_component in raw_components:
        item = _object(raw_component)
        component_type = item.get("type")
        if not isinstance(component_type, str):
            raise DependencyReportError
        ref = item.get("bom-ref")
        if ref is not None:
            ref = _safe_label(ref, _BOM_REF)
            if ref in seen_refs:
                raise DependencyReportError
            seen_refs.add(ref)
        if component_type not in {"library", "framework"}:
            continue
        name = _safe_label(item.get("name"), _PACKAGE_COORDINATE)
        group = _safe_label(item.get("group"), _PACKAGE_COORDINATE, optional=True)
        version = _safe_label(item.get("version"), _PACKAGE_VERSION, optional=True)
        component = DependencyComponent(
            component_type=component_type,
            group=group,
            name=name,
            version=version,
        )
        if ref is None:
            unlinked_count += 1
        else:
            by_ref[ref] = component

    if unlinked_count > MAX_COMPONENTS:
        raise DependencyReportError
    components_by_key = {_component_key(item): item for item in by_ref.values()}
    unique_components = [components_by_key[key] for key in sorted(components_by_key)]
    candidates: set[tuple[tuple[str, str, str, str], str]] = set()
    for raw_vulnerability in raw_vulnerabilities:
        vulnerability = _object(raw_vulnerability)
        raw_ids: list[object] = []
        if "id" in vulnerability:
            raw_ids.append(vulnerability["id"])
        references = _list(vulnerability.get("references", []), limit=128)
        for raw_reference in references:
            reference = _object(raw_reference)
            if "id" in reference:
                raw_ids.append(reference["id"])
        cve_ids = sorted(
            {
                identifier.upper()
                for identifier in raw_ids
                if isinstance(identifier, str) and _CVE.fullmatch(identifier)
            }
        )
        affects = _list(vulnerability.get("affects", []), limit=MAX_AFFECTS_PER_VULNERABILITY)
        affected_component_keys: set[tuple[str, str, str, str]] = set()
        for raw_affect in affects:
            affect = _object(raw_affect)
            ref = affect.get("ref")
            if not isinstance(ref, str) or not _BOM_REF.fullmatch(ref):
                continue
            component = by_ref.get(ref)
            if component is not None:
                affected_component_keys.add(_component_key(component))
        for component_key in affected_component_keys:
            for cve_id in cve_ids:
                candidates.add((component_key, cve_id))
                if len(candidates) > MAX_CANDIDATES:
                    raise DependencyReportError

    candidate_items = [
        DependencyCandidate(
            component=components_by_key[component_key],
            cve_id=cve_id,
            review_status="unreviewed",
            source_format="CycloneDX 1.6",
        )
        for component_key, cve_id in sorted(
            candidates,
            key=lambda pair: (*pair[0], pair[1]),
        )
    ]
    result = DependencyReviewResult(
        schema_version=1,
        engine_version=DEPENDENCY_REVIEW_VERSION,
        cyclonedx_version=CYCLONEDX_VERSION,
        artifact_sha256=artifact_sha256,
        source_tool=source_tool,
        source_version=source_version,
        component_count=len(unique_components),
        unlinked_component_count=unlinked_count,
        components=unique_components,
        candidates=candidate_items,
        limitations=LIMITATIONS,
    )
    return result.model_dump()
