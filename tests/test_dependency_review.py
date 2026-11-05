import json

import pytest

from droidshield.dependency_review import (
    MAX_CANDIDATES,
    MAX_REPORT_BYTES,
    DependencyReportError,
    normalize_cyclonedx_report,
)

ARTIFACT_HASH = "a" * 64


def component(*, ref="pkg:maven/org.example/library@1.2.3", name="library", version="1.2.3"):
    return {
        "type": "library",
        "bom-ref": ref,
        "group": "org.example",
        "name": name,
        "version": version,
        "purl": "pkg:maven/org.example/library@1.2.3",
        "properties": [{"name": "private.token", "value": "DO_NOT_EXPORT_THIS"}],
    }


def report(*, components=None, vulnerabilities=None, spec_version="1.6"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {"tools": [{"name": "Private tool metadata", "version": "secret"}]},
        "components": [component()] if components is None else components,
        "vulnerabilities": [
            {
                "id": "CVE-2025-12345",
                "description": "Bearer raw-secret-value",
                "detail": "PRIVATE_SOURCE_PATH",
                "recommendation": "arbitrary report-controlled text",
                "references": [{"id": "GHSA-aaaa-bbbb-cccc", "url": "https://private.invalid"}],
                "ratings": [{"severity": "critical", "score": 10.0}],
                "affects": [
                    {
                        "ref": "pkg:maven/org.example/library@1.2.3",
                        "versions": [{"status": "affected"}],
                    }
                ],
            }
        ]
        if vulnerabilities is None
        else vulnerabilities,
    }


def normalize(value, **kwargs):
    return normalize_cyclonedx_report(
        json.dumps(value).encode(),
        artifact_sha256=kwargs.get("artifact_sha256", ARTIFACT_HASH),
        source_tool=kwargs.get("source_tool", "Approved SCA Tool"),
        source_version=kwargs.get("source_version", "4.2.1"),
    )


def test_import_returns_only_bounded_inventory_and_unreviewed_cve_candidates():
    result = normalize(report())

    assert result["schema_version"] == 1
    assert result["engine_version"] == "droidshield-dependency-review-1"
    assert result["cyclonedx_version"] == "1.6"
    assert result["artifact_sha256"] == ARTIFACT_HASH
    assert result["source_tool"] == "Approved SCA Tool"
    assert result["source_version"] == "4.2.1"
    assert result["component_count"] == 1
    assert result["components"] == [
        {"component_type": "library", "group": "org.example", "name": "library", "version": "1.2.3"}
    ]
    assert result["candidates"] == [
        {
            "component": result["components"][0],
            "cve_id": "CVE-2025-12345",
            "review_status": "unreviewed",
            "source_format": "CycloneDX 1.6",
        }
    ]
    serialized = json.dumps(result)
    for withheld in (
        "DO_NOT_EXPORT_THIS",
        "Bearer raw-secret-value",
        "PRIVATE_SOURCE_PATH",
        "arbitrary report-controlled text",
        "private.invalid",
        "Private tool metadata",
        "critical",
        "pkg:maven/",
    ):
        assert withheld not in serialized
    assert "unreviewed external candidates" in " ".join(result["limitations"])


def test_alias_cve_is_normalized_and_non_cve_ids_are_not_imported():
    data = report(
        vulnerabilities=[
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "references": [{"id": "cve-2024-9999"}],
                "affects": [{"ref": "pkg:maven/org.example/library@1.2.3"}],
            },
            {
                "id": "not-a-cve",
                "affects": [{"ref": "pkg:maven/org.example/library@1.2.3"}],
            },
        ]
    )
    result = normalize(data)
    assert [item["cve_id"] for item in result["candidates"]] == ["CVE-2024-9999"]


def test_unmatched_refs_and_empty_vulnerability_lists_do_not_claim_cleanliness():
    data = report(
        vulnerabilities=[{"id": "CVE-2025-12345", "affects": [{"ref": "unknown-component-ref"}]}]
    )
    result = normalize(data)
    assert result["candidates"] == []
    assert any("does not establish" in line for line in result["limitations"])


def test_unlinked_dependency_is_counted_without_inventing_candidate():
    data = report(components=[component(ref=None)])
    result = normalize(data)
    assert result["components"] == []
    assert result["component_count"] == 0
    assert result["unlinked_component_count"] == 1
    assert result["candidates"] == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(specVersion="1.7"),
        lambda value: value.update(version=True),
        lambda value: value.update(bomFormat="SPDX"),
    ],
)
def test_unsupported_format_versions_and_malformed_version_types_fail_closed(mutate):
    data = report()
    mutate(data)
    with pytest.raises(DependencyReportError):
        normalize(data)


def test_duplicate_json_keys_are_rejected():
    raw = b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6","version":1}'
    with pytest.raises(DependencyReportError):
        normalize_cyclonedx_report(
            raw,
            artifact_sha256=ARTIFACT_HASH,
            source_tool="tool",
            source_version="1",
        )


def test_non_finite_numbers_and_duplicate_references_across_component_types_fail():
    raw = b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"ignored":1e999}'
    with pytest.raises(DependencyReportError):
        normalize_cyclonedx_report(
            raw,
            artifact_sha256=ARTIFACT_HASH,
            source_tool="tool",
            source_version="1",
        )

    app = {"type": "application", "bom-ref": "shared-ref", "name": "app"}
    library = component(ref="shared-ref")
    with pytest.raises(DependencyReportError):
        normalize(report(components=[app, library]))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"artifact_sha256": "not-a-hash"},
        {"source_tool": "tool\nsecret"},
        {"source_version": "../secret"},
    ],
)
def test_caller_declared_provenance_is_validated(kwargs):
    with pytest.raises(DependencyReportError):
        normalize(report(), **kwargs)


def test_size_depth_duplicate_refs_and_candidate_budgets_are_enforced():
    with pytest.raises(DependencyReportError):
        normalize_cyclonedx_report(
            b" " * (MAX_REPORT_BYTES + 1),
            artifact_sha256=ARTIFACT_HASH,
            source_tool="tool",
            source_version="1",
        )

    deeply_nested = b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"extra":' + (
        b"[" * 34 + b"0" + b"]" * 34 + b"}"
    )
    with pytest.raises(DependencyReportError):
        normalize_cyclonedx_report(
            deeply_nested,
            artifact_sha256=ARTIFACT_HASH,
            source_tool="tool",
            source_version="1",
        )

    with pytest.raises(DependencyReportError):
        normalize(report(components=[component(), component()]))

    vulnerabilities = [
        {
            "id": f"CVE-2025-{10000 + index}",
            "affects": [{"ref": "pkg:maven/org.example/library@1.2.3"}],
        }
        for index in range(MAX_CANDIDATES + 1)
    ]
    with pytest.raises(DependencyReportError):
        normalize(report(vulnerabilities=vulnerabilities))
