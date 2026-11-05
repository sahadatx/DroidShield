# External dependency report normalization

`droidshield-dependency-review-1` is a bounded import helper for an
externally generated CycloneDX 1.6 JSON vulnerability report. CycloneDX's
official schemas define the input format; this helper consumes only the
component and vulnerability fields needed to produce a small analyst-review
inventory. It does not execute or contact a dependency scanner, query an
advisory database, resolve a dependency graph, or test an application.

The helper is currently a Python library function, not an HTTP endpoint, CLI
command, or static-worker engine. Callers must obtain the report from an
authorized engagement and keep it in an approved environment. The artifact
SHA-256 and scanner name/version are caller-supplied labels. The helper cannot
verify the report signature, scanner identity, source-tool version, or whether
the report actually describes the stated artifact.

## Normalized result

`normalize_cyclonedx_report(payload, artifact_sha256=..., source_tool=...,
source_version=...)` returns a strict versioned object containing:

- A sorted, deduplicated inventory of root-level `library` and `framework`
  components with constrained group/name/version values.
- CVE identifiers from vulnerability `id` and `references[].id`, associated
  only through a matching component `bom-ref` in `affects[].ref`.
- A review status fixed to `unreviewed` for every candidate.
- The caller-reported artifact hash and source-tool labels, plus the helper
  version and fixed limitation statements.

Descriptions, recommendations, URLs, ratings/severity, proof-of-concept data,
properties, package URLs, raw BOM references, and all other source-report text
are discarded. No candidate is a DroidShield Finding or a confirmed
vulnerability. The adapter does not interpret affected-version ranges,
reachability, exploitability, or advisory freshness. An empty candidate list
means only that no candidate was imported; it does not establish that the
artifact is secure.

## Input limits

The helper accepts UTF-8 JSON only, with duplicate object keys and non-standard
JSON constants rejected. It requires `bomFormat: "CycloneDX"`, `specVersion:
"1.6"`, and a positive integer BOM `version`. Input is limited to 2 MiB, 5,000
root components, 5,000 vulnerabilities, 512 affected references per
vulnerability, 1,024 output candidates, 100,000 JSON nodes, and depth 32.
Library/framework components without a `bom-ref` are omitted from the linked
inventory and counted separately. Invalid library/framework coordinates or
duplicate component references reject the report rather than silently
changing its meaning.

This helper does not persist the original report or its result. Future API or
worker integration must add the normal authorization, project/artifact binding,
protected intake, independent review, and immutable provenance controls before
making imported data part of an engagement record.

Reference: [CycloneDX official specification and schemas](https://github.com/CycloneDX/specification).
