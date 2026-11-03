"""Regression checks for the generated API contract and its endpoint index."""

import json
import re
from pathlib import Path

from tests.openapi_snapshot import FIXTURE, build_contract_snapshot

REPOSITORY = Path(__file__).resolve().parents[1]
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
ENDPOINT_ROW = re.compile(r"`([A-Z]+) (/[^`]+)`")
PATH_PARAMETER = re.compile(r"\{[^{}]+\}")


def test_generated_openapi_matches_reviewed_contract_snapshot():
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    actual = build_contract_snapshot()
    assert actual == expected, (
        "Generated OpenAPI contract changed. Review the schema diff, update "
        "docs/api-contract.md, then refresh the fixture with "
        "`python -m tests.openapi_snapshot --write`."
    )


def test_implemented_endpoint_index_matches_generated_operations():
    contract = (REPOSITORY / "docs" / "api-contract.md").read_text(encoding="utf-8")
    endpoint_section = contract.split("## 2. Implemented endpoints", 1)[1].split("\n## ", 1)[0]
    # Only the endpoint index table is authoritative here. Later prose may use
    # shorthand paths such as ``GET /settings`` when describing an indexed route.
    documented_rows = [
        match.groups()
        for line in endpoint_section.splitlines()
        if line.startswith("| `")
        for match in ENDPOINT_ROW.finditer(line)
    ]
    documented = {(method, PATH_PARAMETER.sub("{}", path)) for method, path in documented_rows}
    actual = {
        (method.upper(), PATH_PARAMETER.sub("{}", path))
        for path, path_item in build_contract_snapshot()["paths"].items()
        for method in path_item
        if method in HTTP_METHODS
    }

    assert len(documented_rows) == len(documented), "Endpoint index contains duplicate rows"
    assert documented == actual, (
        f"Endpoint index differs from generated OpenAPI; missing={sorted(actual - documented)}, "
        f"stale={sorted(documented - actual)}"
    )
