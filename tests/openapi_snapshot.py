"""Build the reviewed OpenAPI wire-contract snapshot used by regression tests.

After an intentional API contract change, review the generated diff and refresh
the fixture with ``python -m tests.openapi_snapshot --write``.
"""

import argparse
import json
from pathlib import Path
from typing import Any

from droidshield.config import Settings
from droidshield.main import create_app

FIXTURE = Path(__file__).parent / "fixtures" / "openapi-contract.json"
DOC_ONLY_KEYS = {"description", "summary", "title", "example", "examples", "externalDocs", "tags"}


def _without_documentation(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_documentation(item)
            for key, item in value.items()
            if key not in DOC_ONLY_KEYS
        }
    if isinstance(value, list):
        return [_without_documentation(item) for item in value]
    return value


def build_contract_snapshot() -> dict[str, Any]:
    app = create_app(Settings(_env_file=None, environment="test", database_url="sqlite://"))
    try:
        return _without_documentation(app.openapi())
    finally:
        app.state.engine.dispose()


def write_contract_snapshot() -> None:
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(
        json.dumps(build_contract_snapshot(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="replace the reviewed snapshot")
    args = parser.parse_args()
    if not args.write:
        parser.error("pass --write to update the reviewed OpenAPI contract fixture")
    write_contract_snapshot()
