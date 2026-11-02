"""CVSS base scores using the pinned Red Hat implementation linked by FIRST.

No supplied score is trusted. Threat/environmental adjustments are intentionally
excluded from this first contract so a score always denotes the base metric set.
The independently distributed ``cvss`` dependency retains its LGPL-3.0 license.
"""

import math

from cvss import CVSS3, CVSS4

_BASE = {
    "4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
    "3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
}


def score_cvss(vector: str) -> dict:
    if not isinstance(vector, str) or len(vector) > 255 or vector.strip() != vector:
        raise ValueError("Provide a bounded CVSS v4.0 or v3.1 base vector")
    version = next((v for v in _BASE if vector.startswith(f"CVSS:{v}/")), None)
    if version is None:
        raise ValueError("Only CVSS v4.0 and v3.1 base vectors are supported")
    metrics = vector.split("/")[1:]
    keys = [metric.split(":")[0] for metric in metrics]
    if len(keys) != len(set(keys)) or set(keys) != _BASE[version]:
        raise ValueError("Provide every base metric exactly once, without optional metrics")
    try:
        calculator = CVSS4(vector) if version == "4.0" else CVSS3(vector)
        score = float(calculator.scores()[0])
    except Exception as exc:
        # Library errors can echo the supplied vector; keep validation messages fixed.
        raise ValueError("Provide a valid CVSS base vector") from exc
    severity = (
        "info"
        if score == 0
        else "low"
        if score < 4
        else "medium"
        if score < 7
        else "high"
        if score < 9
        else "critical"
    )
    return {
        "version": version,
        "vector": calculator.clean_vector(),
        "score": score,
        "severity": severity,
    }


def validate_cvss(vector: str | None, score: float | None) -> None:
    if vector is None and score is None:
        return
    if vector is None or score is None or isinstance(score, bool):
        raise ValueError("CVSS vector and calculated score must be supplied together")
    calculated = score_cvss(vector)
    if not math.isfinite(score) or not math.isclose(score, calculated["score"], abs_tol=0.000001):
        raise ValueError("CVSS score does not match the calculated base vector")
