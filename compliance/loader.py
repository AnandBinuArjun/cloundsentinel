"""Load version-controlled compliance frameworks and evaluate tenant posture transparently."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_FRAMEWORKS_PATH = Path(__file__).resolve().parent / "frameworks.json"


@lru_cache(maxsize=1)
def load_compliance_catalog() -> dict[str, Any]:
    """Read version-controlled compliance framework mappings from disk."""
    raw = json.loads(_FRAMEWORKS_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Invalid compliance catalog JSON structure.")
    return raw


def compute_compliance_posture(
    results_by_rule: dict[str, list[str]],
) -> dict[str, Any]:
    """Compute per-framework and per-control posture from real assessment check outcomes.

    Never marks a control as PASS if no underlying rules have been evaluated or if any
    underlying rule ended in FAIL or ERROR.
    """
    catalog = load_compliance_catalog()
    frameworks_out: list[dict[str, Any]] = []

    for fw in catalog["frameworks"]:
        controls_out: list[dict[str, Any]] = []
        passed_controls = 0
        failed_controls = 0
        not_assessed_controls = 0

        for ctrl in fw["controls"]:
            rule_ids: list[str] = list(ctrl["rule_ids"])
            observed_statuses: list[str] = []
            for rid in rule_ids:
                observed_statuses.extend(results_by_rule.get(rid, []))

            if not observed_statuses:
                status = "NOT_ASSESSED"
                not_assessed_controls += 1
            elif "FAIL" in observed_statuses:
                status = "FAIL"
                failed_controls += 1
            elif "ERROR" in observed_statuses:
                status = "ERROR"
                not_assessed_controls += 1
            elif all(st == "PASS" for st in observed_statuses):
                status = "PASS"
                passed_controls += 1
            else:
                status = "NOT_ASSESSED"
                not_assessed_controls += 1

            controls_out.append(
                {
                    "control_id": ctrl["control_id"],
                    "title": ctrl["title"],
                    "related_rules": rule_ids,
                    "status": status,
                    "rationale": ctrl["rationale"],
                    "coverage_status": ctrl["coverage_status"],
                    "limitations": ctrl["limitations"],
                }
            )

        total = len(controls_out)
        assessed = passed_controls + failed_controls
        coverage_pct = round((passed_controls / assessed) * 100.0, 1) if assessed > 0 else None

        frameworks_out.append(
            {
                "id": fw["id"],
                "name": fw["name"],
                "version": fw["version"],
                "description": fw["description"],
                "summary": {
                    "total_controls": total,
                    "passed": passed_controls,
                    "failed": failed_controls,
                    "not_assessed_or_error": not_assessed_controls,
                    "technical_pass_rate_pct": coverage_pct,
                },
                "controls": controls_out,
            }
        )

    return {
        "schema_version": catalog["schema_version"],
        "disclaimer": catalog["disclaimer"],
        "frameworks": frameworks_out,
    }
