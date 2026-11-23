"""Transparent, documented internal risk scoring algorithm (0-100).

DISCLAIMER: This score is an internally calculated prioritization metric documented in
docs/TECHNICAL_SPEC.md. It is NOT an externally certified CVSS or industry compliance standard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packages.assessment.interface import Confidence, Severity

_SEVERITY_BASE: dict[str, float] = {
    Severity.CRITICAL.value: 45.0,
    Severity.HIGH.value: 34.0,
    Severity.MEDIUM.value: 22.0,
    Severity.LOW.value: 10.0,
}

_CRITICALITY_BONUS: dict[str, float] = {
    "high": 12.0,
    "standard": 6.0,
    "low": 2.0,
}

_PRIVILEGE_BONUS: dict[str, float] = {
    "admin": 16.0,
    "elevated": 10.0,
    "standard": 4.0,
    "none": 0.0,
}

_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    Confidence.HIGH.value: 1.0,
    Confidence.MEDIUM.value: 0.9,
    Confidence.LOW.value: 0.75,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    priority_tier: str
    explanation: dict[str, Any]


def calculate_risk_score(
    *,
    severity: str,
    internet_exposed: bool = False,
    asset_criticality: str = "standard",
    identity_privilege: str = "none",
    exploitability: str = "moderate",
    business_impact: str = "moderate",
    confidence: str = "high",
) -> RiskAssessment:
    """Compute a deterministic, fully explainable risk score between 0 and 100."""
    sev_points = _SEVERITY_BASE.get(severity.lower(), 15.0)
    exposure_points = 15.0 if internet_exposed else 0.0
    criticality_points = _CRITICALITY_BONUS.get(asset_criticality.lower(), 6.0)
    privilege_points = _PRIVILEGE_BONUS.get(identity_privilege.lower(), 0.0)
    exploit_points = {"high": 7.0, "moderate": 4.0, "low": 1.0}.get(exploitability.lower(), 4.0)
    impact_points = {"high": 5.0, "moderate": 3.0, "low": 1.0}.get(business_impact.lower(), 3.0)
    conf_mult = _CONFIDENCE_MULTIPLIER.get(confidence.lower(), 0.9)

    raw_total = (
        sev_points
        + exposure_points
        + criticality_points
        + privilege_points
        + exploit_points
        + impact_points
    )
    final_score = round(min(100.0, max(0.0, raw_total * conf_mult)), 1)

    if final_score >= 80.0:
        tier = "P0 - Immediate"
    elif final_score >= 60.0:
        tier = "P1 - Urgent"
    elif final_score >= 35.0:
        tier = "P2 - Scheduled"
    else:
        tier = "P3 - Monitor"

    return RiskAssessment(
        score=final_score,
        priority_tier=tier,
        explanation={
            "algorithm_version": "1.0.0",
            "disclaimer": (
                "Internally calculated prioritization score based on deterministic security inputs; "
                "not an externally validated industry standard."
            ),
            "priority_tier": tier,
            "factors": {
                "severity_base": sev_points,
                "internet_exposure": exposure_points,
                "asset_criticality": criticality_points,
                "identity_privilege": privilege_points,
                "exploitability": exploit_points,
                "business_impact": impact_points,
                "confidence_multiplier": conf_mult,
            },
        },
    )
