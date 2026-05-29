from __future__ import annotations

from collections import Counter
from typing import List

SEVERITY_SCORES = {
    "Critical": 40,
    "High": 30,
    "Medium": 15,
    "Low": 5,
}


def severity_to_score(severity: str) -> int:
    return SEVERITY_SCORES.get(severity, 0)


MAX_SCORE = 100


def calculate_total_score(findings: List) -> int:
    """Sum scores of failed/warning findings only, capped at MAX_SCORE."""
    raw = sum(
        severity_to_score(f.severity)
        for f in findings
        if f.status in ("failed", "warning")
    )
    return min(raw, MAX_SCORE)


def score_to_risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 90:
        return "High"
    return "Critical"


def summarize_by_severity(findings: List) -> dict:
    return dict(Counter(
        f.severity for f in findings if f.status in ("failed", "warning")
    ))
