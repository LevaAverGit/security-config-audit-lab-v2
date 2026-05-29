import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.models import Finding
from audit.scoring import (
    severity_to_score,
    calculate_total_score,
    score_to_risk_level,
    summarize_by_severity,
)


def _f(severity: str, status: str = "failed") -> Finding:
    return Finding(
        id="X", title="t", severity=severity, status=status,
        description="", evidence="", risk="", recommendation="",
    )


def test_severity_to_score():
    assert severity_to_score("Critical") == 40
    assert severity_to_score("High") == 30
    assert severity_to_score("Medium") == 15
    assert severity_to_score("Low") == 5
    assert severity_to_score("Unknown") == 0


def test_calculate_total_score_only_failed():
    findings = [_f("High"), _f("Medium"), _f("Low", status="passed")]
    assert calculate_total_score(findings) == 30 + 15  # passed not counted


def test_calculate_total_score_all_passed():
    findings = [_f("Critical", "passed"), _f("High", "passed")]
    assert calculate_total_score(findings) == 0


def test_warning_findings_counted():
    findings = [_f("Medium", "warning")]
    assert calculate_total_score(findings) == 15


def test_score_to_risk_level():
    assert score_to_risk_level(0) == "Low"
    assert score_to_risk_level(20) == "Low"
    assert score_to_risk_level(21) == "Medium"
    assert score_to_risk_level(50) == "Medium"
    assert score_to_risk_level(51) == "High"
    assert score_to_risk_level(90) == "High"
    assert score_to_risk_level(91) == "Critical"


def test_score_capped_at_100():
    # 3×High(30) + 3×Critical(40) = 210 raw → capped at 100
    findings = [_f("High")] * 3 + [_f("Critical")] * 3
    assert calculate_total_score(findings) == 100


def test_score_not_capped_when_below_100():
    findings = [_f("High"), _f("Medium")]  # 30+15=45
    assert calculate_total_score(findings) == 45


def test_summarize_by_severity():
    findings = [_f("High"), _f("High"), _f("Medium"), _f("Low", "passed")]
    summary = summarize_by_severity(findings)
    assert summary["High"] == 2
    assert summary["Medium"] == 1
    assert "Low" not in summary  # passed not counted
