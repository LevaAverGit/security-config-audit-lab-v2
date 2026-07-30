import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.cli import gating_exit_code
from audit.models import Finding


def _finding(severity: str, status: str = "failed") -> Finding:
    return Finding(
        id="X-001",
        title="t",
        severity=severity,
        status=status,
        description="",
        evidence="",
        risk="",
        recommendation="",
    )


def test_none_never_fails():
    assert gating_exit_code([_finding("Critical")], "none") == 0


def test_high_finding_fails_high_gate():
    assert gating_exit_code([_finding("High")], "high") == 1


def test_medium_finding_does_not_fail_high_gate():
    assert gating_exit_code([_finding("Medium")], "high") == 0


def test_critical_fails_high_gate():
    assert gating_exit_code([_finding("Critical")], "high") == 1


def test_passed_findings_do_not_count():
    assert gating_exit_code([_finding("Critical", status="passed")], "critical") == 0


def test_warning_status_counts():
    assert gating_exit_code([_finding("High", status="warning")], "high") == 1


def test_empty_findings_pass():
    assert gating_exit_code([], "low") == 0
