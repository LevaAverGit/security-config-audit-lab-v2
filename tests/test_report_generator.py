import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.models import AuditResult, Finding
from audit.report_generator import generate_markdown_report, generate_json_report


def _finding(severity: str = "High", status: str = "failed") -> Finding:
    return Finding(
        id="TEST-001", title="Test finding",
        severity=severity, status=status,
        description="A test finding.", evidence="test evidence",
        risk="Some risk.", recommendation="Fix it.",
    )


def _result(mode: str = "vulnerable") -> AuditResult:
    r = AuditResult(target="http://localhost:8080", mode=mode)
    r.findings = [_finding("High"), _finding("Medium"), _finding("Low", "passed")]
    return r


def test_report_contains_title():
    md = generate_markdown_report(_result())
    assert "Security Config Audit Report" in md


def test_report_contains_executive_summary():
    md = generate_markdown_report(_result())
    assert "Executive Summary" in md


def test_report_contains_findings_section():
    md = generate_markdown_report(_result())
    assert "Findings" in md
    assert "TEST-001" in md


def test_report_contains_limitations():
    md = generate_markdown_report(_result())
    assert "Limitations" in md
    assert "educational" in md.lower() or "local" in md.lower()


def test_report_vulnerable_mode_note():
    md = generate_markdown_report(_result("vulnerable"))
    assert "intentionally" in md.lower() or "vulnerable" in md.lower()


def test_report_hardened_mode_note():
    md = generate_markdown_report(_result("hardened"))
    assert "hardened" in md.lower() or "reduced" in md.lower()


def test_report_shows_target_url():
    md = generate_markdown_report(_result())
    assert "http://localhost:8080" in md


def test_passed_findings_in_report():
    md = generate_markdown_report(_result())
    assert "passed" in md


def test_report_contains_before_after_table():
    md = generate_markdown_report(_result())
    assert "Before/After Comparison" in md
    assert "Vulnerable" in md
    assert "Hardened" in md


def test_report_score_has_cap_format():
    md = generate_markdown_report(_result())
    assert "/100" in md


def test_json_report_valid():
    import json
    js = generate_json_report(_result())
    data = json.loads(js)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["risk_score"] <= 100


def test_json_report_has_limitations():
    import json
    js = generate_json_report(_result())
    data = json.loads(js)
    assert "limitations" in data
    assert len(data["limitations"]) > 0
