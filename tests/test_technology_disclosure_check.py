import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.technology_disclosure_check import check_technology_disclosure


def _mock_response(powered_by: str = "", status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"X-Powered-By": powered_by} if powered_by else {}
    return resp


def test_powered_by_present_is_failed():
    with patch("audit.checks.technology_disclosure_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("Express")
        findings = check_technology_disclosure("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].id == "XPB-001"


def test_powered_by_evidence_contains_header_value():
    with patch("audit.checks.technology_disclosure_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("PHP/7.4.3")
        findings = check_technology_disclosure("http://localhost:8080")
    assert "PHP/7.4.3" in findings[0].evidence


def test_powered_by_absent_is_passed():
    with patch("audit.checks.technology_disclosure_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("")
        findings = check_technology_disclosure("http://localhost:8081")
    assert findings[0].status == "passed"


def test_unreachable_target_returns_failed():
    with patch("audit.checks.technology_disclosure_check.requests.get", side_effect=Exception("timeout")):
        findings = check_technology_disclosure("http://localhost:9999")
    assert findings[0].status == "failed"
    assert findings[0].id == "XPB-001"
