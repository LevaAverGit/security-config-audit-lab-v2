import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.hsts_check import check_hsts


def _mock_response(headers: dict = None, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    return resp


def test_hsts_missing_is_failed():
    with patch("audit.checks.hsts_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_hsts("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].id == "HSTS-001"


def test_hsts_present_is_passed():
    headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    with patch("audit.checks.hsts_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_hsts("http://localhost:8081")
    assert findings[0].status == "passed"


def test_hsts_missing_severity_is_medium():
    with patch("audit.checks.hsts_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_hsts("http://localhost:8080")
    assert findings[0].severity == "Medium"


def test_hsts_present_evidence_contains_value():
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    with patch("audit.checks.hsts_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_hsts("http://localhost:8081")
    assert "max-age=31536000" in findings[0].evidence


def test_hsts_unreachable_is_failed():
    with patch("audit.checks.hsts_check.requests.get", side_effect=Exception("timeout")):
        findings = check_hsts("http://localhost:9999")
    assert findings[0].status == "failed"
