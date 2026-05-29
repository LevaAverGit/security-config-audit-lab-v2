import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.cors_check import check_cors


def _mock_response(headers: dict = None, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    return resp


def test_wildcard_cors_is_failed():
    with patch("audit.checks.cors_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"Access-Control-Allow-Origin": "*"})
        findings = check_cors("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].id == "CORS-001"


def test_wildcard_cors_severity_is_medium():
    with patch("audit.checks.cors_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"Access-Control-Allow-Origin": "*"})
        findings = check_cors("http://localhost:8080")
    assert findings[0].severity == "Medium"


def test_no_cors_header_is_passed():
    with patch("audit.checks.cors_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_cors("http://localhost:8081")
    assert findings[0].status == "passed"


def test_specific_origin_cors_is_passed():
    headers = {"Access-Control-Allow-Origin": "https://trusted.example.com"}
    with patch("audit.checks.cors_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_cors("http://localhost:8081")
    assert findings[0].status == "passed"


def test_wildcard_evidence_contains_asterisk():
    with patch("audit.checks.cors_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"Access-Control-Allow-Origin": "*"})
        findings = check_cors("http://localhost:8080")
    assert "*" in findings[0].evidence


def test_unreachable_is_failed():
    with patch("audit.checks.cors_check.requests.get", side_effect=Exception("refused")):
        findings = check_cors("http://localhost:9999")
    assert findings[0].status == "failed"
