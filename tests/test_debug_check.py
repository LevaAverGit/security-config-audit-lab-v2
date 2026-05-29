import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.debug_check import check_debug_endpoint


def _mock_response(status: int = 200, body: str = ""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def test_debug_endpoint_not_accessible_404_is_passed():
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(404)
        findings = check_debug_endpoint("http://localhost:8081")
    assert findings[0].status == "passed"
    assert findings[0].id == "DBG-001"


def test_debug_endpoint_not_accessible_403_is_passed():
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(403)
        findings = check_debug_endpoint("http://localhost:8081")
    assert findings[0].status == "passed"


def test_debug_endpoint_accessible_is_failed():
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, "some response")
        findings = check_debug_endpoint("http://localhost:8080")
    assert findings[0].status == "failed"


def test_debug_endpoint_exposes_config_is_high():
    body = '{"flask_debug": true, "secret_key": "abc"}'
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, body)
        findings = check_debug_endpoint("http://localhost:8080")
    assert findings[0].severity == "High"
    assert findings[0].status == "failed"


def test_debug_endpoint_accessible_no_keywords_is_medium():
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, "welcome page")
        findings = check_debug_endpoint("http://localhost:8080")
    assert findings[0].severity == "Medium"
    assert findings[0].status == "failed"


def test_debug_endpoint_evidence_contains_url():
    with patch("audit.checks.debug_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(404)
        findings = check_debug_endpoint("http://localhost:8081")
    assert "localhost:8081" in findings[0].evidence


def test_unreachable_target_returns_failed():
    with patch("audit.checks.debug_check.requests.get", side_effect=Exception("refused")):
        findings = check_debug_endpoint("http://localhost:9999")
    assert findings[0].status == "failed"
    assert findings[0].id == "DBG-001"
