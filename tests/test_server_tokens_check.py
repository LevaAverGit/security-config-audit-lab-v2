import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.server_tokens_check import check_server_tokens


def _mock_response(server_header: str = "", status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Server": server_header} if server_header else {}
    return resp


def test_version_disclosed_is_failed():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("nginx/1.25.5")
        findings = check_server_tokens("http://localhost:8080")
    assert len(findings) == 1
    assert findings[0].status == "failed"
    assert findings[0].id == "SRV-001"


def test_version_disclosed_severity_is_low():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("nginx/1.25.5")
        findings = check_server_tokens("http://localhost:8080")
    assert findings[0].severity == "Low"


def test_version_disclosed_evidence_contains_header_value():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("nginx/1.25.5")
        findings = check_server_tokens("http://localhost:8080")
    assert "nginx/1.25.5" in findings[0].evidence


def test_server_header_absent_is_passed():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("")
        findings = check_server_tokens("http://localhost:8081")
    assert findings[0].status == "passed"


def test_server_header_no_version_is_passed():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("nginx")
        findings = check_server_tokens("http://localhost:8081")
    assert findings[0].status == "passed"


def test_server_header_with_digit_only_is_failed():
    with patch("audit.checks.server_tokens_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response("Apache 2")
        findings = check_server_tokens("http://localhost:8080")
    assert findings[0].status == "failed"


def test_unreachable_target_returns_failed():
    with patch("audit.checks.server_tokens_check.requests.get", side_effect=Exception("timeout")):
        findings = check_server_tokens("http://localhost:9999")
    assert findings[0].status == "failed"
    assert findings[0].id == "SRV-001"
