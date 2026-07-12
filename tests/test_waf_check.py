import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.waf_check import check_waf


def _mock_response(status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {}
    return resp


def test_waf_blocking_403_is_passed():
    with patch("audit.checks.waf_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(403)
        findings = check_waf("http://localhost:8082")
    assert findings[0].status == "passed"
    assert findings[0].id == "WAF-001"


def test_waf_blocking_406_is_passed():
    with patch("audit.checks.waf_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(406)
        findings = check_waf("http://localhost:8082")
    assert findings[0].status == "passed"


def test_no_waf_200_is_warning():
    with patch("audit.checks.waf_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200)
        findings = check_waf("http://localhost:8080")
    assert findings[0].status == "warning"
    assert "No WAF" in findings[0].title


def test_attack_payload_is_sent():
    with patch("audit.checks.waf_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200)
        check_waf("http://localhost:8080")
    _, kwargs = mock_get.call_args
    payload = str(kwargs.get("params", {}))
    assert "<script>" in payload or "OR '1'='1" in payload


def test_unreachable_is_failed():
    with patch("audit.checks.waf_check.requests.get", side_effect=Exception("refused")):
        findings = check_waf("http://localhost:9999")
    assert findings[0].status == "failed"
