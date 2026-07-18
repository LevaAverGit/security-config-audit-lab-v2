import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.https_redirect_check import check_https_redirect


def _mock_response(status: int = 200, headers: dict = None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    return resp


def test_redirect_to_https_is_passed():
    with patch("audit.checks.https_redirect_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(301, {"Location": "https://localhost:8443/"})
        findings = check_https_redirect("http://localhost:8080")
    assert findings[0].status == "passed"
    assert "redirected to HTTPS" in findings[0].title


def test_no_redirect_is_failed():
    with patch("audit.checks.https_redirect_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, {})
        findings = check_https_redirect("http://localhost:8080")
    assert findings[0].status == "failed"


def test_redirect_to_http_location_is_failed():
    with patch("audit.checks.https_redirect_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(302, {"Location": "http://localhost:8080/home"})
        findings = check_https_redirect("http://localhost:8080")
    assert findings[0].status == "failed"


def test_unreachable_is_failed():
    with patch("audit.checks.https_redirect_check.requests.get", side_effect=Exception("refused")):
        findings = check_https_redirect("http://localhost:9999")
    assert findings[0].status == "failed"
    assert "failed" in findings[0].title.lower()
