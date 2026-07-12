import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.cookie_security_check import check_cookie_security


def _mock_response(headers: dict = None, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    return resp


def test_cookie_without_flags_is_failed():
    with patch("audit.checks.cookie_security_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"Set-Cookie": "session=abc"})
        findings = check_cookie_security("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].id == "COOKIE-001"


def test_missing_flags_are_listed_in_title():
    with patch("audit.checks.cookie_security_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"Set-Cookie": "session=abc"})
        findings = check_cookie_security("http://localhost:8080")
    title = findings[0].title
    assert "Secure" in title and "HttpOnly" in title and "SameSite" in title


def test_fully_hardened_cookie_is_passed():
    headers = {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}
    with patch("audit.checks.cookie_security_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_cookie_security("http://localhost:8081")
    assert findings[0].status == "passed"


def test_partial_flags_still_failed():
    # HttpOnly present, but Secure and SameSite missing
    headers = {"Set-Cookie": "session=abc; HttpOnly"}
    with patch("audit.checks.cookie_security_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_cookie_security("http://localhost:8080")
    assert findings[0].status == "failed"
    assert "Secure" in findings[0].title
    assert "SameSite" in findings[0].title
    assert "HttpOnly" not in findings[0].title


def test_no_cookie_set_is_passed():
    with patch("audit.checks.cookie_security_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_cookie_security("http://localhost:8081")
    assert findings[0].status == "passed"


def test_unreachable_is_failed():
    with patch("audit.checks.cookie_security_check.requests.get", side_effect=Exception("refused")):
        findings = check_cookie_security("http://localhost:9999")
    assert findings[0].status == "failed"
