import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.headers_check import check_security_headers


def _mock_response(headers: dict, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers
    return resp


def test_missing_all_headers_produces_failed_findings():
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_security_headers("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    assert len(failed) == 5  # all 5 headers missing


def test_all_headers_present_produces_passed_findings():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_security_headers("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    passed = [f for f in findings if f.status == "passed"]
    assert len(failed) == 0
    assert len(passed) == 5


def test_partial_headers_mix_of_passed_and_failed():
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_security_headers("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    passed = [f for f in findings if f.status == "passed"]
    assert len(failed) == 3
    assert len(passed) == 2


def test_unreachable_target_returns_failed_finding():
    with patch("audit.checks.headers_check.requests.get", side_effect=Exception("timeout")):
        findings = check_security_headers("http://localhost:9999")
    assert len(findings) == 1
    assert findings[0].status == "failed"


def test_finding_ids_are_stable():
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_security_headers("http://localhost:8080")
    ids = {f.id for f in findings}
    assert "HDR-CSP" in ids
    assert "HDR-XFO" in ids
    assert "HDR-XCTO" in ids
    assert "HDR-RP" in ids
    assert "HDR-PP" in ids


def test_finding_ids_present_when_headers_set():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(headers)
        findings = check_security_headers("http://localhost:8080")
    ids = {f.id for f in findings}
    assert ids == {"HDR-CSP", "HDR-XFO", "HDR-XCTO", "HDR-RP", "HDR-PP"}
