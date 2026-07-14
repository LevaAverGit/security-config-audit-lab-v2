import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.http_methods_check import check_http_methods


def _mock_response(headers: dict = None, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    return resp


def test_trace_method_is_failed():
    with patch("audit.checks.http_methods_check.requests.options") as mock_opt:
        mock_opt.return_value = _mock_response({"Allow": "GET, HEAD, POST, TRACE"})
        findings = check_http_methods("http://localhost:8080")
    assert findings[0].status == "failed"
    assert "TRACE" in findings[0].title


def test_put_and_delete_are_failed():
    with patch("audit.checks.http_methods_check.requests.options") as mock_opt:
        mock_opt.return_value = _mock_response({"Allow": "GET, PUT, DELETE"})
        findings = check_http_methods("http://localhost:8080")
    assert findings[0].status == "failed"
    assert "PUT" in findings[0].title and "DELETE" in findings[0].title


def test_safe_methods_are_passed():
    with patch("audit.checks.http_methods_check.requests.options") as mock_opt:
        mock_opt.return_value = _mock_response({"Allow": "GET, HEAD, POST, OPTIONS"})
        findings = check_http_methods("http://localhost:8081")
    assert findings[0].status == "passed"


def test_missing_allow_header_is_passed():
    with patch("audit.checks.http_methods_check.requests.options") as mock_opt:
        mock_opt.return_value = _mock_response({})
        findings = check_http_methods("http://localhost:8081")
    assert findings[0].status == "passed"


def test_unreachable_is_failed():
    with patch("audit.checks.http_methods_check.requests.options", side_effect=Exception("refused")):
        findings = check_http_methods("http://localhost:9999")
    assert findings[0].status == "failed"
