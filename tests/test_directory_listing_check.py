import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.directory_listing_check import check_directory_listing


def _mock_response(status: int = 200, body: str = ""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def test_directory_listing_detected_is_failed():
    body = "<html><title>Index of /static/</title><body>Index of / parent directory</body></html>"
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, body)
        findings = check_directory_listing("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].id == "DIR-001"


def test_directory_listing_indicator_index_of():
    body = "index of / some content"
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, body)
        findings = check_directory_listing("http://localhost:8080")
    assert findings[0].status == "failed"


def test_directory_listing_indicator_parent_directory():
    body = "parent directory link here"
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, body)
        findings = check_directory_listing("http://localhost:8080")
    assert findings[0].status == "failed"


def test_no_listing_indicators_is_passed():
    body = "<html><body>404 Not Found</body></html>"
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(404, body)
        findings = check_directory_listing("http://localhost:8081")
    assert findings[0].status == "passed"


def test_403_response_is_passed():
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(403, "Forbidden")
        findings = check_directory_listing("http://localhost:8081")
    assert findings[0].status == "passed"


def test_finding_severity_is_medium():
    with patch("audit.checks.directory_listing_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, "index of /")
        findings = check_directory_listing("http://localhost:8080")
    assert findings[0].severity == "Medium"


def test_unreachable_target_returns_failed():
    with patch("audit.checks.directory_listing_check.requests.get", side_effect=Exception("refused")):
        findings = check_directory_listing("http://localhost:9999")
    assert findings[0].status == "failed"
    assert findings[0].id == "DIR-001"
