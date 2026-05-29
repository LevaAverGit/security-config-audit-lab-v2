import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.env_exposure_check import check_env_exposure


def _mock_response(status: int = 200, body: str = ""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def _responses_for(responses: list):
    """Return a side_effect list for sequential requests.get calls."""
    return [_mock_response(*r) for r in responses]


def test_accessible_file_with_sensitive_content_is_failed():
    sensitive_body = "DEMO_SECRET_KEY=demo-secret\nDEMO_DB_PASSWORD=admin123"
    responses = [
        (200, sensitive_body),  # /static/env-demo.txt
        (404, ""),              # /env-demo.txt
        (404, ""),              # /.env
        (404, ""),              # /.env.demo
    ]
    with patch("audit.checks.env_exposure_check.requests.get") as mock_get:
        mock_get.side_effect = _responses_for(responses)
        findings = check_env_exposure("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    assert len(failed) >= 1


def test_accessible_file_has_high_severity_when_sensitive():
    sensitive_body = "demo-secret key here"
    responses = [
        (200, sensitive_body),
        (404, ""),
        (404, ""),
        (404, ""),
    ]
    with patch("audit.checks.env_exposure_check.requests.get") as mock_get:
        mock_get.side_effect = _responses_for(responses)
        findings = check_env_exposure("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    assert failed[0].severity == "High"


def test_accessible_file_without_sensitive_content_is_medium():
    harmless_body = "just a readme file"
    responses = [
        (200, harmless_body),
        (404, ""),
        (404, ""),
        (404, ""),
    ]
    with patch("audit.checks.env_exposure_check.requests.get") as mock_get:
        mock_get.side_effect = _responses_for(responses)
        findings = check_env_exposure("http://localhost:8080")
    failed = [f for f in findings if f.status == "failed"]
    assert failed[0].severity == "Medium"


def test_all_paths_blocked_produces_only_passed():
    responses = [(404, "")] * 4
    with patch("audit.checks.env_exposure_check.requests.get") as mock_get:
        mock_get.side_effect = _responses_for(responses)
        findings = check_env_exposure("http://localhost:8081")
    failed = [f for f in findings if f.status == "failed"]
    passed = [f for f in findings if f.status == "passed"]
    assert len(failed) == 0
    assert len(passed) == 4


def test_finding_id_is_env_001():
    responses = [(200, "demo-secret")] + [(404, "")] * 3
    with patch("audit.checks.env_exposure_check.requests.get") as mock_get:
        mock_get.side_effect = _responses_for(responses)
        findings = check_env_exposure("http://localhost:8080")
    assert all(f.id == "ENV-001" for f in findings)


def test_network_error_is_skipped_not_crashed():
    with patch("audit.checks.env_exposure_check.requests.get", side_effect=Exception("timeout")):
        findings = check_env_exposure("http://localhost:9999")
    # all paths raise exception → skipped → no findings
    assert findings == []
