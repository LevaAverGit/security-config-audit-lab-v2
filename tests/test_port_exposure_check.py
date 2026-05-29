import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.port_exposure_check import check_port_exposure, _port_open


def test_port_open_returns_failed_finding():
    with patch("audit.checks.port_exposure_check._port_open", return_value=True):
        findings = check_port_exposure("localhost")
    assert findings[0].status == "failed"
    assert findings[0].id == "PORT-001"


def test_port_closed_returns_passed_finding():
    with patch("audit.checks.port_exposure_check._port_open", return_value=False):
        findings = check_port_exposure("localhost")
    assert findings[0].status == "passed"
    assert findings[0].id == "PORT-001"


def test_port_open_severity_is_high():
    with patch("audit.checks.port_exposure_check._port_open", return_value=True):
        findings = check_port_exposure("localhost")
    assert findings[0].severity == "High"


def test_port_closed_severity_is_high():
    with patch("audit.checks.port_exposure_check._port_open", return_value=False):
        findings = check_port_exposure("localhost")
    assert findings[0].severity == "High"


def test_port_open_evidence_mentions_host_and_port():
    with patch("audit.checks.port_exposure_check._port_open", return_value=True):
        findings = check_port_exposure("localhost")
    assert "localhost" in findings[0].evidence
    assert "5432" in findings[0].evidence


def test_port_closed_evidence_mentions_refused():
    with patch("audit.checks.port_exposure_check._port_open", return_value=False):
        findings = check_port_exposure("localhost")
    assert "5432" in findings[0].evidence


def test_port_open_helper_connection_refused():
    import socket
    with patch("socket.create_connection", side_effect=ConnectionRefusedError):
        result = _port_open("localhost", 5432)
    assert result is False


def test_port_open_helper_success():
    from unittest.mock import MagicMock
    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    with patch("socket.create_connection", return_value=mock_conn):
        result = _port_open("localhost", 5432)
    assert result is True
