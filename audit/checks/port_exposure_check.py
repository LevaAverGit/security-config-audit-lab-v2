from __future__ import annotations

import socket
from typing import List

from audit.models import Finding


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def check_port_exposure(host: str = "localhost") -> List[Finding]:
    port = 5432
    is_open = _port_open(host, port)

    if is_open:
        return [Finding(
            id="PORT-001",
            title="PostgreSQL port 5432 exposed on host",
            severity="High",
            status="failed",
            description=f"Port {port} (PostgreSQL) is accessible on {host}.",
            evidence=f"TCP connection to {host}:{port} succeeded",
            risk="Exposed database ports increase attack surface. Direct access enables brute-force and exploitation attempts.",
            recommendation="Remove port mapping from docker-compose.yml. Database should only be accessible within the Docker network.",
        )]

    return [Finding(
        id="PORT-001",
        title="PostgreSQL port 5432 not exposed on host",
        severity="High",
        status="passed",
        description=f"Port {port} is not accessible from the host.",
        evidence=f"TCP connection to {host}:{port} refused or timed out",
        risk="",
        recommendation="",
    )]
