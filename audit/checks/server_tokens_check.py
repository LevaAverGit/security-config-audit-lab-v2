from __future__ import annotations

from typing import List

import requests

from audit.models import Finding


def check_server_tokens(target: str) -> List[Finding]:
    try:
        resp = requests.get(target, timeout=5)
    except Exception as e:
        return [Finding(
            id="SRV-001",
            title="Target unreachable for server tokens check",
            severity="High",
            status="failed",
            description="Could not connect.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    server = resp.headers.get("Server", "")
    if not server:
        return [Finding(
            id="SRV-001",
            title="Server header absent",
            severity="Low",
            status="passed",
            description="No Server header in response.",
            evidence="Server header not present",
            risk="",
            recommendation="",
        )]

    # Check if version is disclosed (e.g. "nginx/1.25.3")
    if "/" in server or any(c.isdigit() for c in server):
        return [Finding(
            id="SRV-001",
            title="Server version disclosed",
            severity="Low",
            status="failed",
            description="The Server header reveals software version information.",
            evidence=f"Server: {server}",
            risk="Version disclosure aids fingerprinting and targeted attacks.",
            recommendation="Set 'server_tokens off' in nginx.conf.",
        )]

    return [Finding(
        id="SRV-001",
        title="Server header present but no version",
        severity="Low",
        status="passed",
        description="Server header present without version disclosure.",
        evidence=f"Server: {server}",
        risk="",
        recommendation="",
    )]
