from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

HSTS_HEADER = "Strict-Transport-Security"


def check_hsts(target: str) -> List[Finding]:
    try:
        resp = requests.get(target, timeout=5)
    except Exception as e:
        return [Finding(
            id="HSTS-001",
            title="Target unreachable for HSTS check",
            severity="Medium",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    if HSTS_HEADER not in resp.headers:
        return [Finding(
            id="HSTS-001",
            title="HSTS header missing",
            severity="Medium",
            status="failed",
            description="The Strict-Transport-Security header is not present.",
            evidence=f"Header '{HSTS_HEADER}' not found in response from {target}",
            risk="Without HSTS, browsers may connect over HTTP, enabling downgrade attacks.",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to nginx configuration.",
        )]

    return [Finding(
        id="HSTS-001",
        title="HSTS header present",
        severity="Medium",
        status="passed",
        description=f"{HSTS_HEADER} is present.",
        evidence=f"{HSTS_HEADER}: {resp.headers[HSTS_HEADER]}",
        risk="",
        recommendation="",
    )]
