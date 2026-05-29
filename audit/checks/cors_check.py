from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

CORS_HEADER = "Access-Control-Allow-Origin"
WILDCARD = "*"


def check_cors(target: str) -> List[Finding]:
    try:
        resp = requests.get(target, timeout=5, headers={"Origin": "https://evil.example.com"})
    except Exception as e:
        return [Finding(
            id="CORS-001",
            title="Target unreachable for CORS check",
            severity="Medium",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    cors_value = resp.headers.get(CORS_HEADER, "")

    if cors_value == WILDCARD:
        return [Finding(
            id="CORS-001",
            title="Permissive CORS policy: wildcard origin",
            severity="Medium",
            status="failed",
            description=f"{CORS_HEADER} is set to '*', allowing any origin.",
            evidence=f"{CORS_HEADER}: {cors_value}",
            risk="Wildcard CORS allows any domain to make cross-origin requests, which may expose sensitive data to malicious sites.",
            recommendation="Restrict Access-Control-Allow-Origin to specific trusted domains.",
        )]

    if not cors_value:
        return [Finding(
            id="CORS-001",
            title="CORS header absent",
            severity="Low",
            status="passed",
            description="No Access-Control-Allow-Origin header present — cross-origin requests are not explicitly permitted.",
            evidence=f"Header '{CORS_HEADER}' not present in response",
            risk="",
            recommendation="",
        )]

    return [Finding(
        id="CORS-001",
        title="CORS header present with specific origin",
        severity="Low",
        status="passed",
        description=f"{CORS_HEADER} is set to a specific origin.",
        evidence=f"{CORS_HEADER}: {cors_value}",
        risk="",
        recommendation="",
    )]
