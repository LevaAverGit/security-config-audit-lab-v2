from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("HDR-CSP", "Medium"),
    "X-Frame-Options": ("HDR-XFO", "Medium"),
    "X-Content-Type-Options": ("HDR-XCTO", "Low"),
    "Referrer-Policy": ("HDR-RP", "Low"),
    "Permissions-Policy": ("HDR-PP", "Low"),
}


def check_security_headers(target: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        resp = requests.get(target, timeout=5)
        headers = resp.headers
    except Exception as e:
        findings.append(Finding(
            id="HDR-000",
            title="Target unreachable",
            severity="High",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Audit could not complete.",
            recommendation="Ensure the target is running and accessible.",
        ))
        return findings

    for header, (finding_id, severity) in REQUIRED_HEADERS.items():
        if header not in headers:
            findings.append(Finding(
                id=finding_id,
                title=f"Missing header: {header}",
                severity=severity,
                status="failed",
                description=f"The HTTP response does not include the {header} header.",
                evidence=f"Header '{header}' not present in response from {target}",
                risk="Browser security controls may not be enforced.",
                recommendation=f"Add '{header}' to server or nginx configuration.",
            ))
        else:
            findings.append(Finding(
                id=finding_id,
                title=f"Header present: {header}",
                severity=severity,
                status="passed",
                description=f"{header} is present.",
                evidence=f"{header}: {headers[header]}",
                risk="",
                recommendation="",
            ))

    return findings
