from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

# A deliberately obvious attack payload. A WAF (e.g. ModSecurity + OWASP CRS)
# should block this with 403/406; an unprotected app will process it (200).
ATTACK_PARAMS = {"q": "<script>alert(1)</script>' OR '1'='1"}
BLOCKED_STATUSES = (403, 406)


def check_waf(target: str) -> List[Finding]:
    """Probes for a WAF by sending an attack payload and inspecting the response."""
    try:
        resp = requests.get(target, params=ATTACK_PARAMS, timeout=5)
    except Exception as e:
        return [Finding(
            id="WAF-001",
            title="Target unreachable for WAF check",
            severity="Medium",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    if resp.status_code in BLOCKED_STATUSES:
        return [Finding(
            id="WAF-001",
            title="WAF blocked a malicious request",
            severity="Low",
            status="passed",
            description="A request carrying an XSS/SQLi payload was rejected, indicating a WAF is present.",
            evidence=f"Attack payload returned HTTP {resp.status_code}",
            risk="",
            recommendation="",
        )]

    return [Finding(
        id="WAF-001",
        title="No WAF detected in front of the application",
        severity="Low",
        status="warning",
        description="An obvious XSS/SQLi payload was not blocked; no web application firewall appears to be filtering requests.",
        evidence=f"Attack payload returned HTTP {resp.status_code} (expected 403/406 if a WAF were present)",
        risk="Without a WAF, exploit attempts reach the application directly, removing a layer of defence-in-depth.",
        recommendation="Deploy a WAF such as ModSecurity with the OWASP Core Rule Set in front of the app (see docs/WAF.md).",
    )]
