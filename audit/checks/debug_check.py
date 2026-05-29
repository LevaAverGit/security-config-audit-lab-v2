from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

DEBUG_KEYWORDS = ["flask_debug", "flask_env", "secret_key", "db_user", "debug", "traceback"]


def check_debug_endpoint(target: str) -> List[Finding]:
    url = target.rstrip("/") + "/debug"
    try:
        resp = requests.get(url, timeout=5)
    except Exception as e:
        return [Finding(
            id="DBG-001",
            title="Debug endpoint check failed",
            severity="High",
            status="failed",
            description="Could not reach /debug endpoint.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    if resp.status_code in (404, 403):
        return [Finding(
            id="DBG-001",
            title="Debug endpoint not accessible",
            severity="High",
            status="passed",
            description=f"/debug returned HTTP {resp.status_code}",
            evidence=f"HTTP {resp.status_code} for {url}",
            risk="",
            recommendation="",
        )]

    body = resp.text.lower()
    exposes_info = any(kw in body for kw in DEBUG_KEYWORDS)

    return [Finding(
        id="DBG-001",
        title="Debug endpoint accessible" + (" and exposes config" if exposes_info else ""),
        severity="High" if exposes_info else "Medium",
        status="failed",
        description=f"/debug is publicly accessible (HTTP {resp.status_code})" +
                    (" and appears to expose environment/config information." if exposes_info else "."),
        evidence=f"HTTP {resp.status_code} for {url}; response contains debug indicators: {exposes_info}",
        risk="Exposed debug endpoints may leak environment variables, credentials, and system info.",
        recommendation="Disable debug endpoint in production. Return 404 or remove the route entirely.",
    )]
