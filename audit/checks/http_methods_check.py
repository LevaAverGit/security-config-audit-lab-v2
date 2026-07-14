from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

# Methods that should almost never be enabled on a web server.
DANGEROUS_METHODS = ("TRACE", "TRACK", "CONNECT", "PUT", "DELETE")


def check_http_methods(target: str) -> List[Finding]:
    """Sends an OPTIONS request and flags dangerous HTTP methods in the Allow header."""
    try:
        resp = requests.options(target, timeout=5)
    except Exception as e:
        return [Finding(
            id="HTTP-METHODS-001",
            title="Target unreachable for HTTP methods check",
            severity="Medium",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    allow = resp.headers.get("Allow", "")
    allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}
    found = sorted(allowed & set(DANGEROUS_METHODS))

    if found:
        return [Finding(
            id="HTTP-METHODS-001",
            title=f"Dangerous HTTP methods enabled: {', '.join(found)}",
            severity="Medium",
            status="failed",
            description="The server advertises HTTP methods that are rarely needed and expand the attack surface.",
            evidence=f"Allow: {allow}",
            risk="TRACE enables Cross-Site Tracing; PUT/DELETE can allow unauthorized file changes; CONNECT can enable proxying.",
            recommendation="Disable unused methods; allow only GET, HEAD, POST (and OPTIONS) as required.",
        )]

    return [Finding(
        id="HTTP-METHODS-001",
        title="No dangerous HTTP methods enabled",
        severity="Low",
        status="passed",
        description="The server does not advertise TRACE, TRACK, CONNECT, PUT, or DELETE.",
        evidence=f"Allow: {allow}" if allow else "No dangerous methods in Allow header",
        risk="",
        recommendation="",
    )]
